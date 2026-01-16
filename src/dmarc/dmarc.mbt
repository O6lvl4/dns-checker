// DMARC Parser and Validator - RFC 7489

///| DMARC Policy (RFC 7489 Section 6.3)
pub(all) enum Policy {
  None        // Monitor only
  Quarantine  // Treat as suspicious
  Reject      // Reject the message
}

///| Convert Policy to string
pub fn Policy::to_string(self : Policy) -> String {
  match self {
    None => "none"
    Quarantine => "quarantine"
    Reject => "reject"
  }
}

///| Parse policy from string
fn parse_policy(s : String) -> Policy? {
  match s.to_lower() {
    "none" => Some(None)
    "quarantine" => Some(Quarantine)
    "reject" => Some(Reject)
    _ => Option::None
  }
}

///| DKIM Alignment Mode (RFC 7489 Section 6.3)
pub(all) enum AlignmentMode {
  Relaxed  // r (default)
  Strict   // s
}

///| Convert AlignmentMode to string
pub fn AlignmentMode::to_string(self : AlignmentMode) -> String {
  match self {
    Relaxed => "r"
    Strict => "s"
  }
}

///| Parse alignment mode from string
fn parse_alignment(s : String) -> AlignmentMode? {
  match s.to_lower() {
    "r" => Some(Relaxed)
    "s" => Some(Strict)
    _ => Option::None
  }
}

///| Failure Reporting Options (RFC 7489 Section 6.3)
pub(all) enum FailureOption {
  All   // 0: Generate report if all fail
  Any   // 1: Generate report if any fail
  Dkim  // d: DKIM failure
  Spf   // s: SPF failure
}

///| Parsed DMARC Record
pub(all) struct DmarcRecord {
  pub version : String              // v (must be DMARC1)
  pub policy : Policy               // p (required)
  pub subdomain_policy : Policy?    // sp (optional)
  pub rua : Array[String]           // rua (aggregate report URIs)
  pub ruf : Array[String]           // ruf (forensic report URIs)
  pub adkim : AlignmentMode         // adkim (DKIM alignment, default: r)
  pub aspf : AlignmentMode          // aspf (SPF alignment, default: r)
  pub pct : Int                     // pct (percentage, default: 100)
  pub fo : Array[FailureOption]     // fo (failure options)
  pub rf : String                   // rf (report format, default: afrf)
  pub ri : Int                      // ri (report interval in seconds, default: 86400)
  pub raw : String
}

///| DMARC Validation Result
pub(all) struct DmarcResult {
  pub valid : Bool
  pub record : DmarcRecord?
  pub errors : Array[String]
  pub warnings : Array[String]
}

///| Create empty DMARC result
pub fn DmarcResult::empty() -> DmarcResult {
  { valid: false, record: None, errors: [], warnings: [] }
}

///| Parse DMARC record from string
pub fn parse(raw : String) -> DmarcResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []

  let normalized = raw.trim().to_string()

  if normalized.is_empty() {
    errors.push("Empty DMARC record")
    return { valid: false, record: None, errors, warnings }
  }

  // Parse tags (semicolon-separated)
  let tags = parse_tags(normalized)

  // Check version tag (required, must be first and DMARC1)
  let version = get_tag(tags, "v")
  match version {
    Some(v) => {
      if v.to_upper() != "DMARC1" {
        errors.push("Invalid DMARC version: " + v + " (must be DMARC1)")
      }
    }
    Option::None => errors.push("Missing required 'v' tag")
  }

  // Check policy tag (required)
  let policy_str = get_tag(tags, "p")
  let policy : Policy = match policy_str {
    Some(p) => {
      match parse_policy(p) {
        Some(pol) => pol
        Option::None => {
          errors.push("Invalid policy value: " + p)
          None  // Default
        }
      }
    }
    Option::None => {
      errors.push("Missing required 'p' tag")
      None
    }
  }

  // Parse subdomain policy (optional)
  let sp : Policy? = match get_tag(tags, "sp") {
    Some(s) => parse_policy(s)
    Option::None => Option::None
  }

  // Parse aggregate report URIs
  let rua = match get_tag(tags, "rua") {
    Some(s) => parse_uri_list(s)
    Option::None => []
  }

  // Parse forensic report URIs
  let ruf = match get_tag(tags, "ruf") {
    Some(s) => parse_uri_list(s)
    Option::None => []
  }

  // Parse DKIM alignment (default: relaxed)
  let adkim = match get_tag(tags, "adkim") {
    Some(s) => parse_alignment(s).or(Relaxed)
    Option::None => Relaxed
  }

  // Parse SPF alignment (default: relaxed)
  let aspf = match get_tag(tags, "aspf") {
    Some(s) => parse_alignment(s).or(Relaxed)
    Option::None => Relaxed
  }

  // Parse percentage (default: 100)
  let pct = match get_tag(tags, "pct") {
    Some(s) => {
      match parse_int(s) {
        Some(n) => {
          if n < 0 || n > 100 {
            warnings.push("pct value out of range (0-100): " + s)
            100
          } else {
            n
          }
        }
        Option::None => {
          warnings.push("Invalid pct value: " + s)
          100
        }
      }
    }
    Option::None => 100
  }

  // Parse failure options (default: 0)
  let fo = match get_tag(tags, "fo") {
    Some(s) => parse_failure_options(s)
    Option::None => [All]
  }

  // Parse report format (default: afrf)
  let rf = match get_tag(tags, "rf") {
    Some(s) => s
    Option::None => "afrf"
  }

  // Parse report interval (default: 86400 = 24 hours)
  let ri = match get_tag(tags, "ri") {
    Some(s) => parse_int(s).or(86400)
    Option::None => 86400
  }

  // Warnings for missing optional but recommended tags
  if rua.length() == 0 {
    warnings.push("No aggregate report URI (rua) specified - you won't receive reports")
  }

  let record = DmarcRecord::{
    version: "DMARC1",
    policy,
    subdomain_policy: sp,
    rua,
    ruf,
    adkim,
    aspf,
    pct,
    fo,
    rf,
    ri,
    raw: normalized,
  }

  {
    valid: errors.length() == 0,
    record: Some(record),
    errors,
    warnings,
  }
}

///| Parse tags from DMARC record
fn parse_tags(s : String) -> Array[(String, String)] {
  let tags : Array[(String, String)] = []
  let parts = split_by_char(s, ';')

  for part in parts {
    let trimmed = part.trim().to_string()
    if trimmed.is_empty() {
      continue
    }

    let eq_idx = find_char(trimmed, '=')
    if eq_idx > 0 {
      let name = trimmed.substring(end=eq_idx).trim().to_string().to_lower()
      let value = trimmed.substring(start=eq_idx + 1).trim().to_string()
      tags.push((name, value))
    }
  }

  tags
}

///| Get tag value by name
fn get_tag(tags : Array[(String, String)], name : String) -> String? {
  for tag in tags {
    if tag.0 == name {
      return Some(tag.1)
    }
  }
  Option::None
}

///| Parse comma-separated URI list
fn parse_uri_list(s : String) -> Array[String] {
  let uris : Array[String] = []
  let parts = split_by_char(s, ',')
  for part in parts {
    let trimmed = part.trim().to_string()
    if not(trimmed.is_empty()) {
      uris.push(trimmed)
    }
  }
  uris
}

///| Parse failure options
fn parse_failure_options(s : String) -> Array[FailureOption] {
  let options : Array[FailureOption] = []
  for c in s {
    match c {
      '0' => options.push(All)
      '1' => options.push(Any)
      'd' => options.push(Dkim)
      's' => options.push(Spf)
      ':' => ()  // separator
      _ => ()
    }
  }
  if options.length() == 0 {
    options.push(All)
  }
  options
}

///| Split string by character
fn split_by_char(s : String, sep : Char) -> Array[String] {
  let parts : Array[String] = []
  let current = StringBuilder::new()

  for c in s {
    if c == sep {
      parts.push(current.to_string())
      current.reset()
    } else {
      current.write_char(c)
    }
  }

  parts.push(current.to_string())
  parts
}

///| Find character in string
fn find_char(s : String, c : Char) -> Int {
  for i, ch in s {
    if ch == c {
      return i
    }
  }
  -1
}

///| Parse integer from string
fn parse_int(s : String) -> Int? {
  let mut result = 0
  let mut has_digit = false

  for c in s {
    let code = c.to_int()
    if code >= 48 && code <= 57 {  // 0-9
      result = result * 10 + (code - 48)
      has_digit = true
    } else {
      return Option::None
    }
  }

  if has_digit { Some(result) } else { Option::None }
}

///| String to lowercase
fn to_lower(s : String) -> String {
  let result = StringBuilder::new()
  for c in s {
    let code = c.to_int()
    if code >= 65 && code <= 90 {
      result.write_char((code + 32).unsafe_to_char())
    } else {
      result.write_char(c)
    }
  }
  result.to_string()
}

///| String to uppercase
fn to_upper(s : String) -> String {
  let result = StringBuilder::new()
  for c in s {
    let code = c.to_int()
    if code >= 97 && code <= 122 {
      result.write_char((code - 32).unsafe_to_char())
    } else {
      result.write_char(c)
    }
  }
  result.to_string()
}

///| Check DMARC record from DNS query
#cfg(target = "native")
pub async fn check(domain : String) -> DmarcResult {
  let dmarc_host = "_dmarc." + domain
  let result = @dns.query_txt(dmarc_host)

  if not(result.success) {
    return {
      valid: false,
      record: None,
      errors: ["DNS query failed: " + result.error],
      warnings: []
    }
  }

  // Find DMARC record among TXT records
  for record in result.records {
    let stripped = @dns.strip_quotes(record)
    if stripped.to_lower().has_prefix("v=dmarc1") {
      return parse(stripped)
    }
  }

  {
    valid: false,
    record: None,
    errors: ["No DMARC record found at " + dmarc_host],
    warnings: []
  }
}

///| String has_prefix helper
fn has_prefix(s : String, prefix : String) -> Bool {
  if prefix.length() > s.length() {
    return false
  }
  for i in 0..<prefix.length() {
    if s[i] != prefix[i] {
      return false
    }
  }
  true
}

///| Format DMARC result for display
pub fn format_result(result : DmarcResult) -> String {
  let sb = StringBuilder::new()

  if result.valid {
    sb.write_string("DMARC: Valid\n")
  } else {
    sb.write_string("DMARC: Invalid\n")
  }

  match result.record {
    Some(r) => {
      sb.write_string("  Policy: " + r.policy.to_string() + "\n")
      match r.subdomain_policy {
        Some(sp) => sb.write_string("  Subdomain Policy: " + sp.to_string() + "\n")
        Option::None => ()
      }
      sb.write_string("  DKIM Alignment: " + r.adkim.to_string() + "\n")
      sb.write_string("  SPF Alignment: " + r.aspf.to_string() + "\n")
      sb.write_string("  Percentage: " + r.pct.to_string() + "%\n")
      if r.rua.length() > 0 {
        sb.write_string("  Report URIs: " + r.rua.length().to_string() + "\n")
      }
    }
    Option::None => ()
  }

  if result.errors.length() > 0 {
    sb.write_string("  Errors:\n")
    for err in result.errors {
      sb.write_string("    - " + err + "\n")
    }
  }

  if result.warnings.length() > 0 {
    sb.write_string("  Warnings:\n")
    for warn in result.warnings {
      sb.write_string("    - " + warn + "\n")
    }
  }

  sb.to_string()
}
