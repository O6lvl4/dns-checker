// DKIM Parser and Validator - RFC 6376

///| Common DKIM selectors used by various providers
let common_selectors : Array[String] = [
  "selector1",      // Microsoft 365
  "selector2",      // Microsoft 365
  "google",         // Google Workspace (legacy)
  "default",        // Common default
  "s1",             // Generic
  "s2",             // Generic
  "k1",             // Mailchimp
  "k2",             // Mailchimp
  "dkim",           // Generic
  "mail",           // Generic
  "smtp",           // Generic
  "mx",             // Generic
  "email",          // Generic
  "mandrill",       // Mandrill
  "everlytickey1",  // Everlytic
  "everlytickey2",  // Everlytic
  "cm",             // Campaign Monitor
  "amazonses",      // Amazon SES
  "postmark",       // Postmark
]

///| DKIM Key Type (RFC 6376 Section 3.6.1)
pub(all) enum KeyType {
  Rsa     // rsa (default)
  Ed25519 // ed25519
}

///| Convert KeyType to string
pub fn KeyType::to_string(self : KeyType) -> String {
  match self {
    Rsa => "rsa"
    Ed25519 => "ed25519"
  }
}

///| Parse key type from string
fn parse_key_type(s : String) -> KeyType {
  match s.to_lower() {
    "ed25519" => Ed25519
    _ => Rsa  // Default
  }
}

///| DKIM Service Type (RFC 6376 Section 3.6.1)
pub(all) enum ServiceType {
  Email  // email (default)
  All    // * (any)
}

///| DKIM Flags (RFC 6376 Section 3.6.1)
pub(all) enum DkimFlag {
  Testing      // y: Domain is testing DKIM
  NoSubdomain  // s: No subdomaining
}

///| Parsed DKIM Record
pub(all) struct DkimRecord {
  pub version : String          // v (optional, should be DKIM1)
  pub key_type : KeyType        // k (default: rsa)
  pub public_key : String       // p (required, base64 encoded)
  pub hash_algorithms : Array[String]  // h (optional)
  pub notes : String            // n (optional)
  pub service_types : Array[ServiceType]  // s (optional)
  pub flags : Array[DkimFlag]   // t (optional)
  pub selector : String         // The selector used
  pub domain : String           // The domain
  pub raw : String
}

///| DKIM Validation Result for a single selector
pub(all) struct DkimSelectorResult {
  pub selector : String
  pub found : Bool
  pub record : DkimRecord?
  pub errors : Array[String]
  pub warnings : Array[String]
}

///| DKIM Validation Result (overall)
pub(all) struct DkimResult {
  pub valid : Bool
  pub selectors_checked : Int
  pub selectors_found : Int
  pub results : Array[DkimSelectorResult]
  pub errors : Array[String]
}

///| Parse DKIM record from string
pub fn parse(raw : String, selector : String, domain : String) -> DkimSelectorResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []

  let normalized = raw.trim().to_string()

  if normalized.is_empty() {
    return {
      selector,
      found: false,
      record: None,
      errors: ["Empty DKIM record"],
      warnings: []
    }
  }

  // Parse tags (semicolon-separated)
  let tags = parse_tags(normalized)

  // Check version tag (optional but if present must be DKIM1)
  let version = match get_tag(tags, "v") {
    Some(v) => {
      if v.to_upper() != "DKIM1" {
        warnings.push("DKIM version should be 'DKIM1', got: " + v)
      }
      v
    }
    None => "DKIM1"
  }

  // Get public key (required)
  let public_key = match get_tag(tags, "p") {
    Some(p) => {
      if p.is_empty() {
        errors.push("Public key (p=) is empty - key has been revoked")
      }
      p
    }
    None => {
      errors.push("Missing required public key (p=) tag")
      ""
    }
  }

  // Parse key type (default: rsa)
  let key_type = match get_tag(tags, "k") {
    Some(k) => parse_key_type(k)
    None => Rsa
  }

  // Parse hash algorithms
  let hash_algorithms = match get_tag(tags, "h") {
    Some(h) => split_by_colon(h)
    None => []
  }

  // Parse notes
  let notes = get_tag(tags, "n").or("")

  // Parse service types
  let service_types = match get_tag(tags, "s") {
    Some(s) => parse_service_types(s)
    None => [Email]
  }

  // Parse flags
  let flags = match get_tag(tags, "t") {
    Some(t) => parse_flags(t)
    None => []
  }

  // Check for testing flag
  for flag in flags {
    match flag {
      Testing => warnings.push("Domain is in DKIM testing mode (t=y)")
      _ => ()
    }
  }

  let record = DkimRecord::{
    version,
    key_type,
    public_key,
    hash_algorithms,
    notes,
    service_types,
    flags,
    selector,
    domain,
    raw: normalized,
  }

  {
    selector,
    found: true,
    record: Some(record),
    errors,
    warnings,
  }
}

///| Parse tags from DKIM record
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
  None
}

///| Split string by semicolon
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

///| Split string by colon
fn split_by_colon(s : String) -> Array[String] {
  split_by_char(s, ':')
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

///| Parse service types
fn parse_service_types(s : String) -> Array[ServiceType] {
  let types : Array[ServiceType] = []
  let parts = split_by_colon(s)
  for part in parts {
    match part.trim().to_string() {
      "*" => types.push(All)
      "email" => types.push(Email)
      _ => types.push(Email)  // Default to email
    }
  }
  if types.length() == 0 {
    types.push(Email)
  }
  types
}

///| Parse flags
fn parse_flags(s : String) -> Array[DkimFlag] {
  let flags : Array[DkimFlag] = []
  let parts = split_by_colon(s)
  for part in parts {
    match part.trim().to_string() {
      "y" => flags.push(Testing)
      "s" => flags.push(NoSubdomain)
      _ => ()
    }
  }
  flags
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

///| Check a single DKIM selector
#cfg(target = "native")
pub async fn check_selector(domain : String, selector : String) -> DkimSelectorResult {
  let dkim_host = selector + "._domainkey." + domain
  let result = @dns.query_txt(dkim_host)

  if not(result.success) {
    return {
      selector,
      found: false,
      record: None,
      errors: ["DNS query failed: " + result.error],
      warnings: []
    }
  }

  if result.records.length() == 0 {
    return {
      selector,
      found: false,
      record: None,
      errors: [],
      warnings: []
    }
  }

  // Concatenate TXT records (DKIM can be split across multiple strings)
  let full_record = StringBuilder::new()
  for record in result.records {
    full_record.write_string(@dns.strip_quotes(record))
  }

  parse(full_record.to_string(), selector, domain)
}

///| Check DKIM with common selectors
#cfg(target = "native")
pub async fn check(domain : String) -> DkimResult {
  let results : Array[DkimSelectorResult] = []
  let mut found_count = 0

  for selector in common_selectors {
    let result = check_selector(domain, selector)
    if result.found {
      found_count = found_count + 1
      results.push(result)
    }
  }

  {
    valid: found_count > 0,
    selectors_checked: common_selectors.length(),
    selectors_found: found_count,
    results,
    errors: if found_count == 0 { ["No DKIM records found for common selectors"] } else { [] }
  }
}

///| Check DKIM with specific selectors
#cfg(target = "native")
pub async fn check_with_selectors(domain : String, selectors : Array[String]) -> DkimResult {
  let results : Array[DkimSelectorResult] = []
  let mut found_count = 0

  for selector in selectors {
    let result = check_selector(domain, selector)
    results.push(result)
    if result.found {
      found_count = found_count + 1
    }
  }

  {
    valid: found_count > 0,
    selectors_checked: selectors.length(),
    selectors_found: found_count,
    results,
    errors: if found_count == 0 { ["No DKIM records found"] } else { [] }
  }
}

///| Format DKIM result for display
pub fn format_result(result : DkimResult) -> String {
  let sb = StringBuilder::new()

  if result.valid {
    sb.write_string("DKIM: Valid\n")
  } else {
    sb.write_string("DKIM: Invalid\n")
  }

  sb.write_string("  Selectors checked: " + result.selectors_checked.to_string() + "\n")
  sb.write_string("  Selectors found: " + result.selectors_found.to_string() + "\n")

  for r in result.results {
    sb.write_string("\n  Selector: " + r.selector + "\n")
    match r.record {
      Some(rec) => {
        sb.write_string("    Key Type: " + rec.key_type.to_string() + "\n")
        sb.write_string("    Public Key: " + (if rec.public_key.length() > 40 { rec.public_key.substring(end=40) + "..." } else { rec.public_key }) + "\n")
        if rec.hash_algorithms.length() > 0 {
          sb.write_string("    Hash Algorithms: " + rec.hash_algorithms.length().to_string() + "\n")
        }
      }
      None => ()
    }

    if r.errors.length() > 0 {
      for err in r.errors {
        sb.write_string("    Error: " + err + "\n")
      }
    }

    if r.warnings.length() > 0 {
      for warn in r.warnings {
        sb.write_string("    Warning: " + warn + "\n")
      }
    }
  }

  if result.errors.length() > 0 {
    sb.write_string("\n  Errors:\n")
    for err in result.errors {
      sb.write_string("    - " + err + "\n")
    }
  }

  sb.to_string()
}
