// SPF Parser and Validator - RFC 7208

///| SPF Qualifier (RFC 7208 Section 4.6.2)
pub(all) enum Qualifier {
  Pass      // + (default)
  Fail      // -
  SoftFail  // ~
  Neutral   // ?
}

///| Convert Qualifier to string
pub fn Qualifier::to_string(self : Qualifier) -> String {
  match self {
    Pass => "+"
    Fail => "-"
    SoftFail => "~"
    Neutral => "?"
  }
}

///| Parse qualifier from character
fn parse_qualifier(c : Char) -> Qualifier? {
  match c {
    '+' => Some(Pass)
    '-' => Some(Fail)
    '~' => Some(SoftFail)
    '?' => Some(Neutral)
    _ => None
  }
}

///| SPF Mechanism Types (RFC 7208 Section 5)
pub(all) enum MechanismType {
  All                     // all
  Include(String)         // include:<domain>
  A(String?)              // a or a:<domain>
  Mx(String?)             // mx or mx:<domain>
  Ptr(String?)            // ptr or ptr:<domain> (deprecated)
  Ip4(String)             // ip4:<ip4-network>
  Ip6(String)             // ip6:<ip6-network>
  Exists(String)          // exists:<domain>
}

///| SPF Mechanism with qualifier
pub(all) struct Mechanism {
  qualifier : Qualifier
  mechanism : MechanismType
}

///| Check if mechanism requires DNS lookup
pub fn MechanismType::requires_dns_lookup(self : MechanismType) -> Bool {
  match self {
    All => false
    Ip4(_) => false
    Ip6(_) => false
    _ => true
  }
}

///| SPF Modifier Types (RFC 7208 Section 6)
pub(all) enum Modifier {
  Redirect(String)  // redirect=<domain>
  Exp(String)       // exp=<domain>
  Unknown(String, String)  // unknown modifiers
}

///| Parsed SPF Record
pub(all) struct SpfRecord {
  version : String // Should be "spf1"
  mechanisms : Array[Mechanism]
  modifiers : Array[Modifier]
  raw : String
}

///| SPF Validation Result
pub(all) struct SpfResult {
  valid : Bool
  record : SpfRecord?
  errors : Array[String]
  warnings : Array[String]
  dns_lookup_count : Int
}

///| Create empty SPF result
pub fn SpfResult::empty() -> SpfResult {
  { valid: false, record: None, errors: [], warnings: [], dns_lookup_count: 0 }
}

///| Parse SPF record from string
pub fn parse(raw : String) -> SpfResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []
  let mechanisms : Array[Mechanism] = []
  let modifiers : Array[Modifier] = []

  // Normalize: remove extra spaces, convert to lowercase for parsing
  let normalized = raw.trim().to_string()

  if normalized.is_empty() {
    errors.push("Empty SPF record")
    return { valid: false, record: None, errors, warnings, dns_lookup_count: 0 }
  }

  // Split into terms
  let terms = split_terms(normalized)

  if terms.length() == 0 {
    errors.push("No terms found in SPF record")
    return { valid: false, record: None, errors, warnings, dns_lookup_count: 0 }
  }

  // First term must be version
  let first = terms[0]
  if not(first.to_lower() == "v=spf1") {
    errors.push("SPF record must start with 'v=spf1', got: " + first)
    return { valid: false, record: None, errors, warnings, dns_lookup_count: 0 }
  }

  // Parse remaining terms
  for i in 1..<terms.length() {
    let term = terms[i]
    if term.contains("=") {
      // It's a modifier
      match parse_modifier(term) {
        Some(m) => modifiers.push(m)
        None => errors.push("Invalid modifier: " + term)
      }
    } else {
      // It's a mechanism
      match parse_mechanism(term) {
        Some(m) => {
          // Check for deprecated ptr mechanism
          match m.mechanism {
            Ptr(_) => warnings.push("'ptr' mechanism is deprecated (RFC 7208 Section 5.5)")
            _ => ()
          }
          mechanisms.push(m)
        }
        None => errors.push("Invalid mechanism: " + term)
      }
    }
  }

  // Count DNS lookups
  let mut dns_lookups = 0
  for m in mechanisms {
    if m.mechanism.requires_dns_lookup() {
      dns_lookups = dns_lookups + 1
    }
  }
  for modifier in modifiers {
    match modifier {
      Redirect(_) => dns_lookups = dns_lookups + 1
      _ => ()
    }
  }

  // Check DNS lookup limit (RFC 7208 Section 4.6.4)
  if dns_lookups > 10 {
    errors.push("Too many DNS lookups: " + dns_lookups.to_string() + " (max 10 allowed)")
  }

  let record = SpfRecord::{
    version: "spf1",
    mechanisms,
    modifiers,
    raw: normalized,
  }

  {
    valid: errors.length() == 0,
    record: Some(record),
    errors,
    warnings,
    dns_lookup_count: dns_lookups,
  }
}

///| Split SPF record into terms (space-separated)
fn split_terms(s : String) -> Array[String] {
  let terms : Array[String] = []
  let current = StringBuilder::new()

  for c in s {
    if c == ' ' || c == '\t' {
      let term = current.to_string()
      if not(term.is_empty()) {
        terms.push(term)
      }
      current.reset()
    } else {
      current.write_char(c)
    }
  }

  let last = current.to_string()
  if not(last.is_empty()) {
    terms.push(last)
  }

  terms
}

///| Parse a single mechanism
fn parse_mechanism(term : String) -> Mechanism? {
  if term.is_empty() {
    return None
  }

  // Check for qualifier prefix - get first char safely
  let first_char = get_first_char(term)
  let (qualifier, rest) = match first_char {
    Some(c) =>
      match parse_qualifier(c) {
        Some(q) => (q, safe_substr_from(term, 1))
        None => (Pass, term) // Default qualifier is Pass
      }
    None => (Pass, term)
  }

  let lower = rest.to_lower()

  // Parse mechanism type
  let mech_type : MechanismType? = if lower == "all" {
    Some(All)
  } else if lower.has_prefix("include:") {
    Some(Include(safe_substr_from(rest, 8)))
  } else if lower == "a" {
    Some(A(None))
  } else if lower.has_prefix("a:") {
    Some(A(Some(safe_substr_from(rest, 2))))
  } else if lower.has_prefix("a/") {
    Some(A(Some(safe_substr_from(rest, 1)))) // a/cidr format
  } else if lower == "mx" {
    Some(Mx(None))
  } else if lower.has_prefix("mx:") {
    Some(Mx(Some(safe_substr_from(rest, 3))))
  } else if lower.has_prefix("mx/") {
    Some(Mx(Some(safe_substr_from(rest, 1)))) // mx/cidr format
  } else if lower == "ptr" {
    Some(Ptr(None))
  } else if lower.has_prefix("ptr:") {
    Some(Ptr(Some(safe_substr_from(rest, 4))))
  } else if lower.has_prefix("ip4:") {
    Some(Ip4(safe_substr_from(rest, 4)))
  } else if lower.has_prefix("ip6:") {
    Some(Ip6(safe_substr_from(rest, 4)))
  } else if lower.has_prefix("exists:") {
    Some(Exists(safe_substr_from(rest, 7)))
  } else {
    None
  }

  match mech_type {
    Some(mt) => Some(Mechanism::{ qualifier, mechanism: mt })
    None => None
  }
}

///| Parse a modifier
fn parse_modifier(term : String) -> Modifier? {
  let idx = find_char(term, '=')
  if idx < 0 {
    return None
  }

  let name = safe_substr_to(term, idx).to_lower()
  let value = safe_substr_from(term, idx + 1)

  if name == "redirect" {
    Some(Redirect(value))
  } else if name == "exp" {
    Some(Exp(value))
  } else {
    Some(Unknown(name, value))
  }
}

///| Find character in string, return index or -1
fn find_char(s : String, c : Char) -> Int {
  for i, ch in s {
    if ch == c {
      return i
    }
  }
  -1
}

///| Get first character from string safely
fn get_first_char(s : String) -> Char? {
  for c in s {
    return Some(c)
  }
  None
}

///| Safe substring from start index
fn safe_substr_from(s : String, start : Int) -> String {
  if start >= s.length() {
    return ""
  }
  let result = StringBuilder::new()
  for i, c in s {
    if i >= start {
      result.write_char(c)
    }
  }
  result.to_string()
}

///| Safe substring to end index
fn safe_substr_to(s : String, end_ : Int) -> String {
  let result = StringBuilder::new()
  for i, c in s {
    if i >= end_ {
      break
    }
    result.write_char(c)
  }
  result.to_string()
}

///| Check SPF record from DNS query
#cfg(target = "native")
pub async fn check(domain : String) -> SpfResult {
  let result = @dns.query_txt(domain)

  if not(result.success) {
    return {
      valid: false,
      record: None,
      errors: ["DNS query failed: " + result.error],
      warnings: [],
      dns_lookup_count: 0
    }
  }

  // Find SPF record among TXT records
  for record in result.records {
    let stripped = @dns.strip_quotes(record)
    if stripped.to_lower().has_prefix("v=spf1") {
      return parse(stripped)
    }
  }

  {
    valid: false,
    record: None,
    errors: ["No SPF record found"],
    warnings: [],
    dns_lookup_count: 0
  }
}

///| Format SPF result for display
pub fn format_result(result : SpfResult) -> String {
  let sb = StringBuilder::new()

  if result.valid {
    sb.write_string("SPF: Valid\n")
  } else {
    sb.write_string("SPF: Invalid\n")
  }

  match result.record {
    Some(r) => {
      sb.write_string("  Raw: " + r.raw + "\n")
      sb.write_string("  Mechanisms: " + r.mechanisms.length().to_string() + "\n")
      sb.write_string("  Modifiers: " + r.modifiers.length().to_string() + "\n")
    }
    None => ()
  }

  sb.write_string("  DNS Lookups: " + result.dns_lookup_count.to_string() + "/10\n")

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
