// BIMI Record Checker - Brand Indicators for Message Identification

///| BIMI Record
pub(all) struct BimiRecord {
  version : String    // BIMI1
  location : String   // Logo SVG URL (l=)
  authority : String  // VMC certificate URL (a=)
}

///| BIMI Validation Result
pub(all) struct BimiResult {
  valid : Bool
  record : BimiRecord?
  errors : Array[String]
  warnings : Array[String]
}

///| Parse BIMI TXT record
fn parse_bimi(raw : String) -> BimiRecord? {
  let mut version = ""
  let mut location = ""
  let mut authority = ""

  // Format: v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem;
  let parts = split_semicolon(raw)
  for part in parts {
    let trimmed = part.trim().to_string()
    if trimmed.has_prefix("v=") {
      version = safe_substr_from(trimmed, 2)
    } else if trimmed.has_prefix("l=") {
      location = safe_substr_from(trimmed, 2)
    } else if trimmed.has_prefix("a=") {
      authority = safe_substr_from(trimmed, 2)
    }
  }

  if version.is_empty() {
    return None
  }

  Some(BimiRecord::{ version, location, authority })
}

///| Split by semicolon
fn split_semicolon(s : String) -> Array[String] {
  let parts : Array[String] = []
  let current = StringBuilder::new()
  for c in s {
    if c == ';' {
      let part = current.to_string()
      if not(part.is_empty()) {
        parts.push(part)
      }
      current.reset()
    } else {
      current.write_char(c)
    }
  }
  let last = current.to_string()
  if not(last.is_empty()) {
    parts.push(last)
  }
  parts
}

///| Safe substring from start
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

///| Remove quotes
fn unquote(s : String) -> String {
  let result = StringBuilder::new()
  for c in s {
    if c != '"' {
      result.write_char(c)
    }
  }
  result.to_string()
}

///| Check BIMI record for domain
#cfg(target = "native")
pub async fn check(domain : String) -> BimiResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []

  // BIMI uses default._bimi subdomain
  let query_domain = "default._bimi." + domain
  let result = @dns.query(query_domain, TXT)

  if not(result.success) || result.records.length() == 0 {
    return {
      valid: true,  // BIMI is optional
      record: None,
      errors: [],
      warnings: ["No BIMI record found - no brand logo for email clients"],
    }
  }

  // Find BIMI record
  for line in result.records {
    let unquoted = unquote(line.trim().to_string())
    if unquoted.has_prefix("v=BIMI1") {
      match parse_bimi(unquoted) {
        Some(rec) => {
          // Validate version
          if rec.version != "BIMI1" {
            errors.push("Invalid BIMI version: " + rec.version)
            return { valid: false, record: Some(rec), errors, warnings }
          }

          // Check location
          if rec.location.is_empty() {
            warnings.push("BIMI record missing logo location (l=)")
          } else if not(rec.location.has_prefix("https://")) {
            warnings.push("BIMI logo should use HTTPS: " + rec.location)
          }

          // Authority (VMC) is recommended but not required
          if rec.authority.is_empty() {
            warnings.push("No VMC certificate (a=) - logo may not display in all clients")
          }

          return { valid: true, record: Some(rec), errors, warnings }
        }
        None => ()
      }
    }
  }

  {
    valid: true,
    record: None,
    errors: [],
    warnings: ["No valid BIMI record found"],
  }
}
