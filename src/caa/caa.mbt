// CAA Record Checker - RFC 8659

///| CAA Record entry
pub(all) struct CaaRecord {
  flags : Int
  tag : String      // issue, issuewild, iodef
  value : String
}

///| CAA Validation Result
pub(all) struct CaaResult {
  valid : Bool
  records : Array[CaaRecord]
  errors : Array[String]
  warnings : Array[String]
}

///| Parse integer from string
fn parse_int(s : String) -> Int? {
  let mut result = 0
  let mut has_digit = false
  for c in s {
    let code = c.to_int()
    if code >= 48 && code <= 57 {
      result = result * 10 + (code - 48)
      has_digit = true
    } else {
      return None
    }
  }
  if has_digit { Some(result) } else { None }
}

///| Parse CAA record line
fn parse_caa_line(line : String) -> CaaRecord? {
  // Format: flags tag "value"
  let parts = split_parts(line)
  if parts.length() < 3 {
    return None
  }

  let flags = match parse_int(parts[0]) {
    Some(n) => n
    None => return None
  }

  let tag = parts[1]

  // Value may be quoted
  let value = if parts.length() >= 3 {
    unquote(parts[2])
  } else {
    ""
  }

  Some(CaaRecord::{ flags, tag, value })
}

///| Split into parts, respecting quotes
fn split_parts(s : String) -> Array[String] {
  let parts : Array[String] = []
  let current = StringBuilder::new()
  let mut in_quote = false

  for c in s {
    if c == '"' {
      in_quote = not(in_quote)
    } else if (c == ' ' || c == '\t') && not(in_quote) {
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

///| Remove quotes from string
fn unquote(s : String) -> String {
  let result = StringBuilder::new()
  for c in s {
    if c != '"' {
      result.write_char(c)
    }
  }
  result.to_string()
}

///| Check CAA records for domain
#cfg(target = "native")
pub async fn check(domain : String) -> CaaResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []
  let records : Array[CaaRecord] = []

  let result = @dns.query(domain, CAA)

  if not(result.success) {
    // CAA records are optional
    return {
      valid: true,
      records: [],
      errors: [],
      warnings: ["No CAA records found - any CA can issue certificates"],
    }
  }

  for line in result.records {
    let trimmed = line.trim().to_string()
    if not(trimmed.is_empty()) {
      match parse_caa_line(trimmed) {
        Some(rec) => records.push(rec)
        None => warnings.push("Failed to parse CAA record: " + trimmed)
      }
    }
  }

  if records.length() == 0 {
    warnings.push("No CAA records found - any CA can issue certificates")
    return { valid: true, records, errors, warnings }
  }

  // Check for required tags
  let mut has_issue = false
  let mut has_issuewild = false
  let mut has_iodef = false

  for rec in records {
    match rec.tag {
      "issue" => has_issue = true
      "issuewild" => has_issuewild = true
      "iodef" => has_iodef = true
      _ => ()
    }
  }

  if not(has_issue) {
    warnings.push("No 'issue' tag - consider adding to restrict certificate issuance")
  }

  if not(has_issuewild) && has_issue {
    warnings.push("No 'issuewild' tag - wildcard certificates follow 'issue' rules")
  }

  if not(has_iodef) {
    warnings.push("No 'iodef' tag - consider adding for violation reports")
  }

  {
    valid: true,
    records,
    errors,
    warnings,
  }
}
