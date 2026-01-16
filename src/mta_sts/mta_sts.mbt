// MTA-STS Record Checker - RFC 8461

///| MTA-STS Record
pub(all) struct MtaStsRecord {
  version : String   // STSv1
  id : String        // Policy ID
}

///| MTA-STS Validation Result
pub(all) struct MtaStsResult {
  valid : Bool
  record : MtaStsRecord?
  errors : Array[String]
  warnings : Array[String]
}

///| Parse MTA-STS TXT record
fn parse_mta_sts(raw : String) -> MtaStsRecord? {
  let mut version = ""
  let mut id = ""

  // Format: v=STSv1; id=20190425T135201;
  let parts = split_semicolon(raw)
  for part in parts {
    let trimmed = part.trim().to_string()
    if trimmed.has_prefix("v=") {
      version = safe_substr_from(trimmed, 2)
    } else if trimmed.has_prefix("id=") {
      id = safe_substr_from(trimmed, 3)
    }
  }

  if version.is_empty() {
    return None
  }

  Some(MtaStsRecord::{ version, id })
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

///| Check MTA-STS record for domain
#cfg(target = "native")
pub async fn check(domain : String) -> MtaStsResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []

  // MTA-STS uses _mta-sts subdomain
  let query_domain = "_mta-sts." + domain
  let result = @dns.query(query_domain, TXT)

  if not(result.success) || result.records.length() == 0 {
    return {
      valid: true,  // MTA-STS is optional
      record: None,
      errors: [],
      warnings: ["No MTA-STS record found - SMTP TLS not enforced via MTA-STS"],
    }
  }

  // Find MTA-STS record
  for line in result.records {
    let unquoted = unquote(line.trim().to_string())
    if unquoted.has_prefix("v=STSv1") {
      match parse_mta_sts(unquoted) {
        Some(rec) => {
          // Validate version
          if rec.version != "STSv1" {
            errors.push("Invalid MTA-STS version: " + rec.version)
            return { valid: false, record: Some(rec), errors, warnings }
          }

          if rec.id.is_empty() {
            warnings.push("MTA-STS record missing 'id' field")
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
    warnings: ["No valid MTA-STS record found"],
  }
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
