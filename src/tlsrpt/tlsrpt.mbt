// TLS-RPT Record Checker - RFC 8460 (SMTP TLS Reporting)

///| TLS-RPT Record
pub(all) struct TlsRptRecord {
  version : String    // TLSRPTv1
  rua : Array[String] // Report URIs
}

///| TLS-RPT Validation Result
pub(all) struct TlsRptResult {
  valid : Bool
  record : TlsRptRecord?
  errors : Array[String]
  warnings : Array[String]
}

///| Parse TLS-RPT TXT record
fn parse_tlsrpt(raw : String) -> TlsRptRecord? {
  let mut version = ""
  let rua : Array[String] = []

  // Format: v=TLSRPTv1; rua=mailto:reports@example.com
  let parts = split_semicolon(raw)
  for part in parts {
    let trimmed = part.trim().to_string()
    if trimmed.has_prefix("v=") {
      version = safe_substr_from(trimmed, 2)
    } else if trimmed.has_prefix("rua=") {
      let uris = safe_substr_from(trimmed, 4)
      // Split by comma for multiple URIs
      let uri_parts = split_comma(uris)
      for uri in uri_parts {
        let u = uri.trim().to_string()
        if not(u.is_empty()) {
          rua.push(u)
        }
      }
    }
  }

  if version.is_empty() {
    return None
  }

  Some(TlsRptRecord::{ version, rua })
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

///| Split by comma
fn split_comma(s : String) -> Array[String] {
  let parts : Array[String] = []
  let current = StringBuilder::new()
  for c in s {
    if c == ',' {
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

///| Check TLS-RPT record for domain
#cfg(target = "native")
pub async fn check(domain : String) -> TlsRptResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []

  // TLS-RPT uses _smtp._tls subdomain
  let query_domain = "_smtp._tls." + domain
  let result = @dns.query(query_domain, TXT)

  if not(result.success) || result.records.length() == 0 {
    return {
      valid: true,  // TLS-RPT is optional
      record: None,
      errors: [],
      warnings: ["No TLS-RPT record found - no SMTP TLS failure reporting"],
    }
  }

  // Find TLS-RPT record
  for line in result.records {
    let unquoted = unquote(line.trim().to_string())
    if unquoted.has_prefix("v=TLSRPTv1") {
      match parse_tlsrpt(unquoted) {
        Some(rec) => {
          // Validate version
          if rec.version != "TLSRPTv1" {
            errors.push("Invalid TLS-RPT version: " + rec.version)
            return { valid: false, record: Some(rec), errors, warnings }
          }

          // Check RUA
          if rec.rua.length() == 0 {
            errors.push("TLS-RPT record missing report URI (rua=)")
            return { valid: false, record: Some(rec), errors, warnings }
          }

          // Validate URIs
          for uri in rec.rua {
            if not(uri.has_prefix("mailto:")) && not(uri.has_prefix("https://")) {
              warnings.push("Report URI should be mailto: or https: - " + uri)
            }
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
    warnings: ["No valid TLS-RPT record found"],
  }
}
