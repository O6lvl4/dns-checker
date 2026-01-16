// SRV Record Checker - RFC 2782

///| SRV Record
pub(all) struct SrvRecord {
  priority : Int
  weight : Int
  port : Int
  target : String
}

///| SRV Validation Result
pub(all) struct SrvResult {
  valid : Bool
  service : String
  records : Array[SrvRecord]
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

///| Split by whitespace
fn split_whitespace(s : String) -> Array[String] {
  let parts : Array[String] = []
  let current = StringBuilder::new()
  for c in s {
    if c == ' ' || c == '\t' || c == '\n' {
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

///| Parse SRV record
fn parse_srv_line(line : String) -> SrvRecord? {
  // Format: priority weight port target
  let parts = split_whitespace(line)
  if parts.length() < 4 {
    return None
  }

  let priority = match parse_int(parts[0]) {
    Some(n) => n
    None => return None
  }

  let weight = match parse_int(parts[1]) {
    Some(n) => n
    None => return None
  }

  let port = match parse_int(parts[2]) {
    Some(n) => n
    None => return None
  }

  let target = parts[3]

  Some(SrvRecord::{ priority, weight, port, target })
}

///| Common email-related SRV services
pub let email_services : Array[(String, String)] = [
  ("_submission._tcp", "Mail submission (587)"),
  ("_imap._tcp", "IMAP (143)"),
  ("_imaps._tcp", "IMAPS (993)"),
  ("_pop3._tcp", "POP3 (110)"),
  ("_pop3s._tcp", "POP3S (995)"),
  ("_autodiscover._tcp", "Autodiscover"),
  ("_carddav._tcp", "CardDAV"),
  ("_caldav._tcp", "CalDAV"),
]

///| Check SRV record for specific service
#cfg(target = "native")
pub async fn check_service(domain : String, service : String) -> SrvResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []
  let records : Array[SrvRecord] = []

  let query_domain = service + "." + domain
  let result = @dns.query(query_domain, SRV)

  if not(result.success) || result.records.length() == 0 {
    return {
      valid: true,
      service,
      records: [],
      errors: [],
      warnings: [],
    }
  }

  for line in result.records {
    let trimmed = line.trim().to_string()
    if not(trimmed.is_empty()) {
      match parse_srv_line(trimmed) {
        Some(rec) => {
          // Check for "no service" indicator
          if rec.target == "." {
            warnings.push(service + ": Service explicitly disabled (target='.')")
          } else {
            records.push(rec)
          }
        }
        None => warnings.push("Failed to parse SRV record: " + trimmed)
      }
    }
  }

  {
    valid: records.length() > 0,
    service,
    records,
    errors,
    warnings,
  }
}

///| Check common email SRV records for domain
#cfg(target = "native")
pub async fn check(domain : String) -> Array[SrvResult] {
  let results : Array[SrvResult] = []

  for service in email_services {
    let result = check_service(domain, service.0)
    results.push(result)
  }

  results
}
