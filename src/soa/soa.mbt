// SOA Record Checker - RFC 1035

///| SOA Record
pub(all) struct SoaRecord {
  mname : String      // Primary nameserver
  rname : String      // Responsible person email
  serial : Int        // Zone serial number
  refresh : Int       // Refresh interval (seconds)
  retry : Int         // Retry interval (seconds)
  expire : Int        // Expire time (seconds)
  minimum : Int       // Minimum TTL (seconds)
}

///| SOA Validation Result
pub(all) struct SoaResult {
  valid : Bool
  record : SoaRecord?
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

///| Check SOA record for domain
#cfg(target = "native")
pub async fn check(domain : String) -> SoaResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []

  let result = @dns.query(domain, SOA)

  if not(result.success) {
    return {
      valid: false,
      record: None,
      errors: ["DNS query failed: " + result.error],
      warnings: [],
    }
  }

  if result.records.length() == 0 {
    return {
      valid: false,
      record: None,
      errors: ["No SOA record found"],
      warnings: [],
    }
  }

  // Parse SOA record: mname rname serial refresh retry expire minimum
  let line = result.records[0]
  let parts = split_whitespace(line)

  if parts.length() < 7 {
    return {
      valid: false,
      record: None,
      errors: ["Invalid SOA record format"],
      warnings: [],
    }
  }

  let serial = match parse_int(parts[2]) {
    Some(n) => n
    None => 0
  }
  let refresh = match parse_int(parts[3]) {
    Some(n) => n
    None => 0
  }
  let retry = match parse_int(parts[4]) {
    Some(n) => n
    None => 0
  }
  let expire = match parse_int(parts[5]) {
    Some(n) => n
    None => 0
  }
  let minimum = match parse_int(parts[6]) {
    Some(n) => n
    None => 0
  }

  let record = SoaRecord::{
    mname: parts[0],
    rname: parts[1],
    serial,
    refresh,
    retry,
    expire,
    minimum,
  }

  // RFC 1912 recommendations
  if refresh < 3600 {
    warnings.push("Refresh interval (" + refresh.to_string() + "s) is less than recommended minimum (3600s)")
  }

  if retry >= refresh {
    warnings.push("Retry interval should be less than refresh interval")
  }

  if expire < 604800 {
    warnings.push("Expire time (" + expire.to_string() + "s) is less than recommended minimum (1 week)")
  }

  if minimum > 86400 {
    warnings.push("Minimum TTL (" + minimum.to_string() + "s) is higher than recommended (86400s)")
  }

  {
    valid: true,
    record: Some(record),
    errors,
    warnings,
  }
}
