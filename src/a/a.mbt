// A/AAAA Record Checker - RFC 1035, RFC 3596

///| A Record entry (IPv4)
pub(all) struct ARecord {
  address : String
}

///| AAAA Record entry (IPv6)
pub(all) struct AAAARecord {
  address : String
}

///| A/AAAA Validation Result
pub(all) struct AddressResult {
  valid : Bool
  a_records : Array[ARecord]
  aaaa_records : Array[AAAARecord]
  errors : Array[String]
  warnings : Array[String]
}

///| Check if string looks like IPv4
fn is_ipv4(s : String) -> Bool {
  let mut dots = 0
  let mut has_digit = false
  for c in s {
    if c == '.' {
      dots = dots + 1
    } else if c.to_int() >= 48 && c.to_int() <= 57 {
      has_digit = true
    } else {
      return false
    }
  }
  dots == 3 && has_digit
}

///| Check if string looks like IPv6
fn is_ipv6(s : String) -> Bool {
  let mut colons = 0
  for c in s {
    if c == ':' {
      colons = colons + 1
    }
  }
  colons >= 2
}

///| Check A and AAAA records for domain
#cfg(target = "native")
pub async fn check(domain : String) -> AddressResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []
  let a_records : Array[ARecord] = []
  let aaaa_records : Array[AAAARecord] = []

  // Query A records
  let a_result = @dns.query(domain, A)
  if a_result.success {
    for line in a_result.records {
      let trimmed = line.trim().to_string()
      if not(trimmed.is_empty()) && is_ipv4(trimmed) {
        a_records.push(ARecord::{ address: trimmed })
      }
    }
  }

  // Query AAAA records
  let aaaa_result = @dns.query(domain, AAAA)
  if aaaa_result.success {
    for line in aaaa_result.records {
      let trimmed = line.trim().to_string()
      if not(trimmed.is_empty()) && is_ipv6(trimmed) {
        aaaa_records.push(AAAARecord::{ address: trimmed })
      }
    }
  }

  // Validation
  if a_records.length() == 0 && aaaa_records.length() == 0 {
    errors.push("No A or AAAA records found")
  }

  if a_records.length() == 0 {
    warnings.push("No IPv4 (A) records - IPv4-only clients cannot connect")
  }

  if aaaa_records.length() == 0 {
    warnings.push("No IPv6 (AAAA) records - not IPv6 ready")
  }

  // Check for private/reserved IPs
  for rec in a_records {
    if rec.address.has_prefix("10.") ||
       rec.address.has_prefix("192.168.") ||
       rec.address.has_prefix("127.") {
      warnings.push("Private/loopback IP detected: " + rec.address)
    }
  }

  {
    valid: a_records.length() > 0 || aaaa_records.length() > 0,
    a_records,
    aaaa_records,
    errors,
    warnings,
  }
}
