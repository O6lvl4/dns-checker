// PTR Record Checker - RFC 1035 (Reverse DNS)

///| PTR Record
pub(all) struct PtrRecord {
  ip : String
  hostname : String
}

///| PTR Validation Result
pub(all) struct PtrResult {
  valid : Bool
  records : Array[PtrRecord]
  errors : Array[String]
  warnings : Array[String]
}

///| Split by dot
fn split_dot(s : String) -> Array[String] {
  let parts : Array[String] = []
  let current = StringBuilder::new()
  for c in s {
    if c == '.' {
      let part = current.to_string()
      parts.push(part)
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

///| Convert IPv4 to reverse DNS format
fn ipv4_to_reverse(ip : String) -> String {
  let parts = split_dot(ip)
  if parts.length() != 4 {
    return ""
  }
  // Reverse the octets
  parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0] + ".in-addr.arpa"
}

///| Check PTR record for IP address
#cfg(target = "native")
pub async fn check_ip(ip : String) -> PtrResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []
  let records : Array[PtrRecord] = []

  // Convert IP to reverse DNS format
  let reverse_domain = ipv4_to_reverse(ip)
  if reverse_domain.is_empty() {
    return {
      valid: false,
      records: [],
      errors: ["Invalid IPv4 address format: " + ip],
      warnings: [],
    }
  }

  let result = @dns.query(reverse_domain, PTR)

  if not(result.success) || result.records.length() == 0 {
    return {
      valid: false,
      records: [],
      errors: ["No PTR record found for " + ip],
      warnings: ["Missing reverse DNS can cause email delivery issues"],
    }
  }

  for line in result.records {
    let trimmed = line.trim().to_string()
    if not(trimmed.is_empty()) {
      records.push(PtrRecord::{ ip, hostname: trimmed })
    }
  }

  if records.length() > 1 {
    warnings.push("Multiple PTR records found - some systems may have issues")
  }

  {
    valid: records.length() > 0,
    records,
    errors,
    warnings,
  }
}

///| Check PTR for domain's MX servers (requires MX IPs)
#cfg(target = "native")
pub async fn check_mx_ptrs(domain : String, mx_hosts : Array[String]) -> Array[PtrResult] {
  let results : Array[PtrResult] = []

  for mx_host in mx_hosts {
    // Resolve MX host to IP
    let a_result = @dns.query(mx_host, A)
    if a_result.success && a_result.records.length() > 0 {
      for ip_line in a_result.records {
        let ip = ip_line.trim().to_string()
        if not(ip.is_empty()) {
          let ptr_result = check_ip(ip)
          results.push(ptr_result)
        }
      }
    }
  }

  results
}
