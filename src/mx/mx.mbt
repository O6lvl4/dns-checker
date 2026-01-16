// MX Record Checker - RFC 5321

///| MX Record entry
pub(all) struct MxEntry {
  pub priority : Int
  pub host : String
}

///| MX Validation Result
pub(all) struct MxResult {
  pub valid : Bool
  pub records : Array[MxEntry]
  pub errors : Array[String]
  pub warnings : Array[String]
}

///| Parse MX record line (format: "priority host")
fn parse_mx_line(line : String) -> MxEntry? {
  let parts = split_whitespace(line)
  if parts.length() < 2 {
    return None
  }

  let priority = match parse_int(parts[0]) {
    Some(p) => p
    None => return None
  }

  let host = parts[1]

  Some(MxEntry::{ priority, host })
}

///| Split by whitespace
fn split_whitespace(s : String) -> Array[String] {
  let parts : Array[String] = []
  let current = StringBuilder::new()

  for c in s {
    if c == ' ' || c == '\t' {
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

///| Sort MX records by priority (lower is higher priority)
fn sort_by_priority(records : Array[MxEntry]) -> Array[MxEntry] {
  // Simple bubble sort for small arrays
  let sorted = records.copy()
  let n = sorted.length()

  for i in 0..<n {
    for j in 0..<(n - i - 1) {
      if sorted[j].priority > sorted[j + 1].priority {
        let tmp = sorted[j]
        sorted[j] = sorted[j + 1]
        sorted[j + 1] = tmp
      }
    }
  }

  sorted
}

///| Check MX records for domain
#cfg(target = "native")
pub async fn check(domain : String) -> MxResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []

  let result = @dns.query_mx(domain)

  if not(result.success) {
    return {
      valid: false,
      records: [],
      errors: ["DNS query failed: " + result.error],
      warnings: []
    }
  }

  if result.records.length() == 0 {
    return {
      valid: false,
      records: [],
      errors: ["No MX records found for " + domain],
      warnings: []
    }
  }

  // Parse MX records
  let entries : Array[MxEntry] = []
  for line in result.records {
    match parse_mx_line(line) {
      Some(entry) => entries.push(entry)
      None => warnings.push("Failed to parse MX record: " + line)
    }
  }

  if entries.length() == 0 {
    return {
      valid: false,
      records: [],
      errors: ["Failed to parse any MX records"],
      warnings
    }
  }

  // Sort by priority
  let sorted = sort_by_priority(entries)

  // Check for common issues
  for entry in sorted {
    // Check for localhost (usually a misconfiguration)
    if entry.host == "localhost" || entry.host == "localhost." {
      warnings.push("MX record points to localhost (priority: " + entry.priority.to_string() + ")")
    }

    // Check for IP address (should be hostname)
    if looks_like_ip(entry.host) {
      warnings.push("MX record appears to be an IP address instead of hostname: " + entry.host)
    }
  }

  // Check if there's only one MX record (no redundancy)
  if sorted.length() == 1 {
    warnings.push("Only one MX record - no redundancy")
  }

  {
    valid: true,
    records: sorted,
    errors,
    warnings
  }
}

///| Check if string looks like an IP address
fn looks_like_ip(s : String) -> Bool {
  // Simple check: starts with digit and contains dots
  if s.is_empty() {
    return false
  }

  let first = s[0]
  let first_code = first.to_int()

  // Check if first char is a digit
  if first_code < 48 || first_code > 57 {
    return false
  }

  // Count dots
  let mut dots = 0
  for c in s {
    if c == '.' {
      dots = dots + 1
    }
  }

  // IPv4 has 3 dots, IPv6 has colons (not checked here)
  dots == 3
}

///| Format MX result for display
pub fn format_result(result : MxResult) -> String {
  let sb = StringBuilder::new()

  if result.valid {
    sb.write_string("MX: Valid\n")
  } else {
    sb.write_string("MX: Invalid\n")
  }

  sb.write_string("  Records: " + result.records.length().to_string() + "\n")

  for entry in result.records {
    sb.write_string("    " + entry.priority.to_string() + " " + entry.host + "\n")
  }

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
