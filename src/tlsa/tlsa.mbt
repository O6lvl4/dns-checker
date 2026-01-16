// TLSA Record Checker - RFC 6698 (DANE)

///| TLSA Record (DANE)
pub(all) struct TlsaRecord {
  usage : Int         // 0-3: Certificate usage
  selector : Int      // 0-1: Selector
  matching_type : Int // 0-2: Matching type
  certificate_data : String
}

///| TLSA Validation Result
pub(all) struct TlsaResult {
  valid : Bool
  records : Array[TlsaRecord]
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

///| Parse TLSA record line
fn parse_tlsa_line(line : String) -> TlsaRecord? {
  // Format: usage selector matching_type certificate_data
  let parts = split_whitespace(line)
  if parts.length() < 4 {
    return None
  }

  let usage = match parse_int(parts[0]) {
    Some(n) => n
    None => return None
  }

  let selector = match parse_int(parts[1]) {
    Some(n) => n
    None => return None
  }

  let matching_type = match parse_int(parts[2]) {
    Some(n) => n
    None => return None
  }

  // Certificate data may be split across multiple parts
  let cert_data = StringBuilder::new()
  for i in 3..<parts.length() {
    cert_data.write_string(parts[i])
  }

  Some(TlsaRecord::{ usage, selector, matching_type, certificate_data: cert_data.to_string() })
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

///| Get usage description
pub fn usage_description(usage : Int) -> String {
  match usage {
    0 => "PKIX-TA (CA constraint)"
    1 => "PKIX-EE (Service certificate constraint)"
    2 => "DANE-TA (Trust anchor assertion)"
    3 => "DANE-EE (Domain-issued certificate)"
    _ => "Unknown"
  }
}

///| Get selector description
pub fn selector_description(selector : Int) -> String {
  match selector {
    0 => "Full certificate"
    1 => "SubjectPublicKeyInfo"
    _ => "Unknown"
  }
}

///| Get matching type description
pub fn matching_description(matching : Int) -> String {
  match matching {
    0 => "Exact match"
    1 => "SHA-256 hash"
    2 => "SHA-512 hash"
    _ => "Unknown"
  }
}

///| Check TLSA records for domain (SMTP port 25)
#cfg(target = "native")
pub async fn check(domain : String) -> TlsaResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []
  let records : Array[TlsaRecord] = []

  // TLSA for SMTP uses _25._tcp.domain
  let query_domain = "_25._tcp." + domain
  let result = @dns.query(query_domain, TLSA)

  if not(result.success) || result.records.length() == 0 {
    return {
      valid: true,  // TLSA/DANE is optional
      records: [],
      errors: [],
      warnings: ["No TLSA records found - DANE not configured for SMTP"],
    }
  }

  for line in result.records {
    let trimmed = line.trim().to_string()
    if not(trimmed.is_empty()) {
      match parse_tlsa_line(trimmed) {
        Some(rec) => {
          // Validate fields
          if rec.usage > 3 {
            warnings.push("Unknown TLSA usage value: " + rec.usage.to_string())
          }
          if rec.selector > 1 {
            warnings.push("Unknown TLSA selector value: " + rec.selector.to_string())
          }
          if rec.matching_type > 2 {
            warnings.push("Unknown TLSA matching type: " + rec.matching_type.to_string())
          }

          // Recommend DANE-EE (3) or DANE-TA (2)
          if rec.usage == 0 || rec.usage == 1 {
            warnings.push("PKIX modes (0,1) require DNSSEC and valid PKI - consider DANE modes (2,3)")
          }

          records.push(rec)
        }
        None => warnings.push("Failed to parse TLSA record: " + trimmed)
      }
    }
  }

  {
    valid: records.length() > 0,
    records,
    errors,
    warnings,
  }
}
