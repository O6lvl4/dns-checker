// DNSSEC Checker - RFC 4033, 4034, 4035

///| DNSKEY Record
pub(all) struct DnskeyRecord {
  flags : Int         // 256=ZSK, 257=KSK
  protocol : Int      // Should be 3
  algorithm : Int     // Algorithm number
  public_key : String
}

///| DS Record
pub(all) struct DsRecord {
  key_tag : Int
  algorithm : Int
  digest_type : Int
  digest : String
}

///| DNSSEC Validation Result
pub(all) struct DnssecResult {
  valid : Bool
  enabled : Bool
  dnskey_records : Array[DnskeyRecord]
  ds_records : Array[DsRecord]
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

///| Parse DNSKEY record
fn parse_dnskey(line : String) -> DnskeyRecord? {
  // Format: flags protocol algorithm public_key
  let parts = split_whitespace(line)
  if parts.length() < 4 {
    return None
  }

  let flags = match parse_int(parts[0]) {
    Some(n) => n
    None => return None
  }

  let protocol = match parse_int(parts[1]) {
    Some(n) => n
    None => return None
  }

  let algorithm = match parse_int(parts[2]) {
    Some(n) => n
    None => return None
  }

  // Public key is the rest
  let pk = StringBuilder::new()
  for i in 3..<parts.length() {
    pk.write_string(parts[i])
  }

  Some(DnskeyRecord::{ flags, protocol, algorithm, public_key: pk.to_string() })
}

///| Parse DS record
fn parse_ds(line : String) -> DsRecord? {
  // Format: key_tag algorithm digest_type digest
  let parts = split_whitespace(line)
  if parts.length() < 4 {
    return None
  }

  let key_tag = match parse_int(parts[0]) {
    Some(n) => n
    None => return None
  }

  let algorithm = match parse_int(parts[1]) {
    Some(n) => n
    None => return None
  }

  let digest_type = match parse_int(parts[2]) {
    Some(n) => n
    None => return None
  }

  // Digest is the rest
  let d = StringBuilder::new()
  for i in 3..<parts.length() {
    d.write_string(parts[i])
  }

  Some(DsRecord::{ key_tag, algorithm, digest_type, digest: d.to_string() })
}

///| Get algorithm name
pub fn algorithm_name(algo : Int) -> String {
  match algo {
    5 => "RSASHA1"
    7 => "RSASHA1-NSEC3-SHA1"
    8 => "RSASHA256"
    10 => "RSASHA512"
    13 => "ECDSAP256SHA256"
    14 => "ECDSAP384SHA384"
    15 => "ED25519"
    16 => "ED448"
    _ => "Unknown (" + algo.to_string() + ")"
  }
}

///| Get digest type name
pub fn digest_type_name(dt : Int) -> String {
  match dt {
    1 => "SHA-1"
    2 => "SHA-256"
    4 => "SHA-384"
    _ => "Unknown (" + dt.to_string() + ")"
  }
}

///| Check DNSSEC for domain
#cfg(target = "native")
pub async fn check(domain : String) -> DnssecResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []
  let dnskey_records : Array[DnskeyRecord] = []
  let ds_records : Array[DsRecord] = []

  // Query DNSKEY records
  let dnskey_result = @dns.query(domain, DNSKEY)
  if dnskey_result.success {
    for line in dnskey_result.records {
      let trimmed = line.trim().to_string()
      if not(trimmed.is_empty()) {
        match parse_dnskey(trimmed) {
          Some(rec) => {
            // Validate algorithm
            if rec.algorithm == 5 || rec.algorithm == 7 {
              warnings.push("RSASHA1 algorithm is deprecated - consider upgrading")
            }
            if rec.protocol != 3 {
              warnings.push("DNSKEY protocol should be 3, got: " + rec.protocol.to_string())
            }
            dnskey_records.push(rec)
          }
          None => ()
        }
      }
    }
  }

  // Query DS records (at parent zone, but we check at domain level)
  let ds_result = @dns.query(domain, DS)
  if ds_result.success {
    for line in ds_result.records {
      let trimmed = line.trim().to_string()
      if not(trimmed.is_empty()) {
        match parse_ds(trimmed) {
          Some(rec) => {
            // Validate digest type
            if rec.digest_type == 1 {
              warnings.push("SHA-1 digest (type 1) is weak - consider SHA-256 (type 2)")
            }
            ds_records.push(rec)
          }
          None => ()
        }
      }
    }
  }

  let enabled = dnskey_records.length() > 0 || ds_records.length() > 0

  if not(enabled) {
    warnings.push("DNSSEC not enabled - DNS responses are not authenticated")
  } else {
    // Check for KSK and ZSK
    let mut has_ksk = false
    let mut has_zsk = false
    for rec in dnskey_records {
      if rec.flags == 257 {
        has_ksk = true
      } else if rec.flags == 256 {
        has_zsk = true
      }
    }

    if dnskey_records.length() > 0 {
      if not(has_ksk) {
        warnings.push("No KSK (flags=257) found")
      }
      if not(has_zsk) {
        warnings.push("No ZSK (flags=256) found")
      }
    }
  }

  {
    valid: true,  // DNSSEC is optional
    enabled,
    dnskey_records,
    ds_records,
    errors,
    warnings,
  }
}
