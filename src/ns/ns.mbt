// NS Record Checker - RFC 1035

///| NS Record entry
pub(all) struct NsRecord {
  nameserver : String
}

///| NS Validation Result
pub(all) struct NsResult {
  valid : Bool
  records : Array[NsRecord]
  errors : Array[String]
  warnings : Array[String]
}

///| Check NS records for domain
#cfg(target = "native")
pub async fn check(domain : String) -> NsResult {
  let errors : Array[String] = []
  let warnings : Array[String] = []
  let records : Array[NsRecord] = []

  let result = @dns.query(domain, NS)

  if not(result.success) {
    return {
      valid: false,
      records: [],
      errors: ["DNS query failed: " + result.error],
      warnings: [],
    }
  }

  for line in result.records {
    let trimmed = line.trim().to_string()
    if not(trimmed.is_empty()) {
      records.push(NsRecord::{ nameserver: trimmed })
    }
  }

  if records.length() == 0 {
    errors.push("No NS records found")
    return { valid: false, records, errors, warnings }
  }

  // RFC recommends at least 2 nameservers for redundancy
  if records.length() == 1 {
    warnings.push("Only one nameserver - no redundancy (RFC recommends at least 2)")
  }

  // Check for common issues
  let providers : Array[String] = []
  for rec in records {
    let ns = rec.nameserver.to_lower()

    // Extract provider from nameserver
    if ns.has_suffix("cloudflare.com.") {
      if not(array_contains(providers, "cloudflare")) {
        providers.push("cloudflare")
      }
    } else if ns.has_suffix("awsdns") || ns.has_suffix("amazonaws.com.") {
      if not(array_contains(providers, "aws")) {
        providers.push("aws")
      }
    } else if ns.has_suffix("google.com.") || ns.has_suffix("googledomains.com.") {
      if not(array_contains(providers, "google")) {
        providers.push("google")
      }
    }
  }

  // Single provider is fine but note it
  if providers.length() == 1 && records.length() >= 2 {
    // This is normal - most domains use single provider
  }

  {
    valid: true,
    records,
    errors,
    warnings,
  }
}

fn array_contains(arr : Array[String], item : String) -> Bool {
  for s in arr {
    if s == item {
      return true
    }
  }
  false
}
