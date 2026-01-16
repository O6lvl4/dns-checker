///|
fn print_usage() -> Unit {
  println("Usage: dns-checker <domain> [options]")
  println("")
  println("Comprehensive DNS record checker (RFC compliant)")
  println("")
  println("Checks performed:")
  println("  Basic:")
  println("    - A/AAAA records (IPv4/IPv6)")
  println("    - NS records (Nameservers)")
  println("    - SOA record (Zone info)")
  println("  Email (RFC compliant):")
  println("    - MX records")
  println("    - SPF (RFC 7208)")
  println("    - DMARC (RFC 7489)")
  println("    - DKIM (RFC 6376)")
  println("    - MTA-STS (RFC 8461)")
  println("    - TLS-RPT (RFC 8460)")
  println("    - BIMI")
  println("  Security:")
  println("    - CAA (RFC 8659)")
  println("    - TLSA/DANE (RFC 6698)")
  println("    - DNSSEC")
  println("  Service:")
  println("    - SRV records")
  println("")
  println("Example:")
  println("  dns-checker example.com")
}

///|
fn print_header(domain : String) -> Unit {
  println("╔══════════════════════════════════════════════════════════════════════╗")
  println("║              DNS Record Checker (Comprehensive)                      ║")
  println("╚══════════════════════════════════════════════════════════════════════╝")
  println("")
  println("Domain: " + domain)
  println("")
}

///|
fn print_section(title : String) -> Unit {
  println("───────────────────────────────────────────────────────────────────────")
  println(@lib.bold + title + @lib.reset)
  println("───────────────────────────────────────────────────────────────────────")
}

///|
fn print_subsection(title : String) -> Unit {
  println("  " + @lib.bold + title + @lib.reset)
}

///|
async fn main {
  let args = @env.args()

  if args.length() < 2 {
    print_usage()
    return
  }

  let domain = args[1]

  if domain == "--help" || domain == "-h" {
    print_usage()
    return
  }

  print_header(domain)

  let mut total_errors = 0
  let mut total_warnings = 0
  let mut checks_passed = 0
  let mut checks_total = 0

  // ═══════════════════════════════════════════════════════════════════════════
  // BASIC RECORDS
  // ═══════════════════════════════════════════════════════════════════════════
  print_section("Basic Records")

  // A/AAAA Check
  print_subsection("A/AAAA Records")
  let addr_result = @a.check(domain)
  checks_total = checks_total + 1
  println("    " + @lib.format_status(addr_result.valid) + " Address Records")
  if addr_result.a_records.length() > 0 {
    println("      IPv4:")
    for rec in addr_result.a_records {
      println("        " + rec.address)
    }
  }
  if addr_result.aaaa_records.length() > 0 {
    println("      IPv6:")
    for rec in addr_result.aaaa_records {
      println("        " + rec.address)
    }
  }
  for err in addr_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in addr_result.warnings {
    println("      " + @lib.yellow + "Warning: " + warn + @lib.reset)
    total_warnings = total_warnings + 1
  }
  if addr_result.valid {
    checks_passed = checks_passed + 1
  }
  println("")

  // NS Check
  print_subsection("NS Records")
  let ns_result = @ns.check(domain)
  checks_total = checks_total + 1
  println("    " + @lib.format_status(ns_result.valid) + " Nameservers")
  for rec in ns_result.records {
    println("      " + rec.nameserver)
  }
  for err in ns_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in ns_result.warnings {
    println("      " + @lib.yellow + "Warning: " + warn + @lib.reset)
    total_warnings = total_warnings + 1
  }
  if ns_result.valid {
    checks_passed = checks_passed + 1
  }
  println("")

  // SOA Check
  print_subsection("SOA Record")
  let soa_result = @soa.check(domain)
  checks_total = checks_total + 1
  println("    " + @lib.format_status(soa_result.valid) + " Zone Info")
  match soa_result.record {
    Some(rec) => {
      println("      Primary NS: " + rec.mname)
      println("      Contact: " + rec.rname)
      println("      Serial: " + rec.serial.to_string())
      println("      Refresh: " + rec.refresh.to_string() + "s")
      println("      Retry: " + rec.retry.to_string() + "s")
      println("      Expire: " + rec.expire.to_string() + "s")
      println("      Min TTL: " + rec.minimum.to_string() + "s")
    }
    None => ()
  }
  for err in soa_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in soa_result.warnings {
    println("      " + @lib.yellow + "Warning: " + warn + @lib.reset)
    total_warnings = total_warnings + 1
  }
  if soa_result.valid {
    checks_passed = checks_passed + 1
  }
  println("")

  // ═══════════════════════════════════════════════════════════════════════════
  // EMAIL RECORDS
  // ═══════════════════════════════════════════════════════════════════════════
  print_section("Email Records")

  // MX Check
  print_subsection("MX Records")
  let mx_result = @mx.check(domain)
  checks_total = checks_total + 1
  println("    " + @lib.format_status(mx_result.valid) + " Mail Servers")
  if mx_result.records.length() > 0 {
    for entry in mx_result.records {
      println("      " + entry.priority.to_string() + " " + entry.host)
    }
  }
  for err in mx_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in mx_result.warnings {
    println("      " + @lib.yellow + "Warning: " + warn + @lib.reset)
    total_warnings = total_warnings + 1
  }
  if mx_result.valid {
    checks_passed = checks_passed + 1
  }
  println("")

  // SPF Check
  print_subsection("SPF (RFC 7208)")
  let spf_result = @spf.check(domain)
  checks_total = checks_total + 1
  println("    " + @lib.format_status(spf_result.valid) + " SPF Record")
  match spf_result.record {
    Some(r) => {
      println("      Mechanisms: " + r.mechanisms.length().to_string())
      println("      DNS Lookups: " + spf_result.dns_lookup_count.to_string() + "/10")
    }
    None => ()
  }
  for err in spf_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in spf_result.warnings {
    println("      " + @lib.yellow + "Warning: " + warn + @lib.reset)
    total_warnings = total_warnings + 1
  }
  if spf_result.valid {
    checks_passed = checks_passed + 1
  }
  println("")

  // DMARC Check
  print_subsection("DMARC (RFC 7489)")
  let dmarc_result = @dmarc.check(domain)
  checks_total = checks_total + 1
  println("    " + @lib.format_status(dmarc_result.valid) + " DMARC Record")
  match dmarc_result.record {
    Some(r) => {
      println("      Policy: " + r.policy.to_string())
      println("      DKIM Alignment: " + r.adkim.to_string())
      println("      SPF Alignment: " + r.aspf.to_string())
      println("      Percentage: " + r.pct.to_string() + "%")
      if r.rua.length() > 0 {
        println("      Report URIs: " + r.rua.length().to_string())
      }
    }
    None => ()
  }
  for err in dmarc_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in dmarc_result.warnings {
    println("      " + @lib.yellow + "Warning: " + warn + @lib.reset)
    total_warnings = total_warnings + 1
  }
  if dmarc_result.valid {
    checks_passed = checks_passed + 1
  }
  println("")

  // DKIM Check
  print_subsection("DKIM (RFC 6376)")
  let dkim_result = @dkim.check(domain)
  checks_total = checks_total + 1
  println("    " + @lib.format_status(dkim_result.valid) + " DKIM Records")
  println("      Selectors checked: " + dkim_result.selectors_checked.to_string())
  println("      Selectors found: " + dkim_result.selectors_found.to_string())
  for r in dkim_result.results {
    match r.record {
      Some(rec) =>
        println(
          "      " + @lib.green + "✓" + @lib.reset + " " + r.selector + " (" + rec.key_type.to_string() + ")",
        )
      None => ()
    }
    for err in r.errors {
      println("        " + @lib.red + "Error: " + err + @lib.reset)
      total_errors = total_errors + 1
    }
    for warn in r.warnings {
      println("        " + @lib.yellow + "Warning: " + warn + @lib.reset)
      total_warnings = total_warnings + 1
    }
  }
  for err in dkim_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  if dkim_result.valid {
    checks_passed = checks_passed + 1
  }
  println("")

  // MTA-STS Check
  print_subsection("MTA-STS (RFC 8461)")
  let mta_sts_result = @mta_sts.check(domain)
  checks_total = checks_total + 1
  let mta_sts_valid = match mta_sts_result.record {
    Some(_) => true
    None => false
  }
  println(
    "    " + (if mta_sts_valid {
      @lib.format_status(true)
    } else {
      @lib.yellow + "[SKIP]" + @lib.reset
    }) + " MTA-STS",
  )
  match mta_sts_result.record {
    Some(rec) => {
      println("      Version: " + rec.version)
      println("      Policy ID: " + rec.id)
    }
    None => ()
  }
  for err in mta_sts_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in mta_sts_result.warnings {
    println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
  }
  if mta_sts_valid {
    checks_passed = checks_passed + 1
  }
  println("")

  // TLS-RPT Check
  print_subsection("TLS-RPT (RFC 8460)")
  let tlsrpt_result = @tlsrpt.check(domain)
  checks_total = checks_total + 1
  let tlsrpt_valid = match tlsrpt_result.record {
    Some(_) => true
    None => false
  }
  println(
    "    " + (if tlsrpt_valid {
      @lib.format_status(true)
    } else {
      @lib.yellow + "[SKIP]" + @lib.reset
    }) + " TLS Reporting",
  )
  match tlsrpt_result.record {
    Some(rec) => {
      println("      Version: " + rec.version)
      println("      Report URIs: " + rec.rua.length().to_string())
    }
    None => ()
  }
  for err in tlsrpt_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in tlsrpt_result.warnings {
    println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
  }
  if tlsrpt_valid {
    checks_passed = checks_passed + 1
  }
  println("")

  // BIMI Check
  print_subsection("BIMI")
  let bimi_result = @bimi.check(domain)
  checks_total = checks_total + 1
  let bimi_valid = match bimi_result.record {
    Some(_) => true
    None => false
  }
  println(
    "    " + (if bimi_valid {
      @lib.format_status(true)
    } else {
      @lib.yellow + "[SKIP]" + @lib.reset
    }) + " Brand Logo",
  )
  match bimi_result.record {
    Some(rec) => {
      println("      Version: " + rec.version)
      if not(rec.location.is_empty()) {
        println("      Logo: " + rec.location)
      }
      if not(rec.authority.is_empty()) {
        println("      VMC: " + rec.authority)
      }
    }
    None => ()
  }
  for err in bimi_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in bimi_result.warnings {
    println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
  }
  if bimi_valid {
    checks_passed = checks_passed + 1
  }
  println("")

  // ═══════════════════════════════════════════════════════════════════════════
  // SECURITY RECORDS
  // ═══════════════════════════════════════════════════════════════════════════
  print_section("Security Records")

  // CAA Check
  print_subsection("CAA (RFC 8659)")
  let caa_result = @caa.check(domain)
  checks_total = checks_total + 1
  let caa_has_records = caa_result.records.length() > 0
  println(
    "    " + (if caa_has_records {
      @lib.format_status(true)
    } else {
      @lib.yellow + "[SKIP]" + @lib.reset
    }) + " Certificate Authority Authorization",
  )
  for rec in caa_result.records {
    println("      " + rec.tag + ": " + rec.value)
  }
  for err in caa_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in caa_result.warnings {
    println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
  }
  if caa_has_records {
    checks_passed = checks_passed + 1
  }
  println("")

  // TLSA/DANE Check
  print_subsection("TLSA/DANE (RFC 6698)")
  let tlsa_result = @tlsa.check(domain)
  checks_total = checks_total + 1
  let tlsa_has_records = tlsa_result.records.length() > 0
  println(
    "    " + (if tlsa_has_records {
      @lib.format_status(true)
    } else {
      @lib.yellow + "[SKIP]" + @lib.reset
    }) + " DANE for SMTP",
  )
  for rec in tlsa_result.records {
    println(
      "      Usage: " + @tlsa.usage_description(rec.usage) + " (" + rec.usage.to_string() + ")",
    )
    println(
      "      Selector: " + @tlsa.selector_description(rec.selector) + " (" + rec.selector.to_string() + ")",
    )
    println(
      "      Matching: " + @tlsa.matching_description(rec.matching_type) + " (" + rec.matching_type.to_string() + ")",
    )
  }
  for err in tlsa_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in tlsa_result.warnings {
    println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
  }
  if tlsa_has_records {
    checks_passed = checks_passed + 1
  }
  println("")

  // DNSSEC Check
  print_subsection("DNSSEC")
  let dnssec_result = @dnssec.check(domain)
  checks_total = checks_total + 1
  println(
    "    " + (if dnssec_result.enabled {
      @lib.format_status(true)
    } else {
      @lib.yellow + "[SKIP]" + @lib.reset
    }) + " DNS Security Extensions",
  )
  if dnssec_result.enabled {
    println("      DNSKEY records: " + dnssec_result.dnskey_records.length().to_string())
    for rec in dnssec_result.dnskey_records {
      let key_type = if rec.flags == 257 {
        "KSK"
      } else if rec.flags == 256 {
        "ZSK"
      } else {
        "Unknown"
      }
      println(
        "        " + key_type + " (flags=" + rec.flags.to_string() + ", algo=" + @dnssec.algorithm_name(
          rec.algorithm,
        ) + ")",
      )
    }
    if dnssec_result.ds_records.length() > 0 {
      println("      DS records: " + dnssec_result.ds_records.length().to_string())
    }
  }
  for err in dnssec_result.errors {
    println("      " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in dnssec_result.warnings {
    println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
  }
  if dnssec_result.enabled {
    checks_passed = checks_passed + 1
  }
  println("")

  // ═══════════════════════════════════════════════════════════════════════════
  // SERVICE RECORDS
  // ═══════════════════════════════════════════════════════════════════════════
  print_section("Service Discovery (SRV)")

  let srv_results = @srv.check(domain)
  let mut srv_found = 0
  for result in srv_results {
    if result.records.length() > 0 {
      srv_found = srv_found + 1
      println("  " + @lib.green + "✓" + @lib.reset + " " + result.service)
      for rec in result.records {
        println(
          "      " + rec.priority.to_string() + " " + rec.weight.to_string() + " " + rec.port.to_string() + " " + rec.target,
        )
      }
    }
  }
  if srv_found == 0 {
    println("  " + @lib.yellow + "No SRV records found for common email services" + @lib.reset)
  }
  println("")

  // ═══════════════════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════════════════
  println("═══════════════════════════════════════════════════════════════════════")
  println(@lib.bold + "Summary" + @lib.reset)
  println("═══════════════════════════════════════════════════════════════════════")

  // Core checks summary
  println("  " + @lib.bold + "Core Checks:" + @lib.reset)
  let core_checks = [
    ("A/AAAA", addr_result.valid),
    ("NS", ns_result.valid),
    ("SOA", soa_result.valid),
    ("MX", mx_result.valid),
    ("SPF", spf_result.valid),
    ("DMARC", dmarc_result.valid),
    ("DKIM", dkim_result.valid),
  ]

  for check in core_checks {
    let status = @lib.format_status(check.1)
    println("    " + status + " " + check.0)
  }

  println("")
  println("  " + @lib.bold + "Optional/Enhanced:" + @lib.reset)
  let optional_checks = [
    ("MTA-STS", mta_sts_valid),
    ("TLS-RPT", tlsrpt_valid),
    ("BIMI", bimi_valid),
    ("CAA", caa_has_records),
    ("TLSA/DANE", tlsa_has_records),
    ("DNSSEC", dnssec_result.enabled),
  ]

  for check in optional_checks {
    let status = if check.1 {
      @lib.green + "[OK]" + @lib.reset
    } else {
      @lib.yellow + "[--]" + @lib.reset
    }
    println("    " + status + " " + check.0)
  }

  println("")
  println("  Checks Passed: " + checks_passed.to_string() + "/" + checks_total.to_string())
  println("  Errors: " + total_errors.to_string())
  println("  Warnings: " + total_warnings.to_string())
}
