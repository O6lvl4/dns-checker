///|
fn print_usage() -> Unit {
  println("Usage: dns-checker <domain> [options]")
  println("")
  println("Comprehensive DNS record checker (RFC compliant)")
  println("")
  println("Options:")
  println("  --all, -a                Show all checks including unconfigured (SKIP)")
  println("  --dkim-selector SEL      Add custom DKIM selector (can be used multiple times)")
  println("  --txt                    Show all TXT records (domain verification, etc.)")
  println("")
  println("Examples:")
  println("  dns-checker example.com")
  println("  dns-checker example.com --dkim-selector selector1-azurecomm-prod-net")
  println("  dns-checker example.com --txt")
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

///| Remove quotes from TXT record
fn unquote_txt(s : String) -> String {
  let result = StringBuilder::new()
  for c in s {
    if c != '"' {
      result.write_char(c)
    }
  }
  result.to_string()
}

///|
async fn main {
  let args = @env.args()

  if args.length() < 2 {
    print_usage()
    return
  }

  // Parse arguments
  let mut domain = ""
  let mut show_all = false
  let mut show_txt = false
  let custom_dkim_selectors : Array[String] = []
  let mut i = 1
  while i < args.length() {
    let arg = args[i]
    if arg == "--all" || arg == "-a" {
      show_all = true
    } else if arg == "--txt" {
      show_txt = true
    } else if arg == "--dkim-selector" {
      i = i + 1
      if i < args.length() {
        custom_dkim_selectors.push(args[i])
      }
    } else if arg == "--help" || arg == "-h" {
      print_usage()
      return
    } else if domain.is_empty() {
      domain = arg
    }
    i = i + 1
  }

  if domain.is_empty() {
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

  // TXT Records (optional, shown with --txt flag)
  let mut txt_has_records = false
  if show_txt {
    print_subsection("TXT Records")
    let txt_result = @dns.query_txt(domain)
    checks_total = checks_total + 1
    if txt_result.success && txt_result.records.length() > 0 {
      txt_has_records = true
      checks_passed = checks_passed + 1
      println("    " + @lib.format_status(true) + " TXT Records")
      for record in txt_result.records {
        let unquoted = unquote_txt(record)
        // Categorize the record
        if unquoted.has_prefix("v=spf1") {
          println("      " + @lib.green + "[SPF]" + @lib.reset + " " + unquoted)
        } else if unquoted.has_prefix("ms-domain-verification") {
          println("      " + @lib.blue + "[Microsoft]" + @lib.reset + " " + unquoted)
        } else if unquoted.has_prefix("google-site-verification") {
          println("      " + @lib.blue + "[Google]" + @lib.reset + " " + unquoted)
        } else if unquoted.has_prefix("apple-domain-verification") {
          println("      " + @lib.blue + "[Apple]" + @lib.reset + " " + unquoted)
        } else if unquoted.has_prefix("facebook-domain-verification") {
          println("      " + @lib.blue + "[Facebook]" + @lib.reset + " " + unquoted)
        } else if unquoted.has_prefix("docusign") {
          println("      " + @lib.blue + "[DocuSign]" + @lib.reset + " " + unquoted)
        } else if unquoted.has_prefix("atlassian-domain-verification") {
          println("      " + @lib.blue + "[Atlassian]" + @lib.reset + " " + unquoted)
        } else if unquoted.has_prefix("_globalsign") {
          println("      " + @lib.blue + "[GlobalSign]" + @lib.reset + " " + unquoted)
        } else {
          println("      " + @lib.yellow + "[TXT]" + @lib.reset + " " + unquoted)
        }
      }
    } else {
      println("    " + @lib.format_status(false) + " TXT Records")
      println("      No TXT records found")
    }
    println("")
  }

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
  let dkim_result = if custom_dkim_selectors.length() > 0 {
    @dkim.check_with_selectors(domain, custom_dkim_selectors)
  } else {
    @dkim.check(domain)
  }
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
      None =>
        if custom_dkim_selectors.length() > 0 {
          // Show not found for custom selectors
          println("      " + @lib.red + "✗" + @lib.reset + " " + r.selector + " (not found)")
        }
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
  let mta_sts_result = @mta_sts.check(domain)
  let mta_sts_valid = match mta_sts_result.record {
    Some(_) => true
    None => false
  }
  if mta_sts_valid || show_all {
    print_subsection("MTA-STS (RFC 8461)")
    checks_total = checks_total + 1
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
    if show_all {
      for warn in mta_sts_result.warnings {
        println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
      }
    }
    if mta_sts_valid {
      checks_passed = checks_passed + 1
    }
    println("")
  }

  // TLS-RPT Check
  let tlsrpt_result = @tlsrpt.check(domain)
  let tlsrpt_valid = match tlsrpt_result.record {
    Some(_) => true
    None => false
  }
  if tlsrpt_valid || show_all {
    print_subsection("TLS-RPT (RFC 8460)")
    checks_total = checks_total + 1
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
    if show_all {
      for warn in tlsrpt_result.warnings {
        println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
      }
    }
    if tlsrpt_valid {
      checks_passed = checks_passed + 1
    }
    println("")
  }

  // BIMI Check
  let bimi_result = @bimi.check(domain)
  let bimi_valid = match bimi_result.record {
    Some(_) => true
    None => false
  }
  if bimi_valid || show_all {
    print_subsection("BIMI")
    checks_total = checks_total + 1
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
    if show_all {
      for warn in bimi_result.warnings {
        println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
      }
    }
    if bimi_valid {
      checks_passed = checks_passed + 1
    }
    println("")
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SECURITY RECORDS
  // ═══════════════════════════════════════════════════════════════════════════
  // CAA Check
  let caa_result = @caa.check(domain)
  let caa_has_records = caa_result.records.length() > 0

  // TLSA/DANE Check
  let tlsa_result = @tlsa.check(domain)
  let tlsa_has_records = tlsa_result.records.length() > 0

  // DNSSEC Check
  let dnssec_result = @dnssec.check(domain)

  // Only show section if there are results or show_all
  if caa_has_records || tlsa_has_records || dnssec_result.enabled || show_all {
    print_section("Security Records")

    if caa_has_records || show_all {
      print_subsection("CAA (RFC 8659)")
      checks_total = checks_total + 1
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
      if show_all {
        for warn in caa_result.warnings {
          println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
        }
      }
      if caa_has_records {
        checks_passed = checks_passed + 1
      }
      println("")
    }

    if tlsa_has_records || show_all {
      print_subsection("TLSA/DANE (RFC 6698)")
      checks_total = checks_total + 1
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
      if show_all {
        for warn in tlsa_result.warnings {
          println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
        }
      }
      if tlsa_has_records {
        checks_passed = checks_passed + 1
      }
      println("")
    }

    if dnssec_result.enabled || show_all {
      print_subsection("DNSSEC")
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
      if show_all {
        for warn in dnssec_result.warnings {
          println("      " + @lib.yellow + "Info: " + warn + @lib.reset)
        }
      }
      if dnssec_result.enabled {
        checks_passed = checks_passed + 1
      }
      println("")
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SERVICE RECORDS
  // ═══════════════════════════════════════════════════════════════════════════
  let srv_results = @srv.check(domain)
  let mut srv_found = 0
  for result in srv_results {
    if result.records.length() > 0 {
      srv_found = srv_found + 1
    }
  }

  if srv_found > 0 || show_all {
    print_section("Service Discovery (SRV)")
    for result in srv_results {
      if result.records.length() > 0 {
        println("  " + @lib.green + "✓" + @lib.reset + " " + result.service)
        for rec in result.records {
          println(
            "      " + rec.priority.to_string() + " " + rec.weight.to_string() + " " + rec.port.to_string() + " " + rec.target,
          )
        }
      }
    }
    if srv_found == 0 && show_all {
      println("  " + @lib.yellow + "No SRV records found for common email services" + @lib.reset)
    }
    println("")
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SUMMARY
  // ═══════════════════════════════════════════════════════════════════════════
  println("═══════════════════════════════════════════════════════════════════════")
  println(@lib.bold + "Summary" + @lib.reset)
  println("═══════════════════════════════════════════════════════════════════════")

  // Core checks summary
  println("  " + @lib.bold + "Core Checks:" + @lib.reset)
  println("    " + @lib.format_status(addr_result.valid) + " A/AAAA")
  println("    " + @lib.format_status(ns_result.valid) + " NS")
  println("    " + @lib.format_status(soa_result.valid) + " SOA")
  if show_txt {
    println("    " + @lib.format_status(txt_has_records) + " TXT")
  }
  println("    " + @lib.format_status(mx_result.valid) + " MX")
  println("    " + @lib.format_status(spf_result.valid) + " SPF")
  println("    " + @lib.format_status(dmarc_result.valid) + " DMARC")
  println("    " + @lib.format_status(dkim_result.valid) + " DKIM")

  // Show optional only if any are configured or show_all
  if mta_sts_valid || tlsrpt_valid || bimi_valid || caa_has_records || tlsa_has_records || dnssec_result.enabled || srv_found > 0 || show_all {
    println("")
    println("  " + @lib.bold + "Optional/Enhanced:" + @lib.reset)
    if mta_sts_valid || show_all {
      let status = if mta_sts_valid { @lib.green + "[OK]" + @lib.reset } else { @lib.yellow + "[--]" + @lib.reset }
      println("    " + status + " MTA-STS")
    }
    if tlsrpt_valid || show_all {
      let status = if tlsrpt_valid { @lib.green + "[OK]" + @lib.reset } else { @lib.yellow + "[--]" + @lib.reset }
      println("    " + status + " TLS-RPT")
    }
    if bimi_valid || show_all {
      let status = if bimi_valid { @lib.green + "[OK]" + @lib.reset } else { @lib.yellow + "[--]" + @lib.reset }
      println("    " + status + " BIMI")
    }
    if caa_has_records || show_all {
      let status = if caa_has_records { @lib.green + "[OK]" + @lib.reset } else { @lib.yellow + "[--]" + @lib.reset }
      println("    " + status + " CAA")
    }
    if tlsa_has_records || show_all {
      let status = if tlsa_has_records { @lib.green + "[OK]" + @lib.reset } else { @lib.yellow + "[--]" + @lib.reset }
      println("    " + status + " TLSA/DANE")
    }
    if dnssec_result.enabled || show_all {
      let status = if dnssec_result.enabled { @lib.green + "[OK]" + @lib.reset } else { @lib.yellow + "[--]" + @lib.reset }
      println("    " + status + " DNSSEC")
    }
    if srv_found > 0 {
      println("    " + @lib.green + "[OK]" + @lib.reset + " SRV (" + srv_found.to_string() + " services)")
    }
  }

  println("")
  println("  Checks Passed: " + checks_passed.to_string() + "/" + checks_total.to_string())
  println("  Errors: " + total_errors.to_string())
  println("  Warnings: " + total_warnings.to_string())
}
