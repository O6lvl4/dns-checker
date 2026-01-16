///|
fn print_usage() -> Unit {
  println("Usage: dns-checker <domain> [options]")
  println("")
  println("Check DNS records for email domain configuration (RFC compliant)")
  println("")
  println("Checks performed:")
  println("  - MX records")
  println("  - SPF (RFC 7208) - Sender Policy Framework")
  println("  - DMARC (RFC 7489) - Domain-based Message Authentication")
  println("  - DKIM (RFC 6376) - DomainKeys Identified Mail")
  println("")
  println("Example:")
  println("  dns-checker example.com")
}

///|
fn print_header(domain : String) -> Unit {
  println("╔══════════════════════════════════════════════════════════════╗")
  println("║           DNS Record Checker (RFC Compliant)                ║")
  println("╚══════════════════════════════════════════════════════════════╝")
  println("")
  println("Domain: " + domain)
  println("")
}

///|
fn print_section(title : String) -> Unit {
  println("─────────────────────────────────────────────────────────────────")
  println(@lib.bold + title + @lib.reset)
  println("─────────────────────────────────────────────────────────────────")
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

  // MX Check
  print_section("MX Records")
  let mx_result = @mx.check(domain)
  println(@lib.format_status(mx_result.valid) + " MX Records")
  if mx_result.records.length() > 0 {
    for entry in mx_result.records {
      println("    " + entry.priority.to_string() + " " + entry.host)
    }
  }
  for err in mx_result.errors {
    println("    " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in mx_result.warnings {
    println("    " + @lib.yellow + "Warning: " + warn + @lib.reset)
    total_warnings = total_warnings + 1
  }
  println("")

  // SPF Check
  print_section("SPF (RFC 7208)")
  let spf_result = @spf.check(domain)
  println(@lib.format_status(spf_result.valid) + " SPF Record")
  match spf_result.record {
    Some(r) => {
      println("    Mechanisms: " + r.mechanisms.length().to_string())
      println("    DNS Lookups: " + spf_result.dns_lookup_count.to_string() + "/10")
    }
    None => ()
  }
  for err in spf_result.errors {
    println("    " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in spf_result.warnings {
    println("    " + @lib.yellow + "Warning: " + warn + @lib.reset)
    total_warnings = total_warnings + 1
  }
  println("")

  // DMARC Check
  print_section("DMARC (RFC 7489)")
  let dmarc_result = @dmarc.check(domain)
  println(@lib.format_status(dmarc_result.valid) + " DMARC Record")
  match dmarc_result.record {
    Some(r) => {
      println("    Policy: " + r.policy.to_string())
      println("    DKIM Alignment: " + r.adkim.to_string())
      println("    SPF Alignment: " + r.aspf.to_string())
      println("    Percentage: " + r.pct.to_string() + "%")
      if r.rua.length() > 0 {
        println("    Report URIs: " + r.rua.length().to_string())
      }
    }
    None => ()
  }
  for err in dmarc_result.errors {
    println("    " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  for warn in dmarc_result.warnings {
    println("    " + @lib.yellow + "Warning: " + warn + @lib.reset)
    total_warnings = total_warnings + 1
  }
  println("")

  // DKIM Check
  print_section("DKIM (RFC 6376)")
  let dkim_result = @dkim.check(domain)
  println(@lib.format_status(dkim_result.valid) + " DKIM Records")
  println("    Selectors checked: " + dkim_result.selectors_checked.to_string())
  println("    Selectors found: " + dkim_result.selectors_found.to_string())
  for r in dkim_result.results {
    match r.record {
      Some(rec) => {
        println("    " + @lib.green + "✓" + @lib.reset + " " + r.selector + " (" + rec.key_type.to_string() + ")")
      }
      None => ()
    }
    for err in r.errors {
      println("      " + @lib.red + "Error: " + err + @lib.reset)
      total_errors = total_errors + 1
    }
    for warn in r.warnings {
      println("      " + @lib.yellow + "Warning: " + warn + @lib.reset)
      total_warnings = total_warnings + 1
    }
  }
  for err in dkim_result.errors {
    println("    " + @lib.red + "Error: " + err + @lib.reset)
    total_errors = total_errors + 1
  }
  println("")

  // Summary
  println("═════════════════════════════════════════════════════════════════")
  println(@lib.bold + "Summary" + @lib.reset)
  println("═════════════════════════════════════════════════════════════════")

  let checks = [
    ("MX", mx_result.valid),
    ("SPF", spf_result.valid),
    ("DMARC", dmarc_result.valid),
    ("DKIM", dkim_result.valid),
  ]

  let mut passed = 0
  for check in checks {
    let status = @lib.format_status(check.1)
    println("  " + status + " " + check.0)
    if check.1 {
      passed = passed + 1
    }
  }

  println("")
  println("  Passed: " + passed.to_string() + "/4")
  println("  Errors: " + total_errors.to_string())
  println("  Warnings: " + total_warnings.to_string())
}
