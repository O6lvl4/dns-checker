///|
fn print_usage() -> Unit {
  println("Usage: dns-checker <domain>")
  println("")
  println("Check DNS records for email domain configuration:")
  println("  - TXT records")
  println("  - SPF (TXT)")
  println("  - DMARC (TXT)")
  println("  - DKIM (CNAME) - selector1 & selector2")
  println("")
  println("Example:")
  println("  dns-checker example.com")
}

///|
async fn main {
  let args = @env.args()

  // args[0] is the program name
  if args.length() < 2 {
    print_usage()
    return
  }

  let domain = args[1]

  if domain == "--help" || domain == "-h" {
    print_usage()
    return
  }

  println("=== DNS Record Checker ===")
  println("Domain: " + domain)
  println("")

  let results = @dns.check_email_domain(domain)

  for result in results {
    println(@dns.format_result(result))
    println("")
  }

  // Summary
  let mut passed = 0
  for result in results {
    if result.passed {
      passed = passed + 1
    }
  }
  let total = results.length()
  println("=== Summary: " + passed.to_string() + "/" + total.to_string() + " passed ===")
}
