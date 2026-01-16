// DNS Record Checker - MoonBit Implementation

///| DNS record type
pub(all) enum RecordType {
  TXT
  CNAME
  DMARC
  DKIM
}

///| Check result
pub(all) struct CheckResult {
  record_type : RecordType
  host : String
  passed : Bool
  value : String
  reason : String
}

///| Convert RecordType to string for display
pub fn RecordType::to_string(self : RecordType) -> String {
  match self {
    TXT => "TXT"
    CNAME => "CNAME"
    DMARC => "DMARC"
    DKIM => "DKIM"
  }
}

///| Run dig command and return output
#cfg(target = "native")
pub async fn run_dig(host : String, query_type : String) -> (Int, String) {
  let (exit_code, output) = @process.collect_stdout(
    "dig",
    [query_type, host, "+short"],
  )
  let result = output.text().trim().to_string()
  (exit_code, result)
}

///| Check if TXT record contains expected value
pub fn check_txt_record(output : String, expected : String) -> (Bool, String) {
  if output.is_empty() {
    (false, "No TXT record found")
  } else if output.contains(expected) {
    (true, "Found: " + output)
  } else {
    (false, "TXT record exists but doesn't contain expected value. Got: " + output)
  }
}

///| Check if CNAME record points to expected target
pub fn check_cname_record(output : String, expected : String) -> (Bool, String) {
  if output.is_empty() {
    (false, "No CNAME record found")
  } else if output.contains(expected) {
    (true, "Points to: " + output)
  } else {
    (false, "CNAME exists but doesn't point to expected target. Got: " + output)
  }
}

///| Check TXT records for domain
#cfg(target = "native")
pub async fn check_txt(domain : String) -> CheckResult {
  let (_, output) = run_dig(domain, "TXT")
  let (passed, reason) = if output.is_empty() {
    (false, "No TXT record found")
  } else {
    (true, "Found: " + output)
  }
  { record_type: TXT, host: domain, passed, value: output, reason }
}

///| Check SPF record
#cfg(target = "native")
pub async fn check_spf(domain : String) -> CheckResult {
  let (_, output) = run_dig(domain, "TXT")
  let (passed, reason) = if output.contains("v=spf1") {
    (true, "SPF record found")
  } else if output.is_empty() {
    (false, "No SPF record found")
  } else {
    (false, "TXT records exist but no SPF")
  }
  { record_type: TXT, host: domain + " (SPF)", passed, value: output, reason }
}

///| Check DMARC record
#cfg(target = "native")
pub async fn check_dmarc(domain : String) -> CheckResult {
  let dmarc_host = "_dmarc." + domain
  let (_, output) = run_dig(dmarc_host, "TXT")
  let (passed, reason) = if output.contains("v=DMARC1") {
    (true, "DMARC record found")
  } else if output.is_empty() {
    (false, "No DMARC record found at " + dmarc_host)
  } else {
    (false, "TXT record exists but not valid DMARC")
  }
  { record_type: DMARC, host: dmarc_host, passed, value: output, reason }
}

///| Check DKIM record
#cfg(target = "native")
pub async fn check_dkim(domain : String, selector : String) -> CheckResult {
  let dkim_host = selector + "._domainkey." + domain
  let (_, output) = run_dig(dkim_host, "CNAME")
  let (passed, reason) = if output.is_empty() {
    (false, "No DKIM CNAME record found at " + dkim_host)
  } else {
    (true, "DKIM CNAME points to: " + output)
  }
  { record_type: DKIM, host: dkim_host, passed, value: output, reason }
}

// ANSI color codes
let green = "\u001b[32m"
let red = "\u001b[31m"
let reset = "\u001b[0m"
let bold = "\u001b[1m"

///| Format check result with colors
pub fn format_result(result : CheckResult) -> String {
  let (color, status) = if result.passed {
    (green, "[OK]")
  } else {
    (red, "[NG]")
  }
  let type_str = result.record_type.to_string()
  color + bold + status + reset + " " + type_str + " @ " + result.host + "\n    " + result.reason
}

///| Run all DNS checks for email domain
#cfg(target = "native")
pub async fn check_email_domain(domain : String) -> Array[CheckResult] {
  let results : Array[CheckResult] = []

  // TXT records
  let txt = check_txt(domain)
  results.push(txt)

  // SPF
  let spf = check_spf(domain)
  results.push(spf)

  // DMARC
  let dmarc = check_dmarc(domain)
  results.push(dmarc)

  // DKIM (common selectors)
  let dkim1 = check_dkim(domain, "selector1")
  results.push(dkim1)

  let dkim2 = check_dkim(domain, "selector2")
  results.push(dkim2)

  results
}
