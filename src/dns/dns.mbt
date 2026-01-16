// DNS Query Module - Common DNS query functions

///| DNS Record Types
pub(all) enum RecordType {
  A
  AAAA
  CNAME
  MX
  TXT
  NS
  PTR
  SOA
  CAA
  SRV
  TLSA
  DNSKEY
  DS
}

///| Convert RecordType to dig query string
pub fn RecordType::to_query_string(self : RecordType) -> String {
  match self {
    A => "A"
    AAAA => "AAAA"
    CNAME => "CNAME"
    MX => "MX"
    TXT => "TXT"
    NS => "NS"
    PTR => "PTR"
    SOA => "SOA"
    CAA => "CAA"
    SRV => "SRV"
    TLSA => "TLSA"
    DNSKEY => "DNSKEY"
    DS => "DS"
  }
}

///| DNS Query Result
pub(all) struct QueryResult {
  success : Bool
  records : Array[String]
  raw_output : String
  error : String
}

///| Create empty result
pub fn QueryResult::empty() -> QueryResult {
  { success: false, records: [], raw_output: "", error: "" }
}

///| Create success result
pub fn QueryResult::ok(records : Array[String], raw : String) -> QueryResult {
  { success: true, records, raw_output: raw, error: "" }
}

///| Create error result
pub fn QueryResult::err(msg : String) -> QueryResult {
  { success: false, records: [], raw_output: "", error: msg }
}

///| Query DNS records using dig
#cfg(target = "native")
pub async fn query(host : String, record_type : RecordType) -> QueryResult {
  let query_type = record_type.to_query_string()
  let (exit_code, output) = @process.collect_stdout(
    "dig",
    [query_type, host, "+short", "+time=5", "+tries=2"],
  )
  let raw = output.text().trim().to_string()

  if exit_code != 0 {
    return QueryResult::err("dig command failed with exit code " + exit_code.to_string())
  }

  if raw.is_empty() {
    return QueryResult::ok([], raw)
  }

  // Parse multiple records (one per line)
  let records = parse_lines(raw)
  QueryResult::ok(records, raw)
}

///| Query TXT records (convenience function)
#cfg(target = "native")
pub async fn query_txt(host : String) -> QueryResult {
  query(host, TXT)
}

///| Query MX records (convenience function)
#cfg(target = "native")
pub async fn query_mx(host : String) -> QueryResult {
  query(host, MX)
}

///| Query CNAME records (convenience function)
#cfg(target = "native")
pub async fn query_cname(host : String) -> QueryResult {
  query(host, CNAME)
}

///| Query A records (convenience function)
#cfg(target = "native")
pub async fn query_a(host : String) -> QueryResult {
  query(host, A)
}

///| Parse lines from output
fn parse_lines(s : String) -> Array[String] {
  let lines : Array[String] = []
  let current = StringBuilder::new()

  for c in s {
    if c == '\n' {
      let line = current.to_string().trim().to_string()
      if not(line.is_empty()) {
        lines.push(line)
      }
      current.reset()
    } else {
      current.write_char(c)
    }
  }

  // Don't forget the last line
  let last = current.to_string().trim().to_string()
  if not(last.is_empty()) {
    lines.push(last)
  }

  lines
}

///| Strip quotes from TXT record value
pub fn strip_quotes(s : String) -> String {
  let len = s.length()
  if len >= 2 && s[0] == '"' && s[len - 1] == '"' {
    s.substring(start=1, end=len - 1)
  } else {
    s
  }
}

///| Concatenate multiple TXT record strings (RFC allows splitting)
pub fn concat_txt_records(records : Array[String]) -> String {
  let result = StringBuilder::new()
  for record in records {
    result.write_string(strip_quotes(record))
  }
  result.to_string()
}
