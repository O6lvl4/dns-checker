// DNS Record Checker - Main Library
// RFC Compliant: SPF (7208), DMARC (7489), DKIM (6376)

// Re-export modules for convenience
// Users can import this package and access all functionality

// ANSI color codes
pub let green : String = "\u001b[32m"
pub let red : String = "\u001b[31m"
pub let yellow : String = "\u001b[33m"
pub let blue : String = "\u001b[34m"
pub let cyan : String = "\u001b[36m"
pub let reset : String = "\u001b[0m"
pub let bold : String = "\u001b[1m"

///| Overall check result
pub(all) struct CheckSummary {
  pub domain : String
  pub mx_valid : Bool
  pub spf_valid : Bool
  pub dmarc_valid : Bool
  pub dkim_valid : Bool
  pub total_errors : Int
  pub total_warnings : Int
}

///| Format colored status
pub fn format_status(valid : Bool) -> String {
  if valid {
    green + bold + "[OK]" + reset
  } else {
    red + bold + "[NG]" + reset
  }
}

///| Format warning status
pub fn format_warning() -> String {
  yellow + bold + "[WARN]" + reset
}
