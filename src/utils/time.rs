//! Time helpers.

use chrono::{SecondsFormat, Utc};

pub fn now_timestamp_string() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true)
}
