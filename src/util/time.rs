//! Time formatting helpers.
//!
//! The only time logic `grip` needs is "expires 2026-11-15 (77 days)" for
//! the human output. We keep it isolated so the output layer doesn't pull
//! in ad-hoc chrono formatting.

use chrono::{DateTime, Utc};

/// Format a `not_after` timestamp as `YYYY-MM-DD (N days)`.
///
/// `not_after` is expected to be a `DateTime<Utc>` (from `x509-parser`).
/// The day count is `ceil((not_after - now) / 86400)` for future dates,
/// negative for expired certs.
#[must_use]
pub fn format_expiry(not_after: DateTime<Utc>) -> String {
    let now = Utc::now();
    let duration = not_after.signed_duration_since(now);
    let days = duration.num_days();
    // Round up partial days for future expiries so "23 hours" shows as 1 day.
    let days_display = if duration.num_seconds() > 0 && duration.num_seconds() % 86400 != 0 {
        days + 1
    } else {
        days
    };

    let date = not_after.format("%Y-%m-%d").to_string();
    if days_display >= 0 {
        format!("{date}   ({days_display} days)")
    } else {
        format!("{date}   (expired {days_display} days ago)")
    }
}

/// Simple helper for tests — returns just the date part.
#[cfg(test)]
#[must_use]
pub fn format_date_only(not_after: DateTime<Utc>) -> String {
    not_after.format("%Y-%m-%d").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn future_expiry() {
        let now = Utc::now();
        let future = now + chrono::Duration::days(77);
        let s = format_expiry(future);
        assert!(s.contains("77 days") || s.contains("78 days")); // allow rounding
    }

    #[test]
    fn past_expiry() {
        let past = Utc.with_ymd_and_hms(2020, 1, 1, 0, 0, 0).unwrap();
        let s = format_expiry(past);
        assert!(s.contains("expired"));
    }
}
