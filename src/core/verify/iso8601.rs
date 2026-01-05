//! ISO 8601 timestamp parsing utilities
//!
//! Provides simple, dependency-free ISO 8601 timestamp parsing
//! for converting timestamps to nanoseconds since Unix epoch.

/// Days in each month (non-leap year)
const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Parse ISO 8601 timestamp to nanoseconds (simple implementation)
///
/// Supports basic format: `YYYY-MM-DDTHH:MM:SSZ`
///
/// Returns nanoseconds since Unix epoch (1970-01-01T00:00:00Z).
///
/// ## Arguments
///
/// * `timestamp` - ISO 8601 formatted timestamp string
///
/// ## Returns
///
/// * `Some(u64)` - Nanoseconds since Unix epoch if parsing succeeds
/// * `None` - If timestamp format is invalid or values are out of range
///
/// ## Examples
///
/// ```
/// use atl_core::core::verify::parse_iso8601_to_nanos;
///
/// // Unix epoch
/// assert_eq!(parse_iso8601_to_nanos("1970-01-01T00:00:00Z"), Some(0));
///
/// // Valid timestamp
/// let nanos = parse_iso8601_to_nanos("2026-01-15T10:31:00Z");
/// assert!(nanos.is_some());
///
/// // Invalid format
/// assert_eq!(parse_iso8601_to_nanos("invalid"), None);
/// ```
#[must_use]
pub fn parse_iso8601_to_nanos(timestamp: &str) -> Option<u64> {
    // Expected format: YYYY-MM-DDTHH:MM:SSZ
    if timestamp.len() != 20 || !timestamp.ends_with('Z') {
        return None;
    }

    let parts: Vec<&str> = timestamp[..19].split('T').collect();
    if parts.len() != 2 {
        return None;
    }

    // Parse date part: YYYY-MM-DD
    let date_parts: Vec<&str> = parts[0].split('-').collect();
    if date_parts.len() != 3 {
        return None;
    }
    let year = date_parts[0].parse::<i32>().ok()?;
    let month = date_parts[1].parse::<u32>().ok()?;
    let day = date_parts[2].parse::<u32>().ok()?;

    // Parse time part: HH:MM:SS
    let time_parts: Vec<&str> = parts[1].split(':').collect();
    if time_parts.len() != 3 {
        return None;
    }
    let hour = time_parts[0].parse::<u32>().ok()?;
    let minute = time_parts[1].parse::<u32>().ok()?;
    let second = time_parts[2].parse::<u32>().ok()?;

    // Validate ranges
    if !(1970..=9999).contains(&year)
        || !(1..=12).contains(&month)
        || hour >= 24
        || minute >= 60
        || second >= 60
    {
        return None;
    }

    // Validate day of month
    let max_day = if month == 2 && is_leap_year(year) {
        29
    } else {
        DAYS_IN_MONTH[usize::try_from(month - 1).ok()?]
    };
    if day < 1 || day > max_day {
        return None;
    }

    // Days since Unix epoch (1970-01-01)
    let days_since_epoch = days_since_unix_epoch(year, month, day)?;

    // Total seconds since epoch
    let total_seconds = u64::from(days_since_epoch) * 86400
        + u64::from(hour) * 3600
        + u64::from(minute) * 60
        + u64::from(second);

    // Convert to nanoseconds
    Some(total_seconds * 1_000_000_000)
}

/// Calculate days since Unix epoch (1970-01-01)
///
/// ## Arguments
///
/// * `year` - Year (must be >= 1970)
/// * `month` - Month (1-12)
/// * `day` - Day of month (1-31)
///
/// ## Returns
///
/// * `Some(u32)` - Number of days since 1970-01-01
/// * `None` - If calculation overflows
fn days_since_unix_epoch(year: i32, month: u32, day: u32) -> Option<u32> {
    // Calculate days from year 1970 to the given year
    let mut days = 0u32;

    // Add days for complete years
    for y in 1970..year {
        days = days.checked_add(if is_leap_year(y) { 366 } else { 365 })?;
    }

    // Add days for complete months in the given year
    for m in 1..month {
        let days_in_m = if m == 2 && is_leap_year(year) {
            29
        } else {
            DAYS_IN_MONTH[usize::try_from(m - 1).ok()?]
        };
        days = days.checked_add(days_in_m)?;
    }

    // Add remaining days
    days = days.checked_add(day - 1)?;

    Some(days)
}

/// Check if a year is a leap year
///
/// ## Arguments
///
/// * `year` - Year to check
///
/// ## Returns
///
/// * `true` if the year is a leap year
/// * `false` otherwise
///
/// ## Leap Year Rules
///
/// - Divisible by 4: leap year
/// - Divisible by 100: NOT a leap year
/// - Divisible by 400: leap year
#[must_use]
pub const fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

// ========== Tests ==========

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_iso8601_to_nanos_valid() {
        // Unix epoch
        assert_eq!(parse_iso8601_to_nanos("1970-01-01T00:00:00Z"), Some(0));

        // Example timestamp: 2026-01-15T10:31:00Z
        assert_eq!(
            parse_iso8601_to_nanos("2026-01-15T10:31:00Z"),
            Some(1_768_473_060 * 1_000_000_000)
        );

        // Leap year test: 2024-02-29T12:00:00Z
        assert_eq!(
            parse_iso8601_to_nanos("2024-02-29T12:00:00Z"),
            Some(1_709_208_000 * 1_000_000_000)
        );
    }

    #[test]
    fn test_parse_iso8601_to_nanos_invalid() {
        // Invalid format
        assert_eq!(parse_iso8601_to_nanos("2026-01-15"), None);
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00"), None); // Missing Z
        assert_eq!(parse_iso8601_to_nanos("invalid"), None);

        // Invalid date
        assert_eq!(parse_iso8601_to_nanos("2026-13-01T00:00:00Z"), None); // Month 13
        assert_eq!(parse_iso8601_to_nanos("2026-02-30T00:00:00Z"), None); // Feb 30
        assert_eq!(parse_iso8601_to_nanos("1969-01-01T00:00:00Z"), None); // Before epoch

        // Invalid time
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T25:00:00Z"), None); // Hour 25
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:60:00Z"), None); // Minute 60
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:60Z"), None); // Second 60
    }

    #[test]
    fn test_is_leap_year() {
        assert!(is_leap_year(2000)); // Divisible by 400
        assert!(is_leap_year(2024)); // Divisible by 4, not by 100
        assert!(!is_leap_year(1900)); // Divisible by 100, not by 400
        assert!(!is_leap_year(2023)); // Not divisible by 4
    }

    #[test]
    fn test_days_since_unix_epoch() {
        // 1970-01-01
        assert_eq!(days_since_unix_epoch(1970, 1, 1), Some(0));

        // 1970-01-02
        assert_eq!(days_since_unix_epoch(1970, 1, 2), Some(1));

        // 1971-01-01 (365 days after epoch)
        assert_eq!(days_since_unix_epoch(1971, 1, 1), Some(365));

        // 2000-01-01 (leap years: 1972, 1976, ..., 1996; non-leap: 1900, 2100)
        // 30 years * 365 + 7 leap years (1972-1996) = 10957 days
        assert_eq!(days_since_unix_epoch(2000, 1, 1), Some(10957));
    }
}
