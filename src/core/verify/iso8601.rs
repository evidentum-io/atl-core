//! ISO 8601 timestamp parsing utilities
//!
//! Provides simple, dependency-free ISO 8601 timestamp parsing
//! for converting timestamps to nanoseconds since Unix epoch.

/// Days in each month (non-leap year)
const DAYS_IN_MONTH: [u32; 12] = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Parse an RFC 3339 timestamp to nanoseconds since the Unix epoch.
///
/// # Accepted forms
///
/// `YYYY-MM-DDThh:mm:ss[.fraction](Z|±hh:mm)`, with `T` and `Z` accepted in
/// either case. Both a `Z` and a numeric offset are accepted, and an offset
/// is applied — `2026-01-19T08:01:20+01:00` and `2026-01-19T07:01:20Z` are
/// the same instant and return the same value.
///
/// **The numeric offset is not a nicety.** This parser previously required
/// exactly 20 characters ending in `Z`, while the ATL server writes its
/// anchor timestamps with `to_rfc3339()`, which renders UTC as `+00:00`. The
/// reference implementation therefore could not read the output of its own
/// reference server: 37 of the 38 anchor timestamps in the production corpus
/// were rejected, and every `claimed_timestamp` derived from one came out
/// `None`. ATL v2.0 §4.2 types these fields as `<ISO8601>` and constrains
/// them no further, so a verifier that accepts only one spelling of an
/// instant is the thing that is wrong.
///
/// # Rejected, and deliberately so
///
/// * Anything with no offset at all: an instant with no zone is not an
///   instant, and guessing UTC would invent information.
/// * A second field of `60`. RFC 3339 permits it for leap seconds; this
///   parser does not model them, and returning an approximate instant would
///   be worse than returning nothing.
/// * More than nine fractional digits, unless every digit past the ninth is
///   `0`. Nanoseconds are the finest resolution this function's return type
///   can express, and silently truncating below that would report two
///   *different* instants as one value — which a caller comparing instants
///   would then publish as a match.
/// * Anything before 1970-01-01T00:00:00Z, after applying the offset.
///
/// A `None` return means **this build could not read the string**, never
/// that the string is wrong. Callers must classify it as an inability.
///
/// ## Examples
///
/// ```
/// use atl_core::core::verify::parse_iso8601_to_nanos;
///
/// // Unix epoch
/// assert_eq!(parse_iso8601_to_nanos("1970-01-01T00:00:00Z"), Some(0));
///
/// // The spelling the ATL server actually writes
/// assert_eq!(
///     parse_iso8601_to_nanos("2026-01-19T07:01:20+00:00"),
///     parse_iso8601_to_nanos("2026-01-19T07:01:20Z"),
/// );
///
/// // An offset is applied, not ignored
/// assert_eq!(
///     parse_iso8601_to_nanos("2026-01-19T08:01:20+01:00"),
///     parse_iso8601_to_nanos("2026-01-19T07:01:20Z"),
/// );
///
/// // Sub-second precision is preserved, not rounded away
/// assert_eq!(
///     parse_iso8601_to_nanos("1970-01-01T00:00:00.000000001Z"),
///     Some(1),
/// );
///
/// // Invalid format
/// assert_eq!(parse_iso8601_to_nanos("invalid"), None);
/// ```
#[must_use]
pub fn parse_iso8601_to_nanos(timestamp: &str) -> Option<u64> {
    // Everything below indexes BYTES, never the `&str`.
    //
    // This is a hard rule for this function, not a style preference. `str`
    // slicing panics when an index is not a UTF-8 character boundary, and
    // every byte position here is computed from lengths rather than found by
    // a search -- so a multi-byte character anywhere in the input can put an
    // index mid-character. That is exactly what happened: `split_at(len - 6)`
    // aborted the process on a `bitcoin_block_time` of "💥abc".
    //
    // These fields are deserialized as unvalidated `String`s straight out of
    // a receipt, which is adversarial input by definition. A verifier must
    // answer "refuted" or "could not check"; dying on a signal answers
    // nothing. Slice indexing returns `None` for an out-of-range index and
    // has no notion of character boundaries, so working in bytes removes the
    // whole class rather than guarding one instance of it.
    let (civil, offset_secs) = split_offset(timestamp.as_bytes())?;

    // RFC 3339 separates date and time with `T`; lowercase is permitted.
    let sep = civil.iter().position(|b| matches!(b, b'T' | b't'))?;
    let (year, month, day) = parse_date(civil.get(..sep)?)?;
    let (hour, minute, second, subsec_nanos) = parse_time(civil.get(sep + 1..)?)?;

    // `days_since_unix_epoch` counts forward from 1970 and would silently
    // return 0 for an earlier year, so the range is checked before it.
    if !(1970..=9999).contains(&year) {
        return None;
    }
    let days = days_since_unix_epoch(year, month, day)?;

    // Seconds of the *named* wall clock, then shifted onto UTC. Signed
    // throughout: a positive offset can move an instant just after the epoch
    // to before it, and that must come out as a rejection rather than wrap.
    let civil_secs = i64::from(days)
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3_600 + i64::from(minute) * 60 + i64::from(second))?;
    let utc_secs = civil_secs.checked_sub(offset_secs)?;

    u64::try_from(utc_secs).ok()?.checked_mul(1_000_000_000)?.checked_add(u64::from(subsec_nanos))
}

/// Split an RFC 3339 timestamp into its civil part and its offset in seconds
/// east of UTC.
fn split_offset(timestamp: &[u8]) -> Option<(&[u8], i64)> {
    if let Some((last, civil)) = timestamp.split_last() {
        if matches!(last, b'Z' | b'z') {
            return Some((civil, 0));
        }
    }

    // `±hh:mm`, exactly six bytes, colon required (RFC 3339 5.6). Other
    // spellings (`+hhmm`, `+hh`) are ISO 8601 but not RFC 3339, and guessing
    // at them would mean accepting a form nothing in ATL guarantees.
    let split = timestamp.len().checked_sub(6)?;
    let civil = timestamp.get(..split)?;
    let offset = timestamp.get(split..)?;

    let sign = match offset.first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    if offset.get(3)? != &b':' {
        return None;
    }
    let hours: i64 = parse_digits(offset.get(1..3)?)?.into();
    let minutes: i64 = parse_digits(offset.get(4..6)?)?.into();
    if hours > 23 || minutes > 59 {
        return None;
    }
    Some((civil, sign * (hours * 3_600 + minutes * 60)))
}

/// `YYYY-MM-DD`, with the day validated against the month and the year.
///
/// RFC 3339's `full-date` is fixed width, so the fields are read at fixed
/// byte offsets rather than split out — one length check covers every access.
fn parse_date(date: &[u8]) -> Option<(i32, u32, u32)> {
    if date.len() != 10 || date.get(4)? != &b'-' || date.get(7)? != &b'-' {
        return None;
    }
    let year = i32::try_from(parse_digits(date.get(..4)?)?).ok()?;
    let month = parse_digits(date.get(5..7)?)?;
    let day = parse_digits(date.get(8..10)?)?;

    if !(1..=12).contains(&month) {
        return None;
    }
    let max_day = if month == 2 && is_leap_year(year) {
        29
    } else {
        *DAYS_IN_MONTH.get(usize::try_from(month - 1).ok()?)?
    };
    if day < 1 || day > max_day {
        return None;
    }
    Some((year, month, day))
}

/// `hh:mm:ss` with an optional `.fraction`, returned as whole fields plus
/// nanoseconds.
fn parse_time(time: &[u8]) -> Option<(u32, u32, u32, u32)> {
    let (whole, fraction) = match time.iter().position(|b| *b == b'.') {
        Some(dot) => (time.get(..dot)?, Some(time.get(dot + 1..)?)),
        None => (time, None),
    };

    // `partial-time`'s seconds-bearing form is fixed width too.
    if whole.len() != 8 || whole.get(2)? != &b':' || whole.get(5)? != &b':' {
        return None;
    }
    let hour = parse_digits(whole.get(..2)?)?;
    let minute = parse_digits(whole.get(3..5)?)?;
    let second = parse_digits(whole.get(6..8)?)?;
    // 60 would be a leap second, which this function does not model.
    if hour >= 24 || minute >= 60 || second >= 60 {
        return None;
    }

    let subsec_nanos = match fraction {
        None => 0,
        Some(digits) => parse_fraction_nanos(digits)?,
    };
    Some((hour, minute, second, subsec_nanos))
}

/// A fractional-second field, scaled to nanoseconds.
///
/// Returns `None` when the value cannot be represented exactly. Truncating
/// instead would collapse distinct instants onto one number, and a caller
/// comparing instants would report the collapse as agreement.
fn parse_fraction_nanos(digits: &[u8]) -> Option<u32> {
    let cut = digits.len().min(9);
    let head = digits.get(..cut)?;
    let tail = digits.get(cut..)?;
    if !tail.iter().all(|b| *b == b'0') {
        return None;
    }
    let mut nanos = parse_digits(head)?;
    for _ in head.len()..9 {
        nanos = nanos.checked_mul(10)?;
    }
    Some(nanos)
}

/// Parse a field of ASCII digits.
///
/// Folds the bytes itself rather than going through `str::parse`, which
/// would accept a leading sign and surrounding whitespace, and which would
/// need a `&str` -- the type this function exists to stop indexing.
fn parse_digits(field: &[u8]) -> Option<u32> {
    if field.is_empty() {
        return None;
    }
    field.iter().try_fold(0u32, |acc, byte| {
        let digit = byte.checked_sub(b'0').filter(|d| *d <= 9)?;
        acc.checked_mul(10)?.checked_add(u32::from(digit))
    })
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
            // `get`, not `[]`: the caller validates `month`, but a bound
            // enforced in another function is an argument rather than a
            // guarantee, and this one costs nothing to make local.
            *DAYS_IN_MONTH.get(usize::try_from(m.checked_sub(1)?).ok()?)?
        };
        days = days.checked_add(days_in_m)?;
    }

    // Add remaining days. `checked_sub` for the same reason: `day >= 1` is
    // the caller's check, and an unsigned underflow here would panic in a
    // debug build and wrap in a release one.
    days = days.checked_add(day.checked_sub(1)?)?;

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

    /// **The spelling the ATL server actually writes.** `to_rfc3339()`
    /// renders UTC as `+00:00`, and this parser used to reject it outright
    /// — the reference implementation unable to read its own reference
    /// server's output, on 37 of the 38 anchor timestamps in the production
    /// corpus.
    #[test]
    fn the_numeric_utc_offset_the_server_writes_is_accepted() {
        let z = parse_iso8601_to_nanos("2026-01-19T07:01:20Z");
        assert!(z.is_some());
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T07:01:20+00:00"), z);
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T07:01:20-00:00"), z);
        // Lower case is permitted by RFC 3339 for both `T` and `Z`.
        assert_eq!(parse_iso8601_to_nanos("2026-01-19t07:01:20z"), z);
    }

    /// An offset is *applied*, never ignored. Reading `+01:00` as if it were
    /// UTC would place the instant an hour away from where it is.
    #[test]
    fn a_numeric_offset_shifts_the_instant() {
        let utc = parse_iso8601_to_nanos("2026-01-19T07:01:20Z").unwrap();
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T08:01:20+01:00"), Some(utc));
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T02:01:20-05:00"), Some(utc));
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T07:31:20+00:30"), Some(utc));
        // Across a date boundary, in both directions.
        assert_eq!(parse_iso8601_to_nanos("2026-01-20T00:01:20+17:00"), Some(utc));
    }

    /// **Sub-second precision is preserved, not rounded away.** A caller
    /// comparing instants must not be handed a value that makes two
    /// different moments equal — the defect that let a receipt claiming
    /// `07:01:20.000000001` pass as matching a block stamped `07:01:20`.
    #[test]
    fn fractional_seconds_are_exact() {
        let base = parse_iso8601_to_nanos("2026-01-19T07:01:20Z").unwrap();
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T07:01:20.0Z"), Some(base));
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T07:01:20.000000000Z"), Some(base));
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T07:01:20.000000001Z"), Some(base + 1));
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T07:01:20.5Z"), Some(base + 500_000_000));
        assert_eq!(
            parse_iso8601_to_nanos("2026-01-19T07:01:20.123456789Z"),
            Some(base + 123_456_789)
        );
        // Trailing zeros past nanosecond resolution change nothing.
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T07:01:20.0000000010Z"), Some(base + 1));
    }

    /// Precision finer than a nanosecond cannot be represented, so it is
    /// refused rather than truncated. Truncation would return the value of a
    /// *different* instant, and the caller would compare that value and find
    /// it equal.
    #[test]
    fn sub_nanosecond_precision_is_refused_not_truncated() {
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T07:01:20.0000000001Z"), None);
        assert_eq!(parse_iso8601_to_nanos("2026-01-19T07:01:20.1234567891Z"), None);
    }

    #[test]
    fn test_parse_iso8601_to_nanos_invalid() {
        // Invalid format
        assert_eq!(parse_iso8601_to_nanos("2026-01-15"), None);
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00"), None); // No offset
        assert_eq!(parse_iso8601_to_nanos("invalid"), None);

        // An instant with no zone is not an instant; UTC is not assumed.
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00.5"), None);

        // Offsets that are not RFC 3339 5.6's `±hh:mm`.
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00+0000"), None);
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00+00"), None);
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00 00:00"), None);
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00+24:00"), None);
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00+00:60"), None);

        // Fields that are not plain digits: `str::parse` alone would take a
        // sign or surrounding whitespace.
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T+0:31:00Z"), None);
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00.Z"), None);
        assert_eq!(parse_iso8601_to_nanos("2026-01-15T10:31:00.+1Z"), None);

        // A leap second is not modelled, so it is refused rather than
        // approximated.
        assert_eq!(parse_iso8601_to_nanos("2016-12-31T23:59:60Z"), None);

        // An offset that moves the instant before the epoch.
        assert_eq!(parse_iso8601_to_nanos("1970-01-01T00:00:00+01:00"), None);

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
