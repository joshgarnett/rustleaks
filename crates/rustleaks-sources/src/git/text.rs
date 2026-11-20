use super::patch::{
    PatchError, PatchResult, copy_limited, patch_allocation, poll_patch_cancellation,
};
use crate::Cancellation;

pub(super) fn git_date_to_rfc3339(value: &[u8], limit: usize) -> PatchResult<Option<Vec<u8>>> {
    let Ok(text) = std::str::from_utf8(value) else {
        return Ok(None);
    };
    let mut parts = text.split_ascii_whitespace();
    let Some(_weekday) = parts.next() else {
        return Ok(None);
    };
    let Some(month_name) = parts.next() else {
        return Ok(None);
    };
    let Some(day_text) = parts.next() else {
        return Ok(None);
    };
    let Some(clock_text) = parts.next() else {
        return Ok(None);
    };
    let Some(year_text) = parts.next() else {
        return Ok(None);
    };
    let Some(zone_text) = parts.next() else {
        return Ok(None);
    };
    if parts.next().is_some() {
        return Ok(None);
    }
    let month = match month_name {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return Ok(None),
    };
    let Ok(day) = day_text.parse::<i64>() else {
        return Ok(None);
    };
    let mut clock = clock_text.split(':');
    let Some(Ok(hour)) = clock.next().map(str::parse::<i64>) else {
        return Ok(None);
    };
    let Some(Ok(minute)) = clock.next().map(str::parse::<i64>) else {
        return Ok(None);
    };
    let Some(Ok(second)) = clock.next().map(str::parse::<i64>) else {
        return Ok(None);
    };
    if clock.next().is_some() {
        return Ok(None);
    }
    let Ok(year) = year_text.parse::<i64>() else {
        return Ok(None);
    };
    let zone = zone_text.as_bytes();
    if zone.len() != 5
        || !matches!(zone[0], b'+' | b'-')
        || !zone[1..].iter().all(u8::is_ascii_digit)
    {
        return Ok(None);
    }
    let zone_hours = i64::from((zone[1] - b'0') * 10 + (zone[2] - b'0'));
    let zone_minutes = i64::from((zone[3] - b'0') * 10 + (zone[4] - b'0'));
    let sign = if zone[0] == b'-' { -1 } else { 1 };
    let offset = sign * (zone_hours * 3600 + zone_minutes * 60);
    let Some(days) = days_from_civil(year, month, day) else {
        return Ok(None);
    };
    let Some(clock_seconds) = hour
        .checked_mul(3600)
        .and_then(|value| minute.checked_mul(60)?.checked_add(value))
        .and_then(|value| value.checked_add(second))
    else {
        return Ok(None);
    };
    let Some(timestamp) = days
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(clock_seconds))
        .and_then(|value| value.checked_sub(offset))
    else {
        return Ok(None);
    };
    let Some((utc_year, utc_month, utc_day, utc_hour, utc_minute, utc_second)) =
        civil_from_timestamp(timestamp)
    else {
        return Ok(None);
    };
    let rendered = format!(
        "{utc_year:04}-{utc_month:02}-{utc_day:02}T{utc_hour:02}:{utc_minute:02}:{utc_second:02}Z"
    );
    copy_limited(rendered.as_bytes(), limit, "Git commit date").map(Some)
}

fn days_from_civil(year: i64, month: i64, day: i64) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let adjusted_year = year.checked_sub(i64::from(month <= 2))?;
    let era = adjusted_year.div_euclid(400);
    let year_of_era = adjusted_year.rem_euclid(400);
    let shifted_month = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era.checked_mul(146_097)?
        .checked_add(day_of_era)?
        .checked_sub(719_468)
}

fn civil_from_timestamp(timestamp: i64) -> Option<(i64, i64, i64, i64, i64, i64)> {
    let days = timestamp.div_euclid(86_400);
    let seconds = timestamp.rem_euclid(86_400);
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_piece = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_piece + 2) / 5 + 1;
    let month = month_piece + if month_piece < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    Some((
        year,
        month,
        day,
        seconds / 3600,
        seconds % 3600 / 60,
        seconds % 60,
    ))
}

pub(super) fn split_inclusive_lines<'a>(
    input: &'a [u8],
    max_lines: usize,
    cancellation: &dyn Cancellation,
) -> PatchResult<Vec<&'a [u8]>> {
    let mut lines = Vec::new();
    lines
        .try_reserve_exact(max_lines.min(4096))
        .map_err(|error| patch_allocation("Git patch lines", error))?;
    let mut start = 0;
    for (index, byte) in input.iter().enumerate() {
        if index % 4096 == 0 {
            poll_patch_cancellation(cancellation)?;
        }
        if *byte == b'\n' {
            if lines.len() >= max_lines {
                return Err(PatchError::Limit(format!(
                    "Git patch exceeds the configured {max_lines}-line ceiling"
                )));
            }
            lines
                .try_reserve(1)
                .map_err(|error| patch_allocation("Git patch lines", error))?;
            lines.push(&input[start..=index]);
            start = index + 1;
        }
    }
    if start < input.len() {
        if lines.len() >= max_lines {
            return Err(PatchError::Limit(format!(
                "Git patch exceeds the configured {max_lines}-line ceiling"
            )));
        }
        lines
            .try_reserve(1)
            .map_err(|error| patch_allocation("Git patch lines", error))?;
        lines.push(&input[start..]);
    }
    Ok(lines)
}

pub(super) fn trim_line(value: &[u8]) -> &[u8] {
    let value = value.strip_suffix(b"\n").unwrap_or(value);
    value.strip_suffix(b"\r").unwrap_or(value)
}

pub(super) fn trim_unicode_space(mut value: &[u8]) -> &[u8] {
    value = trim_unicode_space_start(value);
    trim_unicode_space_end(value)
}

pub(super) fn trim_unicode_space_start(mut value: &[u8]) -> &[u8] {
    while let Some((character, width)) = utf8_prefix(value) {
        if !is_go_space(character) {
            break;
        }
        value = &value[width..];
    }
    value
}

pub(super) fn trim_unicode_space_end(mut value: &[u8]) -> &[u8] {
    while let Some((character, start)) = utf8_suffix(value) {
        if !is_go_space(character) {
            break;
        }
        value = &value[..start];
    }
    value
}

fn utf8_prefix(value: &[u8]) -> Option<(char, usize)> {
    let first = *value.first()?;
    let width = match first {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return None,
    };
    let text = std::str::from_utf8(value.get(..width)?).ok()?;
    Some((text.chars().next()?, width))
}

fn utf8_suffix(value: &[u8]) -> Option<(char, usize)> {
    let mut start = value.len().checked_sub(1)?;
    while start > 0 && value[start] & 0xc0 == 0x80 {
        start -= 1;
    }
    let text = std::str::from_utf8(&value[start..]).ok()?;
    Some((text.chars().next()?, start))
}

fn is_go_space(character: char) -> bool {
    matches!(
        character,
        '\t'..='\r'
            | ' '
            | '\u{0085}'
            | '\u{00a0}'
            | '\u{1680}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2028}'
            | '\u{2029}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{3000}'
    )
}
