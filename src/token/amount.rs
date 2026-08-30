//! Decimal-safe amount parsing and formatting.

use anyhow::{bail, Context, Result};

/// Parse a human-readable decimal amount into smallest units.
pub fn parse_amount(input: &str, decimals: u8) -> Result<i128> {
    let input = input.trim();
    if input.is_empty() {
        bail!("amount cannot be empty");
    }
    if input.starts_with('-') {
        bail!("amount must be positive");
    }

    let parts: Vec<&str> = input.split('.').collect();
    if parts.len() > 2 {
        bail!("invalid amount format: multiple decimal points");
    }

    let whole: i128 = parts[0]
        .parse()
        .with_context(|| format!("invalid whole part '{input}'"))?;

    let fraction_str = parts.get(1).copied().unwrap_or("");
    if fraction_str.len() > decimals as usize {
        bail!(
            "amount has {} fractional digits but token only supports {}",
            fraction_str.len(),
            decimals
        );
    }

    let fraction: i128 = if fraction_str.is_empty() {
        0
    } else {
        let padded = format!("{:0<width$}", fraction_str, width = decimals as usize);
        padded
            .parse()
            .with_context(|| format!("invalid fractional part '{fraction_str}'"))?
    };

    let scale = ten_pow(decimals);
    whole
        .checked_mul(scale)
        .and_then(|w| w.checked_add(fraction))
        .context("amount overflow")
}

/// Format raw smallest units as a decimal string.
pub fn format_amount(raw: i128, decimals: u8) -> String {
    if decimals == 0 {
        return raw.to_string();
    }
    let scale = ten_pow(decimals);
    let whole = raw / scale;
    let fraction = raw % scale;
    if fraction == 0 {
        return format!("{whole}.0");
    }
    let frac_str = format!("{:0width$}", fraction, width = decimals as usize);
    let trimmed = frac_str.trim_end_matches('0');
    if trimmed.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{trimmed}")
    }
}

fn ten_pow(exp: u8) -> i128 {
    (0..exp).fold(1i128, |acc, _| acc.saturating_mul(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decimal_amount() {
        assert_eq!(parse_amount("1.5", 7).unwrap(), 15_000_000);
        assert_eq!(parse_amount("100", 7).unwrap(), 1_000_000_000);
    }

    #[test]
    fn rejects_excess_precision() {
        assert!(parse_amount("1.12345678", 7).is_err());
    }

    #[test]
    fn format_round_trip() {
        let raw = parse_amount("42.125", 3).unwrap();
        assert_eq!(format_amount(raw, 3), "42.125");
    }
}
