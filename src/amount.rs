use crate::{Error, Result};

pub const MRK_DECIMALS: usize = 8;
pub const MRK_SCALE: u128 = 100_000_000;
pub const MAX_SUPPLY: u128 = 1_000_000_000 * MRK_SCALE;
pub const GENESIS_TREASURY_ALLOCATION: u128 = 500_000_000 * MRK_SCALE;
pub const NODE_EMISSION_ALLOCATION: u128 = MAX_SUPPLY - GENESIS_TREASURY_ALLOCATION;

pub fn parse_mrk(input: &str) -> Result<u128> {
    let value = input.trim();
    let value = value
        .strip_suffix("MRK")
        .or_else(|| value.strip_suffix("mrk"))
        .unwrap_or(value)
        .trim();
    if value.is_empty() || value.starts_with('-') || value.starts_with('+') {
        return Err(Error::msg("amount must be a positive decimal MRK value"));
    }
    if value.contains(['e', 'E']) {
        return Err(Error::msg("scientific notation is not allowed"));
    }
    let mut parts = value.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next();
    if parts.next().is_some() || whole.is_empty() || !whole.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::msg("invalid MRK amount"));
    }
    let whole = whole
        .parse::<u128>()
        .map_err(|_| Error::msg("MRK amount is too large"))?;
    let fraction = fraction.unwrap_or_default();
    if fraction.len() > MRK_DECIMALS || !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::msg(format!(
            "MRK supports at most {MRK_DECIMALS} decimal places"
        )));
    }
    let mut fraction_text = fraction.to_owned();
    fraction_text.extend(std::iter::repeat_n('0', MRK_DECIMALS - fraction.len()));
    let fraction = if fraction_text.is_empty() {
        0
    } else {
        fraction_text
            .parse::<u128>()
            .map_err(|_| Error::msg("invalid MRK fractional amount"))?
    };
    let amount = whole
        .checked_mul(MRK_SCALE)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| Error::msg("MRK amount is too large"))?;
    if amount > MAX_SUPPLY {
        return Err(Error::msg("amount exceeds MRK maximum supply"));
    }
    Ok(amount)
}

pub fn format_mrk(amount: u128) -> String {
    let whole = amount / MRK_SCALE;
    let fraction = amount % MRK_SCALE;
    if fraction == 0 {
        return format!("{whole} MRK");
    }
    let mut fraction = format!("{fraction:0MRK_DECIMALS$}");
    while fraction.ends_with('0') {
        fraction.pop();
    }
    format!("{whole}.{fraction} MRK")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_exact_amounts() {
        let amount = parse_mrk("12.50000001MRK").unwrap();
        assert_eq!(format_mrk(amount), "12.50000001 MRK");
        assert_eq!(parse_mrk("0.1").unwrap(), MRK_SCALE / 10);
        assert!(parse_mrk("1e3").is_err());
        assert!(parse_mrk("0.000000001").is_err());
    }
}
