use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};
use uuid::Uuid;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid hexadecimal digest")]
    InvalidHash,
    #[error("invalid UUID: {0}")]
    InvalidUuid(String),
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(String),
}

#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Hash([u8; 32]);
impl Hash {
    pub fn digest(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn hex(&self) -> String {
        hex::encode(self.0)
    }
}
impl Hash {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}
impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}
impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}
impl FromStr for Hash {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 64
            || s.bytes()
                .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        {
            return Err(Error::InvalidHash);
        }
        let v = hex::decode(s).map_err(|_| Error::InvalidHash)?;
        let a: [u8; 32] = v.try_into().map_err(|_| Error::InvalidHash)?;
        Ok(Self(a))
    }
}

#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct ObjectId(Uuid);
impl ObjectId {
    pub fn new_v7() -> Self {
        Self(Uuid::now_v7())
    }
    pub fn uuid(&self) -> Uuid {
        self.0
    }
    pub fn is_v7(&self) -> bool {
        self.0.get_version_num() == 7 && self.0.get_variant() == uuid::Variant::RFC4122
    }
}
impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl FromStr for ObjectId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let u = Uuid::parse_str(s).map_err(|e| Error::InvalidUuid(e.to_string()))?;
        if u.get_version_num() != 7 || u.get_variant() != uuid::Variant::RFC4122 {
            return Err(Error::InvalidUuid("UUID is not version 7".into()));
        }
        if s != u.hyphenated().to_string() {
            return Err(Error::InvalidUuid(
                "UUID is not canonical lowercase text".into(),
            ));
        }
        Ok(Self(u))
    }
}

pub fn validate_timestamp(s: &str) -> Result<(), Error> {
    if s.len() != 24
        || !s.ends_with('Z')
        || s.as_bytes().get(10) != Some(&b'T')
        || s.as_bytes().get(13) != Some(&b':')
        || s.as_bytes().get(16) != Some(&b':')
        || s.as_bytes().get(19) != Some(&b'.')
    {
        return Err(Error::InvalidTimestamp(s.into()));
    }
    let bytes = s.as_bytes();
    for (start, end) in [
        (0, 4),
        (5, 7),
        (8, 10),
        (11, 13),
        (14, 16),
        (17, 19),
        (20, 23),
    ] {
        if !bytes[start..end].iter().all(|byte| byte.is_ascii_digit()) {
            return Err(Error::InvalidTimestamp(s.into()));
        }
    }
    let year = s[0..4]
        .parse::<i32>()
        .map_err(|_| Error::InvalidTimestamp(s.into()))?;
    let month = s[5..7]
        .parse::<u8>()
        .map_err(|_| Error::InvalidTimestamp(s.into()))?;
    let day = s[8..10]
        .parse::<u8>()
        .map_err(|_| Error::InvalidTimestamp(s.into()))?;
    let hour = s[11..13]
        .parse::<u8>()
        .map_err(|_| Error::InvalidTimestamp(s.into()))?;
    let minute = s[14..16]
        .parse::<u8>()
        .map_err(|_| Error::InvalidTimestamp(s.into()))?;
    let second = s[17..19]
        .parse::<u8>()
        .map_err(|_| Error::InvalidTimestamp(s.into()))?;
    let millisecond = s[20..23]
        .parse::<u16>()
        .map_err(|_| Error::InvalidTimestamp(s.into()))?;
    let date = time::Date::from_calendar_date(
        year,
        time::Month::try_from(month).map_err(|_| Error::InvalidTimestamp(s.into()))?,
        day,
    )
    .map_err(|_| Error::InvalidTimestamp(s.into()))?;
    let clock = time::Time::from_hms_milli(hour, minute, second, millisecond)
        .map_err(|_| Error::InvalidTimestamp(s.into()))?;
    let _ = time::PrimitiveDateTime::new(date, clock);
    Ok(())
}

/// Parse an already profile-validated UTC timestamp into Unix milliseconds.
/// This is advisory time data; callers must not use it to order causal edges.
pub fn timestamp_millis(s: &str) -> Result<i64, Error> {
    validate_timestamp(s)?;
    let value = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        .map_err(|_| Error::InvalidTimestamp(s.into()))?;
    let nanos = value.unix_timestamp_nanos();
    i64::try_from(nanos / 1_000_000).map_err(|_| Error::InvalidTimestamp(s.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_timestamp_is_accepted() {
        validate_timestamp("2026-07-27T12:00:00.000Z").unwrap();
        let millis = timestamp_millis("2026-07-27T12:00:00.000Z").unwrap();
        assert_eq!(millis % 1000, 0);
        assert_eq!(
            timestamp_millis("2026-07-27T12:00:01.000Z").unwrap() - millis,
            1000
        );
    }
}
