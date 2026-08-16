use fact_core::Hash;
use unicode_normalization::UnicodeNormalization;

/// The deliberately small CBOR value language used by protocol profiles.
///
/// Protocol CBOR is not an interchange format for arbitrary application
/// values: floating point values, indefinite-length items, and unassigned
/// simple values are outside the v0 profile.  Keeping this representation
/// narrow makes it possible to enforce RFC 8949 core deterministic encoding
/// rules instead of inheriting a permissive decoder's behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cbor {
    Unsigned(u64),
    Negative(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Cbor>),
    Map(Vec<(Cbor, Cbor)>),
    Tag(u64, Box<Cbor>),
    Bool(bool),
    Null,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CborError {
    #[error("unexpected end of CBOR")]
    Eof,
    #[error("invalid CBOR encoding")]
    Invalid,
    #[error("CBOR value is outside the v0 profile")]
    Unsupported,
    #[error("CBOR map keys are not in deterministic order")]
    MapOrder,
    #[error("duplicate CBOR map key")]
    DuplicateKey,
    #[error("CBOR text is not valid UTF-8")]
    Utf8,
}

/// Encode a CBOR value using RFC 8949 core deterministic encoding.
pub fn encode_cbor(value: &Cbor) -> Result<Vec<u8>, CborError> {
    let mut out = Vec::new();
    encode_cbor_value(value, &mut out)?;
    Ok(out)
}

/// Decode and validate a complete deterministic-CBOR item.
pub fn decode_cbor(bytes: &[u8]) -> Result<Cbor, CborError> {
    let mut parser = CborParser { bytes, pos: 0 };
    let value = parser.value()?;
    if parser.pos != bytes.len() {
        return Err(CborError::Invalid);
    }
    Ok(value)
}

/// Require that bytes are already the canonical deterministic encoding.
pub fn validate_cbor(bytes: &[u8]) -> Result<(), CborError> {
    let value = decode_cbor(bytes)?;
    if encode_cbor(&value)? == bytes {
        Ok(())
    } else {
        Err(CborError::Invalid)
    }
}

fn encode_cbor_value(value: &Cbor, out: &mut Vec<u8>) -> Result<(), CborError> {
    match value {
        Cbor::Unsigned(n) => argument(0, *n, out),
        Cbor::Negative(n) if *n < 0 => argument(1, (-1i128 - *n as i128) as u64, out),
        Cbor::Negative(_) => Err(CborError::Invalid),
        Cbor::Bytes(bytes) => {
            argument(2, bytes.len() as u64, out)?;
            out.extend_from_slice(bytes);
            Ok(())
        }
        Cbor::Text(text) => {
            if !text.is_char_boundary(text.len()) {
                return Err(CborError::Utf8);
            }
            argument(3, text.len() as u64, out)?;
            out.extend_from_slice(text.as_bytes());
            Ok(())
        }
        Cbor::Array(values) => {
            argument(4, values.len() as u64, out)?;
            for value in values {
                encode_cbor_value(value, out)?;
            }
            Ok(())
        }
        Cbor::Map(entries) => {
            let mut encoded = Vec::with_capacity(entries.len());
            for (key, value) in entries {
                let key_bytes = encode_cbor(key)?;
                let value_bytes = encode_cbor(value)?;
                encoded.push((key_bytes, value_bytes));
            }
            encoded.sort_by(|a, b| a.0.cmp(&b.0));
            if encoded.windows(2).any(|pair| pair[0].0 == pair[1].0) {
                return Err(CborError::DuplicateKey);
            }
            argument(5, encoded.len() as u64, out)?;
            for (key, value) in encoded {
                out.extend_from_slice(&key);
                out.extend_from_slice(&value);
            }
            Ok(())
        }
        Cbor::Tag(tag, value) => {
            argument(6, *tag, out)?;
            encode_cbor_value(value, out)
        }
        Cbor::Bool(false) => {
            out.push(0xf4);
            Ok(())
        }
        Cbor::Bool(true) => {
            out.push(0xf5);
            Ok(())
        }
        Cbor::Null => {
            out.push(0xf6);
            Ok(())
        }
    }
}

fn argument(major: u8, value: u64, out: &mut Vec<u8>) -> Result<(), CborError> {
    match value {
        n @ 0..=23 => out.push((major << 5) | n as u8),
        n @ 24..=255 => out.extend_from_slice(&[(major << 5) | 24, n as u8]),
        n @ 256..=65_535 => {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n @ 65_536..=4_294_967_295 => {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
        n => {
            out.push((major << 5) | 27);
            out.extend_from_slice(&n.to_be_bytes());
        }
    }
    Ok(())
}

struct CborParser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> CborParser<'a> {
    fn value(&mut self) -> Result<Cbor, CborError> {
        let initial = *self.bytes.get(self.pos).ok_or(CborError::Eof)?;
        self.pos += 1;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        if additional == 31 {
            return Err(CborError::Unsupported);
        }
        match major {
            0 => Ok(Cbor::Unsigned(self.argument(additional)?)),
            1 => {
                let n = self.argument(additional)?;
                if n > i64::MAX as u64 {
                    return Err(CborError::Unsupported);
                }
                Ok(Cbor::Negative(-1 - n as i64))
            }
            2 => {
                let count = self.argument(additional)?;
                Ok(Cbor::Bytes(self.bytes(count)?.to_vec()))
            }
            3 => {
                let count = self.argument(additional)?;
                let bytes = self.bytes(count)?;
                Ok(Cbor::Text(
                    String::from_utf8(bytes.to_vec()).map_err(|_| CborError::Utf8)?,
                ))
            }
            4 => {
                let count = self.argument(additional)? as usize;
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(self.value()?);
                }
                Ok(Cbor::Array(values))
            }
            5 => {
                let count = self.argument(additional)? as usize;
                let mut entries = Vec::with_capacity(count);
                let mut previous = None;
                for _ in 0..count {
                    let start = self.pos;
                    let key = self.value()?;
                    let key_bytes = &self.bytes[start..self.pos];
                    if let Some(previous) = previous {
                        if key_bytes <= previous {
                            return Err(if key_bytes == previous {
                                CborError::DuplicateKey
                            } else {
                                CborError::MapOrder
                            });
                        }
                    }
                    previous = Some(key_bytes);
                    let value = self.value()?;
                    entries.push((key, value));
                }
                Ok(Cbor::Map(entries))
            }
            6 => Ok(Cbor::Tag(
                self.argument(additional)?,
                Box::new(self.value()?),
            )),
            7 => match additional {
                20 => Ok(Cbor::Bool(false)),
                21 => Ok(Cbor::Bool(true)),
                22 => Ok(Cbor::Null),
                _ => Err(CborError::Unsupported),
            },
            _ => Err(CborError::Invalid),
        }
    }

    fn argument(&mut self, additional: u8) -> Result<u64, CborError> {
        let (width, value) = match additional {
            n @ 0..=23 => return Ok(n as u64),
            24 => (1, 0),
            25 => (2, 0),
            26 => (4, 0),
            27 => (8, 0),
            _ => return Err(CborError::Unsupported),
        };
        let bytes = self.bytes(width)?;
        let value = match width {
            1 => bytes[0] as u64,
            2 => u16::from_be_bytes([bytes[0], bytes[1]]) as u64,
            4 => u32::from_be_bytes(bytes.try_into().map_err(|_| CborError::Invalid)?) as u64,
            8 => u64::from_be_bytes(bytes.try_into().map_err(|_| CborError::Invalid)?),
            _ => value,
        };
        if value
            < match width {
                1 => 24,
                2 => 256,
                4 => 65_536,
                8 => 4_294_967_296,
                _ => 0,
            }
        {
            return Err(CborError::Invalid);
        }
        Ok(value)
    }

    fn bytes(&mut self, count: u64) -> Result<&'a [u8], CborError> {
        let count = usize::try_from(count).map_err(|_| CborError::Invalid)?;
        let end = self.pos.checked_add(count).ok_or(CborError::Invalid)?;
        let result = self.bytes.get(self.pos..end).ok_or(CborError::Eof)?;
        self.pos = end;
        Ok(result)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid UTF-8")]
    Utf8,
    #[error("unexpected end of JSON")]
    Eof,
    #[error("invalid JSON at byte {0}")]
    Syntax(usize),
    #[error("duplicate object key: {0}")]
    Duplicate(String),
    #[error("string is not NFC")]
    NonNfc,
    #[error("unsupported JSON number")]
    Number,
    #[error("object keys are not sorted")]
    NotCanonical,
}
#[derive(Debug, Clone, PartialEq)]
enum Value {
    Null,
    Bool(bool),
    Int(i64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}
struct Parser<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Parser<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn ws(&mut self) {
        while self.b.get(self.p).is_some_and(|c| c.is_ascii_whitespace()) {
            self.p += 1
        }
    }
    fn parse(mut self) -> Result<Value, Error> {
        if self.b.starts_with(&[0xef, 0xbb, 0xbf]) {
            return Err(Error::Utf8);
        }
        self.ws();
        let v = self.val()?;
        self.ws();
        if self.p != self.b.len() {
            return Err(Error::Syntax(self.p));
        }
        Ok(v)
    }
    fn val(&mut self) -> Result<Value, Error> {
        self.ws();
        match self.b.get(self.p) {
            Some(b'n') if self.b[self.p..].starts_with(b"null") => {
                self.p += 4;
                Ok(Value::Null)
            }
            Some(b't') if self.b[self.p..].starts_with(b"true") => {
                self.p += 4;
                Ok(Value::Bool(true))
            }
            Some(b'f') if self.b[self.p..].starts_with(b"false") => {
                self.p += 5;
                Ok(Value::Bool(false))
            }
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(c) if *c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => Err(Error::Syntax(self.p)),
            None => Err(Error::Eof),
        }
    }
    fn string(&mut self) -> Result<String, Error> {
        let start = self.p;
        self.p += 1;
        while let Some(&c) = self.b.get(self.p) {
            match c {
                b'"' => {
                    self.p += 1;
                    let s = std::str::from_utf8(&self.b[start..self.p]).map_err(|_| Error::Utf8)?;
                    let v: String = serde_json::from_str(s).map_err(|_| Error::Syntax(start))?;
                    if v.nfc().ne(v.chars()) {
                        return Err(Error::NonNfc);
                    }
                    return Ok(v);
                }
                b'\\' => {
                    self.p += 2;
                    if self.b.get(self.p - 1) == Some(&b'u') {
                        self.p += 4
                    }
                }
                0..=31 => return Err(Error::Syntax(self.p)),
                _ => self.p += 1,
            }
        }
        Err(Error::Eof)
    }
    fn array(&mut self) -> Result<Value, Error> {
        self.p += 1;
        let mut a = Vec::new();
        self.ws();
        if self.b.get(self.p) == Some(&b']') {
            self.p += 1;
            return Ok(Value::Array(a));
        }
        loop {
            a.push(self.val()?);
            self.ws();
            match self.b.get(self.p) {
                Some(b',') => self.p += 1,
                Some(b']') => {
                    self.p += 1;
                    break;
                }
                _ => return Err(Error::Syntax(self.p)),
            }
        }
        Ok(Value::Array(a))
    }
    fn object(&mut self) -> Result<Value, Error> {
        self.p += 1;
        let mut o = Vec::new();
        self.ws();
        if self.b.get(self.p) == Some(&b'}') {
            self.p += 1;
            return Ok(Value::Object(o));
        }
        loop {
            self.ws();
            if self.b.get(self.p) != Some(&b'"') {
                return Err(Error::Syntax(self.p));
            }
            let k = self.string()?;
            if o.iter().any(|(x, _)| x == &k) {
                return Err(Error::Duplicate(k));
            }
            self.ws();
            if self.b.get(self.p) != Some(&b':') {
                return Err(Error::Syntax(self.p));
            }
            self.p += 1;
            o.push((k, self.val()?));
            self.ws();
            match self.b.get(self.p) {
                Some(b',') => self.p += 1,
                Some(b'}') => {
                    self.p += 1;
                    break;
                }
                _ => return Err(Error::Syntax(self.p)),
            }
        }
        Ok(Value::Object(o))
    }
    fn number(&mut self) -> Result<Value, Error> {
        let s = self.p;
        if self.b.get(self.p) == Some(&b'-') {
            self.p += 1
        }
        let d = self.p;
        while self.b.get(self.p).is_some_and(|c| c.is_ascii_digit()) {
            self.p += 1
        }
        if d == self.p
            || self
                .b
                .get(self.p)
                .is_some_and(|c| *c == b'.' || *c == b'e' || *c == b'E')
        {
            return Err(Error::Number);
        }
        let t = std::str::from_utf8(&self.b[s..self.p]).unwrap();
        if t.starts_with('0') && t.len() > 1 || t.starts_with("-0") {
            return Err(Error::Number);
        }
        t.parse().map(Value::Int).map_err(|_| Error::Number)
    }
}
fn emit(v: &Value, out: &mut Vec<u8>) -> Result<(), Error> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Int(n) => out.extend_from_slice(n.to_string().as_bytes()),
        Value::String(s) => out.extend_from_slice(serde_json::to_string(s).unwrap().as_bytes()),
        Value::Array(a) => {
            out.push(b'[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',')
                }
                emit(x, out)?
            }
            out.push(b']')
        }
        Value::Object(o) => {
            let mut q = o.clone();
            q.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push(b'{');
            for (i, (k, x)) in q.iter().enumerate() {
                if i > 0 {
                    out.push(b',')
                }
                emit(&Value::String(k.clone()), out)?;
                out.push(b':');
                emit(x, out)?
            }
            out.push(b'}')
        }
    }
    Ok(())
}
pub fn encode(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    emit(&Parser::new(input).parse()?, &mut out)?;
    Ok(out)
}
pub fn hash(input: &[u8]) -> Result<Hash, Error> {
    Ok(Hash::digest(&encode(input)?))
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MarkdownError {
    #[error("invalid UTF-8 or byte-order mark")]
    Utf8,
    #[error("markdown is not canonical")]
    NonCanonical,
    #[error("tabs and trailing spaces are forbidden")]
    Whitespace,
    #[error("unsupported markdown construct")]
    Unsupported,
}

/// Canonicalize the constrained `facts-protocol-markdown-v0` profile.
/// Parsing is intentionally conservative: constructs outside the profile are
/// rejected instead of being assigned implementation-specific semantics.
pub fn canonical_markdown(input: &[u8]) -> Result<Vec<u8>, MarkdownError> {
    let text = std::str::from_utf8(input).map_err(|_| MarkdownError::Utf8)?;
    if text.starts_with('\u{feff}') {
        return Err(MarkdownError::Utf8);
    }
    let normalized: String = text
        .replace("\r\n", "\n")
        .replace('\r', "\n")
        .nfc()
        .collect();
    if normalized.contains('\t') {
        return Err(MarkdownError::Whitespace);
    }
    let mut lines: Vec<String> = normalized
        .lines()
        .map(|line| line.trim_end_matches(' ').to_string())
        .collect();
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    let mut out = lines.join("\n");
    out.push('\n');
    validate_markdown_syntax(&out)?;
    Ok(out.into_bytes())
}

pub fn validate_canonical_markdown(input: &[u8]) -> Result<(), MarkdownError> {
    if canonical_markdown(input)? != input {
        return Err(MarkdownError::NonCanonical);
    }
    Ok(())
}

fn validate_markdown_syntax(text: &str) -> Result<(), MarkdownError> {
    let mut fence: Option<char> = None;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(marker) = fence {
            if trimmed.starts_with(&format!("{marker}{marker}{marker}")) {
                fence = None;
            }
            continue;
        }
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            fence = Some(trimmed.chars().next().unwrap());
            continue;
        }
        if line.starts_with("    ") || line.contains('\t') {
            return Err(MarkdownError::Unsupported);
        }
        if trimmed.starts_with(":::") || trimmed.starts_with("| ") || trimmed.starts_with("|-") {
            return Err(MarkdownError::Unsupported);
        }
        if trimmed.starts_with("[^") && trimmed.contains("]: ") {
            return Err(MarkdownError::Unsupported);
        }
        // HTML, autolinks, and tag-like directives are outside the profile.
        let mut in_code = false;
        let chars: Vec<char> = line.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '`' {
                let mut n = 1;
                while i + n < chars.len() && chars[i + n] == '`' {
                    n += 1;
                }
                if n == 1 {
                    in_code = !in_code;
                }
                i += n;
                continue;
            }
            if chars[i] == '<' && !in_code {
                return Err(MarkdownError::Unsupported);
            }
            i += 1;
        }
    }
    if fence.is_some() {
        return Err(MarkdownError::Unsupported);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[test]
    fn vectors() {
        let input = "{\"b\":1,\"a\":\"é\",\"arr\":[true,null]}";
        let x = encode(input.as_bytes()).unwrap();
        assert_eq!(
            String::from_utf8(x.clone()).unwrap(),
            r#"{"a":"é","arr":[true,null],"b":1}"#
        );
        assert_eq!(
            hash(input.as_bytes()).unwrap().hex(),
            "4a9d5f0ec1384a61a28ce043708ddabd064dd9b9e62dc70f505a5673d9d5af33"
        )
    }
    #[test]
    fn rejects() {
        assert!(encode(br#"{"a":1,"a":2}"#).is_err());
        assert!(encode(br#"{"a":1.0}"#).is_err());
        assert!(encode(br#"{"a":-0}"#).is_err())
    }

    #[test]
    fn markdown_profile_canonicalizes_and_rejects_noncanonical_bytes() {
        let source = b"# Cafe\r\n\r\nHello  \r\n";
        let canonical = canonical_markdown(source).unwrap();
        assert_eq!(canonical, b"# Cafe\n\nHello\n");
        assert!(validate_canonical_markdown(source).is_err());
        assert!(validate_canonical_markdown(&canonical).is_ok());
        assert!(canonical_markdown(b"<script>x</script>\n").is_err());
        assert!(canonical_markdown(b"    indented\n").is_err());
    }

    #[test]
    fn deterministic_cbor_sorts_map_keys_and_rejects_noncanonical_forms() {
        let value = Cbor::Map(vec![
            (Cbor::Text("z".into()), Cbor::Unsigned(1)),
            (Cbor::Text("a".into()), Cbor::Bytes(vec![0, 1])),
        ]);
        let encoded = encode_cbor(&value).unwrap();
        assert_eq!(hex::encode(&encoded), "a26161420001617a01");
        assert_eq!(decode_cbor(&encoded).unwrap(), value_sorted_for_cbor());
        assert!(validate_cbor(&encoded).is_ok());

        // 0 encoded with an unnecessarily wide argument is not deterministic.
        assert_eq!(decode_cbor(&[0x18, 0x00]), Err(CborError::Invalid));
        // Map order is by the encoded key bytes, not insertion order.
        assert_eq!(
            decode_cbor(&[0xa2, 0x61, b'z', 0x01, 0x61, b'a', 0x01]),
            Err(CborError::MapOrder)
        );
        assert_eq!(
            decode_cbor(&[0x9f, 0x01, 0xff]),
            Err(CborError::Unsupported)
        );
    }

    fn value_sorted_for_cbor() -> Cbor {
        Cbor::Map(vec![
            (Cbor::Text("a".into()), Cbor::Bytes(vec![0, 1])),
            (Cbor::Text("z".into()), Cbor::Unsigned(1)),
        ])
    }

    proptest! {
        #[test]
        fn canonical_json_is_idempotent(key in "[a-z]{0,16}", value in any::<i64>()) {
            let input = serde_json::to_vec(&serde_json::json!({"z":value,"a":key})).unwrap();
            let first = encode(&input).unwrap();
            prop_assert_eq!(encode(&first).unwrap(), first);
        }
    }
}
