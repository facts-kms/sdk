use ed25519_dalek::{Signer, Verifier};
use fact_canonical::{encode_cbor, Cbor};
use fact_core::Hash;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("seed must be 32 bytes")]
    Seed,
    #[error("invalid public key")]
    Public,
    #[error("invalid signature")]
    Signature,
    #[error("malformed COSE_Sign1")]
    MalformedCose,
    #[error("unsupported COSE_Sign1 form")]
    UnsupportedCose,
}
pub struct SigningKey(ed25519_dalek::SigningKey);
impl SigningKey {
    pub fn from_seed(seed: &[u8]) -> Result<Self, Error> {
        let a: [u8; 32] = seed.try_into().map_err(|_| Error::Seed)?;
        Ok(Self(ed25519_dalek::SigningKey::from_bytes(&a)))
    }
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    pub fn fingerprint(&self) -> Hash {
        Hash::digest(&self.public_key())
    }
    pub fn sign(&self, bytes: &[u8]) -> [u8; 64] {
        self.0.sign(bytes).to_bytes()
    }
}
pub fn verify(public: [u8; 32], bytes: &[u8], signature: [u8; 64]) -> Result<(), Error> {
    let k = ed25519_dalek::VerifyingKey::from_bytes(&public).map_err(|_| Error::Public)?;
    k.verify(bytes, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| Error::Signature)
}

/// The v0 profile only permits an embedded-payload, tagged COSE_Sign1 with
/// an empty unprotected map. Protected bytes are retained verbatim because
/// they are part of the signed protocol input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoseSign1 {
    pub protected: Vec<u8>,
    pub payload: Vec<u8>,
    pub signature: [u8; 64],
}

fn bstr(bytes: &[u8], out: &mut Vec<u8>) {
    match bytes.len() {
        n if n < 24 => out.push(0x40 | n as u8),
        n if n < 256 => {
            out.extend_from_slice(&[0x58, n as u8]);
        }
        n if n <= u16::MAX as usize => {
            out.push(0x59);
            out.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            assert!(
                n <= u32::MAX as usize,
                "COSE byte string exceeds CBOR length range"
            );
            out.push(0x5a);
            out.extend_from_slice(&(n as u32).to_be_bytes());
        }
    }
    out.extend_from_slice(bytes);
}

fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0x84, 0x6a];
    out.extend_from_slice(b"Signature1");
    bstr(protected, &mut out);
    out.push(0x40); // external_aad is the empty bstr
    bstr(payload, &mut out);
    out
}

pub fn sign1(protected: &[u8], payload: &[u8], key: &SigningKey) -> CoseSign1 {
    let signature = key.sign(&sig_structure(protected, payload));
    CoseSign1 {
        protected: protected.to_vec(),
        payload: payload.to_vec(),
        signature,
    }
}

pub fn verify_sign1(public: [u8; 32], cose: &CoseSign1) -> Result<(), Error> {
    verify(
        public,
        &sig_structure(&cose.protected, &cose.payload),
        cose.signature,
    )
}

/// Construct the exact deterministic protected map required by the Facts
/// protocol object COSE profile. The map layout follows the v0 wire profile;
/// ledger-neutral identity objects omit the ledger label and critical entry.
pub fn protocol_protected(
    public_key: [u8; 32],
    object_type: &str,
    schema: &str,
    ledger: Option<[u8; 16]>,
) -> Vec<u8> {
    protected_map(
        public_key,
        object_type,
        schema,
        ledger,
        "facts-protocol-cose-v0",
    )
}

pub fn coordinator_protected(
    public_key: [u8; 32],
    statement_type: &str,
    schema: &str,
    ledger: Option<[u8; 16]>,
) -> Vec<u8> {
    protected_map(
        public_key,
        statement_type,
        schema,
        ledger,
        "facts-protocol-coordinator-cose-v0",
    )
}

fn protected_map(
    public_key: [u8; 32],
    object_type: &str,
    schema: &str,
    ledger: Option<[u8; 16]>,
    profile: &str,
) -> Vec<u8> {
    let fingerprint = Hash::digest(&public_key);
    let content_type = "application/fact+json; profile=facts-protocol-json-v0";
    let mut entries = vec![
        (Cbor::Unsigned(1), Cbor::Negative(-8)),
        (
            Cbor::Unsigned(2),
            Cbor::Array(if ledger.is_some() {
                vec![
                    Cbor::Negative(-70004),
                    Cbor::Negative(-70003),
                    Cbor::Negative(-70002),
                    Cbor::Negative(-70001),
                ]
            } else {
                vec![
                    Cbor::Negative(-70004),
                    Cbor::Negative(-70002),
                    Cbor::Negative(-70001),
                ]
            }),
        ),
        (Cbor::Unsigned(3), Cbor::Text(content_type.to_owned())),
        (
            Cbor::Unsigned(4),
            Cbor::Bytes(fingerprint.as_bytes().to_vec()),
        ),
        (Cbor::Negative(-70001), Cbor::Text(object_type.to_owned())),
        (Cbor::Negative(-70002), Cbor::Text(schema.to_owned())),
    ];
    if let Some(ledger) = ledger {
        entries.push((Cbor::Negative(-70003), Cbor::Bytes(ledger.to_vec())));
    }
    entries.push((Cbor::Negative(-70004), Cbor::Text(profile.to_owned())));
    encode_cbor(&Cbor::Map(entries)).expect("Facts protected header is valid CBOR")
}

/// Validate the protected bytes against the exact object metadata and signing
/// key identity. This intentionally compares the deterministic encoding byte
/// for byte, rejecting alternate but semantically equivalent CBOR forms.
pub fn validate_protocol_protected(
    cose: &CoseSign1,
    public_key: [u8; 32],
    object_type: &str,
    schema: &str,
    ledger: Option<[u8; 16]>,
) -> Result<(), Error> {
    if cose.protected != protocol_protected(public_key, object_type, schema, ledger) {
        return Err(Error::UnsupportedCose);
    }
    Ok(())
}

pub fn validate_coordinator_protected(
    cose: &CoseSign1,
    public_key: [u8; 32],
    statement_type: &str,
    schema: &str,
    ledger: Option<[u8; 16]>,
) -> Result<(), Error> {
    if cose.protected != coordinator_protected(public_key, statement_type, schema, ledger) {
        return Err(Error::UnsupportedCose);
    }
    Ok(())
}

pub fn encode_sign1(cose: &CoseSign1) -> Vec<u8> {
    let mut out = vec![0xd2, 0x84]; // tag 18, four-element COSE_Sign1 array
    bstr(&cose.protected, &mut out);
    out.push(0xa0); // empty unprotected map
    bstr(&cose.payload, &mut out);
    bstr(&cose.signature, &mut out);
    out
}

pub fn decode_sign1(bytes: &[u8]) -> Result<CoseSign1, Error> {
    fact_canonical::validate_cbor(bytes).map_err(|_| Error::MalformedCose)?;
    if bytes.len() < 8 || bytes[0..2] != [0xd2, 0x84] {
        return Err(Error::MalformedCose);
    }
    let mut p = 2;
    let protected = read_bstr(bytes, &mut p)?;
    if protected.is_empty() || protected[0] == 0xbf || protected[0] >> 5 != 5 {
        return Err(Error::MalformedCose);
    }
    if bytes.get(p) != Some(&0xa0) {
        return Err(Error::UnsupportedCose);
    }
    p += 1;
    let payload = read_bstr(bytes, &mut p)?;
    let sig = read_bstr(bytes, &mut p)?;
    if sig.len() != 64 || p != bytes.len() {
        return Err(Error::MalformedCose);
    }
    let signature: [u8; 64] = sig.try_into().map_err(|_| Error::MalformedCose)?;
    Ok(CoseSign1 {
        protected,
        payload,
        signature,
    })
}

fn read_bstr(bytes: &[u8], p: &mut usize) -> Result<Vec<u8>, Error> {
    let first = *bytes.get(*p).ok_or(Error::MalformedCose)?;
    *p += 1;
    let len = match first {
        0x40..=0x57 => (first - 0x40) as usize,
        0x58 => {
            let n = *bytes.get(*p).ok_or(Error::MalformedCose)? as usize;
            if n < 24 {
                return Err(Error::MalformedCose);
            }
            n
        }
        0x59 => {
            let a = *bytes.get(*p).ok_or(Error::MalformedCose)?;
            let b = *bytes.get(*p + 1).ok_or(Error::MalformedCose)?;
            let n = ((a as usize) << 8) | b as usize;
            if n < 256 {
                return Err(Error::MalformedCose);
            }
            n
        }
        0x5a => {
            let a = *bytes.get(*p).ok_or(Error::MalformedCose)?;
            let b = *bytes.get(*p + 1).ok_or(Error::MalformedCose)?;
            let c = *bytes.get(*p + 2).ok_or(Error::MalformedCose)?;
            let d = *bytes.get(*p + 3).ok_or(Error::MalformedCose)?;
            let n = u32::from_be_bytes([a, b, c, d]) as usize;
            if n <= u16::MAX as usize {
                return Err(Error::MalformedCose);
            }
            n
        }
        _ => return Err(Error::MalformedCose),
    };
    if first == 0x58 {
        *p += 1;
    } else if first == 0x59 {
        *p += 2;
    } else if first == 0x5a {
        *p += 4;
    }
    let end = p.checked_add(len).ok_or(Error::MalformedCose)?;
    let out = bytes.get(*p..end).ok_or(Error::MalformedCose)?.to_vec();
    *p = end;
    Ok(out)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc_seed() {
        let k = SigningKey::from_seed(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            hex::encode(k.public_key()),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
        let s = k.sign(b"");
        assert!(verify(k.public_key(), b"", s).is_ok())
    }

    #[test]
    fn cose_fixture_round_trip() {
        let key = SigningKey::from_seed(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        )
        .unwrap();
        let protected = hex::decode("a8012702843a000111733a000111723a000111713a000111700378356170706c69636174696f6e2f666163742b6a736f6e3b2070726f66696c653d66616374732d70726f746f636f6c2d6a736f6e2d763004582021fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b93a0001117064746573743a0001117161303a0001117250018f0a000000700080000000000000013a000111737666616374732d70726f746f636f6c2d636f73652d7630").unwrap();
        let payload = br#"{"a":1,"b":"x"}"#;
        let cose = sign1(&protected, payload, &key);
        assert_eq!(
            hex::encode(&protected),
            "a8012702843a000111733a000111723a000111713a000111700378356170706c69636174696f6e2f666163742b6a736f6e3b2070726f66696c653d66616374732d70726f746f636f6c2d6a736f6e2d763004582021fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b93a0001117064746573743a0001117161303a0001117250018f0a000000700080000000000000013a000111737666616374732d70726f746f636f6c2d636f73652d7630"
        );
        assert_eq!(hex::encode(cose.signature), "9bcc50455d56122923c2273a4d1947e06e0d1fffe1ccbe1a9ad7b45dfff19ea035359909bc09ebdeb17f92fdec078b286e469ca33b761f1af1284d4dcbffd408");
        let encoded = encode_sign1(&cose);
        let decoded = decode_sign1(&encoded).unwrap();
        verify_sign1(key.public_key(), &decoded).unwrap();
        assert_eq!(decoded, cose);
    }

    #[test]
    fn cose_large_payload_round_trip() {
        let key = SigningKey::from_seed(&[7u8; 32]).unwrap();
        let protected = protocol_protected(
            key.public_key(),
            "fact",
            "application/fact+json; profile=facts-protocol-json-v0",
            None,
        );
        let payload = vec![b'x'; 70_000];
        let cose = sign1(&protected, &payload, &key);
        let encoded = encode_sign1(&cose);
        assert_eq!(encoded[encoded.len() - payload.len() - 66 - 5], 0x5a);
        let decoded = decode_sign1(&encoded).unwrap();
        assert_eq!(decoded, cose);
        verify_sign1(key.public_key(), &decoded).unwrap();
    }

    #[test]
    fn protocol_headers_bind_scope_and_key_identity() {
        let key = SigningKey::from_seed(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        )
        .unwrap();
        let ledger = hex::decode("018f0a00000070008000000000000001")
            .unwrap()
            .try_into()
            .unwrap();
        let expected = hex::decode("a8012702843a000111733a000111723a000111713a000111700378356170706c69636174696f6e2f666163742b6a736f6e3b2070726f66696c653d66616374732d70726f746f636f6c2d6a736f6e2d763004582021fe31dfa154a261626bf854046fd2271b7bed4b6abe45aa58877ef47f9721b93a0001117064746573743a0001117161303a0001117250018f0a000000700080000000000000013a000111737666616374732d70726f746f636f6c2d636f73652d7630").unwrap();
        assert_eq!(
            protocol_protected(key.public_key(), "test", "0", Some(ledger)),
            expected
        );
        let protected = protocol_protected(key.public_key(), "proposition", "0", Some(ledger));
        let cose = sign1(&protected, b"{}", &key);
        validate_protocol_protected(&cose, key.public_key(), "proposition", "0", Some(ledger))
            .unwrap();
        assert!(matches!(
            validate_protocol_protected(&cose, key.public_key(), "revision", "0", Some(ledger)),
            Err(Error::UnsupportedCose)
        ));
        assert!(matches!(
            validate_protocol_protected(&cose, key.public_key(), "proposition", "0", None),
            Err(Error::UnsupportedCose)
        ));
    }
}
