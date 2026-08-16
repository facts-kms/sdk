//! Human reference formatting helpers.

pub fn short_uuid_reference(id: uuid::Uuid) -> String {
    let text = id.simple().to_string();
    format!("{}-{}", &text[..5], &text[20..25])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_uuid_reference_uses_head_and_tail_entropy() {
        let first = uuid::Uuid::parse_str("019fb594-bf37-72c3-8c1e-3c8c9254fc4a").unwrap();
        let second = uuid::Uuid::parse_str("019fb594-bf37-76f1-9184-758b0fad5164").unwrap();

        assert_eq!(short_uuid_reference(first), "019fb-3c8c9");
        assert_eq!(short_uuid_reference(second), "019fb-758b0");
    }
}
