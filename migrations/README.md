# SQLite migrations

The reference store keeps migrations additive and idempotent. The initial
fixed schema is executable in `0001_initial.sql` and is included by
`Store::migrate`; the small compatibility block in the store preserves the
existing schema-migration markers and dynamically creates one immutable table
for each registered protocol object type. Projected tables are disposable
and are rebuilt from canonical `protocol_object` rows.
