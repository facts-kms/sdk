# Facts reference fixtures

`authority-matrix.json` records the normative source ordering, validation-stage
precedence, and protocol error precedence used by the reference runner.

`manifest.json` is the versioned fixture-corpus index. The committed positive
corpus contains one canonical fixture for every registered v0 object type, and
the negative object directory contains one deterministic mutation for every
registered type, alongside the five initial negative encoding profiles. The
materializer is deterministic and can be rerun with:

```text
fact conformance materialize fixtures
```

The runner validates the committed positive and negative file sets in addition
to its primitive and API-mode vectors. The initial scenario set under
`scenarios/` records causal authorization, topological consensus replay, and
API envelope cases.
