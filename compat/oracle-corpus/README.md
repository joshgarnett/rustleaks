# Oracle corpus

Committed JSONL records contain versioned requests and canonical outcomes from
the pinned Go implementation. Only synthetic or upstream-provided test values
are allowed.

`bootstrap-input.jsonl` proves custom-config matching, byte coordinates and
metadata, arbitrary invalid UTF-8, and `gitleaks:allow` suppression.
`bootstrap-golden.jsonl` is regenerated only after `cargo xtask verify-upstream`
passes. Check it with:

```sh
cargo xtask oracle generate --check
```

Every byte-bearing request/outcome field is standard base64, including paths,
commit metadata, tags, links, and fingerprints. `remote_platform` is a
versioned SCM enum rather than source bytes; together with `remote_url_base64`
it proves source-link behavior instead of silently dropping remote metadata.
Absent/empty values remain explicit, entropy is compared by
`math.Float32bits`, duplicate findings are retained, and only finding order is
canonicalized. The helper lives under
`crates/rustleaks-compat/oracle`; it imports the external pinned checkout through
a local Go-module replacement and is never a production dependency.
