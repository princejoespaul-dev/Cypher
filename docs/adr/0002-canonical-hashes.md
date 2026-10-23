# ADR 0002: Canonical content hashes

**Status:** Accepted, with release validation pending.

Capsule content and evidence manifests are canonicalized before SHA-256 hashing. Where numeric interoperability matters, the canonicalization helper must be checked against RFC 8785 test vectors before using hashes as cross-language signatures. Hashes are provenance and integrity identifiers, not proof that an input is truthful.
