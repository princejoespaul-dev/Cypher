# ADR 0003: Sandbox-only replay

**Status:** Accepted.

V1 rejects targets not marked sandbox-only; resolves and checks allowed hosts against declared sandbox network ranges before reset and send; blocks redirects; pins a verified address per request; and keeps reference targets on an internal Docker network with no published port. These code-level controls require integration tests on the actual Docker network before any external demonstration. No production scanning mode is included.
