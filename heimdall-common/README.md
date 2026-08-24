# heimdall-common

Internal shared wire types for the
[Heimdall](https://github.com/dravengarden/heimdall) userspace CLI and eBPF
programs. Install the public command with:

```bash
cargo install heimdall-egress --locked
```

This crate is published separately only because Cargo requires registry
dependencies to be independently available. Its API is pre-1.0 and not a
standalone product contract.
