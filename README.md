# agent-authz-bench

The same delegation chain and the same 15 attacks, run against several agent permission formats: Tenuo warrants, Biscuit, and UCAN with Ed25519 and ML-DSA-65. It also measures token size and check time.

There are no scores and no winner. The formats make different promises, and the useful question is which promises you need.

**Conflict of interest:** Ekayana maintains `pq-ucan`, one of the libraries tested, and works in the same space as the others. [METHOD.md](METHOD.md) explains how the tests work so you can check them. If we got your library wrong, please open an issue.

## Results

See [RESULTS.md](RESULTS.md), which also gives the reason behind every result. `results.json` has the same data.

## Run it

```bash
cargo run --release
```

This rewrites `RESULTS.md` and `results.json`. Pass a folder to write them somewhere else:

```bash
cargo run --release -- /tmp/my-run
```

The attack results are pinned in `tests/suite.rs`, so a library upgrade that changes one fails the tests:

```bash
cargo test
```

## Add a format

Implement the `Format` trait from `src/model.rs` and add a file in `src/formats/`. Each attack is one match arm. If a crafted token is needed, run a control first so that the crafting alone can't be what caused the block.

## Licence

Apache-2.0
