# Results

Run on 2026-11-04 on Apple M4 Pro, macos aarch64, with rustc 1.98.1 (48a229cea 2026-09-01). These are not scores: read [METHOD.md](METHOD.md) first.

## Attacks

| Attack | Biscuit | Tenuo warrants | UCAN Ed25519 | UCAN ML-DSA-65 |
|---|---|---|---|---|
| Honest request (must be allowed) | Allowed | Allowed | Allowed | Allowed |
| Argument outside the granted scope | Blocked | Blocked | Blocked | Blocked |
| Path that climbs out of scope with ../ | Allowed | Blocked | Allowed | Allowed |
| Tool that was never granted | Blocked | Blocked | Blocked | Blocked |
| A hop grants more than it received | Blocked | Blocked | Blocked | Blocked |
| A signed link is edited | Blocked | Blocked | Blocked | Blocked |
| A middle link is removed | Blocked | Blocked | Blocked | Blocked |
| Chain from a root the verifier doesn't trust | Blocked | Blocked | Blocked | Blocked |
| Expired token | Blocked | Blocked | Blocked | Blocked |
| A hop outlives its parent | Blocked | Blocked | Blocked | Blocked |
| Stolen chain used without the holder's key | Allowed | Blocked | Blocked | Blocked |
| Proof for one argument used for another | n/a | Blocked | Blocked | Blocked |
| The same valid request sent twice | Allowed | Blocked, with your code | Blocked | Blocked |
| A parent token has been revoked | Blocked, with your code | Blocked | Blocked, with your code | Blocked, with your code |
| Delegation past a depth limit | Allowed | Blocked | Allowed | Allowed |

## Size and check time

The same one-tool scenario in each format, with minimal limits. Times cover decoding, every signature and the policy check, and exclude the network. Size is everything the verifier needs, as base64. Biscuit has no per-request proof, so it checks one signature fewer and sends less.

| Format | Hops | Size | Median | 99th percentile | Runs |
|---|---:|---:|---:|---:|---:|
| Biscuit | 1 | 352 bytes | 42 µs | 60 µs | 3000 |
| Biscuit | 3 | 788 bytes | 94 µs | 103 µs | 3000 |
| Biscuit | 5 | 1236 bytes | 147 µs | 161 µs | 3000 |
| Biscuit | 8 | 1940 bytes | 227 µs | 245 µs | 3000 |
| Tenuo warrants | 1 | 436 bytes | 76 µs | 82 µs | 3000 |
| Tenuo warrants | 3 | 1316 bytes | 152 µs | 163 µs | 3000 |
| Tenuo warrants | 5 | 2208 bytes | 221 µs | 239 µs | 3000 |
| Tenuo warrants | 8 | 3584 bytes | 328 µs | 354 µs | 3000 |
| UCAN Ed25519 | 1 | 924 bytes | 53 µs | 59 µs | 3000 |
| UCAN Ed25519 | 3 | 1992 bytes | 106 µs | 118 µs | 3000 |
| UCAN Ed25519 | 5 | 3080 bytes | 160 µs | 171 µs | 3000 |
| UCAN Ed25519 | 8 | 4744 bytes | 237 µs | 256 µs | 3000 |
| UCAN ML-DSA-65 | 1 | 27056 bytes | 2501 µs | 2563 µs | 300 |
| UCAN ML-DSA-65 | 3 | 57760 bytes | 5028 µs | 5219 µs | 300 |
| UCAN ML-DSA-65 | 5 | 88480 bytes | 7542 µs | 7860 µs | 300 |
| UCAN ML-DSA-65 | 8 | 134592 bytes | 11269 µs | 11601 µs | 300 |

## IETF draft format, size only

draft-niyikiza-oauth-attenuating-agent-tokens-02 isn't in the tables above. A verifier we wrote would test our reading of the draft rather than the format, and independent verifiers aren't wired in yet. These are chain plus proof sizes in compact JWT form, from the draft's PERMIT vectors in Tenuo's repository (`tests/vectors/aat-jws-vectors.json` at commit 597d88c4). The vectors use varied limits, so they don't line up row by row with the table above.

| Links | Vectors | Median size |
|---:|---:|---:|
| 1 | 17 | 1201 bytes |
| 2 | 30 | 2369 bytes |
| 3 | 6 | 3109 bytes |
| 9 | 1 | 7675 bytes |

## Why each result happened

### Biscuit (biscuit-auth 6.0.0)

A bearer token by design: anyone holding it can use it and attenuate it. Paths are checked with starts_with, one of several ways to write this in Datalog. Revocation is a documented non-goal of the library, which exposes block IDs for you to check.

| Attack | Result | Reason |
|---|---|---|
| Honest request (must be allowed) | Allowed | accepted |
| Argument outside the granted scope | Blocked | FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 0, rule: "check if resource($r), $r.starts_with(\"/data/\")" }), Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($r), $r.starts_with(\"/data/h1/\")" }), Block(FailedBlockCheck { block_id: 2, check_id: 0, rule: "check if resource($r), $r.starts_with(\"/data/h1/h2/\")" })] }) |
| Path that climbs out of scope with ../ | Allowed | accepted: starts_with compares text, so normalise paths before checking |
| Tool that was never granted | Blocked | FailedLogic(NoMatchingPolicy { checks: [] }) |
| A hop grants more than it received | Blocked | FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 1, check_id: 0, rule: "check if resource($r), $r.starts_with(\"/data/h1/\")" })] }) |
| A signed link is edited | Blocked | rejected all 295 single-bit edits across the link |
| A middle link is removed | Blocked | Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))) |
| Chain from a root the verifier doesn't trust | Blocked | Format(Signature(InvalidSignature("signature error: Verification equation was not satisfied"))) |
| Expired token | Blocked | FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 1, rule: "check if time($t), $t < 2026-11-04T16:11:11Z" })] }) |
| A hop outlives its parent | Blocked | FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 1, rule: "check if time($t), $t < 2026-11-04T16:11:11Z" })] }) |
| Stolen chain used without the holder's key | Allowed | accepted: a bearer token has no holder key to check, by design |
| Proof for one argument used for another | n/a | no per-request proof; the token isn't tied to arguments |
| The same valid request sent twice | Allowed | accepted: no per-request proof, so requests can't be told apart |
| A parent token has been revoked | Blocked, with your code | revocation_identifiers gives each block's ID; you keep and check the list |
| Delegation past a depth limit | Allowed | accepted: the token can't carry a depth limit; a verifier can use block_count itself |

### Tenuo warrants (tenuo 0.3.5)

Paths use the Subpath constraint. Signed revocation lists need a list issuer you run or buy.

| Attack | Result | Reason |
|---|---|---|
| Honest request (must be allowed) | Allowed | accepted |
| Argument outside the granted scope | Blocked | constraint not satisfied: path - value does not match constraint |
| Path that climbs out of scope with ../ | Blocked | constraint not satisfied: path - value does not match constraint |
| Tool that was never granted | Blocked | warrant does not authorize tool 'delete_file' |
| A hop grants more than it received | Blocked | path '/data' is not contained within root '/data/h1' |
| A signed link is edited | Blocked | rejected all 329 single-bit edits across the link |
| A middle link is removed | Blocked | chain verification failed: I1 violated: child.issuer (17a89bd32e5f6878) != parent.holder (a04cb794b5e67872) |
| Chain from a root the verifier doesn't trust | Blocked | root warrant issuer not trusted |
| Expired token | Blocked | warrant 'tnu_wrt_01a1a74b02c5773f9c94027484af8764' expired at 2026-11-04 16:11:13 UTC |
| A hop outlives its parent | Blocked | warrant 'tnu_wrt_01a1a74b02c5773f9c94027a12e964c9' expired at 2026-11-04 16:11:13 UTC |
| Stolen chain used without the holder's key | Blocked | signature verification failed: Proof-of-Possession verification failed |
| Proof for one argument used for another | Blocked | signature verification failed: Proof-of-Possession verification failed |
| The same valid request sent twice | Blocked, with your code | the verifier accepts a repeat inside the proof's time window; dedup_key lets you reject it |
| A parent token has been revoked | Blocked | warrant revoked: tnu_wrt_01a1a74b02c676358bcde34dbb879ed4 |
| Delegation past a depth limit | Blocked | chain verification failed: child depth 2 exceeds parent's max_depth 1 |

### UCAN Ed25519 (pq-ucan 0.1.2)

Paths use the UCAN policy language's glob match, which treats a path as plain text. pq-ucan is maintained by the authors of this benchmark.

| Attack | Result | Reason |
|---|---|---|
| Honest request (must be allowed) | Allowed | accepted |
| Argument outside the granted scope | Blocked | proof 0: policy statement 0 rejected the arguments |
| Path that climbs out of scope with ../ | Allowed | accepted: the glob compares text, so normalise paths before checking |
| Tool that was never granted | Blocked | proof 2: /mcp/read_file does not cover /mcp/delete_file |
| A hop grants more than it received | Blocked | proof 1: policy statement 0 rejected the arguments |
| A signed link is edited | Blocked | rejected all 356 single-bit edits across the link |
| A middle link is removed | Blocked | proof 0: audience did:key:z6MkrV6NM1SFT41dmh8oXD9qDugnzKQAwpTcsygY7QUv1ogW is not the next issuer did:key:z6MknDPf1HeMhouTxmQADPQQJyZVeDGp7MTcgwfLLoUw1XDa |
| Chain from a root the verifier doesn't trust | Blocked | root delegation issued by did:key:z6MkqfYPFzktFPJzg9oXwU2X56bfQDLK6B3JdrSzHdn2oe62, subject is did:key:z6MkkSSRxvKip8wsZ3bggAXTJPUYvzjMrM8uEP3eNGsHYrtU |
| Expired token | Blocked | proof 0: expired at 1800000600 |
| A hop outlives its parent | Blocked | proof 0: expired at 1800000600 |
| Stolen chain used without the holder's key | Blocked | proof 2: audience did:key:z6MkgFB3TJtiaXab8VpefzMEM4a9hHwAPUeFJFBWrwWUfzLD is not the next issuer did:key:z6MkhzzfiTVJqrLZD5Pzh9zwaY9ujGEoSMPW8drcyADiBFXn |
| Proof for one argument used for another | Blocked | invocation: signature does not verify |
| The same valid request sent twice | Blocked | invocation bafyreibdjdtyw3bqhe2o56dced7zsawp6iokyz436sfkygefmfidc55gay was already executed; needs the optional replay guard |
| A parent token has been revoked | Blocked, with your code | the validator has no revocation store in this version; you check proof CIDs against your list first |
| Delegation past a depth limit | Allowed | accepted: UCAN has no depth limit in the token; a verifier can count proofs itself |

### UCAN ML-DSA-65 (pq-ucan 0.1.2)

Paths use the UCAN policy language's glob match, which treats a path as plain text. pq-ucan is maintained by the authors of this benchmark.

| Attack | Result | Reason |
|---|---|---|
| Honest request (must be allowed) | Allowed | accepted |
| Argument outside the granted scope | Blocked | proof 0: policy statement 0 rejected the arguments |
| Path that climbs out of scope with ../ | Allowed | accepted: the glob compares text, so normalise paths before checking |
| Tool that was never granted | Blocked | proof 2: /mcp/read_file does not cover /mcp/delete_file |
| A hop grants more than it received | Blocked | proof 1: policy statement 0 rejected the arguments |
| A signed link is edited | Blocked | rejected all 261 single-bit edits across the link |
| A middle link is removed | Blocked | proof 0: audience did:key:z5Fbk9qKtYU8yMsJ… is not the next issuer did:key:z5FbbkER3NYeY2EB… |
| Chain from a root the verifier doesn't trust | Blocked | root delegation issued by did:key:z5Fbg82CsATCQ9nZ… subject is did:key:z5FbdCwm7cx48vi1… |
| Expired token | Blocked | proof 0: expired at 1800000600 |
| A hop outlives its parent | Blocked | proof 0: expired at 1800000600 |
| Stolen chain used without the holder's key | Blocked | proof 2: audience did:key:z5FbnWfTod5ynqRq… is not the next issuer did:key:z5FbjZXM4ihyTbXP… |
| Proof for one argument used for another | Blocked | invocation: signature does not verify |
| The same valid request sent twice | Blocked | invocation bafyreiaba23emdaf54xcrvnho2qlebxp2claxbosjswhe3kad63u33plni was already executed; needs the optional replay guard |
| A parent token has been revoked | Blocked, with your code | the validator has no revocation store in this version; you check proof CIDs against your list first |
| Delegation past a depth limit | Allowed | accepted: UCAN has no depth limit in the token; a verifier can count proofs itself |
