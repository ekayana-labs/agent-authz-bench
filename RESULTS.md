# Results

Run on 2026-11-05 on Apple M4 Pro, macos aarch64, with rustc 1.98.1 (48a229cea 2026-09-01). These are not scores: read [METHOD.md](METHOD.md) first.

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
| A parent token has been revoked | Blocked, with your code | Blocked | Blocked | Blocked |
| Delegation past a depth limit | Allowed | Blocked | Blocked | Blocked |

## Size and check time

The same one-tool scenario in each format, with minimal limits. Times cover decoding, every signature and the policy check, and exclude the network. Size is everything the verifier needs, as base64. Biscuit has no per-request proof, so it checks one signature fewer and sends less.

| Format | Hops | Size | Median | 99th percentile | Runs |
|---|---:|---:|---:|---:|---:|
| Biscuit | 1 | 352 bytes | 42 µs | 59 µs | 3000 |
| Biscuit | 3 | 788 bytes | 88 µs | 107 µs | 3000 |
| Biscuit | 5 | 1236 bytes | 141 µs | 159 µs | 3000 |
| Biscuit | 8 | 1940 bytes | 222 µs | 244 µs | 3000 |
| Tenuo warrants | 1 | 436 bytes | 76 µs | 85 µs | 3000 |
| Tenuo warrants | 3 | 1312 bytes | 152 µs | 185 µs | 3000 |
| Tenuo warrants | 5 | 2208 bytes | 217 µs | 246 µs | 3000 |
| Tenuo warrants | 8 | 3584 bytes | 328 µs | 367 µs | 3000 |
| UCAN Ed25519 | 1 | 924 bytes | 48 µs | 62 µs | 3000 |
| UCAN Ed25519 | 3 | 1992 bytes | 104 µs | 114 µs | 3000 |
| UCAN Ed25519 | 5 | 3080 bytes | 156 µs | 197 µs | 3000 |
| UCAN Ed25519 | 8 | 4744 bytes | 234 µs | 263 µs | 3000 |
| UCAN ML-DSA-65 | 1 | 27056 bytes | 2485 µs | 2742 µs | 300 |
| UCAN ML-DSA-65 | 3 | 57760 bytes | 5002 µs | 5910 µs | 300 |
| UCAN ML-DSA-65 | 5 | 88480 bytes | 7494 µs | 8335 µs | 300 |
| UCAN ML-DSA-65 | 8 | 134592 bytes | 11198 µs | 12554 µs | 300 |

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
| Expired token | Blocked | FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 1, rule: "check if time($t), $t < 2026-11-04T22:24:57Z" })] }) |
| A hop outlives its parent | Blocked | FailedLogic(Unauthorized { policy: Allow(0), checks: [Block(FailedBlockCheck { block_id: 0, check_id: 1, rule: "check if time($t), $t < 2026-11-04T22:24:57Z" })] }) |
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
| A middle link is removed | Blocked | chain verification failed: I1 violated: child.issuer (aab0b2b5a903a59f) != parent.holder (87254ef08096fd38) |
| Chain from a root the verifier doesn't trust | Blocked | root warrant issuer not trusted |
| Expired token | Blocked | warrant 'tnu_wrt_01a1a8a1347a722a93fe8479a581b59f' expired at 2026-11-04 22:24:59 UTC |
| A hop outlives its parent | Blocked | warrant 'tnu_wrt_01a1a8a1347a722a93fe847f853814fb' expired at 2026-11-04 22:24:59 UTC |
| Stolen chain used without the holder's key | Blocked | signature verification failed: Proof-of-Possession verification failed |
| Proof for one argument used for another | Blocked | signature verification failed: Proof-of-Possession verification failed |
| The same valid request sent twice | Blocked, with your code | the verifier accepts a repeat inside the proof's time window; dedup_key lets you reject it |
| A parent token has been revoked | Blocked | warrant revoked: tnu_wrt_01a1a8a1347b7181ba5e2672660dff5a |
| Delegation past a depth limit | Blocked | chain verification failed: child depth 2 exceeds parent's max_depth 1 |

### UCAN Ed25519 (pq-ucan 0.1.3)

Paths use the UCAN policy language's glob match, which treats a path as plain text. Replay, revocation and depth limits are optional checks you switch on. The depth limit is the verifier's, one for every chain, rather than set per delegation in the token. pq-ucan is maintained by the authors of this benchmark.

| Attack | Result | Reason |
|---|---|---|
| Honest request (must be allowed) | Allowed | accepted |
| Argument outside the granted scope | Blocked | proof 0: policy statement 0 rejected the arguments |
| Path that climbs out of scope with ../ | Allowed | accepted: the glob compares text, so refuse paths that aren't in normal form before checking |
| Tool that was never granted | Blocked | proof 2: /mcp/read_file does not cover /mcp/delete_file |
| A hop grants more than it received | Blocked | proof 1: policy statement 0 rejected the arguments |
| A signed link is edited | Blocked | rejected all 356 single-bit edits across the link |
| A middle link is removed | Blocked | proof 0: audience did:key:z6MksJPS9wcmRg2mEzhkJuuw3XpCB5uDmoTZr3RnTbQDyCmV is not the next issuer did:key:z6MkmDEvxzEfd76A4WkdvQbfLLr8uHLtaJ3tXQJ6QaVzNcLt |
| Chain from a root the verifier doesn't trust | Blocked | root delegation issued by did:key:z6MkvubH3xCkXR7vsbQvJu57k8FmpugbyiDVxn2SATSpPP6a, subject is did:key:z6MkmbNMJFp2iWQTpiowYRbjdqff33Vy4Uoy7ZZUh3ahq5Lo |
| Expired token | Blocked | proof 0: expired at 1800000600 |
| A hop outlives its parent | Blocked | proof 0: expired at 1800000600 |
| Stolen chain used without the holder's key | Blocked | proof 2: audience did:key:z6Mkhv96pszLLswViWGYzzJ5L6dBbsHYoibX2FLbHFkyY1hg is not the next issuer did:key:z6MknDrBmw8dnoSDWZ1DJMYkvZcp2V3p8DLuzf4rp4g6puTZ |
| Proof for one argument used for another | Blocked | invocation: signature does not verify |
| The same valid request sent twice | Blocked | invocation bafyreihzpfj6zhioqrvcusobvosxvrth3jnazy2rtqxlyrdlxvnrfnshuu was already executed; needs the optional replay guard |
| A parent token has been revoked | Blocked | proof 0: delegation bafyreiaovlebnk5ud2v7orulrxghogaouxbr346s5ywrxuek5fvsqtmkji has been revoked; needs the optional revocation store |
| Delegation past a depth limit | Blocked | invocation carries 12 proofs, the limit is 11; the verifier sets the limit, not the token |

### UCAN ML-DSA-65 (pq-ucan 0.1.3)

Paths use the UCAN policy language's glob match, which treats a path as plain text. Replay, revocation and depth limits are optional checks you switch on. The depth limit is the verifier's, one for every chain, rather than set per delegation in the token. pq-ucan is maintained by the authors of this benchmark.

| Attack | Result | Reason |
|---|---|---|
| Honest request (must be allowed) | Allowed | accepted |
| Argument outside the granted scope | Blocked | proof 0: policy statement 0 rejected the arguments |
| Path that climbs out of scope with ../ | Allowed | accepted: the glob compares text, so refuse paths that aren't in normal form before checking |
| Tool that was never granted | Blocked | proof 2: /mcp/read_file does not cover /mcp/delete_file |
| A hop grants more than it received | Blocked | proof 1: policy statement 0 rejected the arguments |
| A signed link is edited | Blocked | rejected all 261 single-bit edits across the link |
| A middle link is removed | Blocked | proof 0: audience did:key:z5FbVSg8cSaUatxV… is not the next issuer did:key:z5FbTz5bP9GR9ZZy… |
| Chain from a root the verifier doesn't trust | Blocked | root delegation issued by did:key:z5FbcTuUXeD75frv… subject is did:key:z5Fbdotf3ppQXGb7… |
| Expired token | Blocked | proof 0: expired at 1800000600 |
| A hop outlives its parent | Blocked | proof 0: expired at 1800000600 |
| Stolen chain used without the holder's key | Blocked | proof 2: audience did:key:z5FbWiMBoD2m2Wp1… is not the next issuer did:key:z5FbiqhDjYaZAGuk… |
| Proof for one argument used for another | Blocked | invocation: signature does not verify |
| The same valid request sent twice | Blocked | invocation bafyreibep2ve3p2w626zmvdavutl3qiszu7f3rxzpothfnxeytpji25pa4 was already executed; needs the optional replay guard |
| A parent token has been revoked | Blocked | proof 0: delegation bafyreibumv7u5i7iu6y3aa6btcw43t75iirduxbxmxilqdj63u26m64ray has been revoked; needs the optional revocation store |
| Delegation past a depth limit | Blocked | invocation carries 12 proofs, the limit is 11; the verifier sets the limit, not the token |
