# Method

## The scenario

One agent delegates to another along a chain. Each hop narrows access to `read_file` under a deeper path: `/data`, then `/data/h1`, then `/data/h1/h2`. The last agent asks to read a file inside its own scope. The tests use three hops unless they need more, and each hop has its own key where the format has holder keys.

Every format gets the same scenario, written the way its own docs suggest.

## How results are recorded

Each attack ends in one of these:

| Result | Meaning |
|---|---|
| Allowed | The library accepted the request. |
| Blocked | The library refused it with its normal verify call. |
| Blocked, with your code | The library gives you what you need, but you have to write the check or keep the store. |
| n/a | The attack can't be expressed in this format. |

"Allowed" isn't always a flaw. Biscuit is a bearer token on purpose, so a stolen token working is what it promises. The reason column says so where that's the case.

The reason column holds the library's own error text when it blocks something. We read these while writing the tests, because a rejection for the wrong reason would be a false result. Two examples we caught that way:

- A UCAN "outlives its parent" test passed by accident at first, because it ran inside the validator's 60 second clock allowance.
- A UCAN "unknown root" test was being rejected because the subject didn't match, before the root was ever looked at. It now forges the subject, so the rejection comes from the root check.

## Crafted tokens

Honest builders refuse to make a bad token, so some attacks need one built by hand: edit the payload, then sign it with the dishonest hop's real key. Where that's done, a control runs first to show that the crafting alone doesn't cause a rejection.

"A signed link is edited" flips single bits across the encoded link, every byte for small links and evenly spaced bytes for large ones, and stops at the first edit that gets through.

## Timing

- Built with `--release`. Keys and tokens are made before the clock starts.
- The timed section covers decoding, every signature and the policy check. Network and storage are out.
- 3,000 runs per case, or 300 for ML-DSA-65, which is about 50 times slower. The run count is in the table.
- Size is everything the verifier needs for one request, as base64.

Biscuit has no per-request proof, so it does one signature check fewer and sends less. That's a real difference between the formats and also the reason for the stolen token result, so read those two together.

These numbers come from one machine with minimal limits. Real limits add work, and a library may be faster on another CPU.

## What this doesn't tell you

- **Which format to use.** There are no scores on purpose. A bearer token is right for some systems and wrong for others.
- **How well the libraries are built.** This is 15 attacks, not an audit. Passing here doesn't mean a library is secure.
- **How the other languages behave.** Only the Rust libraries are tested.
- **Everything each format can do.** Biscuit's third-party blocks and Tenuo's other constraint types aren't tested, for example. A format may have a way to handle something that we didn't use.

Optional checks count as the library's when the library ships them and you only have to switch them on. UCAN's replay, revocation and depth results are like that: a validator with none of them switched on allows all three. The reason column says which option each one needs.

Paths are a good example of that last point. Tenuo has a constraint built for paths and blocks `../`. Biscuit and UCAN compare text here, so they accept it unless you normalise paths first. That's a difference in what comes built in, and a real one, but a normalising check in your own code closes it.

## The IETF draft

The draft format gets sizes only, taken from its published vectors. We left it out of the attack table because a verifier we wrote would test our reading of the draft rather than the format. Independent verifiers exist, and using one of them is the right way to add it.

## Who wrote this

Ekayana maintains `pq-ucan`, one of the libraries tested, and we build in the same space as the others. Treat our choices with the suspicion that deserves, and check them: the tests are short and every adapter is in `src/formats/`.

The first results showed `pq-ucan` 0.1.2 with no revocation store and no depth limit, so we added both in 0.1.3, and its results for those two attacks changed. Neither is the same feature as Tenuo's. Tenuo's depth limit is in the token and set per delegation, so a delegator can say how much further a grant may go. `pq-ucan`'s is the verifier's own, one limit for every chain, because a UCAN has nowhere to carry one. The path result didn't change: the same text comparison stays Allowed for both UCAN and Biscuit. The `pq-ucan` docs show how to refuse such paths, and Biscuit could write the same check, so doing it for UCAN alone wouldn't be a fair comparison.

If we've misused your library or described it wrongly, please open an issue. We'd rather fix the result than defend it.
