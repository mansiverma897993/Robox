# Detection benchmark

Robox was checked against [Anchor's Sealevel Attacks examples](https://github.com/coral-xyz/sealevel-attacks) at commit `24555d0`. That repository labels one `insecure`, one `secure`, and one `recommended` variant for each of eleven Solana exploit categories. Its own documentation says the examples are isolated teaching cases and the repaired variants are not necessarily complete programs.

| Example category | Relevant finding in `insecure` | Findings in `recommended` |
|---|---|---:|
| Signer authorization | RBX001 | 0 |
| Account data matching | RBX014 / RBX015 | 0 |
| Owner checks | RBX015 | 0 |
| Type cosplay | RBX019 | 0 |
| Initialization | RBX020 | 0 |
| Arbitrary CPI | RBX011 | 0 |
| Duplicate mutable accounts | RBX018 | 0 |
| Bump seed canonicalization | RBX017 | 0 |
| PDA sharing | RBX022 | 0 |
| Closing accounts | RBX021 | 0 |
| Sysvar address checking | RBX016 | 0 |

All eleven `insecure` examples produced a finding for their labeled issue; all eleven `recommended` examples produced no findings in this run. Some intermediate `secure` examples still produced findings, usually for a different issue left in the teaching example or for generic `unwrap` and manual lamport review rules. These checks were refined using this example set, so the result is **not an independent accuracy estimate** and must not be presented as a detection guarantee.

To reproduce locally, clone the example repository to a temporary directory on D, build `robox-cli`, then scan each `programs/<category>/<variant>` directory. The scanner reports a code location, confidence, sensitive asset, attack scenario, fix guidance, and a secure pattern for each match. Review every match against the actual handler and protocol invariants.

Robox still does not execute transactions, prove data flow across calls, understand protocol economics, audit off-chain services, or discover every business-logic flaw. The numeric score is a prioritization aid and cannot certify deployment safety. Independent testing and manual Solana security review remain necessary for high-value programs.
