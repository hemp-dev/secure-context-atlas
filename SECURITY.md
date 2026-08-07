# Security policy

## Scope

Secure Context Atlas is a static defensive knowledge repository. It does not operate a hosted service and does not accept production credentials or live targets.

Report repository security issues such as accidentally committed secrets, unsafe release automation, malicious dependency changes or a genuinely dangerous instruction in the knowledge base through [GitHub private vulnerability reporting](https://github.com/hemp-dev/secure-context-atlas/security/advisories/new). If private reporting is unavailable, contact the repository maintainer through the GitHub profile for `hemp-dev`; do not open a public issue containing secrets, personal data or a working exploit chain. Maintainers target an acknowledgement within 3 business days.

## Safe reports

Include:

- affected file and exact line/field;
- why the content could cause unsafe execution or disclosure;
- a redacted, non-operational reproduction or synthetic fixture;
- suggested remediation and regression test.

Do not include real credentials, persistence steps, evasion, public scanning instructions or exfiltrated data.

## Release handling

Maintainers should quarantine the affected artifact, rotate any exposed credential, remove it from generated indexes, regenerate hashes, run the quality gates and publish a changelog/security note before the next release.
