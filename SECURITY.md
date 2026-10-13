# Security policy

DSH Security reads untrusted code, holds secrets from it, and can send code to model providers. We take
vulnerabilities in the plugin itself seriously. The threat model is in
[docs/security-model.md](docs/security-model.md).

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub Security Advisories: go to the repository's **Security** tab and choose
**Report a vulnerability** (<https://github.com/dsh-security/dsh-security-plugin/security/advisories/new>).

Please include:

- the affected version (`package.json` version, or the commit), DSH version, Node version and OS;
- what an attacker controls (for example, contents of the scanned repository, a remote page, a network position)
  and what they gain;
- steps to reproduce, ideally a minimal repository or request. Do not include real secrets or private source code;
- any logs, with tokens and paths removed.

What to expect:

- an acknowledgement within 5 working days;
- an initial assessment within 14 days;
- for confirmed issues, a fix and a published advisory, coordinated with you on timing (we aim for 90 days or less).
  Reporters are credited unless they ask not to be.

This is a volunteer project without a bug bounty.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (latest release) | yes |
| older | no; please upgrade |

While the project is below 1.0, only the latest minor release line gets security fixes.

## Scope

**In scope:** vulnerabilities in this plugin's code and its published package, for example:

- content in a scanned repository that makes the plugin read files outside the snapshot, run code, reach the
  network, write files, or exfiltrate data through tools;
- secrets or withheld files reaching a model, a report, the browser or the database unredacted, when the rules
  claim to cover them;
- a way to suppress or forge findings or verification results without verified code evidence;
- RPC flaws: missing validation, bypassing the remote-page rule for high-risk settings, leaking absolute paths,
  secrets or other data to the browser;
- managed toolkit flaws: installing a binary that does not match its pinned hash, unsafe extraction, path
  traversal;
- unsafe handling of external analyzer output, or argument or environment injection into those processes;
- dependency vulnerabilities that are reachable through this plugin.

**Out of scope:**

- **Vulnerabilities in the code you scan.** Findings about your own project are the plugin working as intended.
  Report false positives or missed issues as regular issues (there is a false-positive template); they are
  quality bugs, not security vulnerabilities.
- Vulnerabilities in DeepSeek Harness itself, in model providers, or in Gitleaks, OSV-Scanner, Semgrep or ast-grep.
  Report those upstream. If the plugin makes such an issue worse, it is in scope.
- Prompt injection that only lowers review quality (missed issues, wasted budget, findings argued down to
  *inconclusive*) without breaking a boundary listed above. This is a documented residual risk. Bypassing the
  verified-evidence rules is in scope.
- Attacks that require control of the DSH Host process, another installed DSH plugin, or the user's account.
- Behavior that matches documented configuration, for example `allowRemoteHighRiskSettings: true` letting
  authenticated remote pages enable code upload.
- Secret formats the built-in rules do not claim to detect. Rule improvements are welcome as regular issues or
  pull requests.
