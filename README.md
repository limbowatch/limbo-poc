# Fixed upstream, still clean in your scanner: a proof

This repository pins seven real packages at versions with a **security advisory published by the package's own maintainers**, and a **fix already released**. The advisories wait for GitHub's review, so they aren't in GitHub's reviewed Advisory Database or in OSV, and the scanners that read those databases say nothing.

**[Open the latest run of the `proof` workflow →](../../actions/workflows/proof.yml)** Its job summary is the evidence: Limbowatch, OSV-Scanner, npm audit, pip-audit and bundler-audit run on the same files, and GitHub is asked about each advisory. It runs on every push and daily, so the table stays current. When GitHub reviews an advisory, its row shows it.

## The packages (checked 2026-11-12)

| Package | Severity | Fix released | Maintainers' advisory | GitHub Advisory Database | OSV |
|---|---|---|---|---|---|
| `@sinclair/typebox` 0.34.51 (npm) | high | 0.34.52, 2026-07-11 | [GHSA-976x-prgx-qv35](https://github.com/sinclairzx81/sinclair-typebox/security/advisories/GHSA-976x-prgx-qv35) | [not found](https://github.com/advisories/GHSA-976x-prgx-qv35) | [not found](https://api.osv.dev/v1/vulns/GHSA-976x-prgx-qv35) |
| `github.com/nats-io/nats-server/v2` v2.12.6 (Go) | high | v2.12.7, 2026-04-14 | [GHSA-38x3-76xf-cq45](https://github.com/nats-io/nats-server/security/advisories/GHSA-38x3-76xf-cq45) | [not found](https://github.com/advisories/GHSA-38x3-76xf-cq45) | [not found](https://api.osv.dev/v1/vulns/GHSA-38x3-76xf-cq45) |
| `github.com/go-openapi/spec` v0.22.4 (Go) | critical | v0.22.9, 2026-07-20 | [GHSA-gqhc-vf4h-h7hg](https://github.com/go-openapi/spec/security/advisories/GHSA-gqhc-vf4h-h7hg) | [not found](https://github.com/advisories/GHSA-gqhc-vf4h-h7hg) | [not found](https://api.osv.dev/v1/vulns/GHSA-gqhc-vf4h-h7hg) |
| `github.com/pelletier/go-toml/v2` v2.4.2 (Go) | high | v2.4.3, 2026-07-05 | [GHSA-frc4-6h9q-39fq](https://github.com/pelletier/go-toml/security/advisories/GHSA-frc4-6h9q-39fq) | [not found](https://github.com/advisories/GHSA-frc4-6h9q-39fq) | [not found](https://api.osv.dev/v1/vulns/GHSA-frc4-6h9q-39fq) |
| `mustache` 1.1.2 (RubyGems) | critical | 1.1.3, 2026-08-20 | [GHSA-5hrj-7fc3-cmx9](https://github.com/mustache/mustache/security/advisories/GHSA-5hrj-7fc3-cmx9) | [not found](https://github.com/advisories/GHSA-5hrj-7fc3-cmx9) | [not found](https://api.osv.dev/v1/vulns/GHSA-5hrj-7fc3-cmx9) |
| `rubyntlm` 0.6.5 (RubyGems) | critical | 0.6.6, 2026-09-09 | [GHSA-cx24-f932-rr55](https://github.com/winrb/rubyntlm/security/advisories/GHSA-cx24-f932-rr55) | [not found](https://github.com/advisories/GHSA-cx24-f932-rr55) | [not found](https://api.osv.dev/v1/vulns/GHSA-cx24-f932-rr55) |
| `scapy` 2.7.0 (PyPI) | high | 2.8.0, 2026-10-02 | [GHSA-c547-xwrv-q9jm](https://github.com/secdev/scapy/security/advisories/GHSA-c547-xwrv-q9jm) | [not found](https://github.com/advisories/GHSA-c547-xwrv-q9jm) | [not found](https://api.osv.dev/v1/vulns/GHSA-c547-xwrv-q9jm) |

Check it yourself: each "Maintainers' advisory" link opens the published advisory. The "GitHub Advisory Database" link gives a 404 page until GitHub reviews it; a reviewed one, such as [lodash's GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm), opens. The OSV link returns "not found". Dependabot alerts only on advisories in GitHub's reviewed database.

At these versions, neither GitHub's reviewed database nor OSV has any other advisory, so no scanner points people to the fix by another route.

## Controls

The same files also pin old versions with **reviewed** advisories: lodash 4.17.20, requests 2.31.0, rack 2.2.0, golang.org/x/net v0.17.0 and jackson-databind 2.9.10. Every scanner reports those, so its silence on the seven packages isn't a broken tool.

## Dependabot

Dependabot alerts are on for this repository, but GitHub shows them only to its maintainers. In a private copy of these files on 2026-11-12, Dependabot raised 95 alerts on the controls and none for these seven advisories ([Limbowatch research log, F-158](https://github.com/limbowatch/limbowatch/blob/main/docs/FINDINGS.md#f-158)).

## Run it yourself

```sh
pipx install limbowatch-cli    # needs OSV-Scanner 2.7.1 on PATH
limbowatch scan .
osv-scanner scan source -r node python java go ruby
```

## About

Files only, no application code. The workflow is [.github/workflows/proof.yml](.github/workflows/proof.yml) and the comparison [proof/compare.py](proof/compare.py). More at [limbo.watch](https://limbo.watch).

The maintainers of these packages did their part: they published the advisory and shipped the fix. The review queue is the delay.

Advisory data: GitHub repository security advisories and the GitHub Advisory Database (https://github.com/advisories, CC BY 4.0).
