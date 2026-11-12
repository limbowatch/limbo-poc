"""Compare what each scanner reports for the packages in proof/packages.json, and write the evidence table.

Inputs are the JSON outputs of the tools run earlier in the workflow (a missing file means the tool didn't run).
GitHub is asked directly, with the job's token, whether each advisory is published by its maintainers and whether
it is in GitHub's reviewed Advisory Database, the database Dependabot alerts from. Standard library only.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(os.environ.get("PROOF_OUT", "out"))
API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
TOKEN = os.environ.get("GITHUB_TOKEN", "")
REPO = os.environ.get("GITHUB_REPOSITORY", "")
RUN = os.environ.get("GITHUB_SERVER_URL", "https://github.com") + f"/{REPO}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"


def load(name: str) -> object | None:
    p = OUT / name
    if not p.exists() or not p.stat().st_size:
        return None
    try:
        return json.loads(p.read_text())
    except ValueError:
        return None


def gh(path: str) -> tuple[int, object]:
    req = urllib.request.Request(API + path, headers={"Accept": "application/vnd.github+json",
                                                      "X-GitHub-Api-Version": "2022-11-28",
                                                      **({"Authorization": f"Bearer {TOKEN}"} if TOKEN else {})})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, None


def norm(name: str) -> str:
    return name.lower().replace("_", "-")


def ids(v: dict) -> set[str]:
    return {v.get("id", "")} | set(v.get("aliases") or [])


def limbowatch() -> dict[str, set[str]] | None:
    d = load("limbowatch.json")
    if not isinstance(d, dict):
        return None
    out: dict[str, set[str]] = {}
    for f in d.get("findings", []):
        out.setdefault(norm(f["dependency"]["name"]), set()).add(f["ghsa_id"])
    return out


def osv() -> dict[str, set[str]] | None:
    d = load("osv-scanner.json")
    if not isinstance(d, dict):
        return None
    out: dict[str, set[str]] = {}
    for res in d.get("results") or []:
        for p in res.get("packages") or []:
            got = out.setdefault(norm(p["package"]["name"]), set())
            for v in p.get("vulnerabilities") or []:
                got |= ids(v)
    return out


def npm_audit() -> dict[str, set[str]] | None:
    d = load("npm-audit.json")
    if not isinstance(d, dict):
        return None
    out: dict[str, set[str]] = {}
    for name, v in (d.get("vulnerabilities") or {}).items():
        got = out.setdefault(norm(name), set())
        for via in v.get("via") or []:
            if isinstance(via, dict) and via.get("url"):
                got.add(via["url"].rstrip("/").rsplit("/", 1)[-1])
    return out


def pip_audit() -> dict[str, set[str]] | None:
    d = load("pip-audit.json")
    if not isinstance(d, dict):
        return None
    return {norm(p["name"]): {i for v in p.get("vulns") or [] for i in ids(v)} for p in d.get("dependencies", [])}


def bundler_audit() -> dict[str, set[str]] | None:
    d = load("bundler-audit.json")
    if not isinstance(d, dict):
        return None
    out: dict[str, set[str]] = {}
    for r in d.get("results") or []:
        adv = r.get("advisory") or {}
        got = out.setdefault(norm((r.get("gem") or {}).get("name", "")), set())
        got |= {x for x in (adv.get("id"), adv.get("ghsa") and f"GHSA-{adv['ghsa']}", adv.get("cve") and f"CVE-{adv['cve']}") if x}
    return out


def dependabot() -> tuple[dict[str, set[str]] | None, str]:
    if not REPO:
        return None, "not run in GitHub Actions"
    out: dict[str, set[str]] = {}
    page = 1
    while True:
        status, body = gh(f"/repos/{REPO}/dependabot/alerts?state=open&per_page=100&page={page}")
        if status != 200 or not isinstance(body, list):
            return None, f"the job's token can't read Dependabot alerts (HTTP {status})"
        for a in body:
            out.setdefault(norm(a["dependency"]["package"]["name"]), set()).add(a["security_advisory"]["ghsa_id"])
        if len(body) < 100:
            return out, ""
        page += 1


def cell(found: dict[str, set[str]] | None, name: str, ghsa: str | None) -> str:
    if found is None:
        return "n/a"
    got = found.get(norm(name), set())
    if ghsa is None:  # a control: how many advisories the tool reports for it
        return f"✅ {len(got)} advisories" if got else "❌ nothing"
    return "✅ reported" if ghsa in got else "❌ silent"


def main() -> int:
    pk = json.loads((ROOT / "proof" / "packages.json").read_text())
    alerts, alerts_note = dependabot()
    tools = {
        "Limbowatch": limbowatch(),
        "OSV-Scanner": osv(),
        "npm audit": npm_audit(),
        "pip-audit": pip_audit(),
        "bundler-audit": bundler_audit(),
    }
    native = {"npm": "npm audit", "PyPI": "pip-audit", "RubyGems": "bundler-audit"}
    today = datetime.now(timezone.utc).date()
    rows, evidence = [], []
    for p in pk["limbo"]:
        s, adv = gh(f"/repos/{p['repo']}/security-advisories/{p['ghsa']}")
        published = isinstance(adv, dict) and adv.get("state") == "published"
        sev = adv.get("severity", "?") if isinstance(adv, dict) else "?"
        pub = (adv.get("published_at") or "")[:10] if isinstance(adv, dict) else ""
        rs, _ = gh(f"/advisories/{p['ghsa']}")
        reviewed = rs == 200
        days_fix = (today - date.fromisoformat(p["fix_released"])).days
        days_pub = (today - date.fromisoformat(pub)).days if pub else None
        link = f"https://github.com/{p['repo']}/security/advisories/{p['ghsa']}"
        rows.append([
            f"`{p['name']}` {p['version']}<br>{p['ecosystem']} · `{p['file']}`",
            f"[{p['ghsa']}]({link})<br>{sev}" + ("" if published else " ⚠️ not published"),
            f"{p['fixed']}, {days_fix} days ago",
            f"{days_pub} days" if days_pub is not None else "?",
            cell(tools["Limbowatch"], p["name"], p["ghsa"]),
            cell(tools["OSV-Scanner"], p["name"], p["ghsa"]),
            cell(tools[native[p["ecosystem"]]], p["name"], p["ghsa"]) if p["ecosystem"] in native else "–",
            "⚠️ reviewed" if reviewed else "❌ not in it",
            cell(alerts, p["name"], p["ghsa"]),
        ])
        evidence.append({**p, "severity": sev, "advisory_published": pub, "maintainer_advisory_published": published,
                         "in_github_reviewed_db": reviewed,
                         **{t: (None if f is None else p["ghsa"] in f.get(norm(p["name"]), set())) for t, f in tools.items()},
                         "dependabot": None if alerts is None else p["ghsa"] in alerts.get(norm(p["name"]), set())})
    controls = []
    for c in pk["controls"]:
        lw = (tools["Limbowatch"] or {}).get(norm(c["name"]), set())
        controls.append([f"`{c['name']}` {c['version']}<br>{c['ecosystem']} · `{c['file']}`",
                         f"{len(lw)} in limbo" if lw else "– (reports only advisories in limbo)",
                         cell(tools["OSV-Scanner"], c["name"], None),
                         cell(tools[native[c["ecosystem"]]], c["name"], None) if c["ecosystem"] in native else "–",
                         cell(alerts, c["name"], None)])

    head = ["Package", "Advisory (maintainers')", "Fix released", "Public for", "Limbowatch", "OSV-Scanner",
            "npm audit / pip-audit / bundler-audit", "GitHub reviewed DB (Dependabot's source)", "Dependabot alerts"]
    md = [f"## Advisories in limbo: who reports them? ({today.isoformat()})", "",
          "Each package below has a security advisory **published by its own maintainers on GitHub**, with a fix "
          "**already released**. The advisory isn't in GitHub's reviewed Advisory Database or in OSV yet, so the "
          "scanners that read those databases stay silent.", "",
          "| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    md += ["| " + " | ".join(r) + " |" for r in rows]
    md += ["", "### Controls: every tool works on these", "",
           "Old versions with reviewed advisories. Each scanner reports them, so its silence above isn't a broken tool.", "",
           "| Package | Limbowatch | OSV-Scanner | npm audit / pip-audit / bundler-audit | Dependabot alerts |",
           "|---|---|---|---|---|"]
    md += ["| " + " | ".join(r) + " |" for r in controls]
    if alerts_note:
        md += ["", f"Dependabot alerts: {alerts_note}. See the README for the snapshot of this repository's alerts."]
    md += ["", f"Run: {RUN} · Advisory data: GitHub repository security advisories and the GitHub Advisory Database "
               "(https://github.com/advisories, CC BY 4.0). How this works: https://limbo.watch"]
    text = "\n".join(md) + "\n"
    print(text)
    (OUT / "evidence.json").write_text(json.dumps({"date": today.isoformat(), "run": RUN, "packages": evidence,
                                                   "dependabot_note": alerts_note}, indent=2))
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a") as f:
            f.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
