#/usr/bin/env python3
"""
policy/gate.py
~~~~~~~~~~~~~~
Aggregates Gitleaks + Semgrep + Trivy scan results into a single deployment
decision. The goal is one authoritative verdict (BLOCK / WARN / PASS) instead
of three separate scanner exit codes that developers learn to ignore.

Why a custom engine instead of using scanner exit codes directly?
  - Trivy exits 1 on any CRITICAL, even unfixable ones in base images we don't control
  - Semgrep exits 1 on any ERROR, including things we've explicitly accepted
  - Neither scanner knows about EPSS, PCI scope, or our specific risk appetite
  - We want one JSON artifact that maps findings to PCI requirements for the QSA

EPSS note: Exploit Prediction Scoring System score (0-1) estimates the probability
a vulnerability will be exploited in the wild. A HIGH CVE with EPSS=0.02 is very
different from one with EPSS=0.91. We use 0.70 as the blocking threshold — above
that, we treat it equivalent to CRITICAL for deployment purposes.
"""

import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


# Packages that directly handle cardholder data or authenticate to processors.
# A HIGH CVE in any of these on main branch is a blocking condition.
PCI_SENSITIVE = {
    "cryptography", "pyopenssl", "pyjwt", "httpx",
    "fastapi", "uvicorn", "pydantic", "sqlalchemy",
}

SEVERITY_SCORE = {"CRITICAL": 100, "HIGH": 40, "MEDIUM": 10, "LOW": 2, "INFO": 0}
EPSS_BLOCK_THRESHOLD = 0.70


@dataclass
class Finding:
    tool:          str
    severity:      str
    title:         str
    location:      str
    cve:           Optional[str]
    fix_version:   Optional[str]
    fix_available: bool
    description:   str
    pci_relevant:  bool  = False
    epss:          float = 0.0


@dataclass
class Decision:
    verdict:       str   # BLOCK | WARN | PASS
    timestamp:     str
    commit:        str
    strict:        bool
    findings:      list[Finding]      = field(default_factory=list)
    blocks:        list[str]          = field(default_factory=list)
    warnings:      list[str]          = field(default_factory=list)
    metrics:       dict               = field(default_factory=dict)
    pci_map:       dict               = field(default_factory=dict)
    summary_md:    str                = ""


# ── Parsers ────────────────────────────────────────────────────────────────────

def parse_gitleaks(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    if not data:
        return []

    return [
        Finding(
            tool="gitleaks",
            severity="CRITICAL",
            title=f"secret: {leak.get('RuleID', 'unknown')}",
            location=f"{leak.get('File', '?')}:{leak.get('StartLine', '?')}",
            cve=None,
            fix_version=None,
            fix_available=True,
            description=leak.get("Description", "hardcoded secret"),
            pci_relevant=True,
            epss=1.0,   # treat any exposed credential as immediately exploitable
        )
        for leak in (data if isinstance(data, list) else [])
    ]


def parse_semgrep(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    sev_map = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}
    findings = []

    for r in data.get("results", []):
        rule_id = r.get("check_id", "")
        sev_raw = r.get("extra", {}).get("severity", "WARNING").upper()
        findings.append(Finding(
            tool="semgrep",
            severity=sev_map.get(sev_raw, "MEDIUM"),
            title=r.get("extra", {}).get("message", rule_id),
            location=f"{r.get('path', '?')}:{r.get('start', {}).get('line', '?')}",
            cve=None,
            fix_version=None,
            fix_available=True,
            description=r.get("extra", {}).get("metadata", {}).get("description", ""),
            pci_relevant=any(t in rule_id for t in ("pci", "owasp", "injection", "crypto")),
        ))

    return findings


def parse_trivy(path: Path, source: str = "fs") -> list[Finding]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return []

    findings = []
    for result in data.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            sev = v.get("Severity", "UNKNOWN").upper()
            if sev not in SEVERITY_SCORE:
                sev = "MEDIUM"
            pkg = v.get("PkgName", "")
            epss_raw = v.get("EPSS", {})
            findings.append(Finding(
                tool=f"trivy-{source}",
                severity=sev,
                title=f"{v.get('VulnerabilityID', '?')}: {v.get('Title', '')}",
                location=f"{pkg}@{v.get('InstalledVersion', '?')}",
                cve=v.get("VulnerabilityID"),
                fix_version=v.get("FixedVersion") or None,
                fix_available=bool(v.get("FixedVersion")),
                description=v.get("Description", "")[:280],
                pci_relevant=pkg.lower() in PCI_SENSITIVE,
                epss=epss_raw.get("Score", 0.0) if isinstance(epss_raw, dict) else 0.0,
            ))

    return findings


# ── Policy evaluation ──────────────────────────────────────────────────────────

def evaluate(findings: list[Finding], strict: bool) -> tuple[str, list[str], list[str]]:
    blocks, warns = [], []

    for f in findings:
        fix = f"fix: {f.fix_version}" if f.fix_version else "no fix yet"

        if f.tool == "gitleaks":
            blocks.append(
                f"[Req.8] secret at {f.location} — "
                f"hardcoded credential in CDE violates PCI 8.2.1"
            )

        elif f.severity == "CRITICAL":
            blocks.append(
                f"[Req.6/11] {f.cve or f.title} (CRITICAL) in {f.location} — {fix}"
            )

        elif f.severity == "HIGH" and f.epss >= EPSS_BLOCK_THRESHOLD:
            blocks.append(
                f"[Req.11] {f.cve or f.title} (HIGH, EPSS={f.epss:.2f}) in "
                f"{f.location} — active exploit probability above threshold. {fix}"
            )

        elif f.severity == "HIGH" and f.pci_relevant and strict:
            # On main branch, HIGH in PCI-sensitive packages blocks.
            # On feature branches it just warns — developers need to iterate.
            blocks.append(
                f"[Req.6] {f.cve or f.title} (HIGH) in PCI-sensitive package "
                f"{f.location} — strict mode. {fix}"
            )

        elif f.severity == "HIGH":
            warns.append(
                f"{f.cve or f.title} (HIGH) in {f.location}. "
                f"EPSS={f.epss:.2f}. {fix}"
            )

        elif f.severity == "MEDIUM" and strict:
            warns.append(f"{f.cve or f.title} (MEDIUM) in {f.location}. {fix}")

        # LOW and INFO are written to the artifact but don't surface as warnings.

    verdict = "BLOCK" if blocks else ("WARN" if warns else "PASS")
    return verdict, blocks, warns


def metrics(findings: list[Finding]) -> dict:
    by_sev  = {}
    by_tool = {}
    for f in findings:
        by_sev[f.severity]  = by_sev.get(f.severity, 0) + 1
        by_tool[f.tool]     = by_tool.get(f.tool, 0) + 1
    return {
        "risk_score":    sum(SEVERITY_SCORE.get(f.severity, 0) for f in findings),
        "by_severity":   by_sev,
        "by_tool":       by_tool,
        "pci_relevant":  sum(1 for f in findings if f.pci_relevant),
        "fixable":       sum(1 for f in findings if f.fix_available),
    }


def pci_map(findings: list[Finding]) -> dict:
    """Map active controls to PCI requirements — readable by a QSA."""
    return {
        "req_6": {
            "desc":     "Secure SDLC — SAST + SCA on every commit",
            "tools":    ["semgrep", "trivy-fs"],
            "findings": sum(1 for f in findings if f.tool in ("semgrep", "trivy-fs")),
        },
        "req_8": {
            "desc":     "Secrets management — no hardcoded credentials",
            "tools":    ["gitleaks"],
            "findings": sum(1 for f in findings if f.tool == "gitleaks"),
        },
        "req_10": {
            "desc":     "Audit logging — every pipeline run emits structured events to GCP",
            "tools":    ["gcp-cloud-logging"],
            "findings": 0,
        },
        "req_11": {
            "desc":     "Vulnerability scanning — container image scanned on every build",
            "tools":    ["trivy-image"],
            "findings": sum(1 for f in findings if f.tool == "trivy-image"),
        },
    }


def summary_md(d: Decision) -> str:
    icon = {"BLOCK": "[BLOCK]", "WARN": "[WARN]", "PASS": "[PASS]"}[d.verdict]
    m = d.metrics
    lines = [
        f"### {icon} Security Gate: **{d.verdict}**\n",
        f"| | |",
        f"|---|---|",
        f"| Risk score | {m.get('risk_score', 0)} |",
        f"| Total findings | {len(d.findings)} |",
        f"| PCI-relevant | {m.get('pci_relevant', 0)} |",
        f"| Fixable | {m.get('fixable', 0)} |",
        f"| Strict mode | {'yes' if d.strict else 'no'} |\n",
    ]
    if d.blocks:
        lines += ["**Blocking:**\n"]
        lines += [f"- {r}" for r in d.blocks]
        lines.append("")
    if d.warnings:
        lines += ["**Warnings:**\n"]
        lines += [f"- {r}" for r in d.warnings[:5]]
        if len(d.warnings) > 5:
            lines.append(f"- _...and {len(d.warnings) - 5} more_")
    return "\n".join(lines)


# ── CLI ────────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--secrets-report", type=Path, default=Path("gl.json"))
    p.add_argument("--sast-report",    type=Path, default=Path("semgrep.json"))
    p.add_argument("--sca-report",     type=Path, default=Path("trivy-fs.json"))
    p.add_argument("--image-report",   type=Path, default=Path("trivy-image.json"))
    p.add_argument("--output",         type=Path, default=Path("decision.json"))
    p.add_argument("--stage",          choices=["full", "image"], default="full")
    args = p.parse_args()

    strict = os.environ.get("POLICY_STRICT_MODE", "false").lower() == "true"
    commit = os.environ.get("GITHUB_SHA", "local")

    findings: list[Finding] = []
    if args.stage == "full":
        findings += parse_gitleaks(args.secrets_report)
        findings += parse_semgrep(args.sast_report)
        findings += parse_trivy(args.sca_report, "fs")
    else:
        findings += parse_trivy(args.image_report, "image")

    verdict, blocks, warns = evaluate(findings, strict)

    d = Decision(
        verdict=verdict,
        timestamp=datetime.now(timezone.utc).isoformat(),
        commit=commit,
        strict=strict,
        findings=findings,
        blocks=blocks,
        warnings=warns,
        metrics=metrics(findings),
        pci_map=pci_map(findings),
    )
    d.summary_md = summary_md(d)

    args.output.write_text(json.dumps(asdict(d), indent=2, default=str))

    # stdout for pipeline logs
    print(f"\n{'─'*55}")
    print(f"  verdict : {verdict}")
    print(f"  findings: {len(findings)}  risk: {d.metrics.get('risk_score', 0)}")
    print(f"  strict  : {strict}  commit: {commit[:8]}")
    if blocks:
        print(f"\n  blocking ({len(blocks)}):")
        for r in blocks:
            print(f"     {r[:100]}")
    if warns:
        print(f"\n  warnings ({len(warns)}):")
        for r in warns[:3]:
            print(f"     {r[:100]}")
    print(f"\n  → {args.output}\n{'─'*55}\n")

    sys.exit(1 if verdict == "BLOCK" else 0)


if __name__ == "__main__":
    main()
