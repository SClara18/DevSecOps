# ChronosPay Security Deployment Policy
**Version 1.2.0 | Effective: 2025-03-27 | Owner: Security Engineering**

---

## Purpose

This document defines the automated security policy enforced by `policy/gate.py`
at every CI/CD pipeline run for the ChronosPay service. It is the authoritative
source of truth for what constitutes a deployable vs. non-deployable build.

This policy is **code-adjacent documentation** — any change to gate thresholds
must update both `gate.py` and this document in the same PR.

---

## Enforcement Levels

### BLOCK — Hard stop, pipeline fails

The build cannot proceed to deployment. No exceptions without a documented
security exception approved by CISO + Engineering VP.

**Triggers:**

1. **Any secret detected by Gitleaks**
   - Covers: API keys, tokens, passwords, private keys, connection strings
   - Rationale: PCI Req. 8.2.1. Hardcoded credentials in a CDE are an
     immediate compliance violation and operational security risk.
   - Remediation: Remove from code. Rotate the credential immediately (treat
     as compromised). Use `os.environ` + External Secrets Operator.

2. **CRITICAL CVE (any scanner)**
   - CVSS base score ≥ 9.0 OR scanner-assigned CRITICAL
   - No exceptions in the CDE. Fix or vendor-patch before deploying.
   - Rationale: PCI Req. 6.3.3. All critical vulnerabilities addressed promptly.

3. **HIGH CVE with active exploit (EPSS ≥ 0.70)**
   - EPSS (Exploit Prediction Scoring System) > 0.70 = 70th percentile
     of actively exploited vulnerabilities
   - Rationale: A HIGH CVE with a public exploit in a payment service is
     functionally equivalent to a CRITICAL in risk terms.

4. **HIGH CVE in PCI-sensitive package on main branch (strict mode)**
   - Packages: `cryptography`, `httpx`, `fastapi`, `uvicorn`, `pyjwt`,
     `pydantic`, `sqlalchemy`, `pyopenssl`
   - Rationale: These packages directly handle cardholder data or authentication.
     The blast radius of a HIGH vulnerability in them is disproportionately large.

5. **Container runs as root (UID 0)**
   - Rationale: CIS Docker Benchmark 4.1. Running as root enables trivial
     container escape. PCI Req. 7 (least privilege).

---

### WARN — Advisory, pipeline continues

Deployment proceeds. A ticket is automatically created with a defined SLA.
Engineers are not blocked but are accountable for remediation.

**Triggers:**

1. **HIGH CVE without known exploit (EPSS < 0.70)**
   - SLA: Remediate within 30 days
   - Creates: JIRA ticket tagged `security-sla-30d`

2. **MEDIUM CVE on main branch (strict mode)**
   - SLA: Remediate within 90 days
   - Creates: JIRA ticket tagged `security-sla-90d`

3. **HIGH CVE in non-PCI-sensitive package**
   - SLA: 30 days

---

### PASS — All clear

No blocking or warning conditions found. Deployment proceeds.
LOW and INFO findings are logged in the artifact but generate no tickets.

---

## Exception Process

If a BLOCK condition cannot be remediated before deployment is required:

1. Engineer creates exception request in security portal
2. CISO + Engineering VP approve in writing
3. Exception logged in GRC tool with: CVE/finding ID, justification,
   compensating control, expiry date (max 30 days)
4. Pipeline override: `SECURITY_EXCEPTION_ID` env var with approved exception ID
5. Exception and override logged to GCP Cloud Audit Logs (PCI Req. 10 evidence)

---

## Severity Thresholds (Configurable)

| Parameter | Default | Env var override |
|---|---|---|
| EPSS block threshold | 0.70 | `POLICY_EPSS_THRESHOLD` |
| Strict mode | true on main | `POLICY_STRICT_MODE` |
| Artifact retention | 90 days | `POLICY_RETENTION_DAYS` |

---

## PCI-DSS Compliance Mapping

| This Policy | Satisfies |
|---|---|
| Secret scanning blocks (Rule 1) | PCI Req. 8.2.1, 8.3.6 |
| CRITICAL CVE blocks (Rule 2) | PCI Req. 6.3.3 |
| EPSS-aware HIGH blocking (Rule 3) | PCI Req. 6.3.3, 11.3.1 |
| PCI-package strict mode (Rule 4) | PCI Req. 6.2, 6.3 |
| Root container block (Rule 5) | PCI Req. 7.2 |
| WARN SLA tracking | PCI Req. 6.3.3 (ranked remediation) |
| Artifact retention 90 days | PCI Req. 10.5 |

---

## Change Log

| Version | Date | Change | Author |
|---|---|---|---|
| 1.0.0 | 2025-03-01 | Initial policy | Security Eng |
| 1.1.0 | 2025-03-14 | Added EPSS threshold | Security Eng |
| 1.2.0 | 2025-03-27 | Added PCI-sensitive package list | Security Eng |
