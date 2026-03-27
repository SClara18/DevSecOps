# ChronosPay — Threat Analysis & Design Decisions
**Payment Orchestration Platform | DevSecOps Pipeline Review**

---

## 1. Threat Model

### 1.1 System Context

ChronosPay is a **cardholder data environment (CDE)** component. It receives authorization requests containing PAN, CVV, and expiry data, and routes them to external card networks. Any breach of this service falls under PCI-DSS scope and triggers mandatory disclosure, fines, and potential loss of card processing rights.

The CI/CD pipeline is not merely infrastructure — it is an **attack surface**. A compromised pipeline can deploy backdoored code to production without developer awareness. This is the central threat this architecture defends against.

```
 THREAT ACTORS                    ATTACK SURFACE
 ─────────────                    ─────────────────────────────────────────────
 Insider threat                → Git repository, pipeline secrets, artifact registry
 Supply chain attacker         → npm/pip packages, Docker base images, GitHub Actions
 External attacker             → Exposed API endpoints, webhook endpoints
 Credential thief              → CI/CD secrets, cloud IAM keys, k8s service accounts
```

### 1.2 Attack Vectors — Ranked by Likelihood × Impact

| # | Attack Vector | Likelihood | Impact | Blast Radius | Control |
|---|---|---|---|---|---|
| 1 | **Hardcoded secret committed to Git** | High | Critical | Full CDE breach | Gitleaks (pre-commit + CI) |
| 2 | **Vulnerable dependency exploited in prod** | High | High | RCE on payment service | Trivy SCA + policy gate |
| 3 | **Malicious GitHub Action in pipeline** | Medium | Critical | Full pipeline compromise | Pinned action versions (`@v4` hashes) |
| 4 | **Poisoned Docker base image** | Medium | High | Container escape | Trivy image scan |
| 5 | **Leaked GCP service account key** | Medium | Critical | Full cloud environment | OIDC workload identity (no static keys) |
| 6 | **Insider deploys unscanned image** | Low | Critical | Undetected backdoor | Policy gate blocks non-pipeline images |
| 7 | **Webhook spoofing (payment callbacks)** | Medium | High | Fraudulent payments | HMAC-SHA256 signature verification |
| 8 | **Container privilege escalation** | Low | Critical | Node-level compromise | Non-root UID + seccomp + read-only FS |

### 1.3 Blast Radius Analysis

ChronosPay operates at the **highest PCI scope tier**:

- Processes live PAN data in transit
- Holds active payment processor API keys
- Routes real-money authorizations in real time

**If a critical vulnerability reaches production:**
- Financial exposure: PCI Level 1 fines ($500K–$1M) + card brand sanctions
- Operational exposure: Visa/Mastercard can suspend processing rights
- Reputational exposure: Mandatory breach disclosure (PCI Req. 12.10.1)
- Timeline: Median time from exploit to breach detection in fintech: 197 days

This justifies a conservative policy: **CRITICAL CVEs always block, no exceptions**.

---

## 2. Design Decisions

### 2.1 Why GitHub Actions over GitLab CI or Jenkins?

**Chosen:** GitHub Actions

| Factor | GitHub Actions | GitLab CI | Jenkins |
|---|---|---|---|
| OIDC to GCP | Native support | Requires config | Plugin required |
| Marketplace ecosystem | Rich (Trivy, Semgrep actions) | Moderate | Sparse |
| Secrets at rest | Encrypted via GitHub | Encrypted via GitLab | Depends on config |
| Runner security | Ephemeral (no state bleed) | Ephemeral option | Persistent (risk) |
| Maintenance burden | Zero (SaaS) | Low | High |

**Trade-off accepted:** GitHub Actions vendor lock-in. Migrating would require rewriting YAML. Acceptable given the team's GitHub-first workflow.

### 2.2 Why parallel scanning?

**Design:** All three source-level scanners (Gitleaks, Semgrep, Trivy FS) run simultaneously as separate jobs.

**Alternative considered:** Sequential scanning (simpler dependency graph).

```
Sequential:  Gitleaks(45s) → Semgrep(90s) → Trivy(60s) → Total: ~3.5min
Parallel:    All three simultaneously                     → Total: ~1.5min (max of three)
```

**Saved: ~2 minutes.** Within an 8-minute budget, this is significant. The trade-off is slightly more complex pipeline YAML — worth it.

**Boundary condition:** The policy gate job (`needs: [secrets-scan, sast-scan, sca-scan]`) only starts after all three complete, preserving correctness.

### 2.3 Why a Python policy gate instead of native scanner exit codes?

**Problem with native exit codes:** Each scanner has its own severity model. Trivy exits 1 on any CRITICAL. Semgrep exits 1 on any ERROR. If we use their exit codes directly:
- We can't implement nuanced policy (e.g., HIGH blocks only if EPSS > 0.7)
- We can't aggregate across multiple scanners for a single decision
- We can't generate structured evidence for the QSA audit package

**Solution:** Custom Python policy engine (`policy/gate.py`) that:
- Reads all scanner JSON outputs
- Applies weighted severity rules
- Considers context (strict mode on `main`, relaxed on feature branches)
- Generates PCI-DSS evidence mapping
- Posts structured summaries to GitHub PRs

**Trade-off:** Additional Python dependency in pipeline. Mitigated by simple `requirements.txt` and fast install (`pip cache`).

### 2.4 Why GCP Secret Manager + External Secrets Operator over HashiCorp Vault?

| Factor | GCP Secret Manager + ESO | HashiCorp Vault |
|---|---|---|
| Operational overhead | Low (managed) | High (self-hosted, HA setup) |
| Cost | ~$0.06/10K accesses | Infrastructure + license |
| Audit logging | Native GCP Cloud Audit Logs | Vault audit device (requires config) |
| Rotation | Native + ESO auto-sync | Requires Vault Agent or custom |
| Cloud lock-in | GCP-specific | Cloud-agnostic |
| PCI audit evidence | Cloud Audit Logs OOTB | Requires audit log export |

**Chosen: GCP SM + ESO.** The stack is GCP-first. The managed service reduces ops burden, and GCP Cloud Audit Logs provide PCI Req. 10 evidence automatically.

**Trade-off accepted:** GCP vendor lock-in. If the team migrates to multi-cloud, Vault would be reconsidered.

### 2.5 Scan depth vs. speed trade-offs

| Scanner | Depth setting | Time | Trade-off |
|---|---|---|---|
| Gitleaks | Full git history | ~20s | Higher recall, slower than HEAD-only |
| Semgrep | `p/python` + `p/owasp-top-ten` + `p/pci-dss` | ~60s | Targeted ruleset vs. full scan (~5min) |
| Trivy FS | All severities, all vuln types | ~45s | Comprehensive but can have false positives |
| Trivy image | OS + library, ignore-unfixed: false | ~60s | Includes unfixed CVEs for awareness |

**Semgrep decision:** Full Semgrep analysis (`--all-rules`) would take 5+ minutes. We run three targeted rulesets that cover the highest-value checks for a Python payment service. Custom rules for PAN/CVV pattern detection are a future enhancement.

**Trivy decision:** `ignore-unfixed: false` means we see CVEs without fixes. These go to WARN, not BLOCK, keeping developer friction reasonable while maintaining visibility.

### 2.6 OIDC workload identity instead of static GCP service account keys

**Problem:** Long-lived GCP service account keys in CI secrets are a common breach vector. If the key leaks, an attacker gets persistent GCP access.

**Solution:** GitHub Actions OIDC integration with GCP Workload Identity Federation. The pipeline exchanges a short-lived GitHub OIDC token for a GCP access token scoped to the specific job. No static key ever exists.

**PCI alignment:** PCI Req. 8.6.1 — "System/application accounts are managed" — OIDC eliminates the management overhead and exposure of static credentials.

---

## 3. PCI-DSS Control Mapping

| Pipeline Control | PCI Requirement | How It Satisfies the Requirement |
|---|---|---|
| Gitleaks secrets scanning | **Req. 8.2.1** | Prevents hardcoded credentials from reaching source control or deployment |
| Semgrep SAST | **Req. 6.2.4** | Automated code review to detect common vulnerabilities |
| Trivy SCA | **Req. 6.3.3** | Maintains all software components free from known vulnerabilities |
| Trivy image scan | **Req. 11.3.1** | Internal vulnerability scanning of deployed components |
| Policy gate — CRITICAL block | **Req. 6.4.1** | Security vulnerabilities ranked by risk; critical addressed immediately |
| GCP Secret Manager | **Req. 8.3** | Strong cryptographic controls for authentication credentials |
| ESO audit logging | **Req. 10.2** | Logs all access to system components and secrets |
| OIDC for pipeline auth | **Req. 8.6** | System/application accounts managed and monitored |
| Non-root container | **Req. 7.2** | Least privilege applied to application components |
| GCP Cloud Logging (deploy event) | **Req. 10.3** | Audit trail of all deployment events |
| Pre-commit hooks | **Req. 6.5** | Security addressed in software development processes |

**QSA Evidence Package:** Every pipeline run produces:
- `gitleaks-report.json` — secrets scan evidence (Req. 8)
- `semgrep-report.json` — SAST evidence (Req. 6)
- `trivy-fs-report.json` — SCA evidence (Req. 6, 11)
- `trivy-image-report.json` — container scan evidence (Req. 11)
- `policy-decision.json` — policy enforcement log (Req. 6)
- GCP Cloud Logging entry — deployment audit trail (Req. 10)

All artifacts are retained for 90 days (configurable to 12 months for PCI).

---

## 4. Residual Risks

| Risk | Why Not Fully Addressed | Mitigation |
|---|---|---|
| **Zero-day vulnerabilities** | Scanners rely on known CVE databases. A zero-day in httpx would not be caught. | Defense in depth: network policies, WAF, runtime anomaly detection (future) |
| **GitHub Actions supply chain attack** | A compromised upstream Action (`aquasecurity/trivy-action`) could inject malicious code. Pinning to tags is insufficient (tags are mutable). | **Mitigation needed:** Pin to immutable SHA hashes, not tags. `uses: aquasecurity/trivy-action@a20de5420d57c4102486cdd9349b532bf5b3c8d0` |
| **Semgrep false negatives** | We use curated rulesets, not exhaustive analysis. Complex business logic vulnerabilities (e.g., TOCTOU in payment routing) are invisible to SAST. | Annual penetration testing (PCI Req. 11.4) as complementary control |
| **Secret rotation gap** | ESO polls every 5 minutes. A secret rotated in GCP SM won't reach running pods for up to 5 minutes. | Acceptable for quarterly rotation cadence. For emergency rotation, add `kubectl rollout restart` to rotation runbook |
| **Insider deployment bypass** | A developer with kubectl access could `kubectl apply` a non-scanned image directly. | Mitigated by: (1) RBAC limits kubectl apply to service account, (2) admission controller (OPA Gatekeeper) can enforce image registry source |
| **Trivy database staleness** | Trivy downloads CVE DB at scan time. A very recently disclosed CVE may not be in the DB. | Trivy pulls latest DB on each run. Gap is typically < 24 hours. |
| **DAST not implemented** | Dynamic Application Security Testing requires a running instance. Not in current pipeline. | Future: add OWASP ZAP or Burp Suite scan against staging environment pre-production |

---

## 5. Future Enhancements (Prioritized)

### Priority 1 — Short term (next sprint)

**1a. Pin GitHub Actions to SHA hashes**
```yaml
# Instead of:
uses: aquasecurity/trivy-action@master
# Use:
uses: aquasecurity/trivy-action@a20de5420d57c4102486cdd9349b532bf5b3c8d0
```
Prevents supply chain attacks via compromised action tags.

**1b. OPA Gatekeeper admission controller**
```yaml
# Deny pods using images not from our Artifact Registry:
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sAllowedRepos
spec:
  match:
    kinds: [{apiGroups: [""], kinds: ["Pod"]}]
  parameters:
    repos: ["us-central1-docker.pkg.dev/payments-prod/"]
```
Closes the kubectl bypass gap.

### Priority 2 — Medium term (next quarter)

**2a. DAST stage against staging environment**
- Tool: OWASP ZAP or Nuclei
- Trigger: After deployment to staging, before production promotion
- Catches: XSS, SSRF, authentication bypasses, API misconfigurations

**2b. Semgrep custom rules for PAN/CVV patterns**
```yaml
rules:
  - id: pci-pan-in-logs
    patterns:
      - pattern: logging.$METHOD(..., $PAN, ...)
      - metavariable-regex:
          metavariable: $PAN
          regex: '\d{13,19}'
    message: "Potential PAN logged — PCI Req. 3.3 prohibits logging full PAN"
    severity: ERROR
```

**2c. SBOM-based vulnerability tracking dashboard**
- Use CycloneDX SBOM generated by Trivy
- Feed into Dependency-Track for trend analysis across releases
- Enables "which version introduced CVE-XXXX?" queries for QSA

### Priority 3 — Long term

**3a. Runtime security monitoring**
- Falco rules for ChronosPay: alert on unexpected process spawns, file writes outside `/tmp`, outbound connections to non-processor IPs

**3b. Automated remediation PRs**
```python
# When Trivy finds a fixable HIGH/CRITICAL in requirements.txt:
# 1. Create a branch: security/fix-CVE-2024-XXXXX
# 2. Update requirements.txt
# 3. Open PR with scan results as body
# 4. Tag security team for review
```

**3c. Multi-environment pipeline promotion**
```
feature → staging (full scan) → canary (5% traffic + DAST) → production
```
Currently: feature → main → production (no canary).

---

## 6. Architecture Diagram

```
                           DEVELOPER LAPTOP
                           ─────────────────
                           git commit
                               │
                    ┌──────────▼──────────┐
                    │  pre-commit hooks   │  ← Gitleaks + Bandit + Safety
                    │  (first line of     │    Catches secrets before push
                    │   defense)          │
                    └──────────┬──────────┘
                               │ git push
                               ▼
                    ┌─────────────────────┐
                    │   GitHub Actions    │
                    │   Trigger           │
                    └──────────┬──────────┘
                               │
           ┌───────────────────┼───────────────────┐
           │ PARALLEL (fan-out)│                   │
           ▼                   ▼                   ▼
    ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
    │  Gitleaks    │  │   Semgrep    │  │   Trivy (FS)     │
    │  Secrets     │  │   SAST       │  │   SCA            │
    │  ~20s        │  │   ~60s       │  │   ~45s           │
    └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘
           │                 │                   │
           └────────────┬────┘───────────────────┘
                        │ All complete
                        ▼
               ┌─────────────────┐
               │  Policy Gate    │  ← Python engine
               │  (gate.py)      │    Reads all JSON outputs
               │  ~15s           │    BLOCK | WARN | PASS
               └────────┬────────┘
                        │ (PASS or WARN)
                        ▼
               ┌─────────────────┐
               │  Docker Build   │  ← Multi-stage, non-root
               │  + GAR Push     │    SBOM + provenance
               │  ~60s           │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │  Trivy Image    │  ← OS + library CVE scan
               │  Scan           │    on actual built image
               │  ~60s           │
               └────────┬────────┘
                        │
                        ▼
               ┌─────────────────┐
               │  Deploy to GKE  │  ← ESO injects secrets
               │  ~60s           │    from GCP Secret Manager
               └─────────────────┘

    Total wall clock time: ~5m 30s (under 8m budget)

                    GCP INFRASTRUCTURE
                    ──────────────────
                    GCP Secret Manager
                         │
                    External Secrets Operator (ESO)
                         │ polls every 5m
                    k8s Secret (chronospay-secrets)
                         │ env injection
                    ChronosPay Pod
```
