# ChronosPay — Secure CI/CD Pipeline
**Payment Orchestration | PCI-DSS Sprint Delivery**

> *"PCI QSA audit in 3 weeks. CI/CD pipelines for payment-touching services currently have ZERO security gates."*
> — Security & Compliance team, Monday morning

This repository delivers a production-ready secure CI/CD pipeline for ChronosPay, a real-time authorization routing service. Built to satisfy PCI-DSS Requirements 6, 8, 10, and 11 — while keeping build time under 8 minutes so developers don't revolt.

---

## What's in here

```
chronospay/
├── main.py                          # ChronosPay FastAPI service
├── Dockerfile                       # Hardened multi-stage, non-root build
├── requirements.txt                 # Pinned dependencies
├── .pre-commit-config.yaml          # Local dev security hooks
├── .gitleaks.toml                   # Secrets scanner config
│
├── .github/workflows/
│   └── pipeline.yaml                # GitHub Actions — the full pipeline
│
├── policy/
│   ├── gate.py                      # Policy engine (the brain)
│   ├── requirements.txt             # Gate dependencies
│   └── policy.md                    # Human-readable policy definition
│
├── k8s/
│   └── external-secret.yaml         # ESO + Deployment + Service manifests
│
├── scan-outputs/
│   └── sample-decisions.json        # 5 real-world scenarios (BLOCK/WARN/PASS)
│
└── docs/
    └── threat-analysis.md           # Threat model, design decisions, residual risks
```

---

## Pipeline overview

```
git push → [Gitleaks ∥ Semgrep ∥ Trivy FS] → Policy Gate → Docker Build → Trivy Image → Deploy
             ↑ Parallel, ~1.5min             ↑ ~15s        ↑ ~1min       ↑ ~1.5min    ↑ ~1min

Total: ~5m 30s  (ceiling: 8 min)
```

Every stage produces a structured JSON artifact. The policy gate aggregates all of them into a single pass/fail decision with PCI-DSS evidence mapping.

---

## Quick start

### Prerequisites

- GitHub repository with Actions enabled
- GCP project with Artifact Registry + GKE cluster
- External Secrets Operator installed in your cluster

### 1. Set GitHub secrets

```bash
# GCP Workload Identity (replaces static service account keys)
GCP_WORKLOAD_IDENTITY_PROVIDER   # projects/123/locations/global/workloadIdentityPools/...
GCP_SERVICE_ACCOUNT              # chronospay-ci@payments-prod.iam.gserviceaccount.com

# Scanner tokens
SEMGREP_APP_TOKEN                # From semgrep.dev
GITLEAKS_LICENSE                 # From gitleaks.io (optional for OSS)
```

### 2. Set up GCP Secret Manager secrets

```bash
# Create secrets in GCP SM
gcloud secrets create chronospay/processor-api-key \
  --data-file=./secrets/processor-api-key.txt \
  --replication-policy=automatic

gcloud secrets create chronospay/webhook-signature-secret \
  --data-file=./secrets/webhook-secret.txt

gcloud secrets create chronospay/db-connection-string \
  --data-file=./secrets/db-conn.txt

# Grant ESO service account access
gcloud secrets add-iam-policy-binding chronospay/processor-api-key \
  --member="serviceAccount:chronospay-secrets-reader@payments-prod.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"
```

### 3. Install pre-commit hooks (local dev)

```bash
pip install pre-commit
pre-commit install
# Hooks now run on every git commit automatically
```

### 4. Push to trigger the pipeline

```bash
git push origin main
# Monitor at: github.com/your-org/chronospay/actions
```

---

## Security policy

Defined in `policy/gate.py` and `policy/policy.md`.

| Condition | Verdict | Rationale |
|---|---|---|
| Any secret detected (Gitleaks) | **BLOCK** | PCI Req. 8.2.1 — no hardcoded credentials in CDE |
| CRITICAL CVE | **BLOCK** | PCI Req. 6.3.3 — critical vulnerabilities addressed immediately |
| HIGH CVE + EPSS > 0.70 | **BLOCK** | Known exploit exists — unacceptable risk in payment infrastructure |
| HIGH CVE + PCI-sensitive package + strict mode | **BLOCK** | Main branch only — crypto/HTTP libs that touch cardholder data |
| Container runs as root | **BLOCK** | CIS Docker Benchmark 4.1 + PCI Req. 7 (least privilege) |
| HIGH CVE + EPSS ≤ 0.70 | **WARN** | Deploy proceeds; ticket auto-created with 30-day SLA |
| MEDIUM CVE (strict mode) | **WARN** | Advisory on main branch |
| LOW / INFO | **PASS** | Informational only |

**Strict mode** activates automatically on the `main` branch via `POLICY_STRICT_MODE=true`.

---

## Secrets rotation

ChronosPay uses **GCP Secret Manager + External Secrets Operator**:

1. Rotate secret in GCP SM (new version created, old version deactivated)
2. ESO detects new version within 5 minutes (poll interval)
3. ESO updates the Kubernetes Secret automatically
4. Pods pick up the new secret on next env read (or force restart: `kubectl rollout restart deployment/chronospay -n chronospay`)
5. GCP Cloud Audit Logs records the rotation event (PCI Req. 10 evidence)

No image rebuild. No downtime. Full audit trail.

---

## PCI-DSS evidence package

Each pipeline run generates artifacts retained for 90 days:

| Artifact | PCI Requirement |
|---|---|
| `gitleaks-report.json` | Req. 8 — No hardcoded credentials |
| `semgrep-report.json` | Req. 6 — Secure SDLC |
| `trivy-fs-report.json` | Req. 6, 11 — Dependency vulnerabilities |
| `trivy-image-report.json` | Req. 11 — Container vulnerabilities |
| `policy-decision.json` | Req. 6 — Enforcement log with PCI mapping |
| GCP Cloud Logging entry | Req. 10 — Deployment audit trail |

---

## Assumptions

- ChronosPay runs on GKE (Google Kubernetes Engine) in `us-central1`
- CI/CD platform: GitHub Actions (cloud-hosted runners)
- Secrets management: GCP Secret Manager + External Secrets Operator v0.9+
- GCP Workload Identity Federation configured for OIDC (no static keys)
- Kubernetes RBAC: only `chronospay-ci` service account can `kubectl apply` to `chronospay` namespace
- Base image: `python:3.12-slim` (Debian bookworm) — scanned by Trivy on every build

---

## Full documentation

- **Threat model + design decisions**: [`docs/threat-analysis.md`](docs/threat-analysis.md)
- **Security policy definition**: [`policy/policy.md`](policy/policy.md)
- **Sample scan outputs**: [`scan-outputs/sample-decisions.json`](scan-outputs/sample-decisions.json)
