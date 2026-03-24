# PDVD — Post-Deployment Vulnerability Remediation

When a critical open source vulnerability is disclosed, most security teams face the same four questions in rapid succession — and struggle to answer any of them quickly:

- **What exactly is the threat?** The CVE ID, CVSS score, and enough detail to know whether it's exploitable in your environment.
- **Where in your codebase do you fix it?** Which repo, which package, and which version introduced the vulnerable dependency.
- **Where is that code actually running right now?** Not where it was deployed last quarter — where it is live in production today, whether that's a Kubernetes cluster, a cloud function, or an edge device in the field.
- **How do you actually fix it?** The upgraded version and a clear remediation path so nothing falls through the cracks.

PDVD answers all four questions in a single platform. It ingests your Software Bill of Materials (SBOM) at build time, matches your deployed components against the OSV vulnerability database every 15 minutes, tracks every CVE from the moment it is introduced into a release through every environment it reaches until it is remediated, and measures how long each step takes against your SLA targets.

---

## Get Started (Hosted)

The fastest way to get started is the hosted version at **[app.deployhub.com](https://app.deployhub.com)** — no infrastructure setup required.

1. Go to [app.deployhub.com](https://app.deployhub.com) and click **Sign Up**
2. Enter your username, email, first name, last name, and organization name
3. Check your email for an invitation link — click it to set your password and log in
4. You're in. Your organization is created and you are its owner.

> **Note:** If your organization already exists in the system, you'll see a conflict message with the org admin's email address. Contact them directly to be added.

---

## Connect Your GitHub Repositories

Once logged in, connect your GitHub account. This is the primary way PDVD discovers your software — it reads your existing workflow runs, finds your container images and releases, and automatically imports everything into your dashboard.

### Step 1 — Connect GitHub

1. In the top-right menu, go to **Profile → Connect GitHub**
2. You'll be redirected to GitHub to install the PDVD GitHub App on your account or organization
3. Select which repositories to give PDVD access to — you can start with one and add more later
4. After approving, you'll be redirected back to PDVD with GitHub connected

### Step 2 — What Happens Automatically

Once connected, PDVD's background scanner runs against every repository in your installation. For each repository it:

1. **Finds your latest successful workflow run** on `main` or `master`, triggered by a push, release, or manual dispatch
2. **Extracts your container image reference** from the workflow logs — specifically the image produced by a Docker manifest push
3. **Discovers your SBOM** using a three-step priority order:
   - First, looks for an SBOM attached directly to the container image as an OCI attestation (cosign/DSSE format or OCI Referrers API)
   - Second, looks for an artifact named `sbom` or `cyclonedx` uploaded during the workflow run
   - Third, if no SBOM is found, generates one automatically by scanning the container image using [Syft](https://github.com/anchore/syft)
4. **Reads OCI image labels** (`org.opencontainers.image.*`) to enrich the release with git metadata — commit SHA, branch, source URL, authors
5. **Fetches your OpenSSF Scorecard** score from securityscorecards.dev automatically
6. **Creates a release record** in PDVD with the version, SBOM, git metadata, and scorecard score
7. **Records a sync** linking the release to the endpoint representing the GitHub Actions environment

The scanner remembers the last workflow run ID it processed per repository, so repeat runs only pick up genuinely new activity.

### Step 3 — Verify Your Data

After a few minutes, go to your dashboard. You should see:

- Your repositories listed under **Releases**
- Vulnerability counts populated (if your SBOM contains packages with known CVEs)
- An OpenSSF Scorecard score on each release
- GitHub Actions listed as an endpoint under **Endpoints**

If a repository shows zero vulnerabilities, see [Why Am I Seeing Zero CVEs?](#why-am-i-seeing-zero-cves) below.

### Getting the Best Results

The scanner works with whatever your pipeline already produces. However, the quality of vulnerability matching improves when your workflow publishes an explicit SBOM. The recommended approach is to generate and attach an SBOM as an OCI attestation at build time — PDVD will find and use it automatically without any additional configuration:

```yaml
# Example: generate and attach an SBOM as an OCI attestation using Syft
- name: Generate and attest SBOM
  run: |
    syft ${{ env.IMAGE_NAME }}:${{ env.IMAGE_TAG }} \
      -o cyclonedx-json \
      --file sbom.json
    cosign attest --predicate sbom.json \
      --type cyclonedx \
      ${{ env.IMAGE_NAME }}@${{ env.IMAGE_DIGEST }}
```

If you already produce SBOMs via Syft, Trivy, or any CycloneDX-compatible tool and upload them as workflow artifacts, PDVD will find those too — no changes needed.

**Supported ecosystems for CVE matching:** npm, PyPI, Maven, Go, NuGet, RubyGems, cargo (crates.io), Composer, apk (Alpine/Wolfi), deb (Debian/Ubuntu)

> **Using a different CI system or want direct API access?** See the [Implementation Guide](docs/implementation.md) for REST API reference.

---

## Why Am I Seeing Zero CVEs?

Two things must be true before vulnerabilities appear:

1. **A release with a valid SBOM has been imported** — components need properly formatted PURLs for CVE matching to work
2. **That release has been synced to at least one endpoint** — the scanner records GitHub Actions runs as endpoints automatically

CVE data is refreshed from OSV.dev every 15 minutes. If you just connected GitHub and see nothing yet, wait a few minutes and refresh.

If you still see zero CVEs after that, the most likely cause is that your SBOM was not found or was generated from an image that uses an unsupported ecosystem. Check that your container image is publicly accessible or that the GitHub App has the appropriate registry access. Components with missing or malformed PURLs are silently skipped during CVE matching.

---

## Read Your Dashboard

The dashboard gives you four top-line numbers:

| Metric | What it means |
|---|---|
| **MTTR** | Mean time to remediate — average days from when a CVE was first detected to when it was fixed, rolling 180-day window |
| **Mean Open Age** | Average age in days of all currently open CVEs across your endpoints |
| **% Beyond SLA** | Percentage of open CVEs that have exceeded their severity-based SLA target |
| **Backlog Delta** | New CVEs detected minus CVEs fixed in the period — negative is good |

The **by severity** breakdown (Critical / High / Medium / Low) gives you the same metrics segmented so you can see where to focus.

The **endpoint impact** section shows which of your production environments are carrying the most risk right now.

---

## Invite Your Team

As an org owner or admin, go to your organization settings to invite colleagues.

Each invited user receives an email with a link to set their password. Links expire after **48 hours**. If a link expires, an admin can resend it.

When choosing a role, use the minimum necessary:

| Role | Can do |
|---|---|
| **Owner** | Everything, including managing billing and deleting the org |
| **Admin** | Everything except billing — invite users, manage roles, access all resources |
| **Editor** | Upload releases, upload SBOMs, sync endpoints — the right role for CI/CD service accounts |
| **Viewer** | Read-only — dashboards, CVE details, endpoint status |

---

## SLA Reference

SLA targets define how many days your team has to remediate a CVE before it counts as overdue. The clock starts when the CVE is first detected on a deployed endpoint.

| Severity | Standard Endpoint | Mission-Critical Endpoint |
|---|---|---|
| Critical | 15 days | 7 days |
| High | 30 days | 15 days |
| Medium | 90 days | 90 days |
| Low | 180 days | 180 days |

Endpoints with `endpoint_type: mission_asset` use the tighter targets in the right column.

---

## Glossary

| Term | Definition |
|---|---|
| **CVE** | Common Vulnerabilities and Exposures — a unique identifier for a known vulnerability |
| **CVSS** | Common Vulnerability Scoring System — a 0–10 severity score (9.0+ = Critical) |
| **SBOM** | Software Bill of Materials — a machine-readable inventory of every library your software depends on |
| **PURL** | Package URL — a standardized identifier for a software package, e.g. `pkg:npm/lodash@4.17.20` |
| **MTTR** | Mean Time To Remediate — average days from CVE detection to fix deployment |
| **SLA** | Service Level Agreement — the target number of days within which a CVE should be remediated |
| **Endpoint** | A running environment where software is deployed (cluster, function, device) |
| **Sync** | The act of telling PDVD what versions are currently deployed to an endpoint |
| **OSV** | Open Source Vulnerabilities — the vulnerability database PDVD pulls from, refreshed every 15 minutes |
| **OCI Attestation** | An SBOM or other artifact attached directly to a container image in the registry |
| **OpenSSF Scorecard** | An automated security health score (0–10) for open source repositories |

---

## Next Steps

- **Running on-premises or self-hosted?** → [Architecture Guide](docs/architecture.md)
- **Integrating the API, writing queries, or contributing code?** → [Implementation Guide](docs/implementation.md)
