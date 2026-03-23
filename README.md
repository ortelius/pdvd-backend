# Post-Deployment Vulnerability Remediation (PDVD)

> **TL;DR:** A graph-based vulnerability management platform that tracks CVEs from discovery through production deployment to remediation, with multi-tenant RBAC, SLA compliance tracking, and automated workflows.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)](https://golang.org/)
[![ArangoDB](https://img.shields.io/badge/ArangoDB-3.11+-E93B8C?logo=arangodb)](https://arangodb.com/)

## 📖 Documentation

- **[Complete Design Document](design.md)** - Full technical architecture, API specs, and implementation details
- **[Hub-and-Spoke Architecture](hub_and_spoke_guide.md)** - Deep dive into graph database design and performance

## 🎯 What Problem Does This Solve?

For every high-risk OSS vulnerability, security teams need answers to four questions:

```mermaid
graph LR
    Q1[❓ What's the threat?] --> A1[✅ CVE-2024-1234<br/>CRITICAL 9.8 CVSS]
    Q2[❓ Where do I fix it?] --> A2[✅ frontend-app repo<br/>lodash@4.17.20]
    Q3[❓ Where is it running?] --> A3[✅ prod-k8s-us-east<br/>edge-device-001]
    Q4[❓ How do I fix it?] --> A4[✅ Upgrade lodash@4.17.21<br/>Auto-create Jira ticket]
    
    style Q1 fill:#ff6b6b
    style Q2 fill:#ffd43b
    style Q3 fill:#cc5de8
    style Q4 fill:#51cf66
```

## 🏗️ Architecture in 30 Seconds

```mermaid
graph LR
    CVE[CVE Data<br/>1M+ records] -->|affects| PURL[PURL Hubs<br/>100K packages]
    PURL -->|used in| SBOM[SBOMs<br/>500K documents]
    SBOM -->|describes| REL[Releases<br/>1M versions]
    REL -->|deployed to| EP[Endpoints<br/>10K systems]
    REL -.->|belongs to| ORG[Organizations<br/>Multi-tenant]
    
    style PURL fill:#4dabf7
    style ORG fill:#cc5de8
```

**Key Innovation:** Hub-and-Spoke architecture with PURL nodes = **99.89% less edges**, **<3s queries**

## 🚀 Quick Start

```bash
# 1. Start ArangoDB
docker run -p 8529:8529 -e ARANGO_ROOT_PASSWORD=password arangodb:latest

# 2. Run PDVD Backend  
export ARANGO_HOST=localhost ARANGO_PASS=password
go run main.go

# 3. Access APIs
# REST: http://localhost:3000/api/v1
# GraphQL: http://localhost:3000/api/v1/graphql
```

## 🔐 Multi-Tenant RBAC with GitOps

```mermaid
sequenceDiagram
    participant User
    participant API
    participant Git as GitHub Repo
    participant DB as ArangoDB
    participant Email
    
    User->>API: POST /signup<br/>(username, email, org)
    API->>Git: Update rbac.yaml
    Git-->>API: Commit pushed
    API->>DB: Create user (pending)<br/>Create org (if new)
    API->>Email: Send invitation token
    
    User->>API: Click invitation link
    API->>User: Prompt for password
    User->>API: Set password + accept
    API->>DB: Activate user<br/>is_active=true
    API->>User: Auto-login (JWT cookie)
```

### RBAC Configuration (Peribolos-style)

```yaml
# rbac.yaml (stored in Git)
orgs:
  - name: acme-corp
    display_name: ACME Corporation
    members:
      - username: alice
        role: owner      # Full access + billing
      - username: bob  
        role: editor     # Read + write

users:
  - username: alice
    email: alice@acme.com
    auth_provider: local
```

**4 Roles:**
- `owner` - Full access + billing management
- `admin` - Full access + user management
- `editor` - Read/write to resources
- `viewer` - Read-only access

**Features:**
- ✅ Token-based email invitations (48h expiry)
- ✅ JWT auth with HttpOnly cookies
- ✅ GitHub App integration
- ✅ Org-scoped data isolation
- ✅ GitOps workflow with auto-sync

## 📊 Dashboard Metrics (NIST/DoD Compliant)

```mermaid
graph TB
    subgraph Executive["Executive Summary"]
        MTTR[MTTR: 23.4 days]
        OPEN[Mean Open Age: 45.2 days]
        SLA[SLA Compliance: 87%]
        BACK[Backlog Delta: -12]
    end
    
    subgraph BySeverity["By Severity"]
        CRIT[Critical: 3 open<br/>MTTR 8.2 days]
        HIGH[High: 15 open<br/>MTTR 21.7 days]
        MED[Medium: 42 open<br/>MTTR 38.5 days]
    end
    
    subgraph Endpoints["Endpoint Impact"]
        EP1[prod-us-east: 23 CVEs]
        EP2[edge-001: 8 CVEs]
        EP3[mission-sat-7: 2 CVEs]
    end
    
    style CRIT fill:#ff6b6b
    style HIGH fill:#ffa94d
    style MED fill:#ffd43b
```

**SLA Targets:**

| Severity | Standard | Mission-Critical |
|----------|----------|------------------|
| Critical | 15 days  | 7 days           |
| High     | 30 days  | 15 days          |
| Medium   | 90 days  | 90 days          |
| Low      | 180 days | 180 days         |

## 🔌 API Examples

### REST API

```bash
# Sign-up (creates org + sends invitation)
POST /api/v1/signup
{
  "username": "alice",
  "email": "alice@acme.com",
  "first_name": "Alice",
  "last_name": "Smith",
  "organization": "acme-corp"
}

# Login
POST /api/v1/auth/login
{ "username": "alice", "password": "secure-pass" }
# Returns: Set-Cookie: auth_token=<jwt>; HttpOnly

# Upload Release + SBOM
POST /api/v1/releases
{
  "name": "payment-service",
  "version": "2.1.0",
  "gitcommit": "abc123",
  "org": "acme-corp",
  "sbom": { "content": { /* CycloneDX */ } }
}

# Sync Deployment
POST /api/v1/sync
{
  "endpoint_name": "prod-us-east-1",
  "releases": [{
    "release": { "name": "payment-service", "version": "2.1.0" }
  }],
  "endpoint": {
    "name": "prod-us-east-1",
    "endpoint_type": "eks",
    "environment": "production"
  }
}
```

### GraphQL API

```graphql
# Get vulnerabilities (org-scoped)
query {
  release(name: "payment-service", version: "2.1.0") {
    vulnerabilities {
      cve_id
      severity_rating
      severity_score
      package
      fixed_in
    }
    synced_endpoints {
      endpoint_name
      environment
    }
  }
}

# Dashboard with MTTR (org-filtered)
query {
  dashboardMTTR(days: 180, org: "acme-corp") {
    executive_summary {
      total_new_cves
      mttr_all
      mttr_post_deployment
      open_cves_beyond_sla_pct
    }
    by_severity {
      severity
      mttr
      open_count
      fixed_within_sla_pct
    }
  }
}
```

## 🗄️ Database Schema

```mermaid
erDiagram
    USERS ||--o{ ORGS : "member_of"
    ORGS ||--o{ RELEASES : "owns"
    ORGS ||--o{ ENDPOINTS : "manages"
    RELEASES ||--|| SBOM : "has"
    RELEASES ||--o{ SYNC : "deployed_in"
    ENDPOINTS ||--o{ SYNC : "hosts"
    SBOM ||--o{ PURL : "contains"
    CVE ||--o{ PURL : "affects"
    RELEASES ||--o{ CVE : "vulnerable_to"
    CVE ||--o{ CVE_LIFECYCLE : "tracked_by"
    USERS ||--o{ INVITATIONS : "invited_as"
    
    USERS {
        string username PK
        string email
        string password_hash
        string role
        array orgs
        bool is_active
    }
    
    ORGS {
        string name PK
        string display_name
    }
    
    RELEASES {
        string name
        string version
        string org
        bool is_public
    }
    
    CVE {
        string id PK
        float cvss_base_score
        string severity_rating
    }
    
    CVE_LIFECYCLE {
        string cve_id
        datetime introduced_at
        datetime remediated_at
    }
```

**Collections:** `cve`, `purl`, `sbom`, `release`, `endpoint`, `sync`, `cve_lifecycle`, `users`, `invitations`, `roles`, `orgs`

## 🎯 Key Features

### ✅ Hub-and-Spoke Architecture
- **99.89% edge reduction** vs traditional graph
- **<3s queries** on millions of records
- **Linear scalability** O(N+M)

### ✅ Multi-Tenancy
- **Org isolation:** Data scoped by membership
- **Empty org = global:** Users with `orgs: []` see all
- **4-level roles:** owner → admin → editor → viewer

### ✅ CVE Lifecycle Tracking
```mermaid
stateDiagram-v2
    [*] --> Detected: CVE discovered
    Detected --> Active: Deployed
    Active --> Remediated: Fixed
    Remediated --> [*]
```

- Tracks: introduced_at, remediated_at, days_to_remediate
- Post-deployment detection flags
- MTTR calculation

## 📈 Performance

| Metric           | Target       | Actual    |
|------------------|--------------|-----------|
| API Response     | <3s          | <1s (p95) |
| CVE Ingestion    | 50K/hour     | ✅         |
| Concurrent Users | 100+         | ✅         |
| Database Scale   | 1M+ releases | ✅         |


## 🛠️ Technology Stack

- **Backend:** Go 1.21+, Fiber, GraphQL
- **Database:** ArangoDB 3.11+
- **Auth:** JWT, bcrypt, HttpOnly cookies
- **CVE Data:** OSV.dev API
- **GitOps:** go-git

## 📦 Environment Variables

```bash
ARANGO_HOST=localhost
ARANGO_PASS=your-password
JWT_SECRET=change-me-in-production
ADMIN_USERNAME=admin
ADMIN_PASSWORD=secure-password
RBAC_REPO=https://github.com/org/rbac
SMTP_HOST=smtp.gmail.com
SMTP_USERNAME=noreply@pdvd.com
BASE_URL=https://pdvd.example.com
GITHUB_APP_ID=123456
```

## 🚢 Deployment

```bash
# Docker Compose
docker-compose up -d

# Kubernetes
helm install pdvd ./helm/pdvd-backend
```

## 📝 License

Apache License 2.0

---

**Built with ❤️ by the Ortelius community** | [Website](https://ortelius.io)
