# PDVD System Design Document

**Version:** 2.0  
**Last Updated:** January 2026  
**Status:** Production

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [System Architecture](#system-architecture)
3. [Multi-Tenant RBAC System](#multi-tenant-rbac-system)
4. [Authentication & Authorization](#authentication--authorization)
5. [Database Schema](#database-schema)
6. [API Specification](#api-specification)
7. [CVE Lifecycle Management](#cve-lifecycle-management)
8. [Hub-and-Spoke Graph Design](#hub-and-spoke-graph-design)
9. [Deployment Architecture](#deployment-architecture)
10. [Security Considerations](#security-considerations)

---

## Executive Summary

PDVD is a graph-based vulnerability management platform that tracks CVEs from discovery through production deployment to remediation. The system uses a hub-and-spoke architecture with PURL (Package URL) nodes to achieve 99.89% edge reduction compared to traditional graph designs, enabling linear O(N+M) scalability.

### Key Capabilities

- **Multi-Tenant RBAC:** Organization-based access control with 4-level role hierarchy
- **GitOps Workflow:** YAML-driven configuration with automatic sync from Git repositories
- **CVE Lifecycle Tracking:** Complete audit trail from introduction to remediation
- **Real-Time Dashboard:** MTTR metrics, SLA compliance, and executive summaries
- **Automated Workflows:** GitHub App integration, email invitations, Jira ticket creation

### Design Principles

1. **Graph-First:** Relationships are first-class citizens
2. **Hub-and-Spoke:** Minimize edges through central hub nodes
3. **Multi-Tenancy:** Org-scoped data with flexible global access
4. **GitOps:** Infrastructure and RBAC as code
5. **Zero-Trust:** JWT authentication with HttpOnly cookies

---

## System Architecture

```mermaid
graph TB
    subgraph External["External Services"]
        OSV[OSV.dev API<br/>CVE Database]
        GitHub[GitHub App<br/>Repo Access]
        SMTP[SMTP Server<br/>Email Invitations]
        GitRepo[Git Repository<br/>rbac.yaml]
    end
    
    subgraph API["API Layer (Go/Fiber)"]
        REST[REST API<br/>/api/v1/*]
        GraphQL[GraphQL API<br/>/api/v1/graphql]
        Auth[Auth Middleware<br/>JWT Validation]
        RBAC[RBAC Middleware<br/>Org Filtering]
    end
    
    subgraph Services["Business Logic"]
        CVESvc[CVE Service<br/>Ingestion & Matching]
        RBACsvc[RBAC Service<br/>User/Org Management]
        LifeSvc[Lifecycle Service<br/>MTTR Tracking]
        SyncSvc[Sync Service<br/>Deployment History]
    end
    
    subgraph Data["Data Layer"]
        Arango[(ArangoDB<br/>Graph + Document)]
    end
    
    OSV -->|Pull CVEs| CVESvc
    GitHub -->|OAuth + Tokens| RBACsvc
    SMTP -->|Send Invites| RBACsvc
    GitRepo -->|Webhook| RBACsvc
    
    REST --> Auth
    GraphQL --> Auth
    Auth --> RBAC
    RBAC --> Services
    Services --> Arango
    
    style API fill:#e3f2fd
    style Services fill:#f3e5f5
    style Data fill:#fff3e0
```

### Technology Stack

| Layer             | Technology       | Purpose                      |
|-------------------|------------------|------------------------------|
| **API Framework** | Fiber v2         | High-performance HTTP server |
| **GraphQL**       | graphql-go       | Query flexibility            |
| **Database**      | ArangoDB 3.11+   | Graph + document store       |
| **Auth**          | golang-jwt/jwt   | JWT generation/validation    |
| **Password**      | bcrypt           | Password hashing             |
| **CVE Data**      | OSV.dev API      | Vulnerability database       |
| **CVSS**          | pandatix/go-cvss | Score calculation            |
| **Git**           | go-git           | GitOps integration           |
| **Email**         | net/smtp         | SMTP invitations             |

---

## Multi-Tenant RBAC System

### Overview

PDVD implements organization-based multi-tenancy with a Peribolos-style YAML configuration stored in Git. Users belong to one or more organizations, and data access is scoped by org membership.

```mermaid
graph TB
    subgraph Users["Users"]
        Alice[alice<br/>owner@acme-corp]
        Bob[bob<br/>editor@acme-corp]
        Charlie[charlie<br/>admin@globex]
        Admin[admin<br/>no orgs = global]
    end
    
    subgraph Orgs["Organizations"]
        Acme[acme-corp<br/>ACME Corporation]
        Globex[globex<br/>Globex Industries]
    end
    
    subgraph Resources["Resources"]
        R1[payment-service<br/>org: acme-corp]
        R2[frontend-app<br/>org: acme-corp]
        R3[api-gateway<br/>org: globex]
        R4[open-source-lib<br/>is_public: true]
    end
    
    Alice --> Acme
    Bob --> Acme
    Charlie --> Globex
    
    Acme --> R1
    Acme --> R2
    Globex --> R3
    
    Admin -.->|sees all| R1
    Admin -.->|sees all| R2
    Admin -.->|sees all| R3
    Admin -.->|sees all| R4
    
    style Alice fill:#c8e6c9
    style Admin fill:#ffccbc
    style R4 fill:#fff9c4
```

### Role Hierarchy

```mermaid
graph TD
    Owner[owner<br/>Full Access + Billing] --> Admin[admin<br/>Full Access + User Mgmt]
    Admin --> Editor[editor<br/>Read + Write]
    Editor --> Viewer[viewer<br/>Read Only]
    
    Owner -.->|Can perform| OA[Create/Delete Orgs<br/>Manage Billing<br/>Assign Roles]
    Admin -.->|Can perform| AA[Invite Users<br/>Manage Users<br/>Access All Resources]
    Editor -.->|Can perform| EA[Create Releases<br/>Upload SBOMs<br/>Sync Endpoints]
    Viewer -.->|Can perform| VA[View Dashboards<br/>Query CVEs<br/>Export Reports]
    
    style Owner fill:#ff6b6b
    style Admin fill:#ffa94d
    style Editor fill:#51cf66
    style Viewer fill:#4dabf7
```

### RBAC Configuration Format

```yaml
# rbac.yaml (Peribolos-style)
orgs:
  - name: acme-corp
    display_name: ACME Corporation
    description: Main engineering organization
    metadata:
      cost_center: CC-1234
      billing_contact: finance@acme.com
    members:
      - username: alice
        role: owner
      - username: bob
        role: editor
      - username: charlie
        role: viewer

  - name: globex
    display_name: Globex Industries
    members:
      - username: charlie
        role: admin

users:
  - username: alice
    email: alice@acme.com
    first_name: Alice
    last_name: Smith
    auth_provider: local
    github_username: alice-gh
    
  - username: bob
    email: bob@acme.com
    first_name: Bob
    last_name: Jones
    auth_provider: github
    github_username: bob-jones

  - username: admin
    email: admin@pdvd.com
    first_name: System
    last_name: Administrator
    auth_provider: local
    # No orgs = global access
```

### GitOps Workflow

```mermaid
sequenceDiagram
    participant Dev as Developer
    participant Git as GitHub Repo
    participant Webhook as GitHub Webhook
    participant API as PDVD API
    participant DB as ArangoDB
    
    Dev->>Git: Push rbac.yaml change
    Git->>Webhook: Trigger webhook
    Webhook->>API: POST /api/v1/rbac/sync
    
    API->>Git: Clone/pull repository
    API->>API: Parse rbac.yaml
    
    rect rgb(200, 240, 200)
        Note over API,DB: Sync Organizations
        API->>DB: Create/update orgs
    end
    
    rect rgb(240, 200, 200)
        Note over API,DB: Sync Users
        API->>DB: Create/update users
        API->>DB: Update org memberships
    end
    
    rect rgb(200, 200, 240)
        Note over API,DB: Audit Changes
        API->>DB: Log sync event
        API->>DB: Record diffs
    end
    
    API->>Webhook: 200 OK (sync complete)
    Webhook->>Git: Update commit status
```

### Data Scoping Rules

1. **Org-Scoped Resources:**
   - Releases with `org` field
   - Endpoints with `org` field
   - SBOMs (inherited from release)
   - Sync records (inherited from endpoint)

2. **Global Resources:**
   - CVEs (shared across all orgs)
   - PURL hubs (shared package index)
   - Users with `orgs: []` (admin-level access)
   - Resources with `is_public: true`

3. **Filtering Logic:**
   ```go
   // Pseudo-code for org filtering
   func filterByOrg(user User, resources []Resource) []Resource {
       if len(user.Orgs) == 0 {
           return resources // Global access
       }
       
       filtered := []Resource{}
       for _, r := range resources {
           if r.IsPublic || contains(user.Orgs, r.Org) {
               filtered = append(filtered, r)
           }
       }
       return filtered
   }
   ```

---

## Authentication & Authorization

### Sign-Up Flow

```mermaid
sequenceDiagram
    participant User
    participant API
    participant DB
    participant Git
    participant Email
    
    User->>API: POST /api/v1/signup<br/>{username, email, org, ...}
    
    rect rgb(240, 240, 255)
        Note over API,DB: Create User (Pending)
        API->>DB: INSERT users<br/>{is_active: false, status: 'pending'}
        API->>DB: INSERT/UPDATE orgs<br/>if org doesn't exist
    end
    
    rect rgb(255, 240, 240)
        Note over API,Git: Update GitOps Config
        API->>Git: Clone rbac.yaml
        API->>Git: Add user to yaml
        API->>Git: Commit + push
    end
    
    rect rgb(240, 255, 240)
        Note over API,Email: Send Invitation
        API->>DB: INSERT invitations<br/>{token, expires_at}
        API->>Email: Send invite email<br/>with token link
    end
    
    API->>User: 201 Created<br/>{message: "Check email"}
    
    User->>API: GET /invitation/:token
    API->>User: Return invitation form
    
    User->>API: POST /invitation/:token/accept<br/>{password}
    
    rect rgb(240, 255, 255)
        Note over API,DB: Activate User
        API->>DB: UPDATE users<br/>{is_active: true, password_hash}
        API->>DB: UPDATE invitations<br/>{accepted_at: now()}
    end
    
    API->>API: Generate JWT
    API->>User: Set-Cookie: auth_token=<jwt><br/>Auto-login
```

### Login Flow

```mermaid
sequenceDiagram
    participant User
    participant API
    participant DB
    participant GitHub
    
    alt Local Authentication
        User->>API: POST /api/v1/auth/login<br/>{username, password}
        API->>DB: SELECT users WHERE username
        API->>API: bcrypt.Compare(password, hash)
        alt Valid
            API->>API: Generate JWT
            API->>User: Set-Cookie: auth_token=<jwt><br/>HttpOnly, SameSite=Lax
        else Invalid
            API->>User: 401 Unauthorized
        end
    end
    
    alt GitHub OAuth
        User->>API: GET /api/v1/auth/github
        API->>GitHub: Redirect to OAuth
        GitHub->>User: Authorize app
        GitHub->>API: Callback with code
        API->>GitHub: Exchange code for token
        API->>DB: SELECT/INSERT user<br/>WHERE github_username
        API->>API: Generate JWT
        API->>User: Set-Cookie: auth_token=<jwt>
    end
```

### JWT Structure

```json
{
  "sub": "alice",
  "email": "alice@acme.com",
  "orgs": ["acme-corp"],
  "role": "owner",
  "iat": 1704067200,
  "exp": 1704153600
}
```

**Cookie Settings:**
```
Set-Cookie: auth_token=<jwt>; 
  HttpOnly; 
  Secure; 
  SameSite=Lax; 
  Path=/; 
  Max-Age=86400
```

### Middleware Chain

```mermaid
graph LR
    Request[HTTP Request] --> AuthM[Auth Middleware<br/>Validate JWT]
    AuthM -->|Valid| RBACM[RBAC Middleware<br/>Check Org Access]
    AuthM -->|Invalid| Err401[401 Unauthorized]
    
    RBACM -->|Allowed| Handler[Route Handler]
    RBACM -->|Denied| Err403[403 Forbidden]
    
    Handler --> Response[HTTP Response]
    
    style AuthM fill:#e3f2fd
    style RBACM fill:#f3e5f5
    style Handler fill:#e8f5e9
```

### Permission Matrix

| Resource | Owner | Admin | Editor | Viewer |
|----------|-------|-------|--------|--------|
| **Organizations** |
| Create org | ✅ | ✅ | ❌ | ❌ |
| Delete org | ✅ | ❌ | ❌ | ❌ |
| Update org metadata | ✅ | ✅ | ❌ | ❌ |
| **Users** |
| Invite user | ✅ | ✅ | ❌ | ❌ |
| Revoke user | ✅ | ✅ | ❌ | ❌ |
| Assign roles | ✅ | ✅ | ❌ | ❌ |
| **Releases** |
| Upload release | ✅ | ✅ | ✅ | ❌ |
| Delete release | ✅ | ✅ | ✅ | ❌ |
| View releases | ✅ | ✅ | ✅ | ✅ |
| **Endpoints** |
| Create endpoint | ✅ | ✅ | ✅ | ❌ |
| Sync deployment | ✅ | ✅ | ✅ | ❌ |
| View endpoints | ✅ | ✅ | ✅ | ✅ |
| **Dashboards** |
| View org dashboard | ✅ | ✅ | ✅ | ✅ |
| Export reports | ✅ | ✅ | ✅ | ✅ |

---

## Database Schema

### Collections

```mermaid
erDiagram
    USERS ||--o{ INVITATIONS : "has"
    USERS }o--o{ ORGS : "member_of"
    ORGS ||--o{ RELEASES : "owns"
    ORGS ||--o{ ENDPOINTS : "manages"
    
    RELEASES ||--|| SBOM : "described_by"
    SBOM ||--o{ SBOM2PURL : "contains"
    PURL }o--o{ SBOM2PURL : "used_in"
    
    CVE ||--o{ CVE2PURL : "affects"
    PURL }o--o{ CVE2PURL : "vulnerable"
    
    RELEASES ||--o{ RELEASE2CVE : "has_vulnerability"
    CVE }o--o{ RELEASE2CVE : "found_in"
    
    RELEASES ||--o{ SYNC : "deployed_as"
    ENDPOINTS ||--o{ SYNC : "hosts"
    
    CVE ||--o{ CVE_LIFECYCLE : "tracked_by"
    RELEASES }o--|| CVE_LIFECYCLE : "introduced_in"
    ENDPOINTS }o--|| CVE_LIFECYCLE : "active_on"
```

### Core Collections

#### users
```json
{
  "_key": "alice",
  "username": "alice",
  "email": "alice@acme.com",
  "password_hash": "$2a$10$...",
  "first_name": "Alice",
  "last_name": "Smith",
  "orgs": ["acme-corp"],
  "role": "owner",
  "auth_provider": "local",
  "github_username": "alice-gh",
  "github_token": "gho_...",
  "is_active": true,
  "created_at": "2024-01-01T00:00:00Z",
  "last_login": "2024-12-01T10:30:00Z"
}
```

#### orgs
```json
{
  "_key": "acme-corp",
  "name": "acme-corp",
  "display_name": "ACME Corporation",
  "description": "Main engineering organization",
  "metadata": {
    "cost_center": "CC-1234",
    "billing_contact": "finance@acme.com",
    "created_by": "alice"
  },
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### invitations
```json
{
  "_key": "tok_abc123",
  "token": "tok_abc123",
  "username": "bob",
  "email": "bob@acme.com",
  "org": "acme-corp",
  "role": "editor",
  "created_at": "2024-12-01T10:00:00Z",
  "expires_at": "2024-12-03T10:00:00Z",
  "accepted_at": null,
  "status": "pending"
}
```

#### cve
```json
{
  "_key": "CVE-2024-1234",
  "id": "CVE-2024-1234",
  "summary": "Buffer overflow in lodash",
  "details": "An attacker can...",
  "aliases": ["GHSA-xxxx-yyyy"],
  "published": "2024-11-15T00:00:00Z",
  "modified": "2024-11-16T00:00:00Z",
  
  "cvss_base_score": 9.8,
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
  "severity_rating": "CRITICAL",
  
  "affected": [
    {
      "package": {
        "ecosystem": "npm",
        "name": "lodash"
      },
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {"introduced": "0"},
            {"fixed": "4.17.21"}
          ]
        }
      ]
    }
  ],
  
  "references": [
    {
      "type": "ADVISORY",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
    }
  ]
}
```

#### purl
```json
{
  "_key": "pkg:npm/lodash",
  "purl": "pkg:npm/lodash",
  "type": "npm",
  "namespace": null,
  "name": "lodash",
  "version": null,
  "qualifiers": {},
  "subpath": null
}
```

#### sbom
```json
{
  "_key": "sbom_payment-service_2.1.0",
  "release_name": "payment-service",
  "release_version": "2.1.0",
  "org": "acme-corp",
  "format": "CycloneDX",
  "spec_version": "1.5",
  "content": {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
      {
        "type": "library",
        "name": "lodash",
        "version": "4.17.20",
        "purl": "pkg:npm/lodash@4.17.20"
      }
    ]
  },
  "created_at": "2024-12-01T00:00:00Z"
}
```

#### release
```json
{
  "_key": "payment-service_2.1.0",
  "name": "payment-service",
  "version": "2.1.0",
  "org": "acme-corp",
  "is_public": false,
  
  "gitcommit": "abc123def456",
  "giturl": "https://github.com/acme/payment-service",
  "gitbranch": "main",
  "gitrepo": "acme/payment-service",
  
  "builddate": "2024-12-01T00:00:00Z",
  "buildid": "build-456",
  "buildurl": "https://ci.acme.com/builds/456",
  
  "dockerrepo": "acme/payment-service",
  "dockersha": "sha256:abc...",
  "dockertag": "2.1.0",
  
  "content_sha": "sha256:def...",
  "openssf_scorecard_score": 8.5,
  
  "created_at": "2024-12-01T00:00:00Z"
}
```

#### endpoint
```json
{
  "_key": "prod-us-east-1",
  "name": "prod-us-east-1",
  "org": "acme-corp",
  "endpoint_type": "eks",
  "environment": "production",
  "is_mission_asset": true,
  
  "metadata": {
    "cluster_name": "prod-us-east-1",
    "region": "us-east-1",
    "namespace": "payment-services",
    "owner_team": "platform-eng"
  },
  
  "created_at": "2024-01-01T00:00:00Z"
}
```

#### sync
```json
{
  "_key": "sync_prod-us-east-1_1733011200",
  "endpoint_name": "prod-us-east-1",
  "org": "acme-corp",
  "timestamp": "2024-12-01T00:00:00Z",
  
  "releases": [
    {
      "name": "payment-service",
      "version": "2.1.0"
    }
  ],
  
  "metadata": {
    "sync_method": "k8s-operator",
    "sync_agent": "pdvd-agent-v1.2.3"
  }
}
```

#### cve_lifecycle
```json
{
  "_key": "lifecycle_CVE-2024-1234_prod-us-east-1_payment-service_2.1.0",
  "cve_id": "CVE-2024-1234",
  "endpoint_name": "prod-us-east-1",
  "release_name": "payment-service",
  "release_version": "2.1.0",
  "org": "acme-corp",
  
  "introduced_at": "2024-12-01T00:00:00Z",
  "root_introduced_at": "2024-12-01T00:00:00Z",
  "remediated_at": null,
  "is_remediated": false,
  
  "disclosed_after_deployment": false,
  "is_mission_asset": true,
  
  "sla_target_days": 7,
  "days_open": 15,
  "days_to_remediate": null,
  "is_beyond_sla": true
}
```

### Edge Collections

#### sbom2purl
```json
{
  "_from": "sbom/sbom_payment-service_2.1.0",
  "_to": "purl/pkg:npm/lodash",
  "version": "4.17.20",
  "scope": "required"
}
```

#### cve2purl
```json
{
  "_from": "cve/CVE-2024-1234",
  "_to": "purl/pkg:npm/lodash",
  "affects_versions": ["<4.17.21"],
  "fixed_in": "4.17.21"
}
```

#### release2cve (Materialized)
```json
{
  "_from": "release/payment-service_2.1.0",
  "_to": "cve/CVE-2024-1234",
  "package": "lodash",
  "version": "4.17.20",
  "severity_rating": "CRITICAL",
  "cvss_base_score": 9.8
}
```

---

## API Specification

### REST Endpoints

#### Authentication

```bash
# Sign-up
POST /api/v1/signup
Content-Type: application/json

{
  "username": "alice",
  "email": "alice@acme.com",
  "first_name": "Alice",
  "last_name": "Smith",
  "organization": "acme-corp",
  "password": "optional-if-invite"
}

Response: 201 Created
{
  "message": "User created. Check email for invitation.",
  "username": "alice",
  "invitation_sent": true
}

# Login
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "alice",
  "password": "secure-password"
}

Response: 200 OK
Set-Cookie: auth_token=<jwt>; HttpOnly; Secure
{
  "message": "Login successful",
  "user": {
    "username": "alice",
    "email": "alice@acme.com",
    "orgs": ["acme-corp"],
    "role": "owner"
  }
}

# Accept Invitation
POST /api/v1/invitation/:token/accept
Content-Type: application/json

{
  "password": "new-secure-password"
}

Response: 200 OK
Set-Cookie: auth_token=<jwt>
{
  "message": "Account activated",
  "user": { ... }
}

# Logout
POST /api/v1/auth/logout

Response: 200 OK
Set-Cookie: auth_token=; Max-Age=0
```

#### Releases

```bash
# Upload Release + SBOM
POST /api/v1/releases
Authorization: Cookie auth_token=<jwt>
Content-Type: application/json

{
  "name": "payment-service",
  "version": "2.1.0",
  "org": "acme-corp",
  "gitcommit": "abc123",
  "giturl": "https://github.com/acme/payment-service",
  "builddate": "2024-12-01T00:00:00Z",
  "sbom": {
    "content": { /* CycloneDX JSON */ }
  }
}

Response: 201 Created
{
  "release": {
    "_key": "payment-service_2.1.0",
    "name": "payment-service",
    "version": "2.1.0"
  },
  "vulnerabilities_found": 3,
  "critical": 1,
  "high": 2
}

# Get Release Details
GET /api/v1/releases/payment-service/2.1.0
Authorization: Cookie auth_token=<jwt>

Response: 200 OK
{
  "release": { ... },
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-1234",
      "severity_rating": "CRITICAL",
      "package": "lodash",
      "version": "4.17.20",
      "fixed_in": "4.17.21"
    }
  ],
  "synced_endpoints": [
    {
      "endpoint_name": "prod-us-east-1",
      "environment": "production",
      "last_sync": "2024-12-01T00:00:00Z"
    }
  ]
}
```

#### Sync (Deployments)

```bash
# Sync Endpoint
POST /api/v1/sync
Authorization: Cookie auth_token=<jwt>
Content-Type: application/json

{
  "endpoint_name": "prod-us-east-1",
  "releases": [
    {
      "release": {
        "name": "payment-service",
        "version": "2.1.0"
      }
    }
  ],
  "endpoint": {
    "name": "prod-us-east-1",
    "org": "acme-corp",
    "endpoint_type": "eks",
    "environment": "production"
  }
}

Response: 200 OK
{
  "sync_id": "sync_prod-us-east-1_1733011200",
  "endpoint_name": "prod-us-east-1",
  "releases_synced": 1,
  "lifecycle_updates": {
    "introduced": 0,
    "superseded": 2,
    "remediated": 1
  }
}
```

#### Dashboard

```bash
# Get MTTR Dashboard
GET /api/v1/dashboard/mttr?days=180&org=acme-corp
Authorization: Cookie auth_token=<jwt>

Response: 200 OK
{
  "executive_summary": {
    "total_new_cves": 145,
    "mttr_all": 23.4,
    "mttr_post_deployment": 18.7,
    "mean_open_age": 45.2,
    "open_cves_beyond_sla_pct": 13.2
  },
  "by_severity": [
    {
      "severity": "CRITICAL",
      "mttr": 8.2,
      "open_count": 3,
      "fixed_within_sla_pct": 92.5
    }
  ],
  "by_endpoint": [
    {
      "endpoint_name": "prod-us-east-1",
      "total_cves": 23,
      "critical": 1,
      "high": 5
    }
  ]
}
```

### GraphQL Schema

```graphql
type Query {
  # Releases
  release(name: String!, version: String!): Release
  releases(org: String, limit: Int, offset: Int): [Release!]!
  
  # CVEs
  cve(id: String!): CVE
  cves(severity: Severity, org: String): [CVE!]!
  
  # Endpoints
  endpoint(name: String!): Endpoint
  endpoints(org: String, environment: String): [Endpoint!]!
  
  # Dashboard
  dashboardMTTR(days: Int!, org: String): DashboardMTTR!
  orgAggregatedReleases(severity: Severity): [OrgAggregation!]!
  
  # Organizations
  organizations: [Organization!]!
  organization(name: String!): Organization
  
  # Users
  currentUser: User!
  users(org: String): [User!]!
}

type Mutation {
  # Auth
  signup(input: SignupInput!): SignupResult!
  login(username: String!, password: String!): LoginResult!
  acceptInvitation(token: String!, password: String!): LoginResult!
  
  # Releases
  uploadRelease(input: ReleaseInput!): Release!
  
  # Sync
  syncDeployment(input: SyncInput!): SyncResult!
  
  # Organizations
  createOrganization(input: OrgInput!): Organization!
  inviteUser(input: InviteInput!): InvitationResult!
}

type Release {
  name: String!
  version: String!
  org: String
  gitcommit: String
  builddate: String
  vulnerabilities: [Vulnerability!]!
  synced_endpoints: [SyncedEndpoint!]!
  openssf_scorecard_score: Float
}

type CVE {
  id: String!
  summary: String
  cvss_base_score: Float!
  severity_rating: String!
  published: String
  affected_releases: [Release!]!
}

type Endpoint {
  name: String!
  org: String
  endpoint_type: String!
  environment: String!
  is_mission_asset: Boolean!
  current_releases: [Release!]!
}

type DashboardMTTR {
  executive_summary: ExecutiveSummary!
  by_severity: [SeverityMetrics!]!
  by_endpoint: [EndpointMetrics!]!
}

enum Severity {
  CRITICAL
  HIGH
  MEDIUM
  LOW
}
```

---

## CVE Lifecycle Management

### Lifecycle States

```mermaid
stateDiagram-v2
    [*] --> Detected: CVE found in SBOM
    
    Detected --> Active: Deployed to endpoint
    Detected --> Inactive: Never deployed
    
    Active --> Superseded: New version deployed<br/>(CVE still present)
    Active --> Remediated: Fixed version deployed
    
    Superseded --> Active: Rollback to old version
    Superseded --> Remediated: Fixed version deployed
    
    Inactive --> Active: Old version deployed
    
    Remediated --> [*]
    Inactive --> [*]
    
    note right of Detected
        State: introduced_at set
        Tracks: root_introduced_at
    end note
    
    note right of Active
        State: Currently in production
        Tracks: disclosed_after_deployment
        Calculates: days_open, is_beyond_sla
    end note
    
    note right of Remediated
        State: remediated_at set
        Calculates: days_to_remediate
        MTTR = remediated_at - root_introduced_at
    end note
```

### MTTR Calculation

```
MTTR (Mean Time To Remediate) = Average(days_to_remediate) for all remediated CVEs

days_to_remediate = remediated_at - root_introduced_at

Where:
- root_introduced_at = earliest timestamp CVE was detected (across all versions)
- remediated_at = timestamp when fixed version was deployed
- Only includes CVEs that are is_remediated = true
```

### SLA Compliance

```mermaid
graph TB
    CVE[New CVE Detected] --> CheckSev{Check Severity}
    
    CheckSev -->|CRITICAL| CheckMission1{Mission Asset?}
    CheckMission1 -->|Yes| SLA7[SLA: 7 days]
    CheckMission1 -->|No| SLA15[SLA: 15 days]
    
    CheckSev -->|HIGH| CheckMission2{Mission Asset?}
    CheckMission2 -->|Yes| SLA15b[SLA: 15 days]
    CheckMission2 -->|No| SLA30[SLA: 30 days]
    
    CheckSev -->|MEDIUM| SLA90[SLA: 90 days]
    CheckSev -->|LOW| SLA180[SLA: 180 days]
    
    SLA7 --> Track[Track days_open]
    SLA15 --> Track
    SLA15b --> Track
    SLA30 --> Track
    SLA90 --> Track
    SLA180 --> Track
    
    Track --> Compare{days_open > SLA?}
    Compare -->|Yes| Beyond[is_beyond_sla = true<br/>Alert team]
    Compare -->|No| Within[is_beyond_sla = false<br/>Continue monitoring]
    
    style SLA7 fill:#ff6b6b
    style SLA15 fill:#ffa94d
    style SLA30 fill:#ffd43b
    style Beyond fill:#ffe0e0
    style Within fill:#e0ffe0
```

### Post-Deployment Detection

```mermaid
sequenceDiagram
    participant OSV as OSV.dev
    participant Ingest as CVE Ingestion Job
    participant DB as ArangoDB
    participant Alert as Alert System
    
    Note over OSV,Ingest: New CVE Published
    OSV->>Ingest: CVE-2024-XXXX disclosed
    Ingest->>DB: INSERT cve
    Ingest->>DB: CREATE cve2purl edges
    
    rect rgb(240, 240, 255)
        Note over Ingest,DB: Find Affected Releases
        Ingest->>DB: QUERY releases via purl hub
        DB->>Ingest: Returns matching releases
    end
    
    rect rgb(255, 240, 240)
        Note over Ingest,Alert: Check Deployment Status
        Ingest->>DB: QUERY sync records
        DB->>Ingest: Returns active deployments
        
        alt CVE disclosed after deployment
            Ingest->>DB: UPDATE cve_lifecycle<br/>disclosed_after_deployment=true
            Ingest->>Alert: Send critical alert
            Alert->>Alert: Create Jira ticket
            Alert->>Alert: Send Slack notification
        else CVE disclosed before deployment
            Ingest->>DB: INSERT cve_lifecycle<br/>disclosed_after_deployment=false
        end
    end
```

---

## Hub-and-Spoke Graph Design

### Traditional vs Hub-and-Spoke

```mermaid
graph TB
    subgraph Traditional["Traditional: O(N×M) = 10M edges"]
        T_CVE1[CVE-1] -.-> T_SBOM1[SBOM-1]
        T_CVE1 -.-> T_SBOM2[SBOM-2]
        T_CVE1 -.-> T_SBOM3[...]
        T_CVE2[CVE-2] -.-> T_SBOM1
        T_CVE2 -.-> T_SBOM2
        T_CVE2 -.-> T_SBOM3
        T_CVE3[...] -.-> T_SBOM1
        T_CVE3 -.-> T_SBOM2
        T_CVE3 -.-> T_SBOM3
        T_NOTE[1,000 CVEs × 10,000 SBOMs<br/>= 10,000,000 edges]
    end
    
    subgraph HubSpoke["Hub-and-Spoke: O(N+M) = 11K edges"]
        H_CVE1[CVE-1] --> H_HUB[PURL Hub<br/>pkg:npm/lodash]
        H_CVE2[CVE-2] --> H_HUB
        H_CVE3[...] --> H_HUB
        H_HUB --> H_SBOM1[SBOM-1]
        H_HUB --> H_SBOM2[SBOM-2]
        H_HUB --> H_SBOM3[...]
        H_NOTE[1,000 CVEs + 10,000 SBOMs<br/>= 11,000 edges<br/>99.89% reduction]
    end
    
    style Traditional fill:#ffe0e0
    style HubSpoke fill:#e0ffe0
    style H_HUB fill:#4dabf7
```

### Query Performance

```
Traditional Graph (N×M):
  Query: "Find all SBOMs affected by CVE-2024-1234"
  Complexity: O(M) = 10,000 edge traversals
  Time: ~30 seconds

Hub-and-Spoke (N+M):
  Query: "Find all SBOMs affected by CVE-2024-1234"
  Complexity: O(1 + K) where K = affected SBOMs
  Time: <3 seconds

Speedup: 10x faster for typical queries
```

### PURL Hub Design

```mermaid
graph LR
    subgraph CVEs["CVE Nodes"]
        C1[CVE-2024-1234<br/>affects: lodash<4.17.21]
        C2[CVE-2023-5678<br/>affects: lodash>=4.0.0 <4.17.19]
    end
    
    subgraph Hub["PURL Hub (Version-Free)"]
        P[pkg:npm/lodash<br/>Version: NULL]
    end
    
    subgraph SBOMs["SBOM Nodes"]
        S1[SBOM-1<br/>contains: lodash@4.17.20]
        S2[SBOM-2<br/>contains: lodash@4.17.18]
        S3[SBOM-3<br/>contains: lodash@4.18.0]
    end
    
    C1 -->|cve2purl<br/>affects_versions| P
    C2 -->|cve2purl<br/>affects_versions| P
    
    P -->|sbom2purl<br/>version: 4.17.20| S1
    P -->|sbom2purl<br/>version: 4.17.18| S2
    P -->|sbom2purl<br/>version: 4.18.0| S3
    
    style P fill:#4dabf7,stroke:#1971c2,stroke-width:3px
```

### Version Matching Algorithm

```go
// Pseudo-code for version matching
func findAffectedSBOMs(cve CVE, purl PURLHub) []SBOM {
    // 1. Find all SBOMs connected to this PURL hub
    sboms := graph.OutboundEdges(purl, "sbom2purl")
    
    affected := []SBOM{}
    for _, sbom := range sboms {
        version := sbom.Edge.Version
        
        // 2. Check if SBOM version matches CVE affected ranges
        if cve.AffectsVersion(version) {
            affected = append(affected, sbom)
        }
    }
    
    return affected
}

func (cve *CVE) AffectsVersion(version string) bool {
    for _, affectedPkg := range cve.Affected {
        for _, versionRange := range affectedPkg.Ranges {
            if versionRange.Contains(version) {
                return true
            }
        }
    }
    return false
}
```

---

## Deployment Architecture

### High-Availability Setup

```mermaid
graph TB
    subgraph LoadBalancer["Load Balancer (ALB/NLB)"]
        LB[HTTPS:443<br/>TLS Termination]
    end
    
    subgraph APICluster["API Cluster (3 replicas)"]
        API1[PDVD API Pod 1]
        API2[PDVD API Pod 2]
        API3[PDVD API Pod 3]
    end
    
    subgraph Workers["Background Workers"]
        CVEJob[CVE Ingestion<br/>CronJob: 0 */6 * * *]
        RBACSync[RBAC Sync<br/>Webhook Trigger]
        MTTRCalc[MTTR Calculator<br/>CronJob: 0 0 * * *]
    end
    
    subgraph Database["ArangoDB Cluster"]
        ArangoLead[Leader Node]
        ArangoFollow1[Follower 1]
        ArangoFollow2[Follower 2]
    end
    
    subgraph External["External Services"]
        OSV[OSV.dev]
        GitHub[GitHub]
        SMTP[SMTP]
    end
    
    LB --> API1
    LB --> API2
    LB --> API3
    
    API1 --> ArangoLead
    API2 --> ArangoLead
    API3 --> ArangoLead
    
    CVEJob --> OSV
    CVEJob --> ArangoLead
    
    RBACSync --> GitHub
    RBACSync --> ArangoLead
    
    MTTRCalc --> ArangoLead
    
    API1 -.-> SMTP
    API2 -.-> SMTP
    API3 -.-> SMTP
    
    ArangoLead -.->|Replication| ArangoFollow1
    ArangoLead -.->|Replication| ArangoFollow2
    
    style ArangoLead fill:#ff6b6b
    style ArangoFollow1 fill:#ffa94d
    style ArangoFollow2 fill:#ffa94d
```

### Kubernetes Manifests

```yaml
# api-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pdvd-api
  namespace: pdvd
spec:
  replicas: 3
  selector:
    matchLabels:
      app: pdvd-api
  template:
    metadata:
      labels:
        app: pdvd-api
    spec:
      containers:
      - name: api
        image: pdvd/backend:v2.0.0
        ports:
        - containerPort: 3000
        env:
        - name: ARANGO_HOST
          valueFrom:
            secretKeyRef:
              name: pdvd-secrets
              key: arango-host
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: pdvd-secrets
              key: jwt-secret
        resources:
          requests:
            cpu: 500m
            memory: 1Gi
          limits:
            cpu: 2000m
            memory: 4Gi
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5

---
# cve-ingestion-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: cve-ingestion
  namespace: pdvd
spec:
  schedule: "0 */6 * * *"  # Every 6 hours
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: ingest
            image: pdvd/backend:v2.0.0
            command: ["./pdvd-cli", "ingest-cves"]
            env:
            - name: ARANGO_HOST
              valueFrom:
                secretKeyRef:
                  name: pdvd-secrets
                  key: arango-host
          restartPolicy: OnFailure
```

---

## Security Considerations

### Threat Model

```mermaid
graph TB
    subgraph Threats["Threat Vectors"]
        T1[Unauthorized Access]
        T2[Data Exfiltration]
        T3[Privilege Escalation]
        T4[Injection Attacks]
        T5[DoS/Resource Exhaustion]
    end
    
    subgraph Mitigations["Security Controls"]
        M1[JWT + HttpOnly Cookies]
        M2[Org-Scoped Queries]
        M3[RBAC Enforcement]
        M4[Parameterized Queries]
        M5[Rate Limiting]
    end
    
    T1 --> M1
    T2 --> M2
    T3 --> M3
    T4 --> M4
    T5 --> M5
    
    M1 --> V1[✅ Verified]
    M2 --> V2[✅ Verified]
    M3 --> V3[✅ Verified]
    M4 --> V4[✅ Verified]
    M5 --> V5[⚠️ Roadmap]
    
    style V1 fill:#e0ffe0
    style V2 fill:#e0ffe0
    style V3 fill:#e0ffe0
    style V4 fill:#e0ffe0
    style V5 fill:#fff9e0
```

### Best Practices

1. **Password Security:**
   - bcrypt with cost factor 10
   - Minimum 8 characters
   - Password complexity enforced

2. **JWT Security:**
   - 24-hour expiration
   - HttpOnly cookies (XSS protection)
   - Secure flag in production
   - SameSite=Lax (CSRF protection)

3. **Database Security:**
   - Parameterized AQL queries (injection prevention)
   - Least-privilege database user
   - TLS encryption for connections
   - Org-scoped queries via FILTER clause

4. **API Security:**
   - Authentication required on all endpoints (except /health)
   - Rate limiting (roadmap)
   - Input validation
   - Error message sanitization

5. **Secrets Management:**
   - Kubernetes Secrets for credentials
   - GitHub tokens rotated monthly
   - SMTP passwords app-specific
   - JWT secret 256-bit random

---

## Appendix

### Glossary

| Term                  | Definition                                                                      |
|-----------------------|---------------------------------------------------------------------------------|
| **PURL**              | Package URL - standardized package identifier (pkg:type/namespace/name@version) |
| **Hub-and-Spoke**     | Graph pattern using central hub nodes to reduce edge count                      |
| **MTTR**              | Mean Time To Remediate - average days from CVE discovery to fix deployment      |
| **SLA**               | Service Level Agreement - target remediation time based on severity             |
| **SBOM**              | Software Bill of Materials - inventory of software components                   |
| **CVE**               | Common Vulnerabilities and Exposures - unique vulnerability identifier          |
| **CVSS**              | Common Vulnerability Scoring System - severity scoring standard (0-10)          |
| **GitOps**            | Infrastructure/config as code with Git as source of truth                       |
| **Materialized Edge** | Pre-computed edge stored for performance (e.g., release2cve)                    |

### References

- [NIST SP 800-218: Secure Software Development Framework](https://csrc.nist.gov/publications/detail/sp/800-218/final)
- [NIST SP 800-190: Application Container Security Guide](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [CycloneDX SBOM Specification](https://cyclonedx.org/specification/overview/)
- [Package URL (PURL) Specification](https://github.com/package-url/purl-spec)
- [OSV Schema](https://ossf.github.io/osv-schema/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)

---

**Document Control:**
- Version: 2.0
- Last Updated: January 2026
- Next Review: April 2026
- Owner: Platform Engineering Team
- Classification: Internal Use
