# Email Verification Platform — Complete System Design
> Stack: Go · MongoDB · Redis ×3 · HAProxy
> Version: Production-Grade · Includes: Catch-All Detection · Network Control Plane · Full DB Schemas

---

## Table of Contents

1. [System Overview & Core Principles](#1-system-overview--core-principles)
2. [Full Architecture Diagram](#2-full-architecture-diagram)
3. [Verification Pipeline — Stage by Stage](#3-verification-pipeline--stage-by-stage)
4. [Catch-All Detection — Code Design Level](#4-catch-all-detection--code-design-level)
5. [Network Control Plane — IP Assignment Logic](#5-network-control-plane--ip-assignment-logic)
6. [Redis Architecture — 3 Servers, 3 Purposes](#6-redis-architecture--3-servers-3-purposes)
7. [MongoDB — Full Schema Design](#7-mongodb--full-schema-design)
8. [Logging Strategy](#8-logging-strategy)
9. [Admin Panel — Full Feature Spec](#9-admin-panel--full-feature-spec)
10. [IP Pool Management (Manual Rating System)](#10-ip-pool-management-manual-rating-system)
11. [Error Handling & Crash Recovery](#11-error-handling--crash-recovery)
12. [Production Hardening Checklist](#12-production-hardening-checklist)
13. [Verification Result States](#13-verification-result-states)
14. [Component Responsibilities](#14-component-responsibilities)
15. [Data Flow — What Gets Written Where](#15-data-flow--what-gets-written-where)

---

## 1. System Overview & Core Principles

A user uploads a list of emails (CSV or TXT) to the platform. The system processes each email through a multi-stage verification pipeline, determines the deliverability status of each address, and returns results. The platform operator manages the IP pool manually via an admin panel.

### Non-Negotiable Design Rules

| Rule | Why |
|---|---|
| Nothing is ever lost on crash | Every stage persists state before acting on it |
| Each stage is isolated | SMTP failure does not stall precheck workers |
| Log every boundary crossing | Queued, dequeued, rejected, failed — all logged |
| Admin has full visibility | Every IP, every job, every queue, every log line |
| Same email never hits SMTP twice in 24h | Dedup cache protects IP reputation |
| Catch-all detection on every successful RCPT | Accuracy is the product |
| No automatic IP status changes | Humans decide what is burned, not the system |

### Throughput Reference

```
1,000,000 emails/day
= 41,666 emails/hour
= 694 emails/minute
= ~12 emails/second (sustained)

At 200ms avg SMTP round-trip:
  1 goroutine = 5 verifications/sec
  1000 goroutines = 5,000 verifications/sec per server
  → 1 SMTP server easily handles 1M/day
  → Add second server = redundancy + headroom for 5M+/day
```

---

## 2. Full Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                       Client Layer                                  │
│      Web Dashboard  ·  REST API  ·  CSV/TXT File Upload             │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ HTTPS / TLS 1.3
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                           HAProxy                                   │
│  SSL Termination  ·  Rate Limit (per API key + per IP)              │
│  Health Check all upstream  ·  Least-connections load balance       │
│  Circuit breaker — drops routing to unhealthy API nodes             │
└──────────────────────────────┬──────────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐   ┌──────────────────────────────┐
│                    API Cluster (Go)                          │──▶│  Redis-3 · Dedup Cache Check │
│  JWT / API Key Auth  ·  File Parse (CSV, TXT)                │   │  SHA256(email) → GET         │
│  Job Creation  ·  Schema Validation                          │   │  HIT  → skip queue entirely  │
│  Quota & Plan enforcement                                    │   │  MISS → proceed to queue     │
│  Job status endpoint  ·  Result download  ·  Webhooks        │   │  TTL: 24h–7d by provider     │
└──────────┬───────────────────────────────────────────────────┘   └──────────────────────────────┘
           │ write job                       │ cache miss only — push email
           ▼                                 ▼
┌──────────────────────────┐    ┌──────────────────────────────────────────┐
│       MongoDB            │    │  Redis-1 · Queue #1 — Precheck Queue     │
│  jobs                    │    │                                          │
│  email_results           │    │  precheck:realtime  (single lookups)     │
│  ip_pool                 │    │  precheck:bulk      (file upload jobs)   │
│  domain_knowledge        │    │                                          │
│  logs                    │    │  Workers: BRPOP realtime first,          │
│  users                   │    │  fall back to bulk when realtime empty   │
└──────────────────────────┘    └───────────────────┬──────────────────────┘
           ▲                                        │ consume
           │ (all results write back here)          ▼
           │                    ┌───────────────────────────────────────────┐
           │                    │         Precheck Workers (Go)             │
           │                    │                                           │
           │                    │  Step 1: Syntax Validation                │
           │                    │  Step 2: Disposable Email Detection       │
           │                    │  Step 3: Role Account Flagging            │
           │                    │  Step 4: DNS / MX Lookup                  │
           │                    │          ↳ Check Redis-3 MX cache first   │
           │                    │          ↳ 1h TTL on MX results           │
           │                    │  Step 5: Provider Classification          │
           │                    │          → GOOGLE / MICROSOFT / GENERIC   │
           │                    └────────────────────┬──────────────────────┘
           │                                         │
           │              rejected (no MX, syntax)   │  valid (has MX)
           │           ┌─────────────────────────────┤
           │           ▼                             ▼
           │  Write result to MongoDB      Provider Routing Layer
           │  (syntax_error, invalid)               │
           │                              ┌─────────▼──────────────────────┐
           │                              │  Redis-2 · Queue #2            │
           │                              │  Per-Provider SMTP Queues      │
           │                              │                                │
           │                              │  smtp:google                   │
           │                              │  smtp:microsoft                │
           │                              │  smtp:generic                  │
           │                              └──────┬─────────────┬───────────┘
           │                                     │             │
           │                     Google only     │             │  Microsoft + Generic
           │                                     ▼             ▼
           │                         ┌────────────────┐  ┌─────────────────┐
           │                         │ SMTP Server A  │  │ SMTP Server B   │
           │                         │ (Go)           │  │ (Go)            │
           │                         │                │  │                 │
           │                         │ • TCP connect  │  │ • Same engine   │
           │                         │ • EHLO parse   │  │ • Own IP pool   │
           │                         │ • STARTTLS     │  │   slice         │
           │                         │ • MAIL FROM    │  │                 │
           │                         │ • RCPT TO      │  │                 │
           │                         │ • Catch-All    │  │                 │
           │                         │   Test Engine  │  │                 │
           │                         │ • 4xx→greylist │  │                 │
           │                         └───────┬────────┘  └────────┬────────┘
           │                                 │                    │
           │                                 └─────────┬──────────┘
           │                                           │
           │                              ┌────────────▼──────────────────────┐
           │                              │   Network Control Plane (Go)      │
           │                              │                                   │
           │                              │  Internal gRPC API                │
           │                              │  • AllocateIP(provider) → IP      │
           │                              │  • ReleaseIP(ip, result_code)     │
           │                              │  • ReportBlock(ip, provider, msg) │
           │                              │  • GetPoolStatus() → admin        │
           │                              │                                   │
           │                              │  In-memory state (backed by Mongo)│
           │                              │  • IP list per provider, by rating│
           │                              │  • Per-IP connection counter       │
           │                              │  • Per-domain request counter      │
           │                              │  • Per-provider rate limiter       │
           │                              └────────────┬──────────────────────┘
           │                                           │
           │          4xx greylist                     │  allocate IP for outbound
           │       ┌───────────────┐                   ▼
           │       │ Redis-2       │      ┌────────────────────────────────────┐
           │       │ Greylist      │      │       IP Pool                      │
           │       │ Sorted Set    │      │                                    │
           │       │               │      │  active[]   — rated, in use        │
           │       │ score =       │      │  inactive[] — rated, standing by   │
           │       │ next_attempt  │      │  burned[]   — flagged, never used  │
           │       │ unix_ts       │      │                                    │
           │       │               │      │  All status changes: manual only   │
           │       │ 5m→15m→1h     │      │  via admin panel                   │
           │       │ max 3 retries │      └────────────────┬───────────────────┘
           │       └───────────────┘                       │ outbound TCP
           │                                               ▼
           │                              ┌────────────────────────────────────┐
           └──────────────────────────────│      External Mail Servers         │
                      results written     │  Gmail · Outlook · Yahoo · Corp MX │
                      to MongoDB          └────────────────────────────────────┘
                      + Redis-3 cache
                      + job progress updated
```

---

## 3. Verification Pipeline — Stage by Stage

### Stage 1 — Job Intake (API Layer)

**Entry point:** POST `/api/v1/jobs` with file or JSON array of emails.

**Sequence:**
```
1. Authenticate request (JWT or API key)
2. Parse uploaded file → extract all email strings
   → strip whitespace, lowercase, deduplicate within the upload
3. Check user quota — does this account have enough credits?
   → 402 if insufficient
4. Create Job document in MongoDB
   → status: "queued", total_emails: N, created_at: now
5. For each email:
   a. SHA256(lowercase(email)) → check Redis-3
   b. Cache HIT  → write result to MongoDB directly, increment job.cached_count
   c. Cache MISS → push to Redis-1 precheck queue with job_id
6. Respond: 202 Accepted
   { job_id, total: N, queued: X, cached: Y, check_url: "/jobs/:id" }
```

**Logs emitted:**
```
job.created       — job_id, user_id, total_emails, source_filename
job.cache_result  — job_id, cached_count (batch log, not per email)
job.enqueued      — job_id, queued_count, queue_depth_at_enqueue
auth.failure      — user_id, ip, reason
quota.exceeded    — user_id, requested, available
```

---

### Stage 2 — Precheck Workers

**Entry point:** Worker calls `BRPOP precheck:realtime precheck:bulk 5`

**Sequence:**
```
Item from queue: { email, job_id, enqueued_at }

1. Write email_results doc with status: "precheck_processing"
   (crash recovery anchor — see Section 11)

2. Syntax Validation
   → Regex + RFC 5322 structural check
   → local@domain format, valid TLD, no double dots, length limits
   FAIL → update result: syntax_error, log precheck.syntax_fail, DONE

3. Disposable Email Check
   → Compare domain against in-memory list loaded from MongoDB
     (list refreshed every 5 minutes from domain_knowledge collection)
   MATCH → update result: disposable, log precheck.disposable, DONE

4. DNS / MX Lookup
   → Check Redis-3: GET mx:{domain} (TTL 1h)
   → Cache miss: do actual DNS MX query, store result in Redis-3
   → No MX records found → update result: invalid (reason: no_mx), DONE
   → MX found → extract MX host list

5. Provider Classification
   → Inspect MX hosts:
     contains google.com, googlemail.com → GOOGLE
     contains outlook.com, hotmail.com, protection.outlook.com → MICROSOFT
     anything else → GENERIC

6. Write provider + mx_hosts back to email_results doc
   Update status: "precheck_done"

7. Push to Redis-2 provider queue:
   smtp:google / smtp:microsoft / smtp:generic
   Payload: { email, domain, mx_hosts[], provider, job_id, precheck_done_at }
```

**Logs emitted:**
```
precheck.syntax_fail   — email_hash, job_id, reason
precheck.disposable    — domain, job_id
precheck.role_flagged  — email_hash, job_id (flag only, still continues)
precheck.no_mx         — domain, job_id
precheck.mx_found      — domain, provider, mx_host, job_id
precheck.smtp_queued   — provider, queue, job_id
```

---

### Stage 3 — SMTP Verification

**Entry point:** Worker calls `BRPOP smtp:google 5` or `BRPOP smtp:microsoft smtp:generic 5`

**Sequence:**
```
Item from queue: { email, domain, mx_hosts[], provider, job_id }

1. Write email_results status: "smtp_processing" (crash anchor)

2. Call Network Control Plane: AllocateIP(provider=GOOGLE)
   → Receive: { ip_address, slot_id }
   → If no IP available: push email back to queue, log warn, sleep 1s

3. Open TCP connection to first MX host on port 25
   Timeout: 5 seconds
   → Connection refused / timeout: try next MX host in list
   → All MX hosts failed: result = unknown, release IP slot

4. Read 220 banner from server
   → Parse server identity from banner text
   → Log smtp.connected

5. Send: EHLO yourdomain.com
   → Parse EHLO capabilities from response
   → Note: STARTTLS available? SIZE limit? Known quirks?

6. If STARTTLS available: upgrade connection to TLS
   → Required for Microsoft servers
   → Optional but preferred for others

7. Send: MAIL FROM:<bounces@yourdomain.com>
   → 250 → continue
   → Any error → result = unknown, release IP, done

8. Send: RCPT TO:<target@theirdomain.com>
   → 250 → mailbox accepted → proceed to catch-all test (Section 4)
   → 4xx → greylisted → push to greylist sorted set, release IP, done
   → 5xx → mailbox rejected → result = invalid, record smtp_code

9. Run Catch-All Detection (see full design in Section 4)
   → result = valid OR accept_all

10. Send: QUIT
    Release IP slot: ReleaseIP(ip, result_code)

11. Write final result to MongoDB
    Write to Redis-3 cache: SET result:{sha256(email)} {result} EX {ttl}
    Update job progress counter in MongoDB
```

**Logs emitted:**
```
smtp.connect_attempt  — ip, mx_host, job_id, email_hash
smtp.connected        — ip, mx_host, banner
smtp.tls_upgraded     — ip, mx_host
smtp.rcpt_response    — ip, email_hash, code, message, duration_ms
smtp.greylist         — ip, email_hash, mx_host, retry_count, next_attempt_ts
smtp.result           — ip, email_hash, result, code, duration_ms, job_id
smtp.ip_block         — ip, mx_host, provider, code, message [CRITICAL]
smtp.mx_exhausted     — email_hash, domain, mx_hosts_tried[], job_id
```

---

### Stage 4 — Greylist Retry

**Entry point:** Scheduler goroutine, runs every 30 seconds.

**Sequence:**
```
ZRANGEBYSCORE greylist:retry 0 <now_unix> LIMIT 0 500
→ Fetch up to 500 emails due for retry

For each email:
  1. Deserialize payload: { email, job_id, mx_host, retry_count, provider }
  2. If retry_count >= 3:
     → Write result: unknown (max_retries_exceeded)
     → Log retry.max_reached
     → ZREM greylist:retry <email_hash>
     → Done
  3. Increment retry_count
  4. Re-push to smtp:{provider} queue
  5. ZREM old entry, ZADD updated entry with next backoff score:
     retry_count=1 → now + 300   (5 min)
     retry_count=2 → now + 900   (15 min)
     retry_count=3 → now + 3600  (1 hour)
  6. Log retry.requeued
```

---

### Stage 5 — Job Completion Monitor

**Entry point:** Background goroutine, polls MongoDB every 10 seconds.

**Query:**
```
db.jobs.find({
  status: "processing",
  $expr: {
    $eq: ["$total_emails", { $add: ["$verified_count", "$rejected_count"] }]
  }
})
```

**Sequence:**
```
For each completed job found:
  1. Calculate result summary percentages
  2. Update job: status=completed, completed_at=now, summary={...}
  3. Generate result file (CSV with all email_results for this job)
  4. Store file path in job document
  5. Fire webhook if configured (with retry queue for failures)
  6. Log job.completed
```

---

## 4. Catch-All Detection — Code Design Level

### What Is a Catch-All Domain

A catch-all (or "accept-all") domain is configured so its mail server accepts `RCPT TO` for **any** address regardless of whether that mailbox actually exists. This is common in Google Workspace and Office 365 tenants. Without detection, your system marks billions of invalid addresses as `valid`.

### Design Overview

```
After RCPT TO returns 250 (accepted):

  ┌──────────────────────────────────────────────────────┐
  │              Catch-All Test Engine                   │
  │                                                      │
  │  1. Check domain_knowledge cache                     │
  │     already known catch-all? → skip test, return    │
  │                                                      │
  │  2. Generate probe address                           │
  │     → random_string@same_domain                      │
  │                                                      │
  │  3. Send second RCPT TO with probe address           │
  │     → 250: domain IS catch-all                       │
  │     → 4xx: inconclusive (count as not catch-all)    │
  │     → 5xx: domain is NOT catch-all                   │
  │                                                      │
  │  4. Cache result in domain_knowledge                 │
  │     TTL: 24h for unknown, 7 days for confirmed       │
  │                                                      │
  │  5. Return final result                              │
  └──────────────────────────────────────────────────────┘
```

### Probe Address Generation

The probe address must be:
- Long enough to be statistically impossible as a real mailbox
- Not guessable or pre-blocked by mail servers
- Different on every test to avoid caching by the remote server

**Format:**
```
vfy_{8_random_hex_chars}_{unix_ts_last_4_digits}@domain.com

Examples:
  vfy_a3f9c821_4291@company.com
  vfy_0d7e5b14_8830@company.com
```

Never use the same probe address twice for the same domain in the same session.

### State Machine

```
RCPT TO target@domain.com
       │
       ▼
   Response?
       │
   ┌───┴───────────────────────────────────┐
   │                                       │
  4xx                                     5xx
(greylist)                            result = invalid
   │                                    DONE
   ▼
push to retry queue
DONE

   │
  250 (accepted)
   │
   ▼
Check domain_knowledge cache for domain
   │
   ├── known: catch_all = TRUE
   │     → result = accept_all (skip SMTP test, save connection)
   │     DONE
   │
   └── not in cache OR catch_all = FALSE
         │
         ▼
   Generate probe: vfy_{rand}@domain
         │
         ▼
   Send RCPT TO <probe_address>
   (on SAME open SMTP connection — no new TCP)
         │
   ┌─────┴─────────────────────────┐
   │                               │
  250                           5xx (rejected)
(catch-all confirmed)         (NOT catch-all)
   │                               │
   ▼                               ▼
Update domain_knowledge:       Update domain_knowledge:
  catch_all = TRUE               catch_all = FALSE
  confirmed_at = now             confirmed_at = now
  TTL = 7 days                   TTL = 24h
   │                               │
   ▼                               ▼
result = accept_all           result = valid
   │                          (unless role_account flag)
   ▼                               ▼
Send QUIT                     Send QUIT
Release IP                    Release IP
Write to MongoDB              Write to MongoDB
Write to Redis-3 cache        Write to Redis-3 cache
```

### Domain-Level Caching (The Performance Multiplier)

The catch-all test is done **per domain**, not per email. Once you know `bigcorp.com` is catch-all, every future email at `bigcorp.com` skips the SMTP connection entirely at the precheck stage.

**Cache lookup flow in precheck workers:**
```
MX found for domain → check domain_knowledge:

GET domain:{domain} from Redis-3

Hit + catch_all = TRUE:
  → result = accept_all immediately
  → skip SMTP queue entirely
  → massive savings at scale

Hit + catch_all = FALSE:
  → proceed to SMTP queue normally

Miss:
  → proceed to SMTP queue
  → catch-all test will run and populate the cache
```

**MongoDB domain_knowledge document update:**
```json
{
  "domain": "bigcorp.com",
  "is_catch_all": true,
  "catch_all_confirmed_at": "2024-01-15T10:23:00Z",
  "catch_all_probe_used": "vfy_a3f9c821_4291@bigcorp.com",
  "catch_all_source_ip": "10.0.1.4",
  "provider_class": "GOOGLE",
  "consecutive_catch_all_hits": 3,
  "last_verified_at": "2024-01-15T10:23:00Z"
}
```

### Edge Cases

| Scenario | Handling |
|---|---|
| Probe RCPT gets greylisted (4xx) | Treat as inconclusive — do NOT mark catch-all. Log warn. |
| Connection drops during probe | Mark catch-all as unknown, retry on next email for same domain |
| Subdomain vs root domain | Cache per full domain. `mail.corp.com` ≠ `corp.com` |
| Domain changes catch-all config | 24h TTL for non-catch-all means you re-test daily |
| SMTP server counts multiple RCPTs as suspicious | Use same session — no extra TCP connection. QUIT after both tests |

### Impact on Throughput

```
Without domain-level catch-all cache:
  Every email = 1 SMTP connection + catch-all probe RCPT

With domain-level catch-all cache:
  First email at domain = 1 SMTP connection + probe
  All subsequent emails at known catch-all domain = 0 SMTP connections

Real-world impact:
  A 50k email list from one company might have 40k emails at the same domain.
  With cache: 1 SMTP connection determines all 40k results.
  Without cache: 40k SMTP connections.
```

---

## 5. Network Control Plane — IP Assignment Logic

### Purpose

The Network Control Plane is a **standalone Go service** with an internal gRPC API. It is the only component that knows about the IP pool and decides which IP gets used for which connection. SMTP workers never pick IPs themselves — they always ask the control plane.

### Why a Separate Service

- Centralizes all IP state in one place
- Workers are stateless — can be restarted freely
- IP-level decisions (rating, limits, block detection) in one brain
- Admin panel queries one service for live IP stats
- Prevents two workers from simultaneously over-using the same IP

### gRPC API (Internal Only)

```
service NetworkControlPlane {

  // Request an IP for outbound connection to a specific provider
  rpc AllocateIP(AllocateIPRequest) returns (AllocateIPResponse);

  // Return the IP after use, report the outcome
  rpc ReleaseIP(ReleaseIPRequest) returns (Empty);

  // Report a block signal received from a remote server
  rpc ReportBlock(ReportBlockRequest) returns (Empty);

  // Get current status of all IPs (for admin panel)
  rpc GetPoolStatus(Empty) returns (PoolStatusResponse);

  // Reload IP pool from MongoDB (called after admin makes changes)
  rpc ReloadPool(Empty) returns (Empty);
}

message AllocateIPRequest {
  string provider = 1;   // "GOOGLE" | "MICROSOFT" | "GENERIC"
}

message AllocateIPResponse {
  string ip_address = 1;
  string slot_id    = 2;  // unique ID for this allocation slot
  bool   available  = 3;  // false = no IP available right now
}

message ReleaseIPRequest {
  string slot_id      = 1;
  int32  smtp_code    = 2;  // final response code from SMTP session
  bool   was_blocked  = 3;
}

message ReportBlockRequest {
  string ip_address       = 1;
  string provider         = 2;
  int32  response_code    = 3;
  string response_message = 4;
  string mx_host          = 5;
}
```

### In-Memory Data Structures

The control plane loads the IP pool from MongoDB on startup and keeps it in memory. It syncs changes back to MongoDB asynchronously.

```
// In-memory pool per provider
type ProviderPool struct {
    active     []IPSlot     // sorted by rating DESC, then connections ASC
    inactive   []IPSlot     // loaded but not serving traffic
    burned     []IPSlot     // for admin visibility only
    mu         sync.RWMutex
}

type IPSlot struct {
    IPAddress          string
    Rating             int        // 1–10, set by admin
    Status             string     // active | inactive | burned
    ProviderAssignment string     // GOOGLE | MICROSOFT | GENERIC | ALL
    MaxConnections     int        // derived from rating
    ActiveConnections  int32      // atomic counter
    TotalVerifications int64      // lifetime counter
    BlockCount         int        // number of blocks received
    LastUsedAt         time.Time
    LastBlockAt        time.Time
}

// Global pools indexed by provider
pools = map[string]*ProviderPool{
    "GOOGLE":    &ProviderPool{},
    "MICROSOFT": &ProviderPool{},
    "GENERIC":   &ProviderPool{},
}
```

### IP Selection Algorithm (AllocateIP)

```
AllocateIP(provider = "GOOGLE"):

Step 1: Acquire read lock on GOOGLE pool

Step 2: Iterate pool.active (already sorted by rating DESC):

    For each IPSlot:
      a. Skip if Status != "active"
      b. Skip if ActiveConnections >= MaxConnections
      c. Skip if domain throttle exceeded
         (check Redis-3: GET throttle:domain:{domain})
      d. FOUND → atomically increment ActiveConnections
         → generate slot_id = UUID
         → store slot_id → ip mapping in local map
         → return {ip_address, slot_id, available: true}

Step 3: If no IP found after full iteration:
    → return {available: false}
    → worker will re-queue email and back off 1 second

Step 4: Release read lock
```

### Max Connections Per Rating

```
Rating  Max Concurrent Connections  Notes
──────  ─────────────────────────── ───────────────────────────
10      60                          Best IPs, maximum throughput
9       50                          High trust
8       40                          Good standing
7       30                          Normal
6       20                          Slightly limited
5       15                          Cautious
4       10                          Low trust, used as fallback
3        7
2        4
1        2                          Nearly retired, minimal use
```

### ReleaseIP Logic

```
ReleaseIP(slot_id, smtp_code, was_blocked):

1. Look up IPSlot from slot_id map
2. Atomically decrement ActiveConnections
3. Update LastUsedAt = now
4. Increment TotalVerifications
5. If was_blocked = true:
   → Increment BlockCount
   → Set LastBlockAt = now
   → Write to MongoDB: ip_pool.block_history[] (async)
   → Log critical: smtp.ip_block
   → Do NOT change IP status automatically
   → Send alert to admin notification queue
6. Async: batch-write stats to MongoDB every 60s
```

### Block Detection Patterns

The SMTP worker identifies a block by inspecting the response code AND message. The control plane registers it via `ReportBlock`. Patterns that trigger a block report:

```
Response patterns that indicate IP block:

Code 421 + message contains any of:
  "too many connections"
  "connection rate limit exceeded"
  "temporarily deferred"

Code 550 + message contains any of:
  "banned"
  "blocked"
  "blacklisted"
  "not allowed"
  "policy violation"

Code 554 + message contains any of:
  "rejected"
  "prohibited"

Connection refused (TCP level) after previously succeeding:
  → Potential IP block, log warn (not critical, might be MX issue)
```

### Domain Throttle Engine

Prevents hammering a single domain regardless of which IP is used.

```
Before allocating IP, worker checks:

INCR throttle:{domain}:{window_minute}
EXPIRE throttle:{domain}:{window_minute} 60

If value > domain_limit:
  → Do not allocate, re-queue with 10s delay
  → Log warn: domain.throttled

Default domain limits:
  gmail.com         → 20 requests/minute (across all IPs)
  outlook.com       → 15 requests/minute
  yahoo.com         → 10 requests/minute
  corporate/generic → 30 requests/minute
```

These limits are configurable in the admin panel and stored in MongoDB `system_config` collection.

### Pool Reload Flow (After Admin Changes)

```
Admin updates IP in panel
        │
        ▼
PUT /admin/ip/:id  (API)
        │
        ▼
MongoDB updated
        │
        ▼
API calls: NetworkControlPlane.ReloadPool()
        │
        ▼
Control plane re-reads ip_pool from MongoDB
        │
        ▼
Rebuilds in-memory pool structures
        │
        ▼
Returns new pool to workers on next AllocateIP call

Note: Reload is non-blocking. In-flight connections
      complete normally. Only new allocations use new pool.
```

### Control Plane Startup

```
On startup:
1. Load all ip_pool documents from MongoDB (status: active or inactive)
2. Build in-memory ProviderPool structs
3. Sort active IPs by rating DESC for each provider
4. Start background goroutine: sync stats to MongoDB every 60s
5. Start gRPC server on :9090 (internal network only, not exposed)
6. Log control_plane.started with pool summary
```

---

## 6. Redis Architecture — 3 Servers, 3 Purposes

### Redis-1 — Precheck Queue (Job Intake)

**Dedicated to:** Holding emails waiting for precheck workers. Nothing else.

```
Keys in Redis-1:

precheck:realtime         LIST  — single email API lookups (high priority)
precheck:bulk             LIST  — file upload jobs (lower priority)
job:lock:{job_id}         STRING EX 3600  — prevents duplicate job starts
stats:queue:total         COUNTER — lifetime emails queued (monitoring)

Workers consume with:
BRPOP precheck:realtime precheck:bulk 5
→ Pops from realtime first. Falls back to bulk only if realtime empty.
→ This is the priority lane, no extra logic needed.

Monitoring:
LLEN precheck:realtime   → should be near 0 (fast workers)
LLEN precheck:bulk       → can be large, represents work backlog
```

**Persistence:** AOF enabled. If Redis-1 restarts, unprocessed jobs replay from log.

---

### Redis-2 — SMTP Queues + Greylist Retry

**Dedicated to:** All SMTP-stage work.

```
Keys in Redis-2:

smtp:google               LIST  — emails ready for Google SMTP verification
smtp:microsoft            LIST  — emails ready for Microsoft verification
smtp:generic              LIST  — emails ready for all other SMTP
greylist:retry            ZSET  — emails in greylist wait (score = next_attempt_ts)
throttle:domain:{domain}  STRING EX 60 — per-domain request rate counter

smtp list payload:
{
  "email": "user@example.com",
  "domain": "example.com",
  "mx_hosts": ["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
  "provider": "GOOGLE",
  "job_id": "abc123",
  "precheck_done_at": 1705312345
}

greylist sorted set member:
{
  "email": "user@corp.com",
  "job_id": "abc123",
  "mx_host": "mail.corp.com",
  "retry_count": 1,
  "provider": "GENERIC",
  "original_ts": 1705312345
}

Scheduler query (every 30s):
ZRANGEBYSCORE greylist:retry 0 <now_unix> LIMIT 0 500

Monitoring:
LLEN smtp:google          → Google SMTP queue depth
LLEN smtp:microsoft       → Microsoft SMTP queue depth
LLEN smtp:generic         → Generic SMTP queue depth
ZCARD greylist:retry      → emails in greylist wait
```

**Persistence:** AOF enabled. Critical that SMTP queue survives restarts.

---

### Redis-3 — Cache, MX Records, Dedup, Counters

**Dedicated to:** Fast lookups. Short-lived state. No queue functions.

```
Keys in Redis-3:

result:{sha256(email)}    STRING — cached verification result
  TTL by result type:
    valid        → EX 86400    (24h)
    invalid      → EX 172800   (48h)
    accept_all   → EX 604800   (7d)
    disposable   → EX 604800   (7d)
    unknown      → EX 21600    (6h)
    syntax_error → EX 604800   (7d)

mx:{domain}               STRING EX 3600 — cached MX lookup result
  Value: { mx_hosts: [], provider: "GOOGLE", cached_at: ts }

domain:catchall:{domain}  STRING — cached catch-all verdict
  Value: { is_catch_all: true, confirmed_at: ts }
  TTL: 604800 (7d) if confirmed, 86400 (24h) if not

ip:connections:{ip}       COUNTER EX 60 — rolling per-minute counter per IP
  Used by domain throttle engine

Monitoring:
INFO stats
  keyspace_hits   / keyspace_misses → cache hit rate
  (target: >60% hit rate at steady state with active customer base)
```

**Persistence:** RDB snapshots every 5 minutes. If Redis-3 goes down, system continues but loses cache — all emails go through full pipeline until cache rebuilds. This is acceptable degraded operation.

---

## 7. MongoDB — Full Schema Design

### Collection: `jobs`

```json
{
  "_id": "ObjectId",
  "job_id": "string (UUID v4)",
  "user_id": "string",
  "status": "queued | processing | completed | failed | cancelled",

  "source": {
    "type": "file | api",
    "filename": "string | null",
    "file_size_bytes": 0,
    "raw_line_count": 0
  },

  "counts": {
    "total_emails": 50000,
    "unique_emails": 49800,
    "queued_for_precheck": 47100,
    "served_from_cache": 2700,
    "precheck_passed": 43500,
    "precheck_rejected": 3600,
    "smtp_verified": 43500,
    "completed_total": 50000
  },

  "summary": {
    "valid": 28900,
    "invalid": 8200,
    "accept_all": 4100,
    "disposable": 780,
    "role_account": 420,
    "unknown": 1100,
    "syntax_error": 3500,
    "percentage_deliverable": 57.8
  },

  "timing": {
    "created_at": "ISODate",
    "started_at": "ISODate",
    "completed_at": "ISODate",
    "duration_seconds": 1840,
    "avg_ms_per_email": 36.8
  },

  "delivery": {
    "result_file_path": "string | null",
    "result_file_size_bytes": 0,
    "webhook_url": "string | null",
    "webhook_status": "pending | sent | failed | not_configured",
    "webhook_attempts": 0,
    "webhook_last_attempt_at": "ISODate | null"
  },

  "credits_used": 47100,
  "updated_at": "ISODate"
}
```

**Indexes:**
```
{ job_id: 1 }                          unique
{ user_id: 1, "timing.created_at": -1 } for user's job list
{ status: 1, "timing.created_at": -1 } for admin job monitor
{ "timing.created_at": -1 }            for time-based queries
```

---

### Collection: `email_results`

```json
{
  "_id": "ObjectId",
  "job_id": "string",
  "email_hash": "string (SHA256 of lowercase email — never store plain)",
  "email_encrypted": "string (AES-256-GCM encrypted, if compliance needed)",
  "domain": "string",
  "local_part_length": 8,

  "precheck": {
    "syntax_valid": true,
    "is_disposable": false,
    "is_role_account": false,
    "mx_hosts": ["aspmx.l.google.com"],
    "provider_class": "GOOGLE | MICROSOFT | GENERIC",
    "done_at": "ISODate"
  },

  "smtp": {
    "mx_host_used": "aspmx.l.google.com",
    "ip_used": "string",
    "response_code": 250,
    "response_message": "string",
    "tls_used": true,
    "catch_all_tested": true,
    "catch_all_result": false,
    "duration_ms": 312,
    "retry_count": 0,
    "done_at": "ISODate"
  },

  "result": "valid | invalid | accept_all | disposable | role_account | unknown | syntax_error",
  "result_reason": "string (e.g. smtp_5xx, no_mx, greylist_max_retries)",
  "from_cache": false,
  "status": "precheck_processing | precheck_done | smtp_processing | completed",

  "verified_at": "ISODate",
  "created_at": "ISODate"
}
```

**Indexes:**
```
{ job_id: 1, verified_at: -1 }         for fetching job results
{ email_hash: 1 }                       for dedup lookups
{ domain: 1, verified_at: -1 }         for domain analytics
{ "smtp.ip_used": 1, verified_at: -1 } for IP performance queries
{ result: 1, verified_at: -1 }         for accuracy analytics
{ status: 1, created_at: 1 }           for crash recovery (find in-progress)

TTL index (optional):
{ verified_at: 1 } expireAfterSeconds: 7776000  (90 days auto-cleanup)
```

---

### Collection: `ip_pool`

```json
{
  "_id": "ObjectId",
  "ip_address": "string",
  "server_id": "smtp-server-a | smtp-server-b",
  "status": "active | inactive | burned",
  "rating": 8,

  "assignment": {
    "provider": "GOOGLE | MICROSOFT | GENERIC | ALL",
    "restricted_to_provider": false
  },

  "limits": {
    "max_connections": 40,
    "max_per_minute": 300
  },

  "stats": {
    "total_verifications": 284000,
    "successful_connections": 279000,
    "failed_connections": 200,
    "timeout_count": 120,
    "block_count": 1,
    "greylist_count": 3200,
    "success_rate_percent": 99.9
  },

  "block_history": [
    {
      "blocked_at": "ISODate",
      "provider": "GOOGLE",
      "mx_host": "aspmx.l.google.com",
      "response_code": 421,
      "response_message": "string",
      "detected_by_worker": "smtp-server-a",
      "resolved_at": "ISODate | null",
      "admin_notes": "string"
    }
  ],

  "timestamps": {
    "added_at": "ISODate",
    "last_used_at": "ISODate",
    "last_block_at": "ISODate | null",
    "status_changed_at": "ISODate",
    "updated_at": "ISODate"
  },

  "admin": {
    "notes": "string",
    "updated_by": "admin_user_id"
  }
}
```

**Indexes:**
```
{ ip_address: 1 }                           unique
{ status: 1, "assignment.provider": 1 }     for control plane pool queries
{ server_id: 1, status: 1 }                for server-specific views
{ rating: -1, status: 1 }                  for sorted pool loading
{ "timestamps.last_block_at": -1 }         for recent block queries
```

---

### Collection: `domain_knowledge`

```json
{
  "_id": "ObjectId",
  "domain": "string",
  "provider_class": "GOOGLE | MICROSOFT | GENERIC",

  "mx": {
    "hosts": ["aspmx.l.google.com", "alt1.aspmx.l.google.com"],
    "last_lookup_at": "ISODate",
    "lookup_count": 4821
  },

  "catch_all": {
    "status": "confirmed_yes | confirmed_no | unknown",
    "last_tested_at": "ISODate",
    "confirmed_at": "ISODate | null",
    "test_count": 3,
    "consecutive_hits": 3,
    "probe_used": "string (the fake address used in last test)"
  },

  "greylist": {
    "behavior": "none | light | aggressive",
    "avg_greylist_rate_percent": 2.1,
    "last_greylisted_at": "ISODate | null"
  },

  "is_disposable": false,
  "is_known_role_only": false,

  "stats": {
    "total_verifications": 48291,
    "valid_count": 31000,
    "invalid_count": 9100,
    "accept_all_count": 4800,
    "unknown_count": 3391
  },

  "first_seen_at": "ISODate",
  "last_verified_at": "ISODate",
  "updated_at": "ISODate"
}
```

**Indexes:**
```
{ domain: 1 }                           unique
{ provider_class: 1 }                   for provider-based queries
{ "catch_all.status": 1 }              for catch-all analytics
{ last_verified_at: -1 }               for staleness checks
```

---

### Collection: `logs`

```json
{
  "_id": "ObjectId",
  "level": "info | warn | error | critical",
  "event": "string (e.g. smtp.ip_block, job.completed)",
  "service": "api | precheck | smtp_a | smtp_b | control_plane | scheduler | job_monitor",

  "context": {
    "job_id": "string | null",
    "email_hash": "string | null",
    "ip_address": "string | null",
    "domain": "string | null",
    "mx_host": "string | null",
    "provider": "string | null",
    "user_id": "string | null"
  },

  "data": {
    "smtp_code": 421,
    "smtp_message": "string",
    "duration_ms": 450,
    "retry_count": 1,
    "queue": "string",
    "queue_depth": 0,
    "error_message": "string | null",
    "stack_trace": "string | null"
  },

  "message": "string",
  "timestamp": "ISODate"
}
```

**Indexes:**
```
{ level: 1, timestamp: -1 }                    for admin error log view
{ event: 1, timestamp: -1 }                    for event-specific queries
{ "context.ip_address": 1, timestamp: -1 }     for per-IP log drill-down
{ "context.job_id": 1, timestamp: -1 }         for job trace view
{ service: 1, level: 1, timestamp: -1 }        for service-level monitoring

TTL indexes:
{ timestamp: 1 } expireAfterSeconds: 2592000   (30d for info/warn)
{ timestamp: 1 } expireAfterSeconds: 7776000   (90d for error/critical)
→ Implement with two separate capped collections or filter at query level
```

---

### Collection: `users`

```json
{
  "_id": "ObjectId",
  "user_id": "string (UUID)",
  "email": "string",
  "api_key_hash": "string (bcrypt of API key — never store plain)",

  "plan": {
    "type": "free | starter | pro | enterprise",
    "credits_total": 100000,
    "credits_used": 47291,
    "credits_reset_at": "ISODate",
    "rate_limit_per_minute": 1000
  },

  "webhook": {
    "default_url": "string | null",
    "secret": "string (HMAC secret for webhook signature)"
  },

  "created_at": "ISODate",
  "last_active_at": "ISODate",
  "status": "active | suspended | deleted"
}
```

**Indexes:**
```
{ user_id: 1 }       unique
{ email: 1 }         unique
{ api_key_hash: 1 }  for auth lookups
```

---

### Collection: `system_config`

```json
{
  "_id": "ObjectId",
  "key": "string",
  "value": "any",
  "description": "string",
  "updated_by": "admin_user_id",
  "updated_at": "ISODate"
}
```

**Example documents:**
```json
{ "key": "domain_throttle.gmail.com",      "value": 20 }
{ "key": "domain_throttle.outlook.com",    "value": 15 }
{ "key": "domain_throttle.yahoo.com",      "value": 10 }
{ "key": "domain_throttle.default",        "value": 30 }
{ "key": "greylist.max_retries",           "value": 3 }
{ "key": "greylist.backoff_seconds",       "value": [300, 900, 3600] }
{ "key": "queue.backpressure_threshold",   "value": 500000 }
{ "key": "cache.ttl.valid_seconds",        "value": 86400 }
{ "key": "cache.ttl.invalid_seconds",      "value": 172800 }
{ "key": "catch_all.probe_prefix",         "value": "vfy_" }
```

**Index:**
```
{ key: 1 }   unique
```

---

## 8. Logging Strategy

### Structured JSON Logs — Every Service

Every service logs to stdout in structured JSON. Use Go's `log/slog` (stdlib, zero dep).

**Standard fields on every log line:**
```json
{
  "ts":      "2024-01-15T14:23:01.234Z",
  "level":   "INFO",
  "svc":     "smtp_a",
  "event":   "smtp.rcpt_response",
  "job_id":  "abc123",
  "eh":      "a3f9c8...",
  "ip":      "10.0.1.4",
  "mx":      "aspmx.l.google.com",
  "code":    250,
  "ms":      312
}
```

### Log Levels

| Level | When | Admin Action |
|---|---|---|
| `INFO` | Normal operation, every result written | None |
| `WARN` | Recoverable — greylist, cache miss storm, queue depth rising | Monitor |
| `ERROR` | Operation failed, retrying — SMTP timeout, DB write failure | Investigate |
| `CRITICAL` | Service impaired — all IPs blocked, Redis down, MongoDB unreachable | Immediate action |

### Log Routing Architecture

```
  All services → stdout (JSON)
        │
        ▼
   Log Aggregator (Vector or Fluent Bit — single process)
        │
        ├──▶ MongoDB logs collection
        │    (WARN + ERROR + CRITICAL only)
        │    (INFO written only for job.completed and key events)
        │
        ├──▶ /var/log/evp/{service}/{date}.log
        │    (all levels, daily rotation, 7-day retention on disk)
        │
        └──▶ Alert queue (Redis-1: alerts list)
             (CRITICAL only → admin panel notification)
             (Optional: Slack webhook / email)
```

### Mandatory Log Events

| Service | Event | Level |
|---|---|---|
| API | `job.created` | INFO |
| API | `auth.failure` | WARN |
| API | `quota.exceeded` | WARN |
| API | `queue.backpressure` | WARN |
| Precheck | `precheck.syntax_fail` | INFO |
| Precheck | `precheck.no_mx` | INFO |
| Precheck | `precheck.mx_found` | INFO |
| Precheck | `worker.panic_recovered` | CRITICAL |
| SMTP | `smtp.connected` | INFO |
| SMTP | `smtp.rcpt_response` | INFO |
| SMTP | `smtp.greylist` | WARN |
| SMTP | `smtp.catchall_detected` | INFO |
| SMTP | `smtp.ip_block` | CRITICAL |
| SMTP | `smtp.mx_exhausted` | WARN |
| SMTP | `worker.panic_recovered` | CRITICAL |
| Control Plane | `ip.allocated` | INFO |
| Control Plane | `ip.released` | INFO |
| Control Plane | `ip.block_reported` | CRITICAL |
| Control Plane | `pool.no_ip_available` | WARN |
| Scheduler | `retry.requeued` | INFO |
| Scheduler | `retry.max_reached` | WARN |
| Job Monitor | `job.completed` | INFO |
| Job Monitor | `webhook.sent` | INFO |
| Job Monitor | `webhook.failed` | ERROR |

---

## 9. Admin Panel — Full Feature Spec

### Dashboard — Home Screen

```
┌─────────────────────────────────────────────────────────┐
│  System Health                         [all green]      │
│  ─────────────────────────────────────────────────────  │
│  Active Jobs:  4       Queue Depths:                    │
│  Jobs Today:   127     precheck:realtime   →    12      │
│  Emails Today: 4.2M    precheck:bulk       →  48,291    │
│                        smtp:google         →   8,412    │
│  Cache Hit Rate: 34%   smtp:microsoft      →   3,105    │
│  Avg Speed: 847/sec    smtp:generic        →   1,940    │
│                        greylist:retry      →   2,201    │
│                                                         │
│  IP Pool:  32 active  ·  6 inactive  ·  2 burned       │
│                                                         │
│  ⚠ 1 alert: IP 10.0.1.8 received block signal from     │
│    Google at 14:23. Review required.                    │
└─────────────────────────────────────────────────────────┘
```

---

### Jobs Management

**Job list columns:**
- Job ID, User, Total Emails, Status, Progress %, Queued At, Duration, Actions

**Per-job detail:**
```
Job: abc-123-def  ·  Status: completed  ·  User: john@corp.com
─────────────────────────────────────────────────────────────
Source: customer_list_jan.csv  (50,000 emails · 2.1 MB)
Duration: 31 min 14 sec  ·  Completed: Jan 15 14:54:00

Results:
  ✅ Valid             31,000  (62.0%)
  ❌ Invalid            9,200  (18.4%)
  ⚠️  Accept-All         4,800   (9.6%)
  🗑  Disposable           620   (1.2%)
  📮 Role Account          340   (0.7%)
  ❓ Unknown             1,140   (2.3%)
  ✖  Syntax Error        2,900   (5.8%)
  💾 From Cache            ---   served instantly

Performance:
  Avg SMTP duration: 284ms
  Cache hits: 2,900 (5.8% of list already cached)
  Greylist retries: 1,890

[Download Results CSV]  [View Email Results]  [View Job Logs]
```

---

### IP Pool Management

**IP list view (per server tab):**

| IP Address | Status | Rating | Provider | Connections | Total Verif | Blocks | Last Used |
|---|---|---|---|---|---|---|---|
| 10.0.1.1 | 🟢 active | 9 | GOOGLE | 42/50 | 284,000 | 1 | just now |
| 10.0.1.2 | 🟢 active | 8 | ALL | 18/40 | 191,000 | 0 | 1 min ago |
| 10.0.1.3 | 🟡 inactive | 7 | MICROSOFT | 0/35 | 0 | 0 | never |
| 10.0.1.8 | 🔴 burned | 3 | GOOGLE | 0 | 41,000 | 7 | 2h ago |

**Per-IP detail page:**
- Block history table (date, provider, code, message, notes)
- Hourly verification chart (7 days)
- Connection success rate over time
- Log view filtered to this IP (last 100 entries)
- Admin notes field

**Admin actions:**
```
[Set Active]  [Set Inactive]  [Mark Burned]
[Change Rating: 1–10 slider]
[Assign Provider: ALL / GOOGLE / MICROSOFT / GENERIC]
[Add Notes]
[Reload in Control Plane]
```

---

### System Health View

**Service status section:**
```
Service                  Status      Workers    Last Heartbeat
──────────────────────────────────────────────────────────────
API Cluster              ● healthy   3 nodes    1s ago
Precheck Workers         ● healthy   5 active   1s ago
SMTP Server A            ● healthy   1,200 conn 1s ago
SMTP Server B            ● healthy     980 conn 1s ago
Network Control Plane    ● healthy   -          1s ago
Retry Scheduler          ● healthy   -          28s ago
Job Monitor              ● healthy   -          9s ago
Redis-1 (Queue)          ● healthy   -          1s ago
Redis-2 (SMTP)           ● healthy   -          1s ago
Redis-3 (Cache)          ● healthy   -          1s ago
MongoDB                  ● healthy   -          1s ago
```

---

### Error Log View

- Real-time tail via SSE (Server-Sent Events)
- Filter bar: level, service, event, IP, domain, job_id, date range
- CRITICAL lines: red background
- ERROR lines: orange
- WARN lines: yellow
- Click any row → expand full JSON metadata
- Alert config: notify on CRITICAL events via email or webhook

---

### Config Management

Admin can edit `system_config` documents directly from the panel:
- Domain throttle limits per provider
- Greylist retry count and backoff schedule
- Cache TTL values
- Queue backpressure threshold
- Changes take effect after control plane reload

---

## 10. IP Pool Management (Manual Rating System)

### The Rating Principle

You decide which IPs are healthy. The system never auto-burns an IP. It reports, you decide.

```
Rating 9–10:  Best performers. Control plane fills these first.
Rating 7–8:   Good standing. Standard workhorse IPs.
Rating 5–6:   Some history but limited. Used as secondary.
Rating 3–4:   Low trust. Fallback only when higher rated are full.
Rating 1–2:   Nearly retired. Minimal connections. About to set inactive.
```

### Status Meaning

```
active    → In-memory pool. Control plane assigns connections.
inactive  → In MongoDB but NOT in memory. Zero connections assigned.
            Use for: cooling down, testing, standing by.
burned    → Recorded for audit. Never assigned. Stays in admin panel.
            Use for: IPs that got hard-blocked and you won't recover.
```

### Typical IP Lifecycle

```
You get a new IP
        │
        ▼
Add to ip_pool: status=inactive, rating=7
        │
        ▼
You set status=active in admin panel
        │
        ▼
API calls ReloadPool on control plane
        │
        ▼
IP enters active pool, begins receiving connections
        │
        ▼
Usage builds up. You monitor block_count and success_rate.
        │
    If block count rises:
        │
        ▼
Admin panel shows alert
        │
        ▼
You lower rating (7 → 4) → IP gets fewer connections
Or you set status=inactive → IP gets zero connections
        │
        ▼
If you determine IP is permanently blocked:
        │
        ▼
You set status=burned → removed from pool, kept in history
```

---

## 11. Error Handling & Crash Recovery

### Worker Crash Pattern (All Workers)

Every Go worker goroutine wraps its main loop in a `defer recover()`:

```
goroutine main loop:
  defer func() {
    if r := recover(); r != nil {
      log CRITICAL: worker.panic_recovered with stack trace
      run crash_recovery()
      restart worker after 2 second delay
    }
  }()
  → do work
```

**crash_recovery() for SMTP workers:**
```
1. Query MongoDB:
   email_results where status="smtp_processing"
   AND smtp.done_at IS NULL
   AND created_at < (now - 2 minutes)
   AND service = "smtp_a" (this worker's ID)

2. For each found: push back to smtp:{provider} queue
3. Update status back to "precheck_done"
4. Log warn: worker.recovery_requeued with count
```

**crash_recovery() for Precheck workers:**
```
1. Query MongoDB:
   email_results where status="precheck_processing"
   AND precheck.done_at IS NULL
   AND created_at < (now - 1 minute)

2. For each found: push back to precheck:bulk queue
3. Update status back to null (re-run precheck)
4. Log warn: worker.recovery_requeued with count
```

---

### Redis Connection Loss

```
Redis-1 or Redis-2 down:
  → Workers stop dequeuing (BRPOP just blocks)
  → No emails lost — they stay in queue until Redis recovers
  → Log CRITICAL once, then WARN every 30s while down
  → Reconnect with exponential backoff: 1s, 2s, 4s, 8s... max 30s

Redis-3 (cache) down:
  → System continues without cache
  → Every email goes through full pipeline
  → Log WARN on first miss: redis3.unavailable_bypassing_cache
  → No data loss. Performance degrades, IP reputation at slight risk.
  → Reconnect with same backoff strategy
```

---

### MongoDB Connection Loss

```
MongoDB down:
  → Workers buffer completed results in memory (ring buffer, max 5000)
  → While buffer has space: continue processing
  → When buffer full: pause processing, wait for MongoDB
  → On reconnect: flush buffer to MongoDB
  → If buffer fills with no reconnect in 5 min:
     → Write buffer to /var/evp/recovery/results_{ts}.json
     → Log CRITICAL: mongodb.recovery_file_written with path
     → Admin sees this in panel, can manually trigger re-import
```

---

### Queue Backpressure

```
If LLEN precheck:bulk > 500,000:
  API returns 503 for new bulk job uploads
  API still accepts single-email realtime lookups
  Log WARN: queue.backpressure_bulk_uploads_paused
  Admin panel: bulk queue shows "pressured" badge

Threshold configurable in system_config:
  key: queue.backpressure_threshold, value: 500000
```

---

## 12. Production Hardening Checklist

### Security

- [ ] API keys stored as bcrypt hash in MongoDB, never plain
- [ ] Emails stored as SHA256 hash in cache keys, encrypted in MongoDB
- [ ] All internal services (control plane, workers) on private network only
- [ ] gRPC control plane not reachable from public internet
- [ ] HAProxy enforces TLS 1.2 minimum, 1.3 preferred
- [ ] Admin panel behind separate auth (separate JWT secret from API)
- [ ] Webhook payloads signed with HMAC-SHA256 (user's secret)
- [ ] MongoDB: separate read/write users per service
- [ ] Redis: requirepass on all 3 instances
- [ ] File uploads: size limit (50MB), type validation (CSV/TXT only)

### Observability

- [ ] Each service exposes `/health` endpoint (returns 200 if healthy)
- [ ] Each service exposes `/metrics` endpoint (Prometheus-compatible counters)
- [ ] HAProxy health checks on `/health` of each API node
- [ ] Job Monitor checks if any job has been `processing` > 2 hours → CRITICAL alert
- [ ] Greylist queue depth > 50,000 → WARN alert
- [ ] Cache hit rate drops below 20% → WARN alert (unusual traffic pattern)
- [ ] Any IP block event → CRITICAL alert, admin notification

### Reliability

- [ ] All Redis instances: AOF persistence enabled (Redis-1, Redis-2)
- [ ] Redis-3: RDB snapshots every 5 minutes
- [ ] MongoDB: replica set minimum (1 primary + 1 secondary)
- [ ] Graceful shutdown: each service catches SIGTERM, finishes in-flight work, then exits
- [ ] All workers: crash recovery on startup (scan for orphaned in-progress records)
- [ ] Webhook failures: retry queue with 3 attempts (5min, 30min, 2h)
- [ ] Result files: stored on persistent volume, not local disk

### Performance

- [ ] MongoDB indexes created before data load (not after)
- [ ] DNS resolver: use local caching resolver (unbound or systemd-resolved)
- [ ] SMTP connection pooling: reuse connections per MX host
- [ ] Batch MongoDB writes: buffer 100 results, flush every 500ms
- [ ] Precheck workers: run DNS lookups in parallel goroutines
- [ ] Redis-3 MX cache: 1h TTL reduces DNS queries by ~95% at steady state

---

## 13. Verification Result States

```
                   Email enters pipeline
                          │
               ┌──────────▼──────────┐
               │    Syntax Check     │──── FAIL ───▶ syntax_error
               └──────────┬──────────┘
                          │ pass
               ┌──────────▼──────────┐
               │  Disposable Check   │──── MATCH ──▶ disposable
               └──────────┬──────────┘
                          │ not disposable
               ┌──────────▼──────────┐
               │   MX / DNS Check    │──── FAIL ───▶ invalid (no_mx)
               └──────────┬──────────┘
                          │ has MX
               ┌──────────▼──────────┐
               │   Dedup Cache       │──── HIT ────▶ (cached result returned)
               └──────────┬──────────┘
                          │ miss
               ┌──────────▼──────────┐
               │  Domain Knowledge:  │──── catch_all ▶ accept_all (skip SMTP)
               │  catch-all known?   │
               └──────────┬──────────┘
                          │ unknown / not catch-all
               ┌──────────▼──────────┐
               │    SMTP RCPT TO     │──── 5xx ────▶ invalid
               └──────────┬──────────┘
                          │
                  ┌───────┴────────┐
                  │                │
                 4xx              2xx
              (greylist)       (accepted)
                  │                │
          retry queue    ┌─────────▼───────────┐
          max retries → │  Catch-All Test      │
          unknown       │  (Section 4 detail)  │
                        └────────┬──────┬──────┘
                                 │      │
                          probe  │      │ probe
                          5xx    │      │ 2xx
                       (not      │      │ (catch-all)
                        catch-   │      │
                         all)    ▼      ▼
                              valid   accept_all
                          (+ role_account flag
                           if role detected)
```

---

## 14. Component Responsibilities

| Component | Tech | Purpose | Scales How |
|---|---|---|---|
| API Cluster | Go | Auth, file parse, job creation, dedup, result delivery | Horizontal behind HAProxy |
| Precheck Workers | Go | Syntax, disposable, DNS/MX, classification | Add more worker processes |
| SMTP Server A | Go | Google SMTP verification | Add more server instances |
| SMTP Server B | Go | Microsoft + Generic SMTP | Add more server instances |
| Network Control Plane | Go | IP assignment, connection counting, block detection | Single instance (fast, low load) |
| Retry Scheduler | Go | Greylist re-queue | Single instance |
| Job Monitor | Go | Job completion detection, webhooks | Single instance |
| Redis-1 | Redis | Precheck queue | Increase memory |
| Redis-2 | Redis | SMTP queues + greylist | Increase memory |
| Redis-3 | Redis | Result cache + MX cache | Increase memory |
| MongoDB | MongoDB | All persistent data | Replica set → sharding if needed |
| HAProxy | HAProxy | TLS, rate limit, load balance | Add nodes |
| Admin Panel | Go + frontend | Visibility + control | Single instance fine |

---

## 15. Data Flow — What Gets Written Where

```
EVENT                             → WRITES TO
────────────────────────────────────────────────────────────────────
User uploads file                 MongoDB: jobs (status=queued)
                                  Log: job.created

Dedup cache hit                   MongoDB: email_results (from_cache=true)
                                  Log: cache.hit (batched)

Email pushed to precheck          Redis-1: precheck:bulk or :realtime
                                  Log: job.enqueued (batched)

Email fails syntax                MongoDB: email_results (syntax_error)
                                  Redis-3: result cache (7d TTL)
                                  Log: precheck.syntax_fail

Email domain is disposable        MongoDB: email_results (disposable)
                                  Redis-3: result cache
                                  Log: precheck.disposable

DNS/MX lookup (new domain)        Redis-3: mx:{domain} (1h TTL)
                                  MongoDB: domain_knowledge (upsert)

Email fails MX check              MongoDB: email_results (invalid, no_mx)
                                  Redis-3: result cache
                                  Log: precheck.no_mx

Email pushed to SMTP queue        Redis-2: smtp:{provider}
                                  MongoDB: email_results (status=precheck_done)
                                  Log: precheck.smtp_queued

SMTP greylist (4xx)               Redis-2: greylist sorted set
                                  MongoDB: logs
                                  Log: smtp.greylist

SMTP result (any)                 MongoDB: email_results (status=completed)
                                  Redis-3: result:{hash} cache
                                  MongoDB: jobs (increment counts)
                                  Log: smtp.result

Catch-all detected                MongoDB: domain_knowledge (catch_all=true)
                                  Redis-3: domain:catchall:{domain}
                                  Log: smtp.catchall_detected

IP block signal                   MongoDB: ip_pool (block_history push)
                                  MongoDB: logs (CRITICAL)
                                  Redis-1: alerts list (admin notification)
                                  Log: smtp.ip_block [CRITICAL]

Greylist max retries              MongoDB: email_results (unknown)
                                  Redis-3: result cache (6h TTL)
                                  Redis-2: remove from greylist set
                                  Log: retry.max_reached

Job completed                     MongoDB: jobs (status=completed, summary)
                                  Webhook fired → log webhook.sent / .failed
                                  Log: job.completed

Control plane pool reload         Memory: rebuilt from MongoDB ip_pool
                                  Log: pool.reloaded
```

---

*End of System Design. Version: Production-Grade. This document covers architecture, pipeline stages, catch-all detection at code-design level, Network Control Plane IP assignment algorithm, all 6 MongoDB schemas with indexes, 3 Redis server configs, logging strategy, admin panel spec, IP management, error handling, crash recovery, and production hardening checklist.*
