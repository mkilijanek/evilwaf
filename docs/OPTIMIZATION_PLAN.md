# Optimization Plan

## Objectives
- Increase throughput and lower median/95p proxy latency.
- Reduce memory footprint during long runs.
- Preserve current interception, rotation, and detection features.

## Areas Needing Rebuild or Deep Refactor
1. `core/interceptor.py` request path: too many responsibilities in one module.
2. `chemistry/origin_server_ip.py` scanner orchestration: synchronous and heavy I/O fan-out.
3. TLS/TCP/Tor rotation path: repeated setup costs per request.
4. In-memory record retention: unbounded growth risk in prolonged sessions.

## Optimization Workstream

### Phase 1: Baseline and Guardrails
- Add benchmark harness for HTTP and HTTPS proxy flows (RPS, p50/p95 latency, memory).
- Add profiler jobs (CPU + allocations) behind `workflow_dispatch`.
- Define performance budgets in CI for non-regression.

### Phase 2: Request Pipeline Split
- Split interception pipeline into components:
  - connection manager
  - protocol parser/serializer
  - retry/decision engine
  - record sink
- Replace repeated object creation with reusable pools where safe.

### Phase 3: Scanner Concurrency Rework
- Migrate origin scanners to async I/O with bounded concurrency and strict timeouts.
- Add result caching (DNS, ASN, CT lookups) with TTL.
- Deduplicate scanner requests by host and source.

### Phase 4: Memory and I/O Efficiency
- Introduce bounded record buffer + optional file-backed storage.
- Stream large payload handling; avoid full-body duplication when not needed.
- Add configurable response body cap for non-critical paths.

### Phase 5: Release Hardening
- Add canary run on representative targets in staging.
- Compare baseline vs optimized metrics; release only on parity or improvement.

## Success Criteria
- >=20% improvement in p95 latency under benchmark load.
- >=30% reduction in peak RSS in long-running proxy sessions.
- No regression in test/coverage/security workflows.
