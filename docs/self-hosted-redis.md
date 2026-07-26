# Running without a managed Redis

`Ednsv.Web` needs a shared store only to run **multiple replicas** (see
[horizontal-scaling.md](horizontal-scaling.md)). A single instance needs nothing at all.

If you want multiple replicas but do not have — or do not want — a managed Redis, you do
not need much: **one pod, no persistence, no replication, a few hundred megabytes of
memory.** This document explains why that is enough, how to run it, and how to check a
substitute server before you commit to it.

## Why one pod is enough

Nothing in the shared store is durable, and nothing in it is the only copy of anything
you care about:

| What lives there | If it is lost |
|---|---|
| **Async job registry** (`job:{id}`) | In-flight `POST /api/validate` jobs become unpollable; clients resubmit. Finished reports have already been returned. This is the one **hard** dependency of distributed mode. |
| **Probe-cache L2** (`cache:{type}:{key}`) | Nothing. Pods notice an emptied shared cache and republish their own memory into it — see [caching-architecture.md](caching-architecture.md) → *Recovering an emptied L2*. Worst case it refills from the network. |
| **Config / user beacons** (`config:head`, `users:head`) | Config and user *reads* keep working from the shared mount; *writes* return 503 until it is back. The files, not Redis, are the source of truth. |

So the design decisions an operator would normally agonise over mostly do not apply:

- **Persistence: turn it off.** There is nothing worth writing to disk. AOF and RDB only
  add I/O and a slower restart.
- **Replication and failover: skip them.** A restart costs in-flight jobs and a cache
  that refills itself. Sentinel or Cluster buys you very little here.
- **Backups: none.** There is nothing to restore.
- **Eviction under pressure: safe, but pick the policy deliberately.** Set `maxmemory`
  with **`volatile-lru`**, not `allkeys-*` — three small keys hold the cross-pod
  coordination state and must never be evicted. See *Eviction policy* below; this is the
  one setting here that is worth reading twice.

The failure model this leans on is documented in full in
[horizontal-scaling.md](horizontal-scaling.md) → *Failure model*.

## Sizing

Measured against this application — one instance, `CacheDir=none`, real validations —
one domain costs roughly **150–300 keys and 75–150 KB**, at about 0.5 KB per key. An
empty server is about 1 MB.

Budget **~150 KB per distinct domain validated per `CacheTtlHours` window**, and round
up:

| Distinct domains per TTL window | Working set | Sensible `maxmemory` |
|---|---|---|
| 100 | ~15 MB | 128 MB |
| 1,000 | ~150 MB | 256 MB |
| 5,000 | ~750 MB | 1 GB |

Overshooting is not a failure mode — with the policy below, eviction drops cache entries
and they are refetched. Under the default two-hour TTL, 256 MB comfortably covers most
deployments.

## Eviction policy

### What the defaults give you

Out of the box (verified on Redis 7.0.15 and Valkey 7.2.13):

| Setting | Default | Consequence here |
|---|---|---|
| `maxmemory` | **`0` — no limit** | Nothing is ever evicted. The server grows until the container's memory limit kills it. |
| `maxmemory-policy` | **`noeviction`** | Irrelevant while `maxmemory` is `0`, and safe for the coordination keys once it is not. |
| `save` | **`3600 1 300 100 60 10000`** | RDB snapshots are **on by default** — periodic disk writes of data that is worthless. This is why the manifests pass `--save ""`. |
| `appendonly` | `no` | Already what you want. |

So the out-of-the-box failure mode is not eviction, it is an **OOMKill**: the pod is
killed and restarted, which drops every key including the coordination ones, along with
any in-flight jobs. The application recovers — that is the documented failure model — but
abruptly, and at a moment of its choosing rather than yours.

Setting `maxmemory` converts that into graceful, continuous eviction. That is the
improvement, and it is also what makes the policy matter: **the danger described below
only exists once you set `maxmemory`.** The default would never have evicted a
coordination key, because it never evicts anything.

### Which policy

**Use `volatile-lru`.** The reason is that not every key here is a cache entry:

| Key | TTL | Written | Read | Size | Count |
|---|---|---|---|---|---|
| `{instance}:cache:{type}:{key}` | `CacheTtlHours`, or 24h when that is `0` | on each fetched result | on every L1 miss | ~0.5 KB | thousands |
| `{instance}:job:{id}` | minutes | ~87× per validation | on each status poll | a few KB | tens |
| `{instance}:config:head` | **none** | on a config change | every freshness check (memoised ~1s) | ~36 B | 1 |
| `{instance}:users:head` | **none** | on a user change | every auth freshness check | ~36 B | 1 |
| `{instance}:cache-epoch` | **none** | at startup, and on a re-warm | once per `SharedCacheWatchSeconds` | ~36 B | 1 |

The last three are the cross-pod coordination state, they carry no TTL because they must
not disappear on their own, and together they are about a hundred bytes.

**Their access pattern is exactly what an eviction policy punishes.** The epoch nonce is
read once every thirty seconds and written almost never; the beacons are read on a
memoised path and written only when a human changes something. Against thousands of cache
keys being touched continuously during validations, those three are permanently the
least-recently-used and by far the least-frequently-used keys in the keyspace. An
`allkeys-*` policy does not merely risk them — it selects them first.

Measured on Redis 7.0.15 with `maxmemory 3mb`, driving TTL'd filler until eviction:

| Policy | `config:head` | `cache-epoch` | Verdict |
|---|---|---|---|
| `allkeys-lru` | **evicted** | **evicted** | 26,379 keys evicted, and it took both coordination keys while 3,782 cache keys survived |
| `volatile-lru` | survived | survived | 26,415 evicted, all of them cache keys |

Repeated with the application running against it rather than a synthetic keyspace: 26,327
keys evicted under sustained pressure, both coordination keys intact, `/health/ready` and
a fresh validation both still returning 200, and no spurious re-warm triggered.

### What losing them actually costs

Not an outage, which is why this is easy to miss:

- **`config:head`** — a pod that finds the beacon missing republishes *its own* head and
  carries on; it does not reload from disk. So a pod whose in-memory config is behind the
  file stays behind it until the next real config change moves the beacon.
- **`users:head`** — the same, for user records. A token revoked on another pod may not
  be noticed until something else changes the beacon.
- **`cache-epoch`** — read as "the shared cache was flushed", triggering a full re-warm
  from memory. Harmless in itself (the warm is add-if-absent), but it republishes several
  hundred keys into a server that is already under memory pressure.

### The other policies

| Policy | Verdict |
|---|---|
| **`volatile-lru`** | **Recommended.** Only TTL'd keys are candidates, so the coordination keys are exempt by construction rather than by luck. |
| `volatile-lfu` | Also safe. LFU favours keeping frequently-requested domains over recently-requested ones; either is defensible, LRU is the conventional and slightly cheaper choice. |
| `volatile-ttl` | Safe for the coordination keys, but evicts whatever expires soonest — and job keys have much shorter TTLs than cache entries, so it targets the one thing that actually hurts. Avoid. |
| `volatile-random` | Safe, but no reason to prefer it. |
| `allkeys-lru` / `allkeys-lfu` / `allkeys-random` | Avoid. LFU is the worst of the three: these keys have the lowest access frequency in the entire keyspace. |
| `noeviction` | Safe for the coordination keys, and it fails loudly rather than quietly — but when full, cache write-through is fire-and-forget so it degrades silently anyway, while job writes fail and validations become unpollable. Only sensible if you are confident in the sizing. |

### Every key here is evictable, including under `CacheTtlHours=0`

`volatile-lru` only evicts keys that carry a TTL, so it is worth knowing that the shared
cache never writes one without. `CacheTtlHours=0` means "do not expire" for the memory
tier — which is safe there, because it is keyed and so bounded by the number of distinct
domains — but Redis is a fixed allocation shared by every pod. Keys written there always
get a lifetime: the configured TTL, or a **24-hour floor** when there is none, the same
floor and the same reasoning the disk tier uses (`DiskCacheService.UncappedRetention`).

The floor is a fallback, not a cap. `CacheTtlHours=168` puts a week on the Redis keys
too; only "no expiry at all" is translated into something finite.

Measured with `CacheTtlHours=0`, `maxmemory 3mb`, `volatile-lru`: keys land with an
86,394-second TTL, 26,334 of them evict cleanly under pressure with **zero write
errors**, and both coordination keys survive.

## Which server

Any server speaking the Redis wire protocol (RESP) is a candidate, because this
application uses almost none of it: `GET`, `SET` with TTL, `SET NX`, one
`WATCH`/`MULTI`/`EXEC` compare-and-set for the config and user beacons, and
fire-and-forget writes. No pub/sub, streams, sorted sets, hashes, Lua or modules.

The widely adopted, well-trodden choices for self-hosting:

- **Redis** — the original, and the most documented deployment path in existence. Both
  Redis Inc. and community images; every Kubernetes tutorial, Helm chart and Compose
  example assumes it.
- **Valkey** — a fork of Redis 7.2.4 under the Linux Foundation, maintained by several
  of the former Redis maintainers and backed by the major cloud providers. Wire- and
  config-compatible; `StackExchange.Redis` connects to it unchanged. The usual drop-in.

Both are packaged as official container images and as Helm charts (Bitnami's are the
most commonly used for either). Either is a boring, safe choice.

Others exist — KeyDB, Redict, Microsoft's Garnet, Dragonfly among them. **Garnet** is
worth a mention for a .NET shop: MIT-licensed, from Microsoft Research, written in .NET,
and it passes every compatibility check in this repository (see below). Note that it does
not implement `maxmemory` or `maxmemory-policy` at all — it bounds memory through its own
options instead — so the eviction guidance above does not transfer, and you would need to
work out the equivalent from its documentation. That is the shape of what the less common
servers cost: not wire compatibility, but familiarity and transferable operational
knowledge — fewer runbooks, fewer people who have run them, less material when something
misbehaves at 3am.

**On licensing:** these projects sit under a mix of licences (BSD, AGPL, LGPL, MIT and
source-available terms), and the terms have changed more than once in recent years.
Deciding what your organisation may run is your call and your legal team's, not this
document's — check the current terms on the project's own site rather than trusting any
summary, including this one. What this application needs from the server is small enough
that the choice is a policy question, not a technical one.

## Kubernetes

One Deployment, one ClusterIP Service, no PVC. `emptyDir` at `/data` keeps the container
filesystem read-only-friendly; nothing in it needs to survive.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ednsv-redis
spec:
  replicas: 1
  strategy:
    type: Recreate            # never two writers; there is nothing to hand over
  selector:
    matchLabels: { app: ednsv-redis }
  template:
    metadata:
      labels: { app: ednsv-redis }
    spec:
      containers:
        - name: redis         # or a Valkey image — same flags
          image: redis:7-alpine
          args:
            - --save
            - ""              # no RDB snapshots
            - --appendonly
            - "no"            # no AOF
            - --maxmemory
            - 256mb
            - --maxmemory-policy
            - volatile-lru    # NOT allkeys-*: see Eviction policy — the coordination
                              # keys carry no TTL and must never be candidates
          ports:
            - { containerPort: 6379, name: redis }
          resources:
            requests: { cpu: 50m, memory: 320Mi }
            limits:   { memory: 384Mi }   # maxmemory + headroom for overhead
          readinessProbe:
            exec: { command: ["redis-cli", "ping"] }
          securityContext:
            runAsNonRoot: true
            runAsUser: 999
            allowPrivilegeEscalation: false
            capabilities: { drop: ["ALL"] }
          volumeMounts:
            - { name: tmp, mountPath: /data }
      volumes:
        - name: tmp
          emptyDir: {}
---
apiVersion: v1
kind: Service
metadata:
  name: ednsv-redis
spec:
  selector: { app: ednsv-redis }
  ports:
    - { port: 6379, targetPort: redis }
```

Set the memory limit above `maxmemory` — that setting bounds the dataset, not the
process, and the server needs headroom for client buffers and allocator overhead.

Then point the app at it:

```yaml
env:
  - name: Redis__ConnectionString
    value: "ednsv-redis:6379"
  - name: CacheDir
    value: "none"            # recommended once Redis is present
```

### Restrict who can reach it

There is no authentication in the manifest above, which is only acceptable behind a
NetworkPolicy. Add one:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: ednsv-redis
spec:
  podSelector:
    matchLabels: { app: ednsv-redis }
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector:
            matchLabels: { app: ednsv }   # the web pods, and nothing else
      ports:
        - { protocol: TCP, port: 6379 }
```

If your cluster does not enforce NetworkPolicy, or the namespace is shared, set a
password instead (`--requirepass`, from a Secret) and pass it through
`Redis:AccessKey` — the connection string supports a `{AccessKey}` placeholder, so the
secret never appears in the connection string itself. See
[configuration.md](configuration.md) → *Redis*.

## Docker Compose

For a single host running the container image rather than Kubernetes:

```yaml
services:
  redis:
    image: redis:7-alpine
    command: ["--save", "", "--appendonly", "no", "--maxmemory", "256mb",
              "--maxmemory-policy", "volatile-lru"]   # not allkeys-* — see the doc
    # no ports: — reachable only on the compose network
  ednsv:
    image: ghcr.io/pkinerd/ednsv:latest
    environment:
      Redis__ConnectionString: "redis:6379"
      CacheDir: "none"
    ports: ["8080:8080"]
    depends_on: [redis]
```

Note that a single-container deployment does not need any of this: leave `Redis` unset
and the app runs on memory plus its disk cache, which is the default and the recommended
shape for one instance.

## Checking a substitute

The repository has a ready-made compatibility harness. Four test classes exercise the
entire shared-store surface and self-skip unless a server answers on **`127.0.0.1:6380`**:

| Test class | Covers |
|---|---|
| `LiveRedisL2Tests` | `GET`, `SET` with TTL, the probe-cache read/write path |
| `SharedCacheWarmTests` | `SET NX`, per-key TTLs, republishing memory into an emptied cache |
| `SharedCacheEpochTests` | the nonce key and flush detection |
| `LiveRedisLeaseTests` | the compare-and-set used by the config and user beacons |

Point any candidate at that port and run them:

```bash
<your-server> --port 6380 &
dotnet test tests/Ednsv.Core.Tests --filter "FullyQualifiedName~LiveRedis|FullyQualifiedName~SharedCache"
```

Green means the server does everything this application asks of it. The compare-and-set
in `LiveRedisLeaseTests` is the one to watch: it is the only operation beyond simple
string commands, and the most likely gap in a partial RESP implementation.

### Results

Run in July 2026, each server started with the flags in the manifest above:

| Server | Version | Harness | Beacon CAS | Full validation | Re-warm after `FLUSHALL` |
|---|---|---|---|---|---|
| Redis | 7.0.15 | 31/31 | honoured | 162 keys | 169 keys republished |
| Valkey | 7.2.13 | 31/31 | honoured | 162 keys | 169 keys republished |
| Garnet | 2.1.0 | 31/31 | honoured | 162 keys | 169 keys republished |

Identical on every measure. *Beacon CAS* was checked separately from the harness, at
protocol level: a transaction carrying a **stale** `Condition.StringEqual` must be
rejected and a correct one must commit. All three reject and commit as required, so
config and user writes are safe on any of them. Both alternatives report a
`redis_version` for client compatibility — Valkey 7.2.4, Garnet 7.4.3 — which is why
`StackExchange.Redis` connects unchanged.

What this does **not** cover: behaviour under sustained load, memory behaviour at the
`maxmemory` boundary, TLS, or cluster mode. None of those are exercised by this
application's usage, but none of them were measured either.

## Why there is no first-party coordinator

A small first-party service implementing the same six operations was designed and
rejected. The contract is tiny enough that writing one is genuinely feasible — but it
would mean roughly a thousand lines of infrastructure code and a service to own, to
replace forty lines of YAML pointing at one of the most widely deployed servers there
is. It would also carry the same blast radius: one replica, no HA, restarts losing
in-flight jobs.

It would only make sense under a policy that forbids third-party datastore images
outright. If that describes your environment, the design is preserved in the project's
planning notes; nothing in the application blocks it, since every shared-store call
already goes through one small class.
