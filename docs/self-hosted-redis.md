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
- **Eviction under pressure: safe.** Set `maxmemory` with `allkeys-lru` and let it drop
  whatever it likes. Evicted cache entries are refetched; an evicted job is one
  resubmission.

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

Overshooting is not a failure mode — `allkeys-lru` evicts, and the cache refills. Under
the default two-hour TTL, 256 MB comfortably covers most deployments.

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

Others exist — KeyDB, Redict, Microsoft's Garnet, Dragonfly among them — with varying
maturity, activity and RESP coverage. They are viable but less trodden; see *Checking a
substitute* below before adopting one.

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
            - allkeys-lru     # evict freely; entries are all reproducible
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
              "--maxmemory-policy", "allkeys-lru"]
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
