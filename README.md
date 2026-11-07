# gocommon
Shared Go library for HTTP, gRPC, and worker processes.
`context.Context` is the in-process source of truth. HTTP headers and gRPC metadata are only used at process boundaries.
```bash
go get github.com/huponx/gocommon@latest
```
Requires Go 1.26+.
## Packages
| Package | Role |
|---|---|
| [`requestctx`](#requestctx) | Identity on context; header/metadata mapping |
| [`logging`](#logging) | Zap; `FromCtx` adds request fields |
| [`config`](#config) | Env load + reusable blocks (`Server`, `Log`, `Postgres`, `Redis`, `GRPCClient`) |
| [`grpcserver`](#grpcserver) | Server + interceptors, gRPC health, graceful stop |
| [`grpcclient`](#grpcclient) | Dial + interceptors (ctx → metadata, unary timeout, logging) |
| [`httpx`](#httpx) | Gin middleware: logger, request context, access log |
| [`healthz`](#healthz) | Gin `/healthz` + `/readyz` |
| [`worker`](#worker) | Signals, in-flight drain, optional stdlib probes |
| [`apperror`](#apperror) | Typed errors → gRPC `status` + HTTP JSON |
## `requestctx`
```go
type Values struct {
	CorrelationID, UserID, TenantID, AgencyID string
	RequestID, TraceID, SpanID                string
}
```
| Boundary | API |
|---|---|
| In-process | `WithValues`, `From`, `SetUserID`, `EnsureIDs` |
| HTTP in | `FromHTTP` — reads `Correlation-ID`, `Request-ID`, `Tenant-ID`, `Agency-ID`, `Trace-ID`, `Span-ID`. **Does not read user id.** Resolve auth, then `SetUserID`. |
| HTTP out | `ToHTTPHeaders` |
| gRPC in | `HydrateIncoming` / `FromMD` (`correlation-id`, `user-id`, …) |
| gRPC out | `AppendOutgoing` — copies `Values` onto outgoing metadata without overwriting keys already set |
`EnsureIDs` generates `correlation_id` and `request_id` when missing.
## `logging`
```go
log, err := logging.New(logging.Config{
	Level:    "info",   // zap level
	Encoding: "console", // or "json"
	Service:  "http-server",
	Env:      "dev",
})
defer logging.Sync(log)
ctx = logging.WithCtx(ctx, log)
logging.FromCtx(ctx).Info("ok") // adds correlation_id, user_id, request_id, tenant_id when present
```
## `config`
Embed blocks on your service config and load from env:
```go
type Config struct {
	Server config.Server
	Log    config.Log
	GRPC   config.GRPCClient
}
cfg := config.MustLoad[Config]()
```
| Block | Env (defaults) |
|---|---|
| `Server` | `HOST` (`0.0.0.0`), `PORT` (`8080`), `SHUTDOWN_TIMEOUT` (`15s`) — `Addr()` |
| `Log` | `LOG_LEVEL` (`info`), `LOG_ENCODING` (`console`), `SERVICE_NAME` (`app`), `ENV` (`dev`) |
| `Postgres` | `POSTGRES_HOST/PORT/USER/PASSWORD/DB/SSLMODE` — `URL()` |
| `Redis` | `REDIS_HOST/PORT/PASSWORD/DB` — `URL()` |
| `GRPCClient` | `GRPC_TARGET` (`localhost:9090`), `GRPC_TIMEOUT` (`5s`), `GRPC_INSECURE` (`true`) |
## `httpx`
Gin middleware. Typical order:
```go
r.Use(gin.Recovery())
r.Use(httpx.Logger(log))
r.Use(httpx.RequestContext())
// app auth → requestctx.SetUserID
r.Use(httpx.AccessLog())
```
## `grpcserver`
Interceptors (unary + stream): recovery → hydrate `requestctx` → optional auth hook → logging.
```go
srv := grpcserver.New(
	grpcserver.WithLogger(log),
	grpcserver.WithReflection(dev),
	grpcserver.WithAuth(func(ctx context.Context) (context.Context, error) {
		return requestctx.SetUserID(ctx, userID), nil
	}),
)
pb.RegisterFooServer(srv.GRPC, impl)
srv.SetServing(pb.Foo_ServiceDesc.ServiceName, true)
// on signal:
srv.Stop(shutdownCtx) // health Shutdown, then GracefulStop; hard Stop if ctx expires
```
Options: `WithHealth`, `WithMaxMsgSize`, `WithServerOptions`.
## `grpcclient`
```go
conn, err := grpcclient.Dial(ctx, cfg.GRPC.Target,
	grpcclient.WithLogger(log),
	grpcclient.WithTimeout(cfg.GRPC.Timeout),
	grpcclient.WithInsecure(cfg.GRPC.Insecure),
)
```
Unary interceptors copy `requestctx` onto outgoing metadata, apply a per-call timeout, and log. TLS via `WithTLS` / `WithInsecure(false)`.
## `healthz`
Gin handlers. JSON: `{"status":"ok","checks":{"name":"ok"}}`. Failed checks → `503` + `"unavailable"`.
```go
r.GET("/healthz", healthz.Live())
r.GET("/readyz", healthz.Ready(healthz.GRPC("grpc", conn, "")))
```
`Check` is `Name` + `Fn(ctx) error`. Reuse the same `Check` values with `worker.NewHealth`.
## `worker`
No queue client. Service owns consume/ack; this package owns process lifecycle.
1. **`Signals()`** — cancel on SIGINT/SIGTERM. Stop accepting new jobs; in-flight work is not cancelled yet.
2. **`Runner`** — `Go(ctx, fn)` runs a job. Job context keeps parent values (`requestctx`, …) and is cancelled only when **`Drain`'s deadline expires**. After drain starts, `Go` returns `false` (nack/requeue).
3. **`Health`** — optional stdlib `/healthz` + `/readyz`. `SetReady(false)` before drain so readiness fails first.
```go
r := worker.New(worker.WithLogger(log))
h := worker.NewHealth(cfg.Server.Addr(), healthz.Check{Name: "redis", Fn: pingRedis})
go func() { _ = h.ListenAndServe() }()
ctx, stop := worker.Signals()
defer stop()
go consume(ctx, r) // receive → r.Go(jobCtx, handle)
<-ctx.Done()
h.SetReady(false)
drainCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
defer cancel()
_ = r.Drain(drainCtx)
_ = h.Shutdown(drainCtx)
```
## `apperror`
gRPC `codes.Code` plus a message. Implements `GRPCStatus()` so handlers can `return err` to gRPC.
```go
return apperror.NotFound("user not found")
apperror.WriteHTTP(c, err) // {"error":{"code":"NotFound","message":"user not found"}}
```
Helpers: `InvalidArgument`, `NotFound`, `Unauthenticated`, `PermissionDenied`, `AlreadyExists`, `FailedPrecondition`, `Unavailable`, `Internal`, `Wrap`, `From`.
HTTP mapping includes `InvalidArgument` → 400, `Unauthenticated` → 401, `NotFound` → 404, `Unavailable` → 502, `DeadlineExceeded` → 504, unknown → 500.
## Identity flow
HTTP edge hydrates context from headers, the app sets `user_id` after auth, the gRPC client copies values into metadata, the gRPC server hydrates context again. The same IDs show up on access logs and `logging.FromCtx`.
Workers should copy `Values` from the enqueue payload into `Go`'s `ctx` if they need the same log fields.
## Local development
Services consume tagged releases; to try unreleased changes locally use `replace github.com/huponx/gocommon => ../gocommon` or a `go.work`. Released versions:
```bash
go get github.com/huponx/gocommon@v0.1.0
```
What CI runs on every PR (run it before pushing):
```bash
go mod tidy && git diff --exit-code go.mod go.sum
gofmt -l .            # must print nothing
go vet ./...
go test -race -count=1 ./...
```
## Service-to-service Bearer auth
Token belongs to the **receiver**. Callers must present the same secret. gRPC helpers take a string; they do not read env or hardcode a service name.

**Convention**

| | |
| --- | --- |
| Env | `{RECEIVER}_S2S_TOKEN` (e.g. `COURIER_S2S_TOKEN`) |
| Source | Kubernetes `Secret` via `secretKeyRef`, key `token`, name `{receiver}-s2s-token` |
| Receiver | Verify with its own env |
| Caller | Send Bearer from the **target** env (multiple peers → multiple env vars) |

```yaml
- name: COURIER_S2S_TOKEN
  valueFrom:
    secretKeyRef:
      name: courier-s2s-token
      key: token
```

**Server**

```go
// Production / staging: panic at New if token is empty.
grpcserver.New(grpcserver.WithBearerAuth(token))

// Local ENV=dev: empty token leaves the server open.
grpcserver.New(grpcserver.WithOptionalBearerAuth(token))
```

`/grpc.health.v1.Health/*` skips auth so kube probes work without a token. Reflection still requires a token when auth is on.

**Client**

```go
grpcclient.Dial(ctx, target, grpcclient.WithBearerToken(os.Getenv("COURIER_S2S_TOKEN")))
```

Empty token is a no-op (no `authorization` header).

## Releases

Every PR goes through two required checks, then is squash-merged into `main`:

| Workflow | Check | What it does |
|---|---|---|
| [`ci.yml`](.github/workflows/ci.yml) | `verify` | `go mod tidy` leaves no diff, `gofmt`, `go vet`, `go build`, `go test -race` |
| [`pr-title.yml`](.github/workflows/pr-title.yml) | `pr-title` | PR title is a conventional commit (`feat(logging): ...`); re-runs when the title is edited |

[`release.yml`](.github/workflows/release.yml) runs on every push to `main`: it builds and tests, then tags `vX.Y.Z` and creates a GitHub Release. Nothing is ever pushed to `main` by CI.

The bump comes from the PR titles (squash commit subjects) since the previous tag:

| Title | Bump |
|---|---|
| `feat: ...` | minor |
| `fix:`, `perf:`, `refactor:`, `docs:`, `chore:`, ... | patch |
| `feat!: ...` / `type!: ...` or `BREAKING CHANGE` in the body | minor (a breaking change never bumps the major automatically) |

- The first release is `v0.1.0`.
- A merge that changes no Go file since the last tag (no `*.go`, `go.mod`, `go.sum`) is not released.
- **Major bumps are manual**: **Actions > Release > Run workflow**, `bump = major` (or `minor`/`patch` to force one).
- From v2 on a Go module needs a new path. Before running a major bump, change `module` in `go.mod` to `github.com/huponx/gocommon/v2` and every import to the same prefix, merge that, then run the release. The workflow refuses a tag whose major does not match the module path (`v2.0.0` needs `/v2`, `v0`/`v1` must have no `/vN`).

## Setup (one time)

```bash
REPO=huponx/gocommon
```

1. **Merge the workflows to `main` first**, while `main` is unprotected. The checks only appear in the ruleset picker after they have run once.
2. **Repository settings**: squash merge only, so the PR title is the commit subject.
   ```bash
   gh api -X PATCH repos/$REPO -F allow_squash_merge=true -F allow_merge_commit=false \
     -F allow_rebase_merge=false -F delete_branch_on_merge=true \
     -f squash_merge_commit_title=PR_TITLE -f squash_merge_commit_message=PR_BODY
   ```
3. **Token** (optional until you add a tag ruleset): `BOT_TOKEN`, a fine-grained PAT with Contents: Read and write on this repo.
   ```bash
   gh secret set BOT_TOKEN --repo $REPO     # prompts for the value; or: pbpaste | gh secret set BOT_TOKEN --repo $REPO
   ```
   Without it `release.yml` falls back to `GITHUB_TOKEN`, which works as long as no ruleset restricts tags.
4. **Branch protection** for `main`: save as `main-ruleset.json` and apply.
   ```json
   {
     "name": "protect main",
     "target": "branch",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
     "rules": [
       { "type": "deletion" },
       { "type": "non_fast_forward" },
       { "type": "pull_request", "parameters": {
           "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": false,
           "require_code_owner_review": false, "require_last_push_approval": false,
           "required_review_thread_resolution": false } },
       { "type": "required_status_checks", "parameters": {
           "strict_required_status_checks_policy": true,
           "required_status_checks": [ { "context": "verify" }, { "context": "pr-title" } ] } }
     ],
     "bypass_actors": []
   }
   ```
   Apply it (run from the folder containing the file; the file is only an input, do not commit it):
   ```bash
   gh api repos/$REPO/rulesets --method POST --input main-ruleset.json
   gh api repos/$REPO/rulesets --jq '.[] | {id, name, enforcement}'   # verify
   ```
   Or in the UI: **Settings > Rules > Rulesets > New ruleset > Import a ruleset**. To change it later: `gh api repos/$REPO/rulesets/<id> --method PUT --input main-ruleset.json`. Rulesets on a private repo need a paid GitHub plan.
5. **Tag protection** (optional): released tags must never move or be deleted.
   ```json
   {
     "name": "protect release tags",
     "target": "tag",
     "enforcement": "active",
     "conditions": { "ref_name": { "include": ["refs/tags/v*.*.*"], "exclude": [] } },
     "rules": [ { "type": "update" }, { "type": "deletion" }, { "type": "non_fast_forward" } ],
     "bypass_actors": []
   }
   ```
   ```bash
   gh api repos/$REPO/rulesets --method POST --input tag-ruleset.json
   ```
   If you also restrict tag *creation*, add the `creation` rule with a bypass for the admin role (`{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}`) and set `BOT_TOKEN`.
6. **Private module**: services that import it need `GOPRIVATE=github.com/huponx/*` and git credentials that can read the repo.

### Troubleshooting

| Symptom | Cause |
|---|---|
| `verify` fails on `go mod tidy` | go.mod/go.sum not tidy; run `go mod tidy`, commit the result |
| `verify` or `pr-title` stuck at "Expected" | PR has a merge conflict, or the workflows are not on `main` yet |
| nothing was released after a merge | no Go file changed since the last tag, or `HEAD` is already tagged (see the run summary) |
| released as patch but a minor was expected | the PR title did not start with `feat`; with squash merge only the title counts |
| Release fails with "does not match tag" | major bump without the `/vN` module path (or a `/vN` path on a v0/v1 tag); see Releases |
| `go get` cannot find the new version | the Go proxy caches misses; retry later or use `GOFLAGS=-mod=mod GOPROXY=direct` |