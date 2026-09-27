# Deploying Robox (Vercel + Render)

Robox ships as two deployables:

| Piece | Location | Platform | What it does |
|---|---|---|---|
| Web dashboard | `apps/web` (Next.js) | **Vercel** | The public, clickable link users open |
| Rust API | `crates/robox-api` (Axum) | **Render** | Scans, rules, jobs, reports — the engine |

Users only ever open the **Vercel link**. The dashboard calls the Render API in the background, so the experience is a single URL.

The repo is already deployment-ready:

- The frontend reads the API base URL from `NEXT_PUBLIC_ROBOX_API` (`apps/web/app/page.tsx`, `apps/web/app/submit/page.tsx`).
- The API binds to the address in `ROBOX_BIND` (CLI flag `--bind`, see `crates/robox-api/src/main.rs`). Set `ROBOX_ALLOWED_ORIGIN` to your exact Vercel origin after deployment to restrict browser requests.
- `apps/web/vercel.json` pins the Vercel build settings.
- `render.yaml` (repo root) is a Render Blueprint that builds and starts the API with a `/health` health check.

---

## Step 1 — Deploy the Rust API on Render

1. Sign up / log in at [render.com](https://render.com) with GitHub.
2. Dashboard → **New → Blueprint**, pick the `Robox` repository, and **Apply** the blueprint.
   - Render reads `render.yaml` and creates one web service, `robox-api`.
   - The blueprint builds with `cargo build --release --bin robox-api --jobs 2` and starts with `./target/release/robox-api --bind 0.0.0.0:$PORT`.
   - `CARGO_PROFILE_RELEASE_LTO=false` and `CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16` are set on purpose: they keep peak compiler memory low so the build fits the 512 MB free instance. Remove them on larger plans for a fully optimized binary.
3. Wait for the build to finish (first build takes a few minutes) and open the service URL:
   `https://<your-service>.onrender.com/health` must return `{"status":"ok","service":"robox-api"}`.
4. Copy that base URL (no trailing slash) — you need it in Step 2.

The Blueprint generates `ROBOX_ADMIN_TOKEN`. Keep that value private. The protected `GET /api/v1/admin/audit-requests` endpoint returns at most 100 recent submissions when called with `Authorization: Bearer <token>`. It returns no data without the token.

To read requests from PowerShell, copy the token from your Render service's Environment page and run:

```powershell
$roboxAdminToken = Read-Host "Robox admin token"
$roboxApiUrl = "https://<your-service>.onrender.com"
Invoke-RestMethod -Uri "$roboxApiUrl/api/v1/admin/audit-requests?limit=50&offset=0" -Headers @{ Authorization = "Bearer $roboxAdminToken" }
```

Increase `offset` by 50 for the next page. Keep exported contact information private.

Manual alternative (no blueprint): **New → Web Service**, runtime **Rust**, same build/start commands, health check path `/health`.

## Step 2 — Deploy the dashboard on Vercel

1. Sign up / log in at [vercel.com](https://vercel.com) with GitHub.
2. **Add New → Project**, import the `Robox` repository.
3. Configure:
   - **Framework Preset:** Next.js (auto-detected)
   - **Root Directory:** `apps/web` ← important, the repo is a monorepo
   - Build/install commands come from `apps/web/vercel.json`.
4. **Environment Variables** (add for Production and Preview):
   - `NEXT_PUBLIC_ROBOX_API` = `https://<your-service>.onrender.com` ← the Render URL from Step 1, **no trailing slash**
5. **Deploy**.

After the Vercel URL is known, set `ROBOX_ALLOWED_ORIGIN` on Render to the exact origin, such as `https://robox-web.vercel.app`, and redeploy the API.

> `NEXT_PUBLIC_*` variables are inlined at build time. If you change the API URL later, you must **redeploy** the Vercel project for the change to take effect.

## Step 3 — Verify end to end

1. Open your Vercel URL (e.g. `https://robox-web.vercel.app`).
2. The sidebar should show the engine card with rules loaded (fetched live from `/api/v1/rules`).
3. Switch the import card to **GitHub**, paste a public Rust/Anchor repo (you can use `https://github.com/mansiverma897993/Robox` itself), and run a scan.
4. Findings, graph, and PDF/SARIF/JSON/Markdown report downloads should all work.

Share the Vercel URL — that single link is the whole product.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Rules list empty / "API rule catalog unavailable" | `NEXT_PUBLIC_ROBOX_API` missing or wrong (check for a trailing slash), or the Render service is asleep. |
| First request after idle is very slow | Render free instances sleep after ~15 min of inactivity; the first request wakes them (~30–60 s). |
| Render build fails with a compiler error / OOM | Keep the `CARGO_PROFILE_RELEASE_*` overrides from `render.yaml`, or upgrade the instance. |
| GitHub scan returns "GitHub clone failed" | The URL must be public and match `https://github.com/owner/repository`; private repos are rejected by design. |
| Changed the API URL but frontend still calls the old one | Redeploy on Vercel — `NEXT_PUBLIC_*` values are baked in at build time. |

## Operational notes

- Scan history and job state live in process memory and disappear after a restart. Audit requests live in SQLite. The default free Render instance has an ephemeral filesystem, so **real submitted contact data can disappear after redeploy or restart**. Do not rely on the free configuration to collect customer leads. Before accepting real submissions, move the service to a paid plan with a persistent disk mounted at `/var/data` and set `ROBOX_DATABASE=/var/data/robox.sqlite3`, or use a durable database integration.
- The paid persistent disk is a billing decision and is not enabled by this repository. [Render's disk documentation](https://render.com/docs/disks) describes current plan and backup constraints.
- `ROBOX_ALLOWED_ORIGIN` restricts browser access, but it is not authentication. The anonymous scan and intake endpoints still need external abuse protection such as request rate limiting at the edge for a public launch.
- API path scans are disabled by default. Set `ROBOX_ALLOW_PATH_SCAN=1` only for a trusted local API; never set it on the public Render service.
- Local development is unchanged: `scripts/dev.ps1` (Windows) or `scripts/dev.sh` (macOS/Linux) still runs both processes locally.
