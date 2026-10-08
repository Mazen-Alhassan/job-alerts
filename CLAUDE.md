# job-alerts

Scans ~2,400 sources for NEW security internships / co-ops (US + Canada) and pushes each one to the owner's
phone with an apply link. The point is to apply within minutes of a posting going live.

## How it works
- `scan.py`: stdlib-only Python. Fetches sources in parallel, keeps titles matching `SEC` (security words)
  AND `INT` (intern/co-op words), drops postings whose every location is outside the US/Canada (`FOREIGN`,
  with US-state / Canadian-province matches winning), diffs against `seen.json`, and alerts on anything new.
  A source seen for the first time is recorded silently (no alert flood).
- Dedupe: `seen.json` `alerted` holds a URL key (120 days) and a company+title key (21 days) for every role
  ever seen, so the same role found via two sources (e.g. Greenhouse and Simplify) only alerts once.
- `boards.json`: `gh` Greenhouse, `lev` Lever, `ash` Ashby, `sr` SmartRecruiters, `wd` core Workday
  `[host, tenant, site]` (checked every 2nd cycle), `wd_more` Workday boards discovered from Simplify (every 7th
  cycle), `names` readable company names. Most of these were mined from Simplify listing URLs and validated
  against each ATS API on Oct 7, 2026.
- Custom fetchers in scan.py: Amazon, Cisco, Kinaxis (iCIMS), Shopify internship page (alerts on ANY new posting),
  Microsoft (Eightfold, needs the careers-page cookie first), Google (parses `ds:1` page data), Apple (CSRF token;
  alerts on any new US/CA Students-team internship since Apple's security interns sit inside generic SWE postings),
  TikTok, Simplify feeds (SimplifyJobs + vanshb03 Summer2027 `listings.json`, last 7 days only), LinkedIn guest
  search (last 24h; links go to the LinkedIn posting, labeled "via LinkedIn").
- Speed tricks: Lever is read from the HTML board (API fallback when the page 404s), Ashby from the hosted page's
  `window.__appData` (public API is ~40x bigger, its GraphQL rate-limits at ~100 req), Workday requests are capped
  at 16 concurrent with one 429 retry (Workday rate-limits per IP across all tenants).
- `.github/workflows/alerts.yml`: a `gate` job + a `scan` job. `scan` runs `python scan.py --loop 340 --commit`
  (a cycle every 90s for ~5.7h, commits `seen.json` right after any alert, otherwise every 15 min), then
  dispatches the next run with GITHUB_TOKEN. The `7,37 * * * *` schedule is a watchdog: `gate` skips it if a
  run is already active. `test` input = send a test alert only.
- Channels: ntfy (`NTFY_TOPIC`) and Discord (`DISCORD_WEBHOOK_URL`) are in use. Telegram is supported
  in code but intentionally not configured. Missing secrets = channel skipped. All values live in
  GitHub Secrets only. Never write secret values into files in this repo (it's public).

## Commands
- One dry-run scan locally (prints instead of sending; full sweep, Workday may 429 from home): `python scan.py`
- Debug one source, nothing saved: `python scan.py --only microsoft` (any task-key prefix: `gh:`, `wd+:`, `simplify`...)
- Test alert to all configured channels: `python scan.py --test` (needs the env vars set)
- Start the scanner: `gh workflow run alerts.yml` (test only: `gh workflow run alerts.yml -f test=true`)
- Stop it: `gh workflow disable alerts.yml` (re-enable, then `gh workflow run alerts.yml`)
- Apply code changes now (otherwise next handoff, within ~6h): `gh run cancel <id>` then `gh workflow run alerts.yml`
- Recent runs / live log: `gh run list --workflow alerts.yml`, `gh run view <id> --log`
- Force a real alert for testing: remove one URL from a list in `seen.json` AND its keys from `alerted`, push,
  then restart the run.

## Adding a company
Find the board name in the careers URL and add it to the right list in `boards.json`:
`boards.greenhouse.io/NAME` -> gh, `jobs.lever.co/NAME` -> lev, `jobs.ashbyhq.com/NAME` -> ash,
`jobs.smartrecruiters.com/NAME` -> sr,
`TENANT.wdN.myworkdayjobs.com/en-US/SITE/...` -> wd `["TENANT.wdN.myworkdayjobs.com","TENANT","SITE"]`.
Verify before adding: `https://boards-api.greenhouse.io/v1/boards/NAME/jobs`, `https://api.lever.co/v0/postings/NAME`,
`https://api.ashbyhq.com/posting-api/job-board/NAME` (404 = wrong name). Add a readable name to `names`.

## Blind spots
Tesla and Meta block automated checks (their roles usually still arrive via Simplify/LinkedIn, later), PwC, CSIS,
Oracle HCM boards (JPMorgan, Goldman) and iCIMS boards other than Kinaxis are only covered via Simplify/LinkedIn,
and the Carleton co-op portal. `research/jobspy_search.py` covers LinkedIn/Indeed/Glassdoor when run from home.

## research/
- `jobspy_search.py`: searches LinkedIn, Indeed, Glassdoor for security internships posted in the last N hours.
- `roles_snapshot.json`: every live security role found by the manual sweeps up to Oct 7, 2026 (company, role,
  location, term, posted date, eligibility note, direct link). Use it to avoid re-reporting known roles.

## Conventions for job search output
- Direct employer application links only. Never Intern Insider / freehire / other login-walled aggregators.
- "New" means posted recently per the employer's own system (Greenhouse first_published, Ashby publishedAt,
  Workday postedOn), not just new to our list. State the posted date.
- Flag work-authorization limits from the posting (US citizens only, no sponsorship, grad-date windows).
  Simplify-sourced alerts include its sponsorship note when it says no sponsorship / citizenship required.
- Re-check links are live before reporting them.
