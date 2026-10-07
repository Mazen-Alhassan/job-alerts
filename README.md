# Job alerts: security internships straight to your phone

Every ~10 minutes this checks ~170 company job boards (Greenhouse, Lever, Ashby, Workday, Amazon,
Cisco, Kinaxis, and Shopify's internship page) and pushes any NEW security internship / co-op to your phone.
Tap the notification and it opens the company's own application page.

## Setup (about 10 minutes)

1. **Phone:** install the free **ntfy** app (iOS/Android). Tap "+" and subscribe to a topic with a long random
   name, like `mazen-jobs-k39fj2x8q1` (anyone who knows the name can read it, so make it unguessable).
2. **GitHub:** create a new **public** repo called `job-alerts` (public = unlimited free runs; nothing personal is in here).
3. Upload everything in this folder to it (drag and drop on the repo page).
   On a Mac the `.github` folder is hidden: press Cmd+Shift+. in Finder to see it. If it won't upload,
   click Add file > Create new file, type `.github/workflows/alerts.yml` as the name, and paste in that file's text.
4. Repo **Settings > Secrets and variables > Actions > New repository secret**:
   name `NTFY_TOPIC`, value = your topic name from step 1.
5. Repo **Actions** tab > enable workflows > **job-alerts** > **Run workflow**.
   Within a minute your phone should buzz with "Job alerts are live". That first run records everything
   that's already open so you only get alerts for NEW postings after that.

## Good to know

- GitHub's scheduler isn't exact: expect alerts roughly 10-30 minutes after a role goes up.
- GitHub pauses scheduled runs on repos with no activity for 60 days. If alerts stop, click "Enable" on the Actions tab.
- If most boards fail to load in a run, GitHub marks the run failed and emails you.
- Add a company: add its board name to `boards.json` (find it in the company's careers URL, e.g.
  `boards.greenhouse.io/COMPANY`, `jobs.lever.co/COMPANY`, `jobs.ashbyhq.com/COMPANY`).
- Change what counts as a match: edit the `SEC` / `INT` patterns near the top of `scan.py`.
- Test your phone any time: add `NTFY_TOPIC` in your terminal and run `python scan.py --test`.

## What it can NOT see

Tesla, Microsoft, Google, Meta, Apple, PwC and CSIS block automated checks, and LinkedIn-only postings
have no public company page. Cover those with phone alerts: LinkedIn saved searches (bell on), and an
Indeed alert for "Tesla security intern". It also can't see your Carleton co-op portal.
