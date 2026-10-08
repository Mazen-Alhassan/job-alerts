# Job alerts: security internships straight to your phone

Around the clock, every ~90 seconds, this checks ~5,100 company job boards across 15 hiring systems (Greenhouse,
Lever, Ashby, Workday, Oracle, Phenom, Eightfold, iCIMS, SuccessFactors, SmartRecruiters, Workable, Rippling,
Jobvite, Jibe, Radancy), custom fetchers for Microsoft, Google, Apple, Amazon, Netflix, TikTok, Cisco, Kinaxis,
Shopify and CSE, the Simplify internship feeds, LinkedIn's public job search and Indeed, and pushes any NEW
security internship / co-op to your phone.
Tap the notification and it opens the application page.

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

- Each run scans in a loop for ~5.7 hours and then starts the next run itself, so it's always on.
  Workday boards are checked every ~3 min (your core list) or ~10 min (the big discovered list), LinkedIn every ~7 min,
  everything else every ~90s. A schedule every 30 min restarts the chain if it ever breaks.
- Stop it: `gh workflow disable alerts.yml`. Start again: `gh workflow enable alerts.yml && gh workflow run alerts.yml`.
- Code changes take effect on the next run (within ~6h). To apply now: cancel the running run, then `gh workflow run alerts.yml`.
- If most boards fail to load, or a notification can't be sent, GitHub marks the run failed and emails you.
- Add a company: add its board name to `boards.json` (find it in the company's careers URL, e.g.
  `boards.greenhouse.io/COMPANY`, `jobs.lever.co/COMPANY`, `jobs.ashbyhq.com/COMPANY`).
- Change what counts as a match: edit the `SEC` / `INT` patterns near the top of `scan.py`.
- Test your phone any time: add `NTFY_TOPIC` in your terminal and run `python scan.py --test`.

## What it can NOT see directly

Tesla and Meta block automated checks. Tesla and Meta internships usually still show up through
the Simplify feed or LinkedIn, just later. It also can't see your Carleton co-op portal.
