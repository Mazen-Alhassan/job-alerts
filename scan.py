#!/usr/bin/env python3
"""
Job alert scanner.
Checks company job boards for new security internships / co-ops and pushes
each new one to your phone through ntfy (free app, no account).

Usage:
  python scan.py            normal run (alerts on new roles)
  python scan.py --test     send one test notification and exit

Env:
  NTFY_TOPIC   your private ntfy topic name (if empty, it just prints what it would send)
"""
import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import sys
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(HERE, "seen.json")
BOARDS = json.load(open(os.path.join(HERE, "boards.json")))
TOPIC = os.environ.get("NTFY_TOPIC", "").strip()

UA = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
    "Accept": "application/json",
}

# ---- what counts as a match (edit these to taste) ----
SEC = re.compile(
    r"secur|cyber|threat|red team|offensive|appsec|infosec|detection|penetration|"
    r"vulnerab|incident|forensic|\bSOC\b|identity|\bIAM\b|\bGRC\b",
    re.I,
)
INT = re.compile(
    r"\bintern\b|\binterns\b|internship|\bco-?op\b|student|new grad|early career|apprentice|stagiaire",
    re.I,
)
BAD = re.compile(r"(?i:securities|system on chip|security guard|security officer)|\bSoC\b")
FOREIGN = re.compile(
    r"Singapore|Malaysia|Manila|United Kingdom|Bristol|London|India|Bangalore|Hyderabad|Ireland|"
    r"Dublin|Poland|Warsaw|Israel|Tel Aviv|Japan|Tokyo|Germany|France|Spain|Brazil|Mexico|China|"
    r"Taiwan|Korea|Australia|Philippines|Costa Rica|Romania|Czech|Netherlands|Hong Kong|Sydney|"
    r"Berlin|Munich|Amsterdam|Zurich|Dubai",
    re.I,
)
CANADA = re.compile(r"Canada|Ottawa|Toronto|Kanata|Montreal|Vancouver|Calgary|Waterloo|, (ON|QC|BC|AB)\b", re.I)


NAMES = {
    "figureai": "Figure AI", "globalhr": "RTX", "ngc": "Northrop Grumman", "bb": "BlackBerry", "td": "TD",
    "rb": "Federal Reserve", "hp": "HP", "sec": "Samsung", "spe": "Sony Pictures", "caci": "CACI",
    "atcllc": "American Transmission", "aero": "Aerospace Corp", "fmr": "Fidelity", "aig": "AIG", "cai": "CAI",
    "selinc": "SEL", "spacex": "SpaceX", "scaleai": "Scale AI", "janestreet": "Jane Street", "rocketlab": "Rocket Lab",
    "memx": "MEMX", "dukeenergy": "Duke Energy", "archgroup": "Arch Capital", "trendmicro": "Trend Micro",
    "paloaltonetworks": "Palo Alto Networks", "crowdstrike": "CrowdStrike", "snapchat": "Snap", "usbank": "U.S. Bank",
    "bmo": "BMO", "cibc": "CIBC", "rbc": "RBC", "bdo": "BDO", "swbc": "SWBC", "upbound": "Upbound", "cleco": "Cleco",
    "mastercard": "Mastercard", "capitalone": "Capital One", "manulife": "Manulife", "nvidia": "NVIDIA",
    "salesforce": "Salesforce", "intel": "Intel", "disney": "Disney", "otis": "Otis", "tanium": "Tanium",
    "robinhood": "Robinhood", "datadog": "Datadog", "cloudflare": "Cloudflare", "palantir": "Palantir",
    "tevora": "Tevora", "magnetforensics": "Magnet Forensics", "telesat": "Telesat", "1password": "1Password",
    "wealthsimple": "Wealthsimple", "coinbase": "Coinbase", "stripe": "Stripe", "anthropic": "Anthropic",
    "entrust": "Entrust", "ciena": "Ciena", "lumentum": "Lumentum", "marvell": "Marvell", "leidos": "Leidos",
}


def nice(t):
    return NAMES.get(t, t.title())


def want(title, loc=""):
    return bool(
        SEC.search(title) and INT.search(title) and not BAD.search(title) and not FOREIGN.search(loc or "")
    )


def http(url, data=None, headers=None, timeout=25):
    h = dict(UA)
    if data is not None:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h)
    return urllib.request.urlopen(req, timeout=timeout).read().decode("utf-8", "ignore")


def getj(url, data=None):
    return json.loads(http(url, data))


def job(url, company, title, loc="", date=""):
    return {"url": url.split("?utm")[0], "company": nice(company), "title": title, "loc": loc or "", "date": date or ""}


# ---------------- fetchers: each returns a list of matching jobs ----------------
def greenhouse(t):
    out = []
    for j in getj(f"https://boards-api.greenhouse.io/v1/boards/{t}/jobs").get("jobs", []):
        loc = j["location"]["name"]
        if want(j["title"], loc):
            try:
                date = getj(f"https://boards-api.greenhouse.io/v1/boards/{t}/jobs/{j['id']}").get("first_published", "")[:10]
            except Exception:
                date = ""
            out.append(job(j["absolute_url"], t, j["title"], loc, date))
    return out


def lever(t):
    out = []
    for p in getj(f"https://api.lever.co/v0/postings/{t}?mode=json"):
        loc = p["categories"].get("location") or ""
        if want(p["text"], loc):
            date = str(dt.datetime.fromtimestamp(p["createdAt"] / 1000, dt.timezone.utc).date())
            out.append(job(p["hostedUrl"], t, p["text"], loc, date))
    return out


def ashby(t):
    out = []
    for j in getj(f"https://api.ashbyhq.com/posting-api/job-board/{t}").get("jobs", []):
        loc = j.get("location") or ""
        if want(j["title"], loc):
            out.append(job(j["jobUrl"], t, j["title"], loc, (j.get("publishedAt") or "")[:10]))
    return out


def workday(spec):
    host, tenant, site = spec
    found = {}
    ok = False
    for q in ("security intern", "cyber", "security co-op"):
        url = f"https://{host}/wday/cxs/{tenant}/{site}/jobs"
        for off in range(0, 100, 20):
            body = json.dumps({"appliedFacets": {}, "limit": 20, "offset": off, "searchText": q}).encode()
            d = getj(url, body)
            ok = True
            posts = d.get("jobPostings", [])
            for j in posts:
                loc = j.get("locationsText") or ""
                title = j.get("title") or ""
                if title and j.get("externalPath") and want(title, loc):
                    found[j["externalPath"]] = job(
                        f"https://{host}/en-US/{site}{j['externalPath']}", tenant, title, loc, j.get("postedOn", "")
                    )
            if not posts or off + 20 >= d.get("total", 0):
                break
    if not ok:
        raise RuntimeError("no response")
    return list(found.values())


def amazon(_):
    found = {}
    for q in ("security intern", "security co-op", "cyber intern"):
        d = getj(f"https://www.amazon.jobs/en/search.json?base_query={urllib.parse.quote(q)}&result_limit=50&sort=recent")
        for j in d.get("jobs", []):
            loc = j.get("location", "")
            if want(j["title"], loc):
                found[j["job_path"]] = job("https://www.amazon.jobs" + j["job_path"], "Amazon", j["title"], loc, j.get("posted_date", ""))
    return list(found.values())


def cisco(_):
    found = {}
    for country in (["Canada"], None):
        for kw in ("security intern", "security co-op", "cyber intern"):
            body = {
                "lang": "en_global", "deviceType": "desktop", "country": "global", "pageName": "search-results",
                "ddoKey": "refineSearch", "sortBy": "Most recent", "subsearch": "", "from": 0, "jobs": True,
                "counts": True, "all_fields": ["category", "country", "state", "city", "type"], "size": 50,
                "clearAll": False, "jdsource": "facets", "isSliderEnable": False, "pageId": "page20",
                "siteType": "external", "keywords": kw, "global": True, "locationData": {},
            }
            if country:
                body["selected_fields"] = {"country": country}
            d = getj("https://careers.cisco.com/widgets", json.dumps(body).encode())
            for j in d.get("refineSearch", {}).get("data", {}).get("jobs", []):
                loc = j.get("location", "")
                if want(j.get("title", ""), loc):
                    found[j["jobId"]] = job(f"https://careers.cisco.com/global/en/job/{j['jobId']}", "Cisco", j["title"], loc, (j.get("postedDate") or "")[:10])
    return list(found.values())


def kinaxis(_):
    found = {}
    for q in ("co-op", "intern", "security"):
        t = http(f"https://careers-kinaxis.icims.com/jobs/search?ss=1&searchKeyword={q}&in_iframe=1")
        for jid, slug in re.findall(r"/jobs/(\d+)/([a-z0-9%\-\.]+)/job", t):
            title = urllib.parse.unquote(slug).replace("--", " / ").replace("-", " ").replace("co op", "co-op")
            if want(title):
                found[jid] = job(f"https://careers-kinaxis.icims.com/jobs/{jid}/{slug}/job", "Kinaxis", title.title().replace("Co-Op","Co-op"), "Ottawa (Kanata), ON")
    return list(found.values())


def shopify(_):
    """Alerts on ANY new posting on Shopify's internship page (they hide security inside general SWE postings)."""
    t = http("https://internships.shopify.com/")
    out = {}
    for m in re.findall(r"https://www\.shopify\.com/careers/[a-z0-9\-]+_[0-9a-f\-]{36}", t):
        title = m.split("/careers/")[1].split("_")[0].replace("-", " ").title().replace("Us ", "US ").replace("Swe", "SWE")
        out[m] = job(m, "Shopify", title, "see posting")
    if not out:
        raise RuntimeError("no links found")
    return list(out.values())


def build_tasks():
    tasks = []
    tasks += [(f"gh:{t}", greenhouse, t) for t in BOARDS["gh"]]
    tasks += [(f"lever:{t}", lever, t) for t in BOARDS["lev"]]
    tasks += [(f"ashby:{t}", ashby, t) for t in BOARDS["ash"]]
    tasks += [(f"wd:{s[1]}/{s[2]}", workday, tuple(s)) for s in BOARDS["wd"]]
    tasks += [("amazon", amazon, None), ("cisco", cisco, None), ("kinaxis", kinaxis, None), ("shopify-page", shopify, None)]
    return tasks


# ---------------- notifications ----------------
def push(title, message, click=None, priority=4, tags=None):
    if not TOPIC:
        print(f"[dry run] PUSH: {title} | {message} | {click}")
        return
    body = {"topic": TOPIC, "title": title, "message": message, "priority": priority, "tags": tags or ["shield"]}
    if click:
        body["click"] = click
        body["actions"] = [{"action": "view", "label": "Apply", "url": click}]
    req = urllib.request.Request("https://ntfy.sh", data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=20).read()


def describe(j):
    flag = "\U0001F341 " if CANADA.search(j["loc"]) or j["company"] in ("Kinaxis",) else ""
    title = f"{flag}NEW: {j['company']} - {j['title']}"[:120]
    bits = [b for b in (j["loc"], f"posted {j['date']}" if j["date"] else "") if b]
    return title, " | ".join(bits) or "tap to open"


def main():
    if "--test" in sys.argv:
        push("Job alerts test", "If you see this, your phone is connected.", priority=3)
        print("test sent" if TOPIC else "no NTFY_TOPIC set, nothing sent")
        return 0

    first_run = not os.path.exists(STATE_FILE)
    state = {} if first_run else json.load(open(STATE_FILE))
    boards = state.get("boards", {})

    tasks = build_tasks()
    results, failed = {}, []
    with cf.ThreadPoolExecutor(24) as ex:
        futs = {ex.submit(fn, arg): key for key, fn, arg in tasks}
        for f in cf.as_completed(futs):
            key = futs[f]
            try:
                results[key] = f.result()
            except Exception as e:  # board unreachable this run: skip, keep old state
                failed.append(f"{key} ({str(e)[:40]})")

    new_jobs, seeded = [], 0
    for key, jobs in results.items():
        urls = [j["url"] for j in jobs]
        if key in boards:
            old = set(boards[key])
            for j in jobs:
                if j["url"] not in old:
                    new_jobs.append(j)
        else:
            seeded += 1  # first time we see this board: record silently, no alerts
        boards[key] = urls

    state = {"boards": boards, "updated": dt.datetime.now(dt.timezone.utc).isoformat()}
    json.dump(state, open(STATE_FILE, "w"), indent=1, sort_keys=True)

    total = sum(len(v) for v in boards.values())
    print(f"boards ok: {len(results)}/{len(tasks)} | failed: {len(failed)} | tracking {total} postings | seeded boards: {seeded} | NEW: {len(new_jobs)}")
    for f in failed[:15]:
        print("  unreachable:", f)

    if first_run:
        push("Job alerts are live", f"Watching {len(results)} job boards. Tracking {total} open security roles. You'll get a push the moment a new one appears.", priority=3, tags=["white_check_mark"])
    else:
        for j in new_jobs[:10]:
            t, m = describe(j)
            push(t, m, click=j["url"], priority=4, tags=["rotating_light"])
        if len(new_jobs) > 10:
            push(f"+{len(new_jobs) - 10} more new roles", "Check the Actions log in your job-alerts repo for the full list.", priority=3)

    # if most boards failed, make the GitHub run show as failed so you get an email
    return 1 if len(results) < len(tasks) * 0.5 else 0


if __name__ == "__main__":
    sys.exit(main())
