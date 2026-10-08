#!/usr/bin/env python3
"""
Job alert scanner.
Checks company job boards (plus Simplify's internship feeds and LinkedIn) for new security
internships / co-ops and pushes each new one to your phone.

Usage:
  python scan.py                 one scan (alerts on new roles)
  python scan.py --loop MIN      keep scanning for MIN minutes (what the GitHub workflow runs)
  python scan.py --commit        with --loop: git commit + push seen.json when it changes
  python scan.py --test          send one test notification and exit
  python scan.py --only PREFIX   scan only tasks whose key starts with PREFIX (debugging, nothing saved)

Env (set any or all; channels without settings are skipped):
  NTFY_TOPIC            ntfy topic name
  TELEGRAM_BOT_TOKEN    token from @BotFather
  TELEGRAM_CHAT_ID      your chat id (from @userinfobot)
  DISCORD_WEBHOOK_URL   webhook URL from your Discord channel's Integrations settings
If none are set, it just prints what it would send.
"""
import concurrent.futures as cf
import datetime as dt
import html
import json
import os
import re
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import zlib
from http.cookiejar import CookieJar

HERE = os.path.dirname(os.path.abspath(__file__))
STATE_FILE = os.path.join(HERE, "seen.json")
BOARDS = json.load(open(os.path.join(HERE, "boards.json")))
TOPIC = os.environ.get("NTFY_TOPIC", "").strip()
TG_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TG_CHAT = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
DISCORD = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
TG_API = os.environ.get("TELEGRAM_API", "https://api.telegram.org")  # override only for testing
PUSH_ERRORS = []

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
BAD = re.compile(
    r"(?i:securities|system on chip|security guard|security officer|ASIC|silicon|tegra|GPU and SOC|"
    r"SOC design|SOC verification|custom SOC)|\bSoC\b"
)
FOREIGN = re.compile(
    r"Singapore|Malaysia|Kuala Lumpur|Manila|Philippines|United Kingdom|\bUK\b|England|Scotland|Bristol|London|"
    r"Manchester|Edinburgh|Belfast|India\b|Bangalore|Bengaluru|Hyderabad|Pune|Chennai|Gurgaon|Gurugram|Noida|Mumbai|"
    r"Ireland|Dublin|Cork|Poland|Warsaw|Krakow|Israel|Tel Aviv|Japan|Tokyo|Germany|Berlin|Munich|France|Paris|"
    r"Spain|Madrid|Barcelona|Italy|Milan|Portugal|Lisbon|Brazil|S[aã]o Paulo|Mexico|Guadalajara|Monterrey|"
    r"Quer[eé]taro|China|Shanghai|Beijing|Shenzhen|Taiwan|Taipei|Korea|Seoul|Australia|"
    r"New Zealand|Auckland|Costa Rica|Romania|Bucharest|Czech|Prague|Hungary|Budapest|Netherlands|Amsterdam|"
    r"Belgium|Switzerland|Zurich|Austria|Vienna|Sweden|Stockholm|Denmark|Copenhagen|Norway|Finland|Hong Kong|"
    r"Dubai|United Arab Emirates|\bUAE\b|Saudi|Riyadh|Qatar|Doha|Egypt|Cairo|South Africa|Nigeria|Kenya|"
    r"Vietnam|Indonesia|Jakarta|Thailand|Bangkok|Argentina|Colombia|Chile|Peru|Turkey|Istanbul|Ukraine|"
    r"Pakistan|Serbia|Greece|Luxembourg|EMEA|APAC|LATAM",
    re.I,
)
CANADA = re.compile(r"Canada|Ottawa|Toronto|Kanata|Montreal|Vancouver|Calgary|Waterloo|, (ON|QC|BC|AB)\b", re.I)
US = re.compile(
    r"United States|\bUSA?\b|, (A[LKZR]|C[AOT]|D[EC]|FL|GA|HI|I[ADLN]|K[SY]|LA|M[ADEINOST]|N[CDEHJMVY]|O[HKR]|PA|RI|"
    r"S[CD]|T[NX]|UT|V[AT]|W[AIVY])\b"
)

# Readable company names. boards.json "names" covers most boards; these override it.
NAMES = BOARDS.get("names", {})
NAMES.update({
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
})

# In --loop mode a scan cycle starts every CYCLE seconds. Cheap single-request boards run every cycle;
# heavier or rate-limited sources run every Nth cycle (by task-key prefix), staggered so each cycle gets a slice.
CYCLE = 90
EVERY = {"wd:": 2, "wd+:": 7, "sr:": 3, "linkedin": 5}
WD_SLOTS = threading.BoundedSemaphore(16)  # Workday rate-limits per IP across all its tenants


def nice(t):
    return NAMES.get(t) or (t if t != t.lower() else t.title())


def foreign(loc):
    """True only if every listed location is outside the US/Canada (multi-location posts with one US/CA spot are kept)."""
    parts = [p for p in re.split(r"[;|]| / ", loc or "") if p.strip()]
    return bool(parts) and all(FOREIGN.search(p) and not (US.search(p) or CANADA.search(p)) for p in parts)


def want(title, loc=""):
    return bool(SEC.search(title) and INT.search(title) and not BAD.search(title) and not foreign(loc))


def http(url, data=None, headers=None, timeout=25, opener=None):
    h = dict(UA)
    if data is not None:
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=h)
    fetch = opener.open if opener else urllib.request.urlopen
    return fetch(req, timeout=timeout).read().decode("utf-8", "ignore")


def getj(url, data=None, headers=None, opener=None):
    return json.loads(http(url, data, headers, opener=opener))


def job(url, company, title, loc="", date="", note="", raw_company=False):
    return {"url": url.split("?utm")[0], "company": company if raw_company else nice(company), "title": title.strip(),
            "loc": loc or "", "date": date or "", "note": note}


def day(ts):
    return str(dt.datetime.fromtimestamp(ts, dt.timezone.utc).date()) if ts else ""


# ---------------- fetchers: each returns a list of matching jobs ----------------
def greenhouse(t):
    out = []
    for j in getj(f"https://boards-api.greenhouse.io/v1/boards/{t}/jobs").get("jobs", []):
        loc = j["location"]["name"]
        if want(j["title"], loc):
            out.append(job(j["absolute_url"], t, j["title"], loc, (j.get("first_published") or "")[:10]))
    return out


LEVER_DATES = {}


def lever(t):
    # the HTML board lists titles only (the API ships every description, 20-60x slower on big boards)
    out = []
    try:
        page = http(f"https://jobs.lever.co/{t}", headers={"Accept": "text/html"})
    except urllib.error.HTTPError as e:  # some companies hide the hosted page but keep the API
        if e.code != 404:
            raise
        return lever_api(t)
    for pid, url, title, loc in re.findall(
            r'data-qa-posting-id="([^"]+)">.*?<a class="posting-title" href="([^"]+)">.*?<h5 data-qa="posting-name">(.*?)</h5>'
            r'.*?location">(.*?)</span>', page, re.S):
        title, loc = html.unescape(title), html.unescape(loc)
        if want(title, loc):
            if pid not in LEVER_DATES:  # the posting API is slow, so look each date up once per run
                try:
                    LEVER_DATES[pid] = day(getj(f"https://api.lever.co/v0/postings/{t}/{pid}")["createdAt"] / 1000)
                except Exception:
                    pass
            out.append(job(url, t, title, loc, LEVER_DATES.get(pid, "")))
    return out


def lever_api(t):
    out = []
    for p in getj(f"https://api.lever.co/v0/postings/{t}?mode=json"):
        loc = p["categories"].get("location") or ""
        if want(p["text"], loc):
            out.append(job(p["hostedUrl"], t, p["text"], loc, day(p["createdAt"] / 1000)))
    return out


def ashby(t):
    # the hosted board page embeds every posting's title (~40x smaller than the public API, which ships descriptions)
    page = http(f"https://jobs.ashbyhq.com/{t}", headers={"Accept": "text/html"})
    i = page.find("window.__appData = ")
    if i < 0:
        raise RuntimeError("no app data")
    data = json.JSONDecoder().raw_decode(page, i + len("window.__appData = "))[0]
    out = []
    for j in (data.get("jobBoard") or {}).get("jobPostings") or []:
        loc = "; ".join([j.get("locationName") or ""] + [x.get("locationName", "") for x in j.get("secondaryLocations") or []])
        if want(j["title"], loc):
            out.append(job(f"https://jobs.ashbyhq.com/{t}/{j['id']}", t, j["title"], loc))
    return out


def smartrecruiters(t):
    out = {}
    for q in ("intern", "co-op", "internship"):
        d = getj(f"https://api.smartrecruiters.com/v1/companies/{t}/postings?q={q}&limit=100")
        for p in d.get("content", []):
            l = p.get("location") or {}
            loc = ", ".join(x for x in (l.get("city"), l.get("region"), (l.get("country") or "").upper()) if x)
            if want(p["name"], loc):
                out[p["id"]] = job(f"https://jobs.smartrecruiters.com/{t}/{p['id']}", t, p["name"], loc, (p.get("releasedDate") or "")[:10])
    return list(out.values())


# Workday search is relevance-ranked OR matching, so these pull the intern + security postings to the top.
WD_QUERIES = (("security intern", 2), ("cyber", 1), ("security co-op", 1))


def wd_post(url, body):
    for attempt in range(2):
        with WD_SLOTS:
            try:
                return getj(url, body)
            except urllib.error.HTTPError as e:
                if e.code != 429 or attempt:
                    raise
        time.sleep(3)


def workday(spec):
    host, tenant, site = spec
    found = {}
    url = f"https://{host}/wday/cxs/{tenant}/{site}/jobs"
    for q, pages in WD_QUERIES:
        for off in range(0, 20 * pages, 20):
            body = json.dumps({"appliedFacets": {}, "limit": 20, "offset": off, "searchText": q}).encode()
            d = wd_post(url, body)
            posts = d.get("jobPostings", [])
            for j in posts:
                loc = j.get("locationsText") or ""
                title = j.get("title") or ""
                if title and j.get("externalPath") and want(title, loc):
                    found[j["externalPath"]] = job(
                        f"https://{host}/en-US/{site}{j['externalPath']}", tenant, title, loc, j.get("postedOn", "")
                    )
            if len(posts) < 20 or off + 20 >= d.get("total", 0):
                break
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


def microsoft(_):
    # their API refuses requests without the session cookie the careers page sets
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    http("https://apply.careers.microsoft.com/careers?domain=microsoft.com", headers={"Accept": "text/html"}, opener=op)
    found = {}
    for q in ("security intern", "intern"):
        for start in (0, 10, 20):
            d = getj(f"https://apply.careers.microsoft.com/api/pcsx/search?domain=microsoft.com&query={urllib.parse.quote(q)}"
                     f"&location=&start={start}&sort_by=timestamp", opener=op,
                     headers={"Referer": "https://apply.careers.microsoft.com/careers?domain=microsoft.com"})
            for p in d.get("data", {}).get("positions", []):
                loc = "; ".join(p.get("locations") or [])
                if want(p.get("name", ""), loc):
                    found[p["id"]] = job(f"https://apply.careers.microsoft.com/careers/job/{p['id']}", "Microsoft", p["name"], loc, day(p.get("postedTs")))
    return list(found.values())


def google(_):
    found = {}
    for q in ("security", "cyber", "threat"):
        t = http(f"https://www.google.com/about/careers/applications/jobs/results/?q={q}&target_level=INTERN_AND_APPRENTICE&sort_by=date",
                 headers={"Accept": "text/html"})
        i = t.find("AF_initDataCallback({key: 'ds:1'")
        if i < 0:
            raise RuntimeError("page layout changed")
        s = t.find("data:", i) + 5
        for r in json.loads(t[s:t.find(", sideChannel", s)])[0] or []:
            jid, title = r[0], r[1]
            loc = "; ".join(x[0] for x in (r[9] or []) if x)
            if want(title if INT.search(title) else title + " intern", loc):  # every result here is an internship
                slug = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
                ts = r[12][0] if isinstance(r[12], list) and r[12] else 0
                found[jid] = job(f"https://www.google.com/about/careers/applications/jobs/results/{jid}-{slug}", "Google", title, loc, day(ts))
    return list(found.values())


def apple(_):
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    resp = op.open(urllib.request.Request("https://jobs.apple.com/api/v1/CSRFToken", headers=UA), timeout=25)
    token = resp.headers.get("x-apple-csrf-token", "")
    found = {}
    # Apple's US internships are broad pipeline postings (security sits inside "Software Engineering Internships"),
    # so like Shopify: alert on any new Students-team posting in the US/Canada, plus any security intern role.
    for q, page in (("internship", 1), ("internship", 2), ("internship", 3), ("security intern", 1)):
        body = {"query": q, "filters": {}, "page": page, "locale": "en-us", "sort": "relevance",
                "format": {"longDate": "MMMM D, YYYY", "mediumDate": "MMM D, YYYY"}}
        d = getj("https://jobs.apple.com/api/v1/search", json.dumps(body).encode(), opener=op,
                 headers={"x-apple-csrf-token": token, "Origin": "https://jobs.apple.com"})
        for r in d.get("res", {}).get("searchResults", []):
            loc = "; ".join(l.get("name", "") for l in r.get("locations", []))
            home = any(l.get("countryName") in ("United States", "United States of America", "Canada") for l in r.get("locations", []))
            student = ((r.get("team") or {}).get("teamCode") == "STDNT" and INT.search(r["postingTitle"])
                       and not re.search(r"MBA|Legal|Marketing|Product Design|Manufacturing|PhD", r["postingTitle"]))
            if (want(r["postingTitle"], loc) or student) and home:
                found[r["positionId"]] = job(f"https://jobs.apple.com/en-us/details/{r['positionId']}/{r.get('transformedPostingTitle', '')}",
                                             "Apple", r["postingTitle"], loc, (r.get("postDateInGMT") or "")[:10])
    return list(found.values())


def tiktok(_):
    found = {}
    for q in ("security intern", "security", "cyber"):
        body = {"recruitment_id_list": [], "job_category_id_list": [], "subject_id_list": [], "location_code_list": [],
                "keyword": q, "limit": 100, "offset": 0}
        d = getj("https://api.lifeattiktok.com/api/v1/public/supplier/search/job/posts", json.dumps(body).encode(),
                 headers={"website-path": "tiktok", "Origin": "https://lifeattiktok.com"})
        for j in (d.get("data") or {}).get("job_post_list") or []:
            c = j.get("city_info") or {}
            country = ((c.get("parent") or {}).get("parent") or {}).get("en_name") or ""
            loc = ", ".join(x for x in (c.get("en_name"), country) if x)
            intern = ((j.get("recruit_type") or {}).get("en_name") or "") == "Intern"
            if want(j["title"], loc) or (intern and want(j["title"] + " intern", loc)):
                found[j["id"]] = job(f"https://lifeattiktok.com/search/{j['id']}", "TikTok", j["title"], loc)
    return list(found.values())


SIMPLIFY_FEEDS = {
    "simplify": "https://raw.githubusercontent.com/SimplifyJobs/Summer2027-Internships/dev/.github/scripts/listings.json",
    "simplify-vansh": "https://raw.githubusercontent.com/vanshb03/Summer2027-Internships/dev/.github/scripts/listings.json",
}


def simplify(feed):
    """Community-maintained internship lists (thousands of companies, incl. ones we can't scan directly)."""
    cutoff = time.time() - 7 * 86400  # ignore old listings that just got re-activated
    out = []
    for x in json.loads(http(SIMPLIFY_FEEDS[feed], headers={"Accept": "*/*"})):
        if not x.get("active") or not x.get("is_visible", True) or (x.get("date_posted") or 0) < cutoff:
            continue
        loc = "; ".join(x.get("locations") or [])
        title = x.get("title", "")
        if want(title if INT.search(title) else title + " intern", loc):  # everything in these lists is an internship
            sp = x.get("sponsorship") or ""
            note = sp if sp and sp not in ("Other", "Offers Sponsorship") else ""
            out.append(job(x["url"], x.get("company_name", "?"), title, loc, day(x.get("date_posted")), note, raw_company=True))
    return out


LI_QUERIES = [
    ("security intern", "Canada"), ("cybersecurity co-op", "Canada"), ("security intern", "United States"),
    ("cybersecurity intern", "United States"), ("security engineer intern", "United States"),
]


def linkedin(_):
    """LinkedIn's public (no login) job search, last 24h. Catches companies whose own boards we can't reach."""
    found, ok = {}, False
    for kw, loc in LI_QUERIES:
        try:
            t = http("https://www.linkedin.com/jobs-guest/jobs/api/seeMoreJobPostings/search?"
                     + urllib.parse.urlencode({"keywords": kw, "location": loc, "f_TPR": "r86400", "sortBy": "DD", "start": 0}),
                     headers={"Accept": "text/html"})
            ok = True
        except Exception:
            continue
        for card in t.split("<li>")[1:]:
            jid = re.search(r"jobPosting:(\d+)", card)
            title = re.search(r'base-search-card__title">\s*(.*?)\s*</h3>', card, re.S)
            comp = re.search(r'base-search-card__subtitle">.*?>\s*(.*?)\s*</a>', card, re.S)
            where = re.search(r'job-search-card__location">\s*(.*?)\s*</span>', card, re.S)
            when = re.search(r'datetime="([\d-]+)"', card)
            if not (jid and title):
                continue
            title, where = html.unescape(title.group(1)), html.unescape(where.group(1)) if where else ""
            if want(title, where):
                found[jid.group(1)] = job(f"https://www.linkedin.com/jobs/view/{jid.group(1)}",
                                          html.unescape(comp.group(1)) if comp else "?", title, where,
                                          when.group(1) if when else "", "via LinkedIn", raw_company=True)
        time.sleep(1)
    if not ok:
        raise RuntimeError("all queries blocked")
    return list(found.values())


def build_tasks():
    tasks = []
    tasks += [(f"gh:{t}", greenhouse, t) for t in BOARDS["gh"]]
    tasks += [(f"lever:{t}", lever, t) for t in BOARDS["lev"]]
    tasks += [(f"ashby:{t}", ashby, t) for t in BOARDS["ash"]]
    tasks += [(f"sr:{t}", smartrecruiters, t) for t in BOARDS.get("sr", [])]
    tasks += [(f"wd:{s[1]}/{s[2]}", workday, tuple(s)) for s in BOARDS["wd"]]
    tasks += [(f"wd+:{s[1]}/{s[2]}", workday, tuple(s)) for s in BOARDS.get("wd_more", [])]
    tasks += [(k, simplify, k) for k in SIMPLIFY_FEEDS]
    tasks += [(n, f, None) for n, f in (("amazon", amazon), ("cisco", cisco), ("kinaxis", kinaxis), ("shopify-page", shopify),
                                         ("microsoft", microsoft), ("google", google), ("apple", apple), ("tiktok", tiktok),
                                         ("linkedin", linkedin))]
    return tasks


def due(key, cycle):
    if cycle is None:
        return True
    n = next((c for p, c in EVERY.items() if key.startswith(p)), 1)
    return (cycle + zlib.crc32(key.encode())) % n == 0


# ---------------- dedupe across sources ----------------
def url_key(u):
    u = u.lower().split("#")[0]
    m = re.search(r"gh_jid=(\d+)", u) or re.search(r"greenhouse\.io/.*?/jobs/(\d+)", u)
    if m:
        return "gh:" + m.group(1)
    u = u.split("?")[0].rstrip("/").replace("/en-us/", "/").replace("://www.", "://")
    return u.replace("/apply", "")


def title_key(j):
    norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())
    return "t:" + norm(j["company"])[:12] + "|" + norm(j["title"])


# ---------------- notifications ----------------
def _post(url, payload, headers=None):
    h = {"Content-Type": "application/json", "User-Agent": "job-alerts (github actions, 1.0)"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=h)
    return urllib.request.urlopen(req, timeout=20).read()


def push(title, message, click=None, priority=4, tags=None):
    """Send one alert to every configured channel. A failing channel never blocks the others."""
    channels = []
    if TOPIC:
        body = {"topic": TOPIC, "title": title, "message": message, "priority": priority, "tags": tags or ["shield"]}
        if click:
            body["click"] = click
            body["actions"] = [{"action": "view", "label": "Apply", "url": click}]
        channels.append(("ntfy", lambda: _post("https://ntfy.sh", body)))
    if TG_TOKEN and TG_CHAT:
        text = f"<b>{html.escape(title, quote=False)}</b>\n{html.escape(message, quote=False)}"
        if click:
            text += f'\n<a href="{html.escape(click, quote=True)}">Open posting</a>'
        tg = {"chat_id": TG_CHAT, "text": text, "parse_mode": "HTML", "disable_web_page_preview": True}
        if click:
            tg["reply_markup"] = {"inline_keyboard": [[{"text": "Apply", "url": click}]]}
        channels.append(("telegram", lambda: _post(f"{TG_API}/bot{TG_TOKEN}/sendMessage", tg)))
    if DISCORD:
        content = f"\U0001F6A8 **{title}**\n{message}" + (f"\n<{click}>" if click else "")
        channels.append(("discord", lambda: _post(DISCORD, {"content": content[:1900], "username": "Job Alerts"})))
    if not channels:
        print(f"[dry run] PUSH: {title} | {message} | {click}")
        return
    for name, send in channels:
        try:
            send()
        except Exception as e:
            err = f"{name}: {str(e)[:80]}"
            PUSH_ERRORS.append(err)
            print("  push failed ->", err)


def describe(j):
    flag = "\U0001F341 " if CANADA.search(j["loc"]) or j["company"] in ("Kinaxis",) else ""
    title = f"{flag}NEW: {j['company']} - {j['title']}"[:120]
    bits = [b for b in (j["loc"][:120], f"posted {j['date']}" if j["date"] else "", j.get("note", "")) if b]
    return title, " | ".join(bits) or "tap to open"


# ---------------- scanning ----------------
def load_state():
    if not os.path.exists(STATE_FILE):
        return {"boards": {}, "alerted": {}}
    s = json.load(open(STATE_FILE))
    s.setdefault("alerted", {})
    s.pop("updated", None)  # old format kept a timestamp, which forced a commit every run
    return s


def save_state(state):
    today = dt.date.today()
    state["alerted"] = {k: d for k, d in state["alerted"].items()
                        if (today - dt.date.fromisoformat(d)).days <= (21 if k.startswith("t:") else 120)}
    json.dump(state, open(STATE_FILE, "w"), indent=1, sort_keys=True)


def scan(state, only=None, cycle=None):
    """One cycle: fetch every due source, alert on anything new. Returns (new_jobs, failed, changed)."""
    boards, alerted = state["boards"], state["alerted"]
    now = time.time()
    tasks = [t for t in build_tasks() if (only is None or t[0].startswith(only)) and due(t[0], cycle)]
    results, failed = {}, []
    with cf.ThreadPoolExecutor(64) as ex:
        futs = {ex.submit(fn, arg): key for key, fn, arg in tasks}
        for f in cf.as_completed(futs):
            key = futs[f]
            try:
                results[key] = f.result()
            except Exception as e:  # board unreachable this run: skip, keep old state
                failed.append(f"{key} ({str(e)[:40]})")

    new_jobs, seeded, changed = [], 0, False
    today = str(dt.date.today())
    for key, jobs in sorted(results.items()):
        urls = sorted({j["url"] for j in jobs})
        first = key not in boards
        old = set(boards.get(key, []))
        for j in jobs:
            keys = (url_key(j["url"]), title_key(j))
            if not first and j["url"] not in old and not any(k in alerted for k in keys):
                new_jobs.append(j)
            for k in keys:  # every role seen anywhere, so another source can't re-alert it while it's still up
                alerted[k] = today
        seeded += first
        if urls != boards.get(key):
            boards[key] = urls
            changed = True

    total = sum(len(v) for v in boards.values())
    stamp = dt.datetime.now().strftime("%H:%M:%S")
    print(f"[{stamp}] scanned {len(results)}/{len(tasks)} due | failed: {len(failed)} | tracking {total} | seeded: {seeded} | NEW: {len(new_jobs)} | {time.time() - now:.0f}s", flush=True)
    for f in failed[:10]:
        print("  unreachable:", f)

    for j in new_jobs[:10]:
        t, m = describe(j)
        print("  ALERT:", t, "|", j["url"])
        push(t, m, click=j["url"], priority=4, tags=["rotating_light"])
    if len(new_jobs) > 10:
        push(f"+{len(new_jobs) - 10} more new roles", "Check the Actions log in your job-alerts repo for the full list.", priority=3)
        for j in new_jobs[10:]:
            print("  ALERT (not pushed):", describe(j)[0], "|", j["url"])
    return new_jobs, failed, len(results), len(tasks), changed


def git_commit(msg):
    cmds = [["git", "add", "seen.json"], ["git", "commit", "-q", "-m", msg], ["git", "pull", "--rebase", "-q"], ["git", "push", "-q"]]
    if subprocess.run(["git", "diff", "--quiet", "--", "seen.json"], cwd=HERE).returncode == 0:
        return
    for c in cmds:
        r = subprocess.run(c, cwd=HERE, capture_output=True, text=True)
        if r.returncode:
            print("  git failed:", " ".join(c), r.stderr.strip()[:200])
            return


def main():
    if "--test" in sys.argv:
        push("Job alerts test", "If you see this, this channel is connected.", priority=3)
        on = [n for n, v in (("ntfy", TOPIC), ("telegram", TG_TOKEN and TG_CHAT), ("discord", DISCORD)) if v]
        print("test sent to:", ", ".join(on) if on else "nothing (no channels set)")
        if PUSH_ERRORS:
            print("errors:", PUSH_ERRORS)
        return 1 if PUSH_ERRORS else 0

    if "--only" in sys.argv:
        scan(load_state(), sys.argv[sys.argv.index("--only") + 1])
        return 0

    first_run = not os.path.exists(STATE_FILE)
    state = load_state()
    commit = "--commit" in sys.argv
    minutes = float(sys.argv[sys.argv.index("--loop") + 1]) if "--loop" in sys.argv else 0
    deadline = time.time() + minutes * 60
    last_commit, health, cycle = time.time(), [], 0 if minutes else None

    while True:
        start = time.time()
        new_jobs, failed, ok, ran, changed = scan(state, cycle=cycle)
        health.append(ok >= ran * 0.5)
        cycle = None if cycle is None else cycle + 1
        if first_run:
            n = sum(len(v) for v in state["boards"].values())
            push("Job alerts are live", f"Watching {len(state['boards'])} sources. Tracking {n} open security roles. You'll get an alert the moment a new one appears.", priority=3, tags=["white_check_mark"])
            first_run = False
        if changed or new_jobs:
            save_state(state)
        # commit right away after alerts (so a crash can't cause repeat alerts), otherwise at most every 15 min
        if commit and (new_jobs or time.time() - last_commit > 900):
            git_commit(f"update seen ({len(new_jobs)} new)" if new_jobs else "update seen")
            last_commit = time.time()
        if time.time() + CYCLE > deadline:
            break
        time.sleep(max(0, CYCLE - (time.time() - start)))

    save_state(state)
    if commit:
        git_commit("update seen")
    if PUSH_ERRORS:
        print("push errors:", PUSH_ERRORS)
    # mark the GitHub run failed (so you get an email) if most cycles had most boards failing, or a channel couldn't send
    return 1 if (sum(health) < len(health) * 0.5 or PUSH_ERRORS) else 0


if __name__ == "__main__":
    sys.exit(main())
