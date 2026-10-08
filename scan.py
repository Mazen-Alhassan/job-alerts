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
    r"(?i:securities|system on chip|security guard|security officer|forensic accounting|ASIC|silicon|tegra|GPU and SOC|"
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
    r"Pakistan|Serbia|Greece|Luxembourg|EMEA|APAC|LATAM|Brno|Hamburg|Frankfurt|Stuttgart|Cologne|D[uü]sseldorf|"
    r"Gen[eè]v[ea]|Lausanne|Basel|Le Sentier|Brussels|Antwerp|Assago|Rome|Turin|Lyon|Toulouse|Rotterdam|Eindhoven|"
    r"Knutsford|Leeds|Glasgow|Ho Chi Minh|Hanoi|Kuala|Penang|Cebu|Bogot[aá]|Medell[ií]n|Buenos Aires|Santiago de|"
    r"Krak[oó]w|Wroc[lł]aw|Gda[nń]sk|Cluj|Ia[sș]i|Sofia|Belgrade|Zagreb|Bratislava|Tallinn|Vilnius|Riga|Kyiv|Haifa",
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
LOOKBACK_DAYS = 7  # Simplify listings older than this are ignored; LinkedIn searches the last day (sweep widens both)
EVERY = {"wd:": 2, "wd+:": 7, "sr:": 3, "linkedin": 5, "jobspy": 5, "icims:": 4, "oracle:": 3, "workable:": 5,
         "rippling:": 3, "phenom:": 2, "eightfold:": 2, "sf:": 3, "jibe:": 2, "radancy:": 2}
WD_SLOTS = threading.BoundedSemaphore(16)  # Workday rate-limits per IP across all its tenants


def nice(t):
    return NAMES.get(t) or (t if t != t.lower() else t.title())


def foreign(loc):
    """True only if every listed location is outside the US/Canada (multi-location posts with one US/CA spot are kept)."""
    parts = [p for p in re.split(r"[;|]| / ", loc or "") if p.strip()]
    return bool(parts) and all(FOREIGN.search(p) and not (US.search(p) or CANADA.search(p)) for p in parts)


def want(title, loc=""):
    return bool(SEC.search(title) and INT.search(title) and not BAD.search(title) and not foreign(loc)
                and not re.search(r"\([mfwd]/[mfwd]/[mfwd]\)|Werkstudent|Praktikum|Stagiaire ing", title, re.I))


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


def norm_date(d):
    """ISO date from whatever a board gives us: ISO, 'October 1, 2026', or Workday's 'Posted 3 Days Ago'."""
    d = (d or "").strip()
    if re.match(r"\d{4}-\d{2}-\d{2}", d):
        return d[:10]
    today = dt.date.today()
    m = re.search(r"Posted (Today|Yesterday|(\d+)\+? Days? Ago)", d, re.I)
    if m:
        n = 0 if m.group(1).lower() == "today" else 1 if m.group(1).lower() == "yesterday" else int(m.group(2))
        return str(today - dt.timedelta(days=n))
    for fmt in ("%B %d, %Y", "%b %d, %Y"):
        try:
            return str(dt.datetime.strptime(d, fmt).date())
        except ValueError:
            pass
    return ""


def job(url, company, title, loc="", date="", note="", raw_company=False):
    return {"url": url.split("?utm")[0], "company": company if raw_company else nice(company), "title": title.strip(),
            "loc": loc or "", "date": norm_date(date), "note": note}


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
                    base = f"https://{host}/en-US/recruiting/{tenant}/{site}" if "myworkdaysite" in host else f"https://{host}/en-US/{site}"
                    found[j["externalPath"]] = job(base + j["externalPath"], tenant, title, loc, j.get("postedOn", ""))
            if len(posts) < 20 or off + 20 >= d.get("total", 0):
                break
    return list(found.values())


def oracle(spec):
    """Oracle Recruiting Cloud (JPMorgan and many banks/enterprises)."""
    host, site = spec
    found = {}
    for q in ("security intern", "cyber", "security co-op"):
        d = getj(f"https://{host}/hcmRestApi/resources/latest/recruitingCEJobRequisitions?onlyData=true"
                 f"&expand=requisitionList.secondaryLocations&finder=findReqs;siteNumber={site},"
                 f"keyword={urllib.parse.quote(q)},limit=50,sortBy=POSTING_DATES_DESC")
        for r in ((d.get("items") or [{}])[0].get("requisitionList") or []):
            loc = "; ".join([r.get("PrimaryLocation") or ""] + [x.get("Name", "") for x in r.get("secondaryLocations") or []])
            if want(r.get("Title", ""), loc):
                found[r["Id"]] = job(f"https://{host}/hcmUI/CandidateExperience/en/sites/{site}/job/{r['Id']}",
                                     host, r["Title"], loc, r.get("PostedDate", ""))
    return list(found.values())


def phenom(spec):
    """Phenom career sites (the /widgets search behind many big-company career pages, e.g. careers.X.com/us/en)."""
    host, path = spec
    region, lang = path.split("/")
    found = {}
    for kw in ("security intern", "cyber intern", "security co-op"):
        body = {"lang": f"{lang}_{region}", "deviceType": "desktop", "country": region, "pageName": "search-results",
                "ddoKey": "refineSearch", "sortBy": "Most recent", "subsearch": "", "from": 0, "jobs": True, "counts": True,
                "all_fields": ["category", "country", "state", "city", "type"], "size": 50, "clearAll": False,
                "jdsource": "facets", "isSliderEnable": False, "pageId": "page20", "siteType": "external",
                "keywords": kw, "global": True, "locationData": {}}
        d = getj(f"https://{host}/widgets", json.dumps(body).encode())
        for j in (((d.get("refineSearch") or {}).get("data") or {}).get("jobs") or []):
            loc = j.get("location") or ", ".join(x for x in (j.get("city"), j.get("country")) if x)
            if want(j.get("title", ""), loc):
                found[j["jobId"]] = job(f"https://{host}/{path}/job/{j['jobId']}", host, j["title"], loc, (j.get("postedDate") or "")[:10])
    return list(found.values())


def eightfold(spec):
    """Eightfold career sites (Qualcomm, PayPal, AmEx, NetApp...); the API needs the career page's session cookie."""
    host, domain = spec
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
    http(f"https://{host}/careers", headers={"Accept": "text/html"}, opener=op)
    found = {}
    for q in ("security intern", "intern"):
        for start in (0, 10, 20):
            d = getj(f"https://{host}/api/pcsx/search?domain={domain}&query={urllib.parse.quote(q)}&location=&start={start}&sort_by=timestamp",
                     opener=op, headers={"Referer": f"https://{host}/careers"})
            for p in (d.get("data") or {}).get("positions") or []:
                loc = "; ".join(p.get("locations") or [])
                if want(p.get("name", ""), loc):
                    found[p["id"]] = job(f"https://{host}/careers/job/{p['id']}", host, p["name"], loc, day(p.get("postedTs")))
    return list(found.values())


def icims(host):
    found = {}
    for q in ("security", "cyber"):
        t = http(f"https://{host}/jobs/search?ss=1&searchKeyword={q}&in_iframe=1", headers={"Accept": "text/html"})
        for jid, slug in re.findall(r"/jobs/(\d+)/([a-z0-9%\-\.]+)/job", t):
            title = urllib.parse.unquote(slug).replace("--", " / ").replace("-", " ").replace("co op", "co-op")
            if want(title):
                found[jid] = job(f"https://{host}/jobs/{jid}/{slug}/job", host, title.title().replace("Co-Op", "Co-op"))
    return list(found.values())


def workable(t):
    out = []
    d = getj(f"https://apply.workable.com/api/v3/accounts/{t}/jobs",
             json.dumps({"query": "", "location": [], "department": [], "worktype": [], "remote": []}).encode())
    for j in d.get("results", []):
        loc = "; ".join(", ".join(x for x in (l.get("city"), l.get("region"), l.get("country")) if x) for l in j.get("locations") or [])
        if want(j["title"], loc):
            out.append(job(f"https://apply.workable.com/{t}/j/{j['shortcode']}/", t, j["title"], loc, (j.get("published") or "")[:10]))
    return out


def rippling(t):
    out = []
    for page in range(5):
        d = getj(f"https://ats.rippling.com/api/v2/board/{t}/jobs?page={page}&pageSize=100")
        for j in d.get("items", []):
            loc = "; ".join(l.get("name", "") for l in j.get("locations") or [])
            if want(j["name"], loc):
                out.append(job(j["url"], t, j["name"], loc))
        if len(d.get("items", [])) < 100:
            break
    return out


def jobvite(t):
    out = []
    page = http(f"https://jobs.jobvite.com/{t}/jobs", headers={"Accept": "text/html"})
    for path, title, loc in re.findall(r'<td class="jv-job-list-name">\s*<a href="(/[^"]+/job/[A-Za-z0-9]+)"[^>]*>\s*(.*?)\s*</a>.*?'
                                       r'<td class="jv-job-list-location">\s*(.*?)\s*</td>', page, re.S):
        title, loc = html.unescape(title), re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", loc))).strip()
        if want(title, loc):
            out.append(job("https://jobs.jobvite.com" + path, t, title, loc))
    return out


def jibe(spec):
    """iCIMS Jibe career sites (AMD, Viasat, KPMG Canada, Johns Hopkins APL...)."""
    host, base = spec
    found = {}
    for q in ("security", "cyber"):
        d = getj(f"https://{host}/api/jobs?keywords={q}&page=1&limit=100&sortBy=posted_date&descending=true&internal=false")
        for j in d.get("jobs", []):
            j = j.get("data", {})
            loc = j.get("full_location") or j.get("location_name") or ""
            if want(j.get("title", ""), loc):
                found[j["slug"]] = job(f"https://{host}/{base}/{j['slug']}", host, j["title"], loc, j.get("posted_date", ""))
    return list(found.values())


def radancy(spec):
    """Radancy/TalentBrew career sites (L3Harris, Lockheed Martin, Intuit...)."""
    host, path = spec
    found = {}
    for q in ("security intern", "cyber intern", "security co-op"):
        d = getj(f"https://{host}{path}/results?ActiveFacetID=0&CurrentPage=1&RecordsPerPage=100&Keywords={urllib.parse.quote(q)}"
                 "&SearchResultsModuleName=Search+Results&SearchFiltersModuleName=Search+Filters&SortCriteria=0&SortDirection=0&SearchType=5",
                 headers={"X-Requested-With": "XMLHttpRequest"})
        for href, title, loc in re.findall(r'<a href="(/[^"]*job/[^"]+)"[^>]*>\s*<h2>(.*?)</h2>.*?job-location[^"]*">(.*?)</span>',
                                           d.get("results", ""), re.S):
            title, loc = html.unescape(title).strip(), html.unescape(loc).strip()
            if want(title, loc):
                found[href] = job(f"https://{host}{href}", host, title, loc)
    return list(found.values())


def successfactors(host):
    """SAP SuccessFactors career sites (Scotiabank, Rogers, Bombardier, Telus, Paramount...)."""
    found = {}
    for q in ("security", "cyber"):
        for start in (0, 25):
            t = http(f"https://{host}/search/?q={q}&sortColumn=referencedate&sortDirection=desc&startrow={start}", headers={"Accept": "text/html"})
            for row in re.split(r'<tr class="data-row', t)[1:]:
                a = re.search(r'<a href="(/job/[^"]+)" class="jobTitle-link"[^>]*>(.*?)</a>', row)
                if not a:
                    continue
                loc = re.search(r'class="jobLocation"[^>]*>\s*(.*?)\s*<', row)
                date = re.search(r'class="jobDate"[^>]*>\s*(.*?)\s*<', row)
                title, loc = html.unescape(a.group(2)).strip(), html.unescape(loc.group(1)) if loc else ""
                if want(title, loc):
                    found[a.group(1)] = job(f"https://{host}{a.group(1)}", host, title, loc, date.group(1) if date else "")
    return list(found.values())


# For a few giants whose security interns hide inside generic intern postings, alert on any new US/CA tech internship.
TECH = re.compile(r"software|engineer|developer|\bSDE\b|cloud|network|systems|infrastructure|\bIT\b|data|security|cyber", re.I)


def big_tech_intern(title, loc, home=True):
    return want(title, loc) or bool(home and INT.search(title) and TECH.search(title) and not foreign(loc) and not BAD.search(title)
                                    and not re.search(r"PhD|Applied Scien|Early Career|Senior|Sr\.", title))


def amazon(_):
    found = {}
    for q in ("intern", "internship", "security intern"):
        d = getj(f"https://www.amazon.jobs/en/search.json?base_query={urllib.parse.quote(q)}&result_limit=100&sort=recent"
                 "&normalized_country_code[]=USA&normalized_country_code[]=CAN")
        for j in d.get("jobs", []):
            loc = j.get("location", "")
            if big_tech_intern(j["title"], loc):
                found[j["job_path"]] = job("https://www.amazon.jobs" + j["job_path"], "Amazon", j["title"], loc, j.get("posted_date", ""))
    return list(found.values())


def netflix(_):
    found = {}
    for q in ("intern", "security"):
        d = getj(f"https://explore.jobs.netflix.net/api/apply/v2/jobs?domain=netflix.com&query={q}&start=0&num=100&sort_by=relevance")
        for p in d.get("positions", []):
            loc = p.get("location") or ""
            home = bool(re.search(r"United States|Canada", loc))
            if big_tech_intern(p.get("name", ""), loc, home):
                found[p["id"]] = job(p.get("canonicalPositionUrl") or f"https://explore.jobs.netflix.net/careers/job/{p['id']}",
                                     "Netflix", p["name"], loc, day(p.get("t_create")))
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
    cutoff = time.time() - LOOKBACK_DAYS * 86400  # ignore old listings that just got re-activated
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


def cse(_):
    """Communications Security Establishment (Ottawa): any student posting, plus intern/co-op security roles elsewhere."""
    found = {}
    for kind in ("students-etudiants", "professionals-professionnels"):
        t = http(f"https://careers.cse-cst.gc.ca/en/careers-carrieres/{kind}/opportunities/", headers={"Accept": "text/html"})
        for href, title in re.findall(r'<a[^>]+href="(/en/careers/[^"]+-CA-\d+-en)"[^>]*>\s*([^<]+?)\s*</a>', t):
            title = html.unescape(title)
            if kind.startswith("students") or want(title, "Ottawa, ON"):
                found[href] = job("https://careers.cse-cst.gc.ca" + href, "CSE", title, "Ottawa, ON")
    return list(found.values())


JOBSPY_QUERIES = [
    ("cybersecurity intern", "Canada", "Canada"), ("security co-op", "Canada", "Canada"), ("cyber security student", "Canada", "Canada"),
    ("cybersecurity intern", "United States", "USA"), ("security engineer intern", "United States", "USA"),
    ("information security intern", "United States", "USA"),
]


def jobspy_sites(_):
    """Indeed through the python-jobspy package (installed by the workflow; skipped if missing).
    Glassdoor is left out on purpose: it duplicates Indeed and links to its own login-walled pages."""
    from jobspy import scrape_jobs
    found = {}
    for term, loc, country in JOBSPY_QUERIES:
        df = scrape_jobs(site_name=["indeed"], search_term=term, location=loc, results_wanted=50,
                         hours_old=24 * max(1, LOOKBACK_DAYS if LOOKBACK_DAYS > 7 else 1), country_indeed=country, verbose=0)
        for r in df.to_dict("records"):
            title, where = str(r.get("title") or ""), str(r.get("location") or "")
            if not want(title, where):
                continue
            direct = r.get("job_url_direct")
            url = direct if isinstance(direct, str) and direct.startswith("http") else r.get("job_url")
            date = r.get("date_posted")
            found[url] = job(url, str(r.get("company") or "?"), title, where, str(date) if date is not None else "",
                             f"via {str(r.get('site')).title()}", raw_company=True)
    return list(found.values())


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
                     + urllib.parse.urlencode({"keywords": kw, "location": loc, "f_TPR": f"r{86400 * (1 if LOOKBACK_DAYS <= 7 else LOOKBACK_DAYS)}", "sortBy": "DD", "start": 0}),
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
    tasks += [(f"oracle:{h}/{s}", oracle, (h, s)) for h, s in BOARDS.get("oracle", [])]
    tasks += [(f"phenom:{h}", phenom, (h, p)) for h, p in BOARDS.get("phenom", [])]
    tasks += [(f"eightfold:{h}", eightfold, (h, d)) for h, d in BOARDS.get("eightfold", [])]
    tasks += [(f"icims:{h}", icims, h) for h in BOARDS.get("icims", [])]
    tasks += [(f"workable:{t}", workable, t) for t in BOARDS.get("workable", [])]
    tasks += [(f"rippling:{t}", rippling, t) for t in BOARDS.get("rippling", [])]
    tasks += [(f"jobvite:{t}", jobvite, t) for t in BOARDS.get("jobvite", [])]
    tasks += [(f"jibe:{h}", jibe, (h, b)) for h, b in BOARDS.get("jibe", [])]
    tasks += [(f"radancy:{h}", radancy, (h, p)) for h, p in BOARDS.get("radancy", [])]
    tasks += [(f"sf:{h}", successfactors, h) for h in BOARDS.get("sf", [])]
    tasks += [(k, simplify, k) for k in SIMPLIFY_FEEDS]
    tasks += [(n, f, None) for n, f in (("amazon-tech", amazon), ("cisco", cisco), ("kinaxis", kinaxis), ("shopify-page", shopify),
                                         ("microsoft", microsoft), ("netflix", netflix), ("google", google), ("apple", apple), ("tiktok", tiktok), ("cse", cse), ("jobspy", jobspy_sites),
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
    return "t:" + norm(j["company"])[:8] + "|" + norm(j["title"])


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


def ashby_dates(t):
    """Posted dates for one Ashby board (the hosted page we scan has none; the public API does)."""
    return {j["id"]: (j.get("publishedAt") or "")[:10] for j in getj(f"https://api.ashbyhq.com/posting-api/job-board/{t}").get("jobs", [])}


def send_digest(header, lines):
    """Post a long list as a few chunked messages instead of one ping per role."""
    def chunks(limit):
        cur = header
        for ln in lines:
            if len(cur) + len(ln) + 1 > limit:
                yield cur
                cur = ""
            cur += ("\n" if cur else "") + ln
        if cur:
            yield cur
    if not (TOPIC or DISCORD or (TG_TOKEN and TG_CHAT)):
        print(header)
        print("\n".join(lines))
        return
    for n, c in enumerate(chunks(1900)):
        if DISCORD:
            try:
                _post(DISCORD, {"content": c, "username": "Job Alerts"})
            except Exception as e:
                PUSH_ERRORS.append(f"discord: {str(e)[:80]}")
            time.sleep(1)  # Discord webhooks allow ~30 messages/min
    for n, c in enumerate(chunks(3800)):
        if TOPIC:
            try:
                _post("https://ntfy.sh", {"topic": TOPIC, "title": re.sub(r"[*_]", "", f"{header.splitlines()[0]} ({n + 1})")[:120],
                                          "message": re.sub(r"[*<>]", "", c), "priority": 3, "tags": ["clipboard"]})
            except Exception as e:
                PUSH_ERRORS.append(f"ntfy: {str(e)[:80]}")


def sweep(days, only="", label=""):
    """Everything matching that was posted in the last N days, sent as one digest. Doesn't touch seen.json."""
    global LOOKBACK_DAYS
    LOOKBACK_DAYS = days
    # shopify-page alerts on non-security roles; `only` is comma-separated task-key prefixes
    tasks = [t for t in build_tasks() if t[0] != "shopify-page" and (not only or t[0].startswith(tuple(only.split(","))))]
    jobs, todo, failed = [], tasks, []
    for rnd in range(4):  # a one-shot sweep bursts every Workday tenant at once, so retry the rate-limited ones slower
        failed = []
        with cf.ThreadPoolExecutor(64 if rnd == 0 else 8) as ex:
            futs = {ex.submit(fn, arg): (key, fn, arg) for key, fn, arg in todo}
            for f in cf.as_completed(futs):
                try:
                    jobs += [dict(j, src=futs[f][0]) for j in f.result()]
                except Exception as e:
                    failed.append((futs[f], str(e)[:40]))
        todo = [t for t, _ in failed]
        if not todo:
            break
        print(f"  round {rnd + 1}: {len(todo)} sources failed, retrying", flush=True)
        time.sleep(30)
    failed = [f"{t[0]} ({e})" for t, e in failed]
    for t in {j["src"].split(":", 1)[1] for j in jobs if j["src"].startswith("ashby:")}:
        try:
            dates = ashby_dates(t)
            for j in jobs:
                if j["src"] == f"ashby:{t}":
                    j["date"] = dates.get(j["url"].rstrip("/").split("/")[-1], "")
        except Exception:
            pass
    cutoff = str(dt.date.today() - dt.timedelta(days=days))
    seen, recent, undated = set(), [], []
    # employer's own listing wins over a LinkedIn copy of the same role (direct link, real posted date)
    for j in sorted(sorted(jobs, key=lambda j: j["date"], reverse=True), key=lambda j: j["src"] in ("linkedin", "jobspy")):
        keys = (url_key(j["url"]), title_key(j))
        if any(k in seen for k in keys):
            continue
        seen.update(keys)
        if j["date"] >= cutoff:
            recent.append(j)
        elif not j["date"]:
            undated.append(j)
    print(f"sweep: {len(tasks) - len(failed)}/{len(tasks)} sources ok | {len(recent)} posted since {cutoff} | {len(undated)} undated")
    for f in failed[:15]:
        print("  unreachable:", f)

    def line(j):
        flag = "\U0001F341 " if CANADA.search(j["loc"]) else ""
        bits = ", ".join(b for b in (j["loc"][:60], j.get("note", "")) if b)
        return f"{flag}`{j['date'] or '?'}` **{j['company']}** - {j['title']}" + (f" ({bits})" if bits else "") + f"\n<{j['url']}>"
    recent.sort(key=lambda j: j["date"], reverse=True)
    ca = [j for j in recent if CANADA.search(j["loc"])]
    rest = [j for j in recent if not CANADA.search(j["loc"])]
    lines = ([f"__**Canada ({len(ca)})**__"] + [line(j) for j in ca] + [f"__**US / other ({len(rest)})**__"] + [line(j) for j in rest]
             + ([f"__**No posted date listed ({len(undated)})**__"] + [line(j) for j in undated] if undated else []))
    for j in recent + undated:
        print(f"  {j['date'] or '?'} | {j['company']} | {j['title']} | {j['loc'][:50]} | {j['url']}")
    send_digest(f"\U0001F4CB **Security internship sweep{label}: last {days} days** ({len(recent)} roles)", lines)
    if PUSH_ERRORS:
        print("push errors:", PUSH_ERRORS)
    return 1 if PUSH_ERRORS else 0


def main():
    if "--test" in sys.argv:
        push("Job alerts test", "If you see this, this channel is connected.", priority=3)
        on = [n for n, v in (("ntfy", TOPIC), ("telegram", TG_TOKEN and TG_CHAT), ("discord", DISCORD)) if v]
        print("test sent to:", ", ".join(on) if on else "nothing (no channels set)")
        if PUSH_ERRORS:
            print("errors:", PUSH_ERRORS)
        return 1 if PUSH_ERRORS else 0

    if "--sweep" in sys.argv:
        only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else ""
        return sweep(int(sys.argv[sys.argv.index("--sweep") + 1]), only, f" ({only} only)" if only else "")

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
