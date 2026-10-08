#!/usr/bin/env python3
"""Search LinkedIn, Indeed, and Glassdoor for security internships posted in the last N hours.
Setup: pip install python-jobspy
Usage: python research/jobspy_search.py [hours]   (default 24) -> prints matches, writes research/jobspy_hits.csv
LinkedIn rate-limits heavy use; run occasionally, not every few minutes."""
import re, sys, time, warnings
warnings.filterwarnings("ignore")
import pandas as pd
from jobspy import scrape_jobs

HOURS = int(sys.argv[1]) if len(sys.argv) > 1 else 24
SEC = re.compile(r"secur|cyber|threat|red team|offensive|appsec|infosec|detection|penetration|vulnerab|incident|forensic|\bSOC\b|identity|\bIAM\b|\bGRC\b", re.I)
INT = re.compile(r"\bintern\b|\binterns\b|internship|\bco-?op\b|student|stagiaire", re.I)
QUERIES = [
    ("cybersecurity intern", "Canada", "Canada"), ("security co-op", "Canada", "Canada"),
    ("security intern", "Ottawa, ON", "Canada"), ("security intern", "Toronto, ON", "Canada"),
    ("cybersecurity intern", "United States", "USA"), ("security engineer intern", "United States", "USA"),
    ("information security intern", "United States", "USA"), ("cloud security intern", "United States", "USA"),
    ("application security intern", "United States", "USA"), ("offensive security intern", "United States", "USA"),
]
frames = []
for term, loc, country in QUERIES:
    for sites in (["linkedin"], ["indeed", "glassdoor"]):
        try:
            df = scrape_jobs(site_name=sites, search_term=term, location=loc, results_wanted=40,
                             hours_old=HOURS, country_indeed=country, verbose=0)
            frames.append(df)
            print(f"{term} | {loc} | {sites}: {len(df)}", flush=True)
        except Exception as e:
            print("error:", term, loc, sites, str(e)[:80])
        time.sleep(2)
if not frames:
    sys.exit("no results")
df = pd.concat(frames, ignore_index=True)
hits = df[df["title"].fillna("").str.contains(SEC) & df["title"].fillna("").str.contains(INT)].copy()
hits["date_posted"] = hits["date_posted"].astype(str)
hits = hits.sort_values("date_posted", ascending=False).drop_duplicates(subset=["company", "title", "location"])
cols = ["date_posted", "site", "company", "title", "location", "job_url", "job_url_direct"]
hits[cols].to_csv("research/jobspy_hits.csv", index=False)
for _, r in hits.iterrows():
    link = r["job_url_direct"] if isinstance(r["job_url_direct"], str) else r["job_url"]
    print(f'{r["date_posted"]} | {r["company"]} | {r["title"]} | {r["location"]} | {link}')
print(f"\n{len(hits)} security internship matches -> research/jobspy_hits.csv")
