"""Pull every email that has a stored security verdict from a deployed PhishSOC
into data/real/emails.jsonl (gitignored — this is private mail).

Auth is Cloudflare Access. From the repo root:
  cloudflared access login "$APP_URL"      # complete SSO in the browser
  APP_URL=https://inbox.example.com \
  CFA=$(cloudflared access token -app="$APP_URL") \
    python3 scripts/classifier-eval/pull_mail.py
"""
import concurrent.futures as cf
import json
import os
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(ROOT, "data", "real", "emails.jsonl")
APP = os.environ["APP_URL"].rstrip("/") + "/api/v1"
TOKEN = os.environ["CFA"]
FOLDERS = ["inbox", "spam", "quarantine", "archive"]


def get(path):
    # Cloudflare's bot rules 403 the default Python-urllib User-Agent.
    req = urllib.request.Request(APP + path, headers={"cf-access-token": TOKEN, "User-Agent": "curl/8.7.1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def list_rows(mailbox):
    q = urllib.parse.quote(mailbox)
    rows = []
    for folder in FOLDERS:
        for page in range(1, 21):
            d = get(f"/mailboxes/{q}/emails?folder={folder}&limit=100&page={page}")
            batch = d.get("emails", []) if isinstance(d, dict) else d
            rows += [dict(r, _mailbox=mailbox, _folder=folder) for r in batch if r.get("security_verdict")]
            if len(batch) < 100:
                break
    return rows


def fetch(row):
    q = urllib.parse.quote(row["_mailbox"])
    e = get(f"/mailboxes/{q}/emails/{row['id']}")
    v = json.loads(e["security_verdict"])
    return {
        "id": e["id"], "mailbox": row["_mailbox"], "folder": row["_folder"], "date": e.get("date"),
        "sender": e["sender"], "subject": e["subject"], "body": e.get("body") or "", "auth": v.get("auth"),
        "verdict": {k: v.get(k) for k in ("action", "score", "confidence", "signals", "classification", "triage")},
        "stage_trace": json.loads(e["stage_trace"]) if e.get("stage_trace") else None,
    }


def main():
    mailboxes = [m["id"] for m in get("/mailboxes")]
    rows = []
    for mb in mailboxes:
        try:
            rows += list_rows(mb)
        except Exception as e:  # a mailbox the caller has no ACL on
            print(f"skip {mb}: {e}")
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with cf.ThreadPoolExecutor(6) as ex, open(OUT, "w") as out:
        for rec in ex.map(fetch, rows):
            out.write(json.dumps(rec) + "\n")
    print(f"{len(rows)} emails with verdicts from {len(mailboxes)} mailboxes -> {OUT}")


if __name__ == "__main__":
    main()
