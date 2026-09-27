"""Build data/cases.jsonl from pulled mail, your labels, an optional public
corpus, and the committed synthetic attack set. Also writes
data/to_label.tsv: every real email production flagged or the classifier
called non-safe, for manual review.

Real mail defaults to truth=legit. Override it in data/labels.json
(gitignored), which holds per-deployment knowledge:
  {
    "ids": {"<email id>": "legit" | "phish" | "spam" | "exclude"},
    "phish_subject_prefixes": ["[sec-test"],   # your own phishing test sends
    "exclude_senders": ["test@example.com"]    # send-flow tests with no real content
  }
"ids" wins over the prefix and sender rules.

Public corpus (optional): data/Phishing_Email.csv from the Hugging Face
dataset zefang-liu/phishing-email-dataset (columns "Email Text", "Email Type").
It is old and spam-heavy, and has no headers, so auth is set to none. Use it
to count phishing labeled `safe` (misses), not to tell phishing from spam.
"""
import csv
import json
import os
import random

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
PUBLIC_PHISH, PUBLIC_LEGIT, SEED = 100, 60, 42


def load_labels():
    path = os.path.join(DATA, "labels.json")
    cfg = json.load(open(path)) if os.path.exists(path) else {}
    return cfg.get("ids", {}), tuple(cfg.get("phish_subject_prefixes", [])), set(cfg.get("exclude_senders", []))


def truth_for(e, ids, prefixes, excluded):
    if e["id"] in ids:
        return ids[e["id"]]
    if prefixes and (e["subject"] or "").startswith(prefixes):
        return "phish"
    if e["sender"] in excluded:
        return "exclude"
    return "legit"


def real_cases():
    ids, prefixes, excluded = load_labels()
    cases, review = [], []
    for e in map(json.loads, open(os.path.join(DATA, "real", "emails.jsonl"))):
        stages = {s["stage"]: s for s in (e["stage_trace"] or [])}
        cls = e["verdict"]["classification"] or {}
        c = {
            "id": e["id"], "set": "real", "truth": truth_for(e, ids, prefixes, excluded),
            "sender": e["sender"], "subject": e["subject"] or "", "bodyHtml": e["body"],
            "auth": e["auth"] or {"spf": "none", "dkim": "none", "dmarc": "none"},
            # What production did at receive time; analyze.py re-simulates from this.
            "prod": {"action": e["verdict"]["action"], "score": e["verdict"]["score"],
                     "llm_contrib": (stages.get("llm") or {}).get("score_contrib"),
                     "label": cls.get("label"), "triage": e["verdict"].get("triage")},
        }
        cases.append(c)
        if c["prod"]["action"] != "allow" or cls.get("label") != "safe":
            review.append((c["id"], c["truth"], c["prod"]["action"], c["prod"]["score"], cls.get("label"), c["sender"], c["subject"][:80]))
    with open(os.path.join(DATA, "to_label.tsv"), "w") as f:
        f.write("id\ttruth\tprod_action\tprod_score\tprod_label\tsender\tsubject\n")
        for r in sorted(review, key=lambda r: (r[2], -(r[3] or 0))):
            f.write("\t".join(str(x) for x in r) + "\n")
    return cases


def public_cases():
    path = os.path.join(DATA, "Phishing_Email.csv")
    if not os.path.exists(path):
        return []
    csv.field_size_limit(10**9)
    rows = list(csv.DictReader(open(path, encoding="utf-8", errors="replace")))
    ok = lambda r, t: r["Email Type"] == t and 200 < len(r["Email Text"]) < 6000
    rnd = random.Random(SEED)
    out = []
    for truth, kind, n in (("phish", "Phishing Email", PUBLIC_PHISH), ("legit", "Safe Email", PUBLIC_LEGIT)):
        for r in rnd.sample([r for r in rows if ok(r, kind)], n):
            out.append({"id": f"pub-{r['']}", "set": "public", "truth": truth, "sender": "(unknown)",
                        "subject": "(no subject)", "bodyHtml": r["Email Text"],
                        "auth": {"spf": "none", "dkim": "none", "dmarc": "none"}, "prod": None})
    return out


def synthetic_cases():
    return [dict(c, prod=None) for c in map(json.loads, open(os.path.join(ROOT, "cases_synthetic.jsonl")))]


def main():
    cases = real_cases() + public_cases() + synthetic_cases()
    with open(os.path.join(DATA, "cases.jsonl"), "w") as f:
        for c in cases:
            f.write(json.dumps(c) + "\n")
    counts = {}
    for c in cases:
        counts[(c["set"], c["truth"])] = counts.get((c["set"], c["truth"]), 0) + 1
    print(json.dumps({f"{s}/{t}": n for (s, t), n in sorted(counts.items())}))
    print("review data/to_label.tsv and put corrections in data/labels.json, then re-run")


if __name__ == "__main__":
    main()
