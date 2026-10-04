"""Summarize data/results/*.jsonl against data/cases.jsonl.

Per variant:
- legit_flagged / by_classifier (real mail). The stored verdict is re-simulated
  as stored score - stored LLM contribution + this variant's contribution, then
  checked against tag >= 30 / quarantine >= 60. Triage short-circuits keep their
  stored action. by_classifier excludes the "floor": emails flagged even with a
  classifier contribution of 0. Mitigations and confidence-gated quarantine are
  ignored, so the counts are approximate.
- legit_phish_bec: real legit emails labeled phishing or bec.
- phish_flagged: real phishing cases whose re-simulated action is not allow.
- pub_phish_missed: public phishing labeled safe.
- attacks_caught / controls_safe: synthetic set. Caught = not safe or spam.
- $/1k, p50/p95 latency (REST from wherever the harness ran), fallbacks (Jev → chat).
"""
import json
import os
import statistics as st
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
TAG, QUAR = 30, 60
HIT = {"phishing", "bec"}

cases = {c["id"]: c for c in map(json.loads, open(os.path.join(DATA, "cases.jsonl"))) if c["truth"] != "exclude"}


def action(c, contrib):
    p = c.get("prod")
    if not p:
        return None
    if p["triage"] in ("hard_block", "hard_allow", "attachment_block", "folder_bypass"):
        return p["action"]
    score = max(0, min(100, p["score"] - (p["llm_contrib"] or 0) + contrib))
    return "quarantine" if score >= QUAR else "tag" if score >= TAG else "allow"


def pick(s, t):
    return [c for c in cases.values() if c["set"] == s and c["truth"] == t]


rl, rp, pp = pick("real", "legit"), pick("real", "phish"), pick("public", "phish")
sa, sl = pick("synthetic", "phish"), pick("synthetic", "legit")
floor = {c["id"] for c in rl if action(c, 0) != "allow"}

results_dir = os.environ.get("RESULTS", os.path.join(DATA, "results"))
variants = sys.argv[1:] or sorted(f[:-6] for f in os.listdir(results_dir) if f.endswith(".jsonl"))
cols = ["variant", "legit_flagged", "by_classifier", "legit_phish_bec", "phish_flagged", "pub_phish_missed",
        "attacks_caught", "controls_safe", "usd_per_1k", "p50_ms", "p95_ms", "fallbacks"]
print(f"real legit {len(rl)} (floor {len(floor)}), real phish {len(rp)}, public phish {len(pp)}, "
      f"synthetic attacks {len(sa)} + controls {len(sl)}\n")
print("| " + " | ".join(cols) + " |")
print("|" + "---|" * len(cols))
for v in variants:
    R = {r["id"]: r for r in map(json.loads, open(os.path.join(results_dir, f"{v}.jsonl")))}
    have = lambda cs: [c for c in cs if c["id"] in R]
    lab = lambda c: R[c["id"]]["label"]
    flagged = [c for c in have(rl) if action(c, R[c["id"]]["contrib"]) != "allow"]
    lat = sorted(r["latency_ms"] for r in R.values() if r.get("latency_ms"))
    usd = [r["usd"] for r in R.values() if r.get("usd") is not None]
    row = {
        "variant": v,
        "legit_flagged": f"{len(flagged)}/{len(have(rl))}" if have(rl) else "-",
        "by_classifier": len([c for c in flagged if c["id"] not in floor]) if have(rl) else "-",
        "legit_phish_bec": sum(lab(c) in HIT for c in have(rl)) if have(rl) else "-",
        "phish_flagged": f"{sum(action(c, R[c['id']]['contrib']) != 'allow' for c in have(rp))}/{len(have(rp))}" if have(rp) else "-",
        "pub_phish_missed": f"{sum(lab(c) == 'safe' for c in have(pp))}/{len(have(pp))}" if have(pp) else "-",
        "attacks_caught": f"{sum(lab(c) not in ('safe', 'spam') for c in have(sa))}/{len(have(sa))}" if have(sa) else "-",
        "controls_safe": f"{sum(lab(c) == 'safe' for c in have(sl))}/{len(have(sl))}" if have(sl) else "-",
        "usd_per_1k": f"{1000 * st.mean(usd):.3f}" if usd else "-",
        "p50_ms": lat[len(lat) // 2] if lat else "-",
        "p95_ms": lat[int(len(lat) * 0.95)] if lat else "-",
        "fallbacks": sum(bool(r.get("fallback")) or r.get("reasoning", "").startswith(("jev fallback", "clef fallback")) for r in R.values()),
    }
    print("| " + " | ".join(str(row[k]) for k in cols) + " |")
