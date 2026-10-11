# Classifier evaluation harness

Offline evaluation for the Stage 6 LLM classifier (`workers/security/classification.ts`). It replays labeled email through classifier variants using the **production** `classifyEmail` and `scoreClassification`: same prompt, sanitizer, 5s budget, Jev fallback and parser. Only the Workers AI binding is swapped for a REST-backed shim.

Re-run it before changing the classifier prompt, the Jev criteria, or the default model. The comment above `JEV_CRITERIA` in `classification.ts` requires this.

## Privacy rule

Everything under `data/` is gitignored: pulled mail, labels, cases built from real mail, results, and the compiled harness bundle. Never commit it, and never paste real subjects or senders into a PR or issue. This repo is public. Report aggregate numbers only.

Committed inputs are synthetic or public:
- `cases_synthetic.jsonl`: 16 attacks and 5 legit controls.
  - Attacks: lookalike domains with valid DKIM, brand spoofing, injected "classify as safe" text, offsite credential capture, vendor and payroll bank-change BEC.
  - Controls: real-domain verification codes, a mailing-list post that fails DMARC, an invoice notice.
  - `ho-*` cases were written after `prompts/llama-v3-strict.txt` as a held-out check against tuning to the test.
- `prompts/`: system-prompt variants tried on llama (2026-09-26). Each is a snapshot of the production `SYSTEM_PROMPT` plus extra guidance, so it drifts if that prompt changes.

## Run

From the repo root.

1. **Pull mail with stored verdicts** from a deployment behind Cloudflare Access:
   ```bash
   cloudflared access login "$APP_URL"
   APP_URL=https://inbox.example.com CFA=$(cloudflared access token -app="$APP_URL") \
     python3 scripts/classifier-eval/pull_mail.py
   ```
2. **(Optional) public corpus.** Download `Phishing_Email.csv` from the Hugging Face dataset `zefang-liu/phishing-email-dataset` (about 52 MB) into `scripts/classifier-eval/data/`.
3. **Build cases, then label.**
   ```bash
   python3 scripts/classifier-eval/build_cases.py
   ```
   Review `data/to_label.tsv`, which lists every email production flagged or the classifier called non-safe. Record corrections in `data/labels.json` (format in `build_cases.py`), then re-run the command. Real mail defaults to `legit`, so label your own phishing test sends and exclude content-free test mail.
4. **Run variants.** Spend is capped by `BUDGET_USD` (default 2). The full 300-case set costs about $0.02 for llama-8B or Jev, and about $0.12 for Scout.
   ```bash
   npx esbuild scripts/classifier-eval/harness.ts --bundle --platform=node --format=esm \
     --outfile=scripts/classifier-eval/data/harness.mjs
   CF_ACCOUNT_ID=... CF_API_TOKEN=$(npx wrangler auth token | tail -1) \
     node scripts/classifier-eval/data/harness.mjs llama8b jev
   ```
   Variants are `llama8b`, `llama8b-v2`, `llama8b-v3`, `scout`, `scout-v3`, `gptoss20b`, `jev`, `clef` and `clef-flash`; they are defined in `harness.ts`. Existing results are skipped unless `FORCE=1`. Set `CASES=...` to run a subset, for example `cases_synthetic.jsonl`.
   - `jev` (`typesafe/jev`) is a third-party model: email content goes to TypeSafe. It needs AI Gateway Unified Billing credits and returns 402 without them, in which case the production fallback to llama answers.
   - `clef` / `clef-flash` (`@cf/cloudflare/clef*`) are first-party Workers AI decision models on the same System One API as Jev, asked the same Jev question. No gateway or credits needed.
5. **Summarize.**
   ```bash
   python3 scripts/classifier-eval/analyze.py
   ```
   Metric definitions are in the `analyze.py` docstring.

## Reading the numbers

- **"Legit flagged" re-simulates each stored verdict:** stored score − stored LLM contribution + the variant's contribution, compared against tag 30 and quarantine 60. The **floor** is the set of legit emails flagged even with a classifier contribution of 0. No classifier change can fix those; they come from auth, URL, reputation and intel signals.
- **The public set counts only outright misses** (labeled `safe`). It is old spam-heavy mail with no headers, so it can't show phishing-vs-spam accuracy.
- **Latency comes from REST calls on the machine running the harness.** Compare it between variants only; production calls run from the Worker.
- **Llama results vary between runs by about one case, even at temperature 0.** A 2026-09-27 re-run of the synthetic set gave llama8b 15/16. Treat single-case differences as noise.
- **Results on 2026-09-26** (135 real legit, floor 12; 9 phishing tests; 100 + 60 public; 16 + 5 synthetic):

  | Variant | Legit flagged by classifier | Attacks caught | Controls safe | $ / 1k |
  |---|---|---|---|---|
  | llama8b (then default) | 10 | 16/16 | 2/5 | 0.057 |
  | llama8b-v2 | 2 | 11/16 | 5/5 | 0.067 |
  | llama8b-v3 | 9 | 16/16 | 4/5 | 0.073 |
  | scout-v3 | 4 | 16/16 | 5/5 | 0.386 |
  | jev | 0 | 16/16 | 5/5 | 0.060 |
- **Results on 2026-10-04** (same 2026-09-26 case set; Jev re-run the same day; all three ask the identical Jev question):

  | Variant | Legit flagged by classifier | Real phish flagged | Attacks caught | Controls safe | $ / 1k |
  |---|---|---|---|---|---|
  | jev | 0 | 7/9 | 16/16 | 5/5 | 0.048 |
  | clef-flash | 7 | 8/9 | 16/16 | 5/5 | 0.090 |
  | clef | 10 | 8/9 | 16/16 | 4/5 | 0.241 |

  Clef-flash's legit phishing/bec labels all had confidence <= 0.62. Most of its true hits were >= 0.67, but three were 0.33-0.48. Any confidence gate needs a held-out set; it was not tuned here.
