# Personalize Outreach

This project automates company‑specific research & outreach using the **OpenAI Responses API** with context from:
- Your **profile** (in the script)
- The company’s **website/About pages** via **Tavily** search + extract
- (Optional) **Company Description** column in your CSV

Resilient script with graceful failures, caching for restarts, debug options, parallel/distributed processing & support for multiple API keys at once.
(This is a vibe coded script for personal usage. It is a result of 5 hours of hacking. not optimized for prod environments) 

It ships with:
1) A **main personalizer script** that enriches rows and writes personalized outreach messages.
2) A **parallel wrapper (`run_multi.py`)** that splits the CSV, runs multiple workers concurrently, assigns different API keys per worker (from `.env`), merges results, and shows a progress bar.

---

## Features

### Personalizer script
- ✅ Uses **OpenAI Responses API** (`/v1/responses`) for summarization + sentence generation
- ✅ Pulls company context via **Tavily** (search + extract)
- ✅ Optional **CSV `Description`** column is included as prompt context
- ✅ **Caching** of per-company results (`company_cache.json`)
- ✅ **Debug/Test mode** (`--test`) prints raw request/response payloads
- ✅ **Force refresh** to bypass cache (`--force-refresh`)
- ✅ **Output CSV**: `<input>.personalized.csv` with columns:
  - `personalized_1`
  - `personalized_2`
  - `sources` (semicolon-separated URLs)
- ✅ Compatible with wrapper for shard-based concurrency

### Wrapper (`run_multi.py`)
- ✅ Loads `.env` robustly (supports `_0..N` and `_1..N` numbering)
- ✅ Auto-detects multiple keys:
  - `OPENAI_API_KEY_1..N` (or `..._0..N`) and `TAVILY_API_KEY_1..N` (or `..._0..N`)
  - Falls back to base `OPENAI_API_KEY` / `TAVILY_API_KEY`
- ✅ Splits input CSV evenly into **N shards**
- ✅ Launches **N worker processes** in parallel, **round‑robin** assigning keys
- ✅ **Progress bar** for shard completion
- ✅ Merges outputs to `<input>.personalized.merged.csv`
- ✅ Per-shard **logs** saved next to merged output
- ✅ Forwards flags: `--model`, `--batch-size`, `--test`, `--force-refresh`
- ✅ Accepts `--workers` **or** `--instances` (alias)

---

## Requirements

- Python 3.9+
- Packages:
  ```bash
  pip install aiohttp pandas python-dotenv tqdm
  ```

---

## Environment Variables (`.env`)

Place a `.env` file at your project root (the wrapper auto-discovers it).

### Single key (fallback)
```env
OPENAI_API_KEY=sk-your-openai-key
TAVILY_API_KEY=tv-your-tavily-key
OPENAI_MODEL=gpt-4o-mini   # optional default model
```

### Multiple keys (recommended for parallel runs)
Supports either `_1..N` **or** `_0..N`:
```env
# OpenAI (any number of keys)
OPENAI_API_KEY_1=sk-openai-1
OPENAI_API_KEY_2=sk-openai-2
# ...

# Tavily (any number of keys)
TAVILY_API_KEY_1=tv-tavily-1
TAVILY_API_KEY_2=tv-tavily-2
# ...
```

> Tip: The wrapper prints how many keys it detected:
> `[keys] OPENAI=4 TAVILY=4 (dotenv: /path/to/.env)`

---

## CSV Format

At minimum, include **company name** and **website**. The script is forgiving with column names.

Recommended columns:
- `Company name` (or `Company Name`)
- `Website` (or `Website url`)
- `Description` *(optional but recommended — added to the prompt context)*

The script writes the following new columns:
- `personalized_1`
- `personalized_2`
- `sources`

---

## Usage

### 1) Run personalizer directly
```bash
python personalize_companies.py \
  --input-csv sample.csv \
  --model gpt-5-mini \
  --batch-size 500 \
  --force-refresh
```

**Flags:**
- `--input-csv` (required): path to your CSV
- `--model` (optional): overrides `OPENAI_MODEL` in `.env`
- `--batch-size` (optional): limit rows this run
- `--test N` (optional): enable debug logging for the first N companies
- `--force-refresh` (optional): ignore cache and re-fetch/re-generate

**Output:**
- Writes `<input>.personalized.csv` in the same folder.

### 2) Run in parallel with wrapper
```bash
python run_multi.py \
  --script personalize_companies.py \
  --input-csv sample.csv \
  --instances 5 \
  --model gpt-5-mini \
  --force-refresh
```
**Notes:**
- Wrapper splits input into 5 shards and runs 5 workers.
- Assigns keys round-robin from `.env`.
- Merged output: `<input>.personalized.merged.csv`
- Per-shard logs: `./logs/` next to merged file.

---

## Debugging & Tips

- **See detected keys**: Wrapper prints counts at startup.
- **Missing key errors**: Ensure `.env` is loaded and variable names match (e.g., `TAVILY_API_KEY_1`).
- **Rate limits**: If Tavily throttles around ~100 req/min per key, you can:
  - Lower overall concurrency
  - Run via wrapper with more keys
  - Add internal rate-limiter & retries (optional snippet provided in the conversation)
- **Tavily credits**: 1 search request ≈ 1 credit. Your usage depends on how many queries you make per company.

---

## Troubleshooting

- *“Missing TAVILY_API_KEY”*: Wrapper launched workers but env vars were not passed/detected. Check `.env` names; the wrapper prints `[keys] ...` counts.
- *Responses API error “Invalid value: 'text'”*: Use `"type": "input_text"` instead of `"text"` for the Responses API inputs.
- *Responses API “status: incomplete” / `max_output_tokens`*: Increase `max_output_tokens` and/or set `reasoning: {"effort": "low"}`.
- *No output captured despite Responses returning text*: Parse `output_text` else walk `output[*].content[*].text` where `type == "output_text"`.

---

## Outputs & Logs

- Worker output CSV: `<input>.personalized.csv`
- Merged output (wrapper): `<input>.personalized.merged.csv`
- Logs (wrapper): `logs/shard{i}.log` next to merged file

---

## Safety & Quotas

- Respect API rate limits. Parallelization helps distribute load across keys but won’t bypass provider quotas.
- Cache is written to `company_cache.json` and updated during runs.
- Use `--force-refresh` to redo stale rows.

---
