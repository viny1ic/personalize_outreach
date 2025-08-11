#!/usr/bin/env python3
import argparse
import asyncio
import math
import os
import re
import sys
import tempfile
import shutil
from typing import List, Optional, Dict
import pandas as pd

# Optional progress bar
try:
    from tqdm import tqdm
except Exception:
    tqdm = None

# Load .env robustly from the current working directory (or parents)
try:
    from dotenv import load_dotenv, find_dotenv  # type: ignore
    DOTENV_PATH = find_dotenv(usecwd=True)
    load_dotenv(DOTENV_PATH, override=False)
except Exception:
    DOTENV_PATH = None

DESCRIPTION = """\
Run multiple instances of the worker script in parallel.

Features
- Auto-detects multiple keys from .env:
    OPENAI_API_KEY_1..N (or ..._0..N)
    TAVILY_API_KEY_1..N (or ..._0..N)
  Falls back to base OPENAI_API_KEY / TAVILY_API_KEY if no suffixed keys are found.
- Splits the input CSV into N shards, runs N workers concurrently, then merges outputs.
- Forwards worker flags: --model, --batch-size, --test, --force-refresh.
- Progress bar shows shard completion.
- Per-shard logs saved next to the merged CSV.
"""

def parse_args():
    p = argparse.ArgumentParser(description=DESCRIPTION)
    p.add_argument("--script", required=True, help="Path to the worker script to run (processes a CSV).")
    p.add_argument("--input-csv", required=True, help="Path to the input CSV file.")
    # Parallelism (support both names)
    p.add_argument("--workers", type=int, default=None, help="Number of parallel workers.")
    p.add_argument("--instances", type=int, default=None, help="Alias for --workers.")
    # Flags forwarded to the worker
    p.add_argument("--model", default=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
                   help="Model to pass to the worker.")
    p.add_argument("--batch-size", type=int, default=None, help="Max rows per shard for this run.")
    p.add_argument("--test", type=int, default=None, help="Forwarded to worker --test (debug mode per shard).")
    p.add_argument("--force-refresh", action="store_true", help="Forwarded to worker --force-refresh.")
    # Output
    p.add_argument("--merge-out", default=None,
                   help="Path for merged output CSV. Default: <input base>.personalized.merged.csv")
    return p.parse_args()

def get_key_list(prefix: str) -> List[str]:
    """
    Discover keys in env like PREFIX_0..N or PREFIX_1..N (supports gaps) and return
    them in numeric order. If none are found, fall back to base PREFIX.
    """
    vals = []
    for k, v in os.environ.items():
        m = re.fullmatch(rf"{re.escape(prefix)}_(\d+)", k)
        if m and isinstance(v, str) and v.strip():
            vals.append((int(m.group(1)), v.strip()))
    if vals:
        vals.sort(key=lambda x: x[0])  # numeric order
        return [v for _, v in vals]
    base = os.getenv(prefix, "").strip()
    return [base] if base else []

def split_dataframe_even(df: pd.DataFrame, n: int) -> List[pd.DataFrame]:
    if n <= 1 or len(df) == 0:
        return [df.copy()]
    splits = []
    indices = list(df.index)
    chunk_size = math.ceil(len(indices) / n)
    for i in range(0, len(indices), chunk_size):
        chunk_idx = indices[i:i+chunk_size]
        if chunk_idx:
            splits.append(df.loc[chunk_idx].copy())
    while len(splits) < n:
        splits.append(pd.DataFrame(columns=df.columns))
    return splits[:n]

async def run_worker(script: str, shard_csv: str, forwarded_flags: List[str],
                     env_overrides: Dict[str, str], log_path: str) -> int:
    """
    Run one worker instance as a subprocess. Stream stdout to console and to a log file.
    Returns the worker's exit code.
    """
    args = [sys.executable, script, "--input-csv", shard_csv] + forwarded_flags
    env = os.environ.copy()
    env.update({k: v for k, v in env_overrides.items() if v})

    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    log_f = open(log_path, "w", encoding="utf-8")

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
    )
    try:
        while True:
            line = await proc.stdout.readline()
            if not line:
                break
            decoded = line.decode("utf-8", errors="replace")
            sys.stdout.write(decoded)
            log_f.write(decoded)
    finally:
        await proc.wait()
        rc = proc.returncode
        log_f.flush()
        log_f.close()
    return rc

async def main_async():
    args = parse_args()

    # Discover keys
    openai_keys = get_key_list("OPENAI_API_KEY")
    tavily_keys = get_key_list("TAVILY_API_KEY")
    print(f"[keys] OPENAI={len(openai_keys)} TAVILY={len(tavily_keys)} (dotenv: {DOTENV_PATH or 'not found'})")

    key_pairs = min(len(openai_keys), len(tavily_keys)) if openai_keys and tavily_keys else 0
    # Determine desired worker count
    desired = args.instances if args.instances is not None else args.workers
    if desired is None:
        desired = key_pairs if key_pairs > 0 else 1  # default to 1 if no pairs discovered

    if desired <= 0:
        print("❌ Invalid worker count. Provide --workers/--instances > 0.")
        sys.exit(2)

    if len(openai_keys) == 0:
        print("❌ No OPENAI_API_KEY found in environment/.env")
        sys.exit(2)
    if len(tavily_keys) == 0:
        print("❌ No TAVILY_API_KEY found in environment/.env")
        sys.exit(2)

    num_workers = desired
    print(f"[plan] Spawning {num_workers} workers")

    # Build flags to forward to each worker
    forwarded: List[str] = []
    if args.model:
        forwarded += ["--model", args.model]
    if args.batch_size is not None:
        forwarded += ["--batch-size", str(args.batch_size)]
    if args.test is not None:
        forwarded += ["--test", str(args.test)]
    if args.force_refresh:
        forwarded += ["--force-refresh"]

    # Read input & split
    input_csv = os.path.abspath(args.input_csv)
    df = pd.read_csv(input_csv)
    shards = split_dataframe_even(df, num_workers)

    # Prepare temp dir & shard files
    base_dir = tempfile.mkdtemp(prefix="multiwrap_")
    input_base, _ = os.path.splitext(input_csv)
    shard_paths: List[str] = []
    for i, part in enumerate(shards):
        shard_path = os.path.join(base_dir, f"{os.path.basename(input_base)}.shard{i}.csv")
        part.to_csv(shard_path, index=False)
        shard_paths.append(shard_path)

    # Logs directory
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)

    # Progress bar
    total = len(shard_paths)
    use_tqdm = tqdm is not None
    pbar = tqdm(total=total, desc="Shards completed", unit="shard") if use_tqdm else None

    # Launch all workers
    async def wrap_run(i: int, shard_csv: str):
        env_overrides = {
            "OPENAI_API_KEY": openai_keys[i % len(openai_keys)],
            "TAVILY_API_KEY": tavily_keys[i % len(tavily_keys)],
        }
        log_path = os.path.join(logs_dir, f"shard{i}.log")
        rc = await run_worker(args.script, shard_csv, forwarded, env_overrides, log_path)
        if pbar:
            pbar.update(1)
        return rc

    shard_tasks = [asyncio.create_task(wrap_run(i, sp)) for i, sp in enumerate(shard_paths)]
    results = await asyncio.gather(*shard_tasks, return_exceptions=True)
    if pbar:
        pbar.close()

    # Check results
    failures = []
    for i, rc in enumerate(results):
        if isinstance(rc, Exception) or rc != 0:
            failures.append((i, rc))

    # Merge outputs
    out_parts = []
    for shard_csv in shard_paths:
        shard_out = shard_csv.replace(".csv", ".personalized.csv")
        if os.path.exists(shard_out):
            out_parts.append(pd.read_csv(shard_out))
        else:
            # include original rows if worker didn't produce output
            out_parts.append(pd.read_csv(shard_csv))

    merged = pd.concat(out_parts, ignore_index=True)
    merged_out = args.merge_out or (input_base + ".personalized.merged.csv")
    merged.to_csv(merged_out, index=False)

    # Copy logs next to merged file
    final_logs_dir = os.path.join(os.path.dirname(merged_out), os.path.basename(logs_dir))
    if os.path.exists(final_logs_dir):
        shutil.rmtree(final_logs_dir)
    shutil.copytree(logs_dir, final_logs_dir)

    # Cleanup temp dir (keep merged + logs)
    shutil.rmtree(base_dir, ignore_errors=True)

    if failures:
        print(f"[DONE] Merged output written to: {merged_out} (with {len(failures)} shard failures)")
        for i, rc in failures:
            print(f"  - Shard {i} failed with: {rc}")
        sys.exit(1)
    else:
        print(f"[DONE] Merged output written to: {merged_out}")
        print(f"[LOGS] Shard logs at: {final_logs_dir}")

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("Interrupted by user.")
        sys.exit(130)

if __name__ == "__main__":
    main()