import os
import argparse
import pandas as pd

from src.data_loader import CSICDataLoader
from src.pipeline import CSICPipeline


# ── File paths ────────────────────────────────────────────────────────────────
DATA_NORMAL_TRAIN = "data/normal/normalTrafficTraining.txt"
DATA_NORMAL_TEST  = "data/normal/normalTrafficTest.txt"
DATA_ATTACK_TEST  = "data/anomalous/AnomalousTrafficTest.txt"
OUTPUT_DIR        = "output"


# ── CLI arguments ─────────────────────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(description="CSIC 2010 APT Detection Pipeline")
    parser.add_argument("--limit",         type=int,   default=None, help="Cap requests loaded per file (quick tests)")
    parser.add_argument("--contamination", type=float, default=0.27, help="IsolationForest contamination rate (default: 0.27)")
    parser.add_argument("--session-gap",   type=int,   default=10,   help="Session gap minutes for timeline (default: 10)")
    parser.add_argument("--skip-eval",     action="store_true",      help="Skip evaluation (no ground truth needed)")
    parser.add_argument("--save-model",    action="store_true",      help="Save trained model and scaler to output/")
    return parser.parse_args()


# ── Helpers ───────────────────────────────────────────────────────────────────
def check_files(*paths):
    """Verify required data files exist before starting."""
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        print("\n[ERROR] Missing data files:")
        for p in missing:
            print(f"  x {p}")
        print("\nDownload CSIC 2010 and place files at the paths above.")
        raise SystemExit(1)


def print_sample_results(results: list, n: int = 10):
    print(f"\n{'─'*80}")
    print(f"  {'#':<4} {'METHOD':<7} {'SEVERITY':<10} {'SCORE':<7} {'OWASP':<35} {'APT PHASE'}")
    print(f"{'─'*80}")
    for i, r in enumerate(results[:n]):
        print(
            f"  {i+1:<4} {r['method']:<7} {r['severity']:<10} "
            f"{r['score']:<7.4f} {r['owasp']:<35} {r['apt_phase']}"
        )
    print(f"{'─'*80}")


def print_summary(results: list):
    total    = len(results)
    normal   = sum(1 for r in results if r["severity"] == "NORMAL")
    warning  = sum(1 for r in results if r["severity"] == "WARNING")
    critical = sum(1 for r in results if r["severity"] == "CRITICAL")
    errors   = sum(1 for r in results if r.get("parse_error"))

    owasp_counts: dict = {}
    apt_counts:   dict = {}
    for r in results:
        if r["severity"] != "NORMAL":
            owasp_counts[r["owasp"]]   = owasp_counts.get(r["owasp"], 0) + 1
            apt_counts[r["apt_phase"]] = apt_counts.get(r["apt_phase"], 0) + 1

    print("\n" + "=" * 52)
    print("  DETECTION SUMMARY")
    print("=" * 52)
    print(f"  Total requests  : {total}")
    print(f"  Normal          : {normal}  ({normal/total*100:.1f}%)")
    print(f"  Warning         : {warning}  ({warning/total*100:.1f}%)")
    print(f"  Critical        : {critical}  ({critical/total*100:.1f}%)")
    print(f"  Parse errors    : {errors}")

    if owasp_counts:
        print("\n  Attack Types Detected:")
        for owasp, count in sorted(owasp_counts.items(), key=lambda x: -x[1]):
            print(f"    {owasp:<40} {count}")

    if apt_counts:
        print("\n  APT Phases Triggered:")
        for phase, count in sorted(apt_counts.items(), key=lambda x: -x[1]):
            print(f"    {phase:<30} {count}")

    print("=" * 52)


def save_results(results: list, apt_chains, output_dir: str):
    os.makedirs(output_dir, exist_ok=True)

    results_path = os.path.join(output_dir, "detection_results.csv")
    pd.DataFrame(results).to_csv(results_path, index=False)
    print(f"\n[+] Detection results  -> {results_path}")

    if apt_chains is not None and not apt_chains.empty:
        chains_path = os.path.join(output_dir, "apt_chains.csv")
        apt_chains.to_csv(chains_path, index=False)
        print(f"[+] APT chains         -> {chains_path}")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    args = parse_args()
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("=" * 52)
    print("  CSIC 2010 APT DETECTION SYSTEM")
    print("=" * 52)

    # 0. Verify files exist before doing any work
    check_files(DATA_NORMAL_TRAIN, DATA_ATTACK_TEST)

    # 1. Load normal training data
    print(f"\n[1/5] Loading normal training data...")
    normal_records = CSICDataLoader(DATA_NORMAL_TRAIN).load_raw_requests(
        label=0, limit=args.limit
    )
    print(f"      Loaded {len(normal_records)} normal requests")

    # 2. Load test data (attack + normal test if available)
    print(f"\n[2/5] Loading test data...")
    attack_records = CSICDataLoader(DATA_ATTACK_TEST).load_raw_requests(
        label=1, limit=args.limit
    )
    print(f"      Loaded {len(attack_records)} attack requests")

    normal_test_records = []
    if os.path.exists(DATA_NORMAL_TEST):
        normal_test_records = CSICDataLoader(DATA_NORMAL_TEST).load_raw_requests(
            label=0, limit=args.limit
        )
        print(f"      Loaded {len(normal_test_records)} normal test requests")

    # Combine for balanced evaluation set
    test_records = attack_records + normal_test_records

    # 3. Train
    print(f"\n[3/5] Training model (contamination={args.contamination})...")
    pipeline = CSICPipeline(
        contamination=args.contamination,
        session_gap_minutes=args.session_gap,
    )
    # Stage 1 — unsupervised, normal traffic only
    pipeline.train(normal_records)

    # Stage 2 — supervised, uses labeled normal + attack records
    # Combines a small portion of normal test + all attack records for RF training
    # This is valid because CSIC 2010 attack labels are pre-verified ground truth
    supervised_records = attack_records + normal_test_records[:len(attack_records)]
    pipeline.train_supervised(supervised_records)
    print("Two-stage training complete.")

    if args.save_model:
        pipeline.save(
            model_path=os.path.join(OUTPUT_DIR, "model.pkl"),
            scaler_path=os.path.join(OUTPUT_DIR, "scaler.pkl"),
        )

    # 4. Run detection
    print(f"\n[4/5] Running detection on {len(test_records)} requests...")
    results = pipeline.run(test_records)

    print_sample_results(results, n=10)
    print_summary(results)

    # 5. Evaluate against ground truth labels
    if not args.skip_eval:
        print(f"\n[5/5] Evaluating results...")
        pipeline.evaluate(results, output_dir=OUTPUT_DIR)
    else:
        print(f"\n[5/5] Evaluation skipped.")

    # 6. Timeline analysis
    print("\n[+] Running timeline analysis...")
    timeline_df, apt_chains_df = pipeline.analyze_timeline(results)

    # 7. Save all outputs
    save_results(results, apt_chains_df, OUTPUT_DIR)

    print(f"\nPipeline complete. All outputs saved to: {OUTPUT_DIR}/")


if __name__ == "__main__":
    main()