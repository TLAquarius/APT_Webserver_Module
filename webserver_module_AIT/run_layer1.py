# run_layer1.py
import json
import os
import time
from filter_layer.unified_engine import Layer1UnifiedEngine


def process_logs_through_layer1(input_file, output_file):
    if not os.path.exists(input_file):
        print(f"[-] Input file '{input_file}' not found. Please run the parser script first!")
        return

    engine = Layer1UnifiedEngine()

    total_processed = 0
    total_flagged = 0
    start_time = time.perf_counter()

    print(f"\n[*] Streaming records from {input_file} through Layer 1...")

    with open(input_file, 'r', encoding='utf-8') as infile, \
            open(output_file, 'w', encoding='utf-8') as outfile:

        for line in infile:
            if not line.strip():
                continue

            # Load the parsed record from Layer 0
            record = json.loads(line)

            # REMOVED: The block skipping 'apache_error' logs.
            # Unified Engine now handles both access logs (for input payloads)
            # and error logs (for RCE execution outputs like wget/curl).

            # Route ALL logs through the Unified Engine
            tagged_record = engine.evaluate_record(record)

            if tagged_record.get('layer1_flagged'):
                total_flagged += 1

            # Save the tagged record to the output file
            outfile.write(json.dumps(tagged_record) + '\n')

            total_processed += 1
            if total_processed % 50000 == 0:
                print(f"  -> Processed {total_processed} records...")

    elapsed = time.perf_counter() - start_time

    print("\n" + "=" * 40)
    print(" LAYER 1 PROCESSING COMPLETE ")
    print("=" * 40)
    print(f"Total Records Processed : {total_processed:,}")

    # Safe calculation
    pct = (total_flagged / total_processed) * 100 if total_processed > 0 else 0
    print(f"Total Records Flagged   : {total_flagged:,} ({pct:.2f}%)")
    print(f"Execution Time          : {elapsed:.2f} seconds")

    tpt = total_processed / elapsed if elapsed > 0 else 0
    print(f"Throughput              : {tpt:,.0f} logs/second")
    print(f"Output saved to         : {output_file}")
    print("=" * 40)


if __name__ == '__main__':
    # Update these filenames if your parser script output something different
    INPUT_NDJSON = "russellmitchell_enterprise_web_timeline.json"
    OUTPUT_NDJSON = "layer1_tagged_timeline.json"

    process_logs_through_layer1(INPUT_NDJSON, OUTPUT_NDJSON)