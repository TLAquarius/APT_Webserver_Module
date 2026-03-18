import json
import os
import time
from typing import Callable, Dict

from filter_layer.unified_engine import Layer1UnifiedEngine


class Layer1Runner:
    """
    Object-Oriented wrapper for Layer 1 Execution.
    Allows dynamic path injection and UI progress tracking.
    """

    def __init__(self):
        self.engine = Layer1UnifiedEngine()

    def run(self, input_ndjson_path: str, output_ndjson_path: str,
            status_callback: Callable[[str, int], None] = None) -> Dict:
        """
        Runs the Unified Engine over the parsed logs.
        Returns a dictionary of execution statistics.
        """
        if not os.path.exists(input_ndjson_path):
            raise FileNotFoundError(f"Input file '{input_ndjson_path}' not found. Parser must run first.")

        total_processed = 0
        total_flagged = 0
        start_time = time.perf_counter()

        # Update UI Progress
        if status_callback:
            status_callback("Layer 1 WAF: Starting deterministic analysis...", 30)

        with open(input_ndjson_path, 'r', encoding='utf-8') as infile, \
                open(output_ndjson_path, 'w', encoding='utf-8') as outfile:

            for line in infile:
                if not line.strip():
                    continue

                record = json.loads(line)
                tagged_record = self.engine.evaluate_record(record)

                if tagged_record.get('layer1_flagged'):
                    total_flagged += 1

                outfile.write(json.dumps(tagged_record) + '\n')
                total_processed += 1

                # Update UI every 50k records to avoid lagging the frontend
                if total_processed % 50000 == 0 and status_callback:
                    status_callback(f"Layer 1 WAF: Scanned {total_processed:,} logs...", 35)

        elapsed = time.perf_counter() - start_time
        tpt = total_processed / elapsed if elapsed > 0 else 0

        # Compile statistics for the Dashboard (Zone 1)
        stats = {
            "total_processed": total_processed,
            "total_flagged_layer1": total_flagged,
            "flagged_percentage": round((total_flagged / total_processed) * 100, 2) if total_processed > 0 else 0.0,
            "execution_time_sec": round(elapsed, 2),
            "throughput_eps": round(tpt, 0)
        }

        if status_callback:
            status_callback(f"Layer 1 WAF: Completed in {stats['execution_time_sec']}s", 40)

        return stats