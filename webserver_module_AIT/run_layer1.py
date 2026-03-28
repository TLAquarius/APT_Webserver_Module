import json
import os
import time
from typing import Callable, Dict
from concurrent.futures import ThreadPoolExecutor

from filter_layer.unified_engine import Layer1UnifiedEngine


def _worker_evaluate_chunk(chunk):
    """
    Evaluates a chunk of logs independently.
    Instantiates its own engine to ensure thread safety.
    """
    engine = Layer1UnifiedEngine()
    processed_lines = []
    flagged_count = 0

    for line in chunk:
        if not line.strip():
            continue
        record = json.loads(line)
        tagged_record = engine.evaluate_record(record)

        if tagged_record.get('layer1_flagged'):
            flagged_count += 1

        processed_lines.append(json.dumps(tagged_record))

    return processed_lines, flagged_count


class Layer1Runner:
    """
    Object-Oriented wrapper for Layer 1 Execution using chronologically-ordered Multi-threading.
    """

    def __init__(self, chunk_size=20000, max_workers=None):
        self.chunk_size = chunk_size
        self.max_workers = max_workers

    def run(self, input_ndjson_path: str, output_ndjson_path: str,
            status_callback: Callable[[str, int], None] = None) -> Dict:
        """
        Runs the Unified Engine over the logs using ThreadPoolExecutor.map to ensure
        the final output remains perfectly sorted by time.
        """
        if not os.path.exists(input_ndjson_path):
            raise FileNotFoundError(f"Input file '{input_ndjson_path}' not found. Parser must run first.")

        total_processed = 0
        total_flagged = 0
        start_time = time.perf_counter()

        if status_callback:
            status_callback("Layer 1 WAF: Starting parallel deterministic analysis...", 30)

        def get_chunks():
            chunk = []
            with open(input_ndjson_path, 'r', encoding='utf-8') as infile:
                for line in infile:
                    chunk.append(line)
                    if len(chunk) >= self.chunk_size:
                        yield chunk
                        chunk = []
                if chunk:
                    yield chunk

        with open(output_ndjson_path, 'w', encoding='utf-8') as outfile:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                # executor.map GUARANTEES the output order matches the input order
                for processed_chunk, flagged_in_chunk in executor.map(_worker_evaluate_chunk, get_chunks()):
                    total_flagged += flagged_in_chunk
                    total_processed += len(processed_chunk)

                    for output_line in processed_chunk:
                        outfile.write(output_line + '\n')

                    if status_callback:
                        status_callback(f"Layer 1 WAF: Scanned {total_processed:,} logs...", 35)

        elapsed = time.perf_counter() - start_time
        tpt = total_processed / elapsed if elapsed > 0 else 0

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