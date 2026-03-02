import sys
import csv
import os
import multiprocessing

sys.path.append('.')

from parsing.access_log_parser import ApacheAccessParser
from parsing.request_header_parser import CSICCSVParser
from processor import LogEnricher, OwaspRuleEngine, Sessionizer
from feature_extractor import SessionFeatureExtractor

# ==========================================
# WORKER PROCESS SETUP (Stateless)
# ==========================================
worker_enricher = None
worker_engine = None


def init_worker():
    global worker_enricher, worker_engine
    worker_enricher = LogEnricher()
    worker_engine = OwaspRuleEngine()


def process_single_event(event):
    global worker_enricher, worker_engine

    if worker_enricher.is_static(event.request_path):
        return None

    enriched = worker_enricher.enrich_event(event)
    rules = worker_engine.evaluate(enriched)

    return enriched, rules


# ==========================================
# MAIN PIPELINE
# ==========================================
def run_pipeline(parser, filepath, source_name, output_file):
    print(f"\n[PIPELINE] Processing {source_name} with Optimized Multiprocessing...")

    sessionizer = Sessionizer(timeout_mins=30, max_duration_mins=60)
    dom_country = "IR" if "Zaker" in source_name else "XX"
    extractor = SessionFeatureExtractor(dominant_country=dom_country)

    total_events = 0
    num_workers = max(1, multiprocessing.cpu_count() - 1)
    print(f"  -> utilizing {num_workers} CPU cores...")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    headers = extractor.FEATURE_COLUMNS + ['ip', 'label', 'evidence_uris']

    # OPTIMIZATION: Buffered Batch Writing
    # We write directly to the open file in batches, keeping RAM usage extremely low.
    BATCH_SIZE = 50000
    vectors_batch = []

    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=headers)
            writer.writeheader()

            with multiprocessing.Pool(processes=num_workers, initializer=init_worker) as pool:
                event_stream = parser.parse(filepath)

                # OPTIMIZATION: Increased chunksize from 2,000 to 20,000
                # This drastically reduces IPC (Inter-Process Communication) overhead.
                for result in pool.imap(process_single_event, event_stream, chunksize=20000):
                    total_events += 1

                    if total_events % 50000 == 0:
                        print(f"  .. {total_events:,} events processed ..")

                    if result is None:
                        continue

                    enriched, rules = result

                    for raw_session in sessionizer.process_event(enriched, rules):
                        vec = extractor.extract_vector(raw_session)
                        vec['ip'] = raw_session['ip']
                        vec['label'] = raw_session['label']
                        vectors_batch.append(vec)

                        # Flush batch to disk to clear RAM
                        if len(vectors_batch) >= BATCH_SIZE:
                            writer.writerows(vectors_batch)
                            vectors_batch.clear()

            # Flush remaining active sessions at the end
            for raw_session in sessionizer.flush():
                vec = extractor.extract_vector(raw_session)
                vec['ip'] = raw_session['ip']
                vec['label'] = raw_session['label']
                vectors_batch.append(vec)

            # Final write
            if vectors_batch:
                writer.writerows(vectors_batch)

    except Exception as e:
        print(f"[ERROR] Pipeline Failed: {e}")
        return

    print(f"[DONE] Processed {total_events:,} events successfully. Saved to {output_file}")


if __name__ == "__main__":
    # 1. Run on CSIC (Validation)
    csic_parser = CSICCSVParser()
    run_pipeline(csic_parser, "data/csic_database.csv", "CSIC 2010", "data/csic_features.csv")

    # 2. Run on Zaker (Baseline)
    zaker_parser = ApacheAccessParser()
    run_pipeline(zaker_parser, "data/access.log", "Zaker 2019", "data/zaker_features.csv")