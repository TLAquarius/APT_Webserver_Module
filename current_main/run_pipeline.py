import sys
import csv
import os
import multiprocessing

sys.path.append('../current_main')

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
def save_csv(vectors, filename, feature_cols):
    if not vectors: return
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    print(f"[IO] Saving {len(vectors)} vectors to {filename}...")
    headers = feature_cols + ['ip', 'label']
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        w.writerows(vectors)


def run_pipeline(parser, filepath, source_name, output_file):
    print(f"\n[PIPELINE] Processing {source_name} with Multiprocessing (Pool.imap)...")

    sessionizer = Sessionizer(timeout_mins=30, max_duration_mins=60)
    dom_country = "VN" if "Zaker" in source_name else "XX"
    extractor = SessionFeatureExtractor(dominant_country=dom_country)

    vectors = []
    total_events = 0

    num_workers = max(1, multiprocessing.cpu_count() - 1)
    print(f"  -> utilizing {num_workers} CPU cores...")

    try:
        # Use Pool instead of ProcessPoolExecutor.
        # Pool.imap is strictly lazy and memory-safe for massive files.
        with multiprocessing.Pool(processes=num_workers, initializer=init_worker) as pool:
            event_stream = parser.parse(filepath)

            # imap guarantees order, and chunksize batches them for IPC efficiency
            for result in pool.imap(process_single_event, event_stream, chunksize=2000):
                total_events += 1

                # You should see this print within the first few seconds now!
                if total_events % 50000 == 0:
                    print(f"  .. {total_events:,} events processed ..")

                if result is None:
                    continue

                enriched, rules = result

                for raw_session in sessionizer.process_event(enriched, rules):
                    vec = extractor.extract_vector(raw_session)
                    vec['ip'] = raw_session['ip']
                    vec['label'] = raw_session['label']
                    vectors.append(vec)

        for raw_session in sessionizer.flush():
            vec = extractor.extract_vector(raw_session)
            vec['ip'] = raw_session['ip']
            vec['label'] = raw_session['label']
            vectors.append(vec)

    except Exception as e:
        print(f"[ERROR] Pipeline Failed: {e}")
        return

    save_csv(vectors, output_file, extractor.FEATURE_COLUMNS)
    print(f"[DONE] Processed {total_events:,} events successfully.")


if __name__ == "__main__":
    # 1. Run on CSIC (Validation)
    csic_parser = CSICCSVParser()
    run_pipeline(csic_parser, "data/csic_database.csv", "CSIC 2010", "data/csic_features.csv")

    # 2. Run on Zaker (Baseline)
    zaker_parser = ApacheAccessParser()
    run_pipeline(zaker_parser, "data/access.log", "Zaker 2019", "data/zaker_features.csv")