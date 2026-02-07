import sys
import csv
import time
import os

sys.path.append('.')

from parsing.access_log_parser import ApacheAccessParser
from parsing.request_header_parser import CSICCSVParser
from processor import LogEnricher, OwaspRuleEngine, Sessionizer
from feature_extractor import SessionFeatureExtractor


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
    print(f"\n[PIPELINE] Processing {source_name}...")

    enricher = LogEnricher()
    engine = OwaspRuleEngine()  # Aggressive Mode
    sessionizer = Sessionizer(timeout_mins=30, max_duration_mins=60)

    # Configure Context for Dataset
    # CSIC is localhost/unknown, so 'XX' is dominant
    dom_country = "VN" if "Zaker" in source_name else "XX"
    extractor = SessionFeatureExtractor(dominant_country=dom_country)

    vectors = []
    total_events = 0

    try:
        for event in parser.parse(filepath):
            total_events += 1
            if enricher.is_static(event.request_path): continue

            enriched = enricher.enrich_event(event)
            rules = engine.evaluate(enriched)

            for raw_session in sessionizer.process_event(enriched, rules):
                vec = extractor.extract_vector(raw_session)
                vec['ip'] = raw_session['ip']
                vec['label'] = raw_session['label']
                vectors.append(vec)

            if total_events % 50000 == 0: print(f"  .. {total_events:,} events ..")

        for raw_session in sessionizer.flush():
            vec = extractor.extract_vector(raw_session)
            vec['ip'] = raw_session['ip']
            vec['label'] = raw_session['label']
            vectors.append(vec)

    except Exception as e:
        print(f"[ERROR] {e}")
        return

    save_csv(vectors, output_file, extractor.FEATURE_COLUMNS)
    print(f"[DONE] Processed {total_events:,} events.")


if __name__ == "__main__":
    # 1. Run on CSIC (Validation)
    csic_parser = CSICCSVParser()
    run_pipeline(csic_parser, "data/csic_database.csv", "CSIC 2010", "data/csic_features.csv")

    # 2. Run on Zaker (Baseline)
    zaker_parser = ApacheAccessParser()
    run_pipeline(zaker_parser, "data/access.log", "Zaker 2019", "data/zaker_features.csv")