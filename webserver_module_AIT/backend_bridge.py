import os
import json
import pandas as pd
from typing import Callable, Dict, List, Any

# Import components from your backend layers
from data_management.profile_manager import ProfileManager
from parser.parser_class import WebServerLogParser


# Note: You will need to slightly adjust your backend classes to accept dynamic paths.
# from filter_layer.unified_engine import UnifiedWAFEngine
# from behaviour_layer.sessionizer import WebSessionizer
# from behaviour_layer.machine_learning.statistical_models import StatisticalAnomalyDetector
# from behaviour_layer.machine_learning.sequential_model import MarkovChainDetector
# from final_layer.correlator import APTCorrelator

class WebserverBridge:
    """
    The Orchestrator/Facade that connects the Streamlit UI with the backend ML pipeline.
    It manages paths dynamically based on the selected Profile (Tenant) and compiles
    data for the 4-Zone Dashboard.
    """

    def __init__(self, profile_name: str, base_data_dir: str = "./module_data"):
        self.profile_name = profile_name
        self.profile_manager = ProfileManager(base_data_dir=base_data_dir)

        # Ensure profile exists
        if profile_name not in self.profile_manager.get_all_profiles():
            self.profile_manager.create_profile(profile_name)

        # Set up dynamic paths for this specific profile
        self.profile_dir = os.path.join(base_data_dir, profile_name)
        self.raw_logs_dir = os.path.join(self.profile_dir, "raw_logs")
        self.models_dir = os.path.join(self.profile_dir, "models")
        self.results_dir = os.path.join(self.profile_dir, "results")

        # Define specific file paths used across the pipeline
        self.paths = {
            "parsed_timeline": os.path.join(self.results_dir, "timeline.ndjson"),
            "layer1_alerts": os.path.join(self.results_dir, "layer1_alerts.json"),
            "ml_features": os.path.join(self.results_dir, "ml_features.csv"),
            "geo_map": os.path.join(self.results_dir, "geo_map.json"),
            "stat_scores": os.path.join(self.results_dir, "statistical_scores.csv"),
            "seq_scores": os.path.join(self.results_dir, "sequential_scores.csv"),
            "incidents": os.path.join(self.results_dir, "incident_reports.ndjson"),

            # Model paths
            "if_model": os.path.join(self.models_dir, "isolation_forest.joblib"),
            "scaler": os.path.join(self.models_dir, "scaler.joblib"),
            "markov_model": os.path.join(self.models_dir, "markov_model.json")
        }

    def process_uploads(self, uploaded_files: List, log_type: str, log_format: str, operation_mode: str) -> List[Dict]:
        """Handles the ingestion of files from the UI via ProfileManager."""
        ingested_metadata = []
        for file in uploaded_files:
            try:
                record = self.profile_manager.ingest_file(
                    profile_name=self.profile_name,
                    uploaded_file=file,
                    log_type=log_type,
                    operation_mode=operation_mode,
                    log_format=log_format
                )
                ingested_metadata.append(record)
            except Exception as e:
                print(f"[!] Error ingesting {file.name}: {e}")
        return ingested_metadata

    def run_full_pipeline(self, status_callback: Callable[[str, int], None] = None):
        """
        Executes the entire APT detection pipeline sequentially.
        Args:
            status_callback: A function `func(message: str, percentage: int)` to update the UI progress bar.
        """

        def update_ui(msg, pct):
            if status_callback:
                status_callback(msg, pct)

        try:
            # ==========================================================
            # STEP 1: PARSING (Format raw logs to NDJSON)
            # ==========================================================
            update_ui("1/5: Đang phân tích cú pháp Log thô (Parsing)...", 10)

            # TODO: Add logic to fetch only "pending" files from metadata.json
            # For now, simulate running the parser
            parser = WebServerLogParser(chunk_size=50000)
            # parser.process_log_file(file_path, log_format, log_type, stream_to_disk=True, temp_out=self.paths["parsed_timeline"])

            # ==========================================================
            # STEP 2: LAYER 1 - WAF (Deterministic Signatures)
            # ==========================================================
            update_ui("2/5: Đang quét Dấu hiệu Tấn công tĩnh (Layer 1 WAF)...", 30)

            # TODO: Instantiate UnifiedWAFEngine with input=self.paths["parsed_timeline"], output=self.paths["layer1_alerts"]
            # waf = UnifiedWAFEngine(input_path=self.paths["parsed_timeline"], output_path=self.paths["layer1_alerts"])
            # waf.run()

            # ==========================================================
            # STEP 3: SESSIONIZER (Feature Extraction)
            # ==========================================================
            update_ui("3/5: Đang nhóm Phiên và trích xuất Đặc trưng hành vi...", 50)

            # TODO: Instantiate Sessionizer
            # sessionizer = WebSessionizer(input_path=self.paths["layer1_alerts"], out_csv=self.paths["ml_features"])
            # sessionizer.run()

            # ==========================================================
            # STEP 4: BEHAVIORAL ML (Layer 2 & 3)
            # ==========================================================
            update_ui("4/5: Đang chạy AI chấm điểm Dị thường (Isolation Forest & Markov)...", 70)

            # TODO: Pass self.paths["models"] so ML scripts load/save the correct tenant models
            # stat_model = StatisticalAnomalyDetector(model_path=self.paths["if_model"])
            # stat_model.predict(input_features=self.paths["ml_features"], output_scores=self.paths["stat_scores"])

            # ==========================================================
            # STEP 5: CORRELATION (Layer 4)
            # ==========================================================
            update_ui("5/5: Đang tổng hợp chuỗi tấn công APT (Data Correlation)...", 90)

            # TODO: Correlator combines stat_scores, seq_scores -> incidents.ndjson
            # correlator = APTCorrelator(...)
            # correlator.run()

            update_ui("Hoàn tất! Đang chuẩn bị dữ liệu Dashboard...", 100)
            return True

        except Exception as e:
            update_ui(f"❌ Lỗi hệ thống: {str(e)}", 100)
            print(f"Pipeline Error: {e}")
            return False

    def compile_dashboard_data(self) -> Dict[str, Any]:
        """
        Reads all the CSV/JSON files scattered in the results folder and
        bundles them into a clean Dictionary perfectly mapped for the 4-Zone UI.
        """
        dashboard_data = {
            "zone1_metrics": {"total_events": 0, "l1_blocks": 0, "anomalous_sessions": 0, "max_threat": "NORMAL"},
            "zone2_waf": {"attack_vectors": {}, "top_ips": {}, "geo_map": {}},
            "zone3_ml": {"scatter_data": [], "timeline_data": []},
            "zone4_incidents": []
        }

        # --- MOCKING DATA FOR UI DEVELOPMENT (Replace with actual file reading later) ---

        # ZONE 1
        dashboard_data["zone1_metrics"] = {
            "total_events": 154200,
            "l1_blocks": 342,
            "anomalous_sessions": 12,
            "max_threat": "CRITICAL"
        }

        # ZONE 2 (Rule-based)
        dashboard_data["zone2_waf"]["attack_vectors"] = {"SQLi": 120, "XSS": 80, "Path Traversal": 142}
        dashboard_data["zone2_waf"]["top_ips"] = {"192.168.1.5": 500, "10.0.0.9": 300, "8.8.8.8": 150}

        # ZONE 3 (Machine Learning Data)
        # In reality, you will read: pd.read_csv(self.paths["stat_scores"]) and merge with seq_scores
        dashboard_data["zone3_ml"]["scatter_data"] = [
            {"session_id": "sess_1", "ip": "1.1.1.1", "stat_score": 95, "seq_score": 88, "label": "CRITICAL"},
            {"session_id": "sess_2", "ip": "2.2.2.2", "stat_score": 40, "seq_score": 20, "label": "NORMAL"},
            {"session_id": "sess_3", "ip": "3.3.3.3", "stat_score": 85, "seq_score": 92, "label": "CRITICAL"}
        ]

        # ZONE 4 (Incidents)
        # In reality, you will read: self.paths["incidents"]
        dashboard_data["zone4_incidents"] = [
            {
                "session_id": "sess_1",
                "ip": "1.1.1.1",
                "threat_level": "CRITICAL",
                "ml_score_avg": 91.5,
                "attack_chain": "Directory Fuzzing -> SQLi -> Web Shell Upload (200 OK)",
                "raw_logs_rle": "[GET /admin]x50 -> [POST /upload.php]x1"
            }
        ]

        return dashboard_data