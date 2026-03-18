import os
import json
import pandas as pd
from typing import Callable, Dict, List, Any

# Import Quản lý dữ liệu
from data_management.profile_manager import ProfileManager

# Import các Tầng Backend (Đã được chúng ta refactor thành chuẩn OOP)
from parser.parser_class import WebServerLogParser
from run_layer1 import Layer1Runner
from behaviour_layer.sessionizer import StatefulStreamingEngine
from behaviour_layer.machine_learning.statistical_models import Layer2AnomalyEnsemble
from behaviour_layer.machine_learning.sequential_model import MarkovSequentialEngine
from final_layer.correlator import DataCorrelator


class WebserverBridge:
    """
    Nhạc trưởng (Orchestrator) kết nối Giao diện Web (Streamlit) với Backend Pipeline.
    Tự động quản lý phân quyền đa khách hàng (Multi-tenant), điều phối luồng dữ liệu
    theo thời gian và chuẩn bị dữ liệu sạch cho 4-Zone Dashboard.
    """

    def __init__(self, profile_name: str, base_data_dir: str = "./module_data"):
        self.profile_name = profile_name
        self.profile_manager = ProfileManager(base_data_dir=base_data_dir)

        # Đảm bảo vương quốc (Workspace) của Profile này tồn tại
        if profile_name not in self.profile_manager.get_all_profiles():
            self.profile_manager.create_profile(profile_name)

        # Khởi tạo các đường dẫn ĐỘNG theo Profile
        self.profile_dir = os.path.join(base_data_dir, profile_name)
        self.raw_logs_dir = os.path.join(self.profile_dir, "raw_logs")
        self.models_dir = os.path.join(self.profile_dir, "models")
        self.results_dir = os.path.join(self.profile_dir, "results")

        # Quy hoạch bản đồ file I/O xuyên suốt Pipeline
        self.paths = {
            "temp_parsed": os.path.join(self.results_dir, "temp_raw_parsed.ndjson"),
            "parsed_timeline": os.path.join(self.results_dir, "timeline.ndjson"),
            "layer1_alerts": os.path.join(self.results_dir, "layer1_alerts.ndjson"),

            "ml_features": os.path.join(self.results_dir, "ml_features.csv"),
            "session_timelines": os.path.join(self.results_dir, "session_timelines.json"),

            "geo_map": os.path.join(self.models_dir, "geo_map.json"),
            "stat_scores": os.path.join(self.results_dir, "statistical_scores.csv"),
            "seq_scores": os.path.join(self.results_dir, "sequential_scores.csv"),

            "incidents": os.path.join(self.results_dir, "incident_reports.ndjson"),

            # AI Models
            "markov_model": os.path.join(self.models_dir, "markov_model.json")
        }

    def process_uploads(self, uploaded_files: List, log_type: str, log_format: str, operation_mode: str) -> List[Dict]:
        """Đẩy file từ UI vào Trình quản lý Hồ sơ để lưu trữ an toàn và băm MD5 chống trùng."""
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
                print(f"[!] Lỗi khi nạp file {file.name}: {e}")
        return ingested_metadata

    def run_full_pipeline(self, status_callback: Callable[[str, int], None] = None) -> bool:
        """
        Khởi chạy toàn bộ quy trình SOC.
        Tự động xác định xem cần Train Baseline hay Detect APT dựa trên file cấu hình.
        """

        def update_ui(msg, pct):
            if status_callback: status_callback(msg, pct)

        try:
            # 0. Xác định công việc cần làm
            metadata = self.profile_manager._load_metadata(self.profile_name)
            pending_files = [f for f in metadata if f.get("status") == "pending_orchestration"]

            if not pending_files:
                update_ui("Không có file mới nào cần xử lý.", 100)
                return True

            # Xác định Operation Mode chung cho đợt chạy này
            modes = {f.get("operation_mode") for f in pending_files}
            run_train = "train" in modes or "both" in modes
            run_detect = "detect" in modes or "both" in modes

            # ==========================================================
            # BƯỚC 1: PARSING TỐC ĐỘ CAO (Đa định dạng, xử lý Time-Window)
            # ==========================================================
            update_ui("1/5: Đang bóc tách Log thô (Multi-format Parser)...", 10)
            parser = WebServerLogParser(chunk_size=50000)

            # Xóa file temp cũ nếu còn sót lại
            if os.path.exists(self.paths["temp_parsed"]): os.remove(self.paths["temp_parsed"])

            for file_rec in pending_files:
                parser.process_log_file(
                    filepath=file_rec["physical_path"],
                    log_format=file_rec["log_format"],
                    log_type=file_rec["file_type"],
                    stream_to_disk=True,
                    temp_out=self.paths["temp_parsed"]
                )

            update_ui("1.5/5: Đang sắp xếp dữ liệu theo Dòng thời gian liền mạch...", 25)
            # Sắp xếp toàn bộ log trộn từ nhiều file theo đúng thứ tự thời gian (Xử lý Kịch bản Xen kẽ/Overlap)
            parser.export_to_ndjson(self.paths["parsed_timeline"], from_disk=True, temp_out=self.paths["temp_parsed"])
            if os.path.exists(self.paths["temp_parsed"]): os.remove(self.paths["temp_parsed"])

            # ==========================================================
            # BƯỚC 2: TẦNG 1 - TƯỜNG LỬA WAF (Phân tích tĩnh)
            # ==========================================================
            l1_runner = Layer1Runner()
            l1_stats = l1_runner.run(
                input_ndjson_path=self.paths["parsed_timeline"],
                output_ndjson_path=self.paths["layer1_alerts"],
                status_callback=status_callback
            )

            # ==========================================================
            # BƯỚC 3: SESSIONIZER (Nhóm dữ liệu thành Phiên hành vi)
            # ==========================================================
            update_ui("3/5: Đang nhóm Phiên và trích xuất Đặc trưng (Sessionizing)...", 45)
            sessionizer = StatefulStreamingEngine(timeout_minutes=15, max_session_hours=2)
            sessionizer.process_stream(
                input_ndjson=self.paths["layer1_alerts"],
                output_csv=self.paths["ml_features"],
                output_json=self.paths["session_timelines"],
                status_callback=status_callback
            )

            # ==========================================================
            # BƯỚC 4: HỌC MÁY HÀNH VI (Tầng 2 & 3)
            # ==========================================================
            stat_ensemble = Layer2AnomalyEnsemble()
            seq_engine = MarkovSequentialEngine()

            if run_train:
                update_ui("4/5: [Đào tạo] Đang cập nhật Baseline cho Profile này...", 60)
                stat_ensemble.train_baseline(self.paths["ml_features"], self.paths["stat_scores"], self.models_dir,
                                             status_callback)

                # Markov Chain Training
                seq_engine.load_model(self.paths["markov_model"])  # Load trí nhớ cũ
                seq_engine.train_baseline(self.paths["session_timelines"], status_callback=status_callback)
                seq_engine.save_model(self.paths["markov_model"])

            if run_detect:
                update_ui("4/5: [Phát hiện] Đang chạy AI chấm điểm Dị thường...", 70)
                stat_ensemble.score_live(self.paths["ml_features"], self.paths["stat_scores"], self.models_dir,
                                         status_callback)

                seq_engine.load_model(self.paths["markov_model"])
                seq_engine.score_sessions(self.paths["session_timelines"], self.paths["seq_scores"], status_callback)

            # ==========================================================
            # BƯỚC 5: DATA CORRELATOR (Dung hợp dữ liệu - Tầng 4)
            # ==========================================================
            if run_detect:
                correlator = DataCorrelator(
                    stat_csv=self.paths["stat_scores"],
                    seq_csv=self.paths["seq_scores"],
                    timelines_json=self.paths["session_timelines"],
                    output_ndjson=self.paths["incidents"]
                )
                correlator.run_correlation(status_callback)

            # Dọn dẹp trạng thái Metadata (Đánh dấu hoàn tất)
            for f in pending_files: f["status"] = "processed"
            self.profile_manager._save_metadata(self.profile_name, metadata)

            update_ui("Hoàn tất! Đang chuẩn bị dữ liệu hiển thị Dashboard...", 100)
            return True

        except Exception as e:
            import traceback
            update_ui(f"❌ Lỗi hệ thống: {str(e)}", 100)
            print(f"Pipeline Error: {traceback.format_exc()}")
            return False

    def compile_dashboard_data(self) -> Dict[str, Any]:
        """
        Đọc kết quả từ file ổ cứng (Incidents, ML Scores) và đóng gói thành 1 biến
        Dictionary sạch sẽ cho giao diện Web vẽ biểu đồ (Không logic, chỉ hiển thị).
        """
        dashboard_data = {
            "zone1_metrics": {"total_events": 0, "l1_blocks": 0, "anomalous_sessions": 0, "max_threat": "NORMAL"},
            "zone2_waf": {"attack_vectors": {}, "top_ips": {}},
            "zone3_ml": {"scatter_data": []},
            "zone4_incidents": []
        }

        # 1. Nếu chưa có file báo cáo, trả về cấu trúc rỗng
        if not os.path.exists(self.paths["incidents"]):
            return dashboard_data

        # 2. Đọc file Incident Reports
        incidents = []
        total_events = 0
        l1_alerts_count = 0
        max_threat_level = "NORMAL"
        anomalous_count = 0

        waf_vectors = {}
        ip_counts = {}

        with open(self.paths["incidents"], 'r', encoding='utf-8') as f:
            for line in f:
                case = json.loads(line.strip())
                incidents.append(case)

                # Gom số liệu Zone 1
                total_events += case.get("total_raw_events", 0)
                threat_level = case.get("overall_threat_level", "NORMAL")

                if threat_level == "CRITICAL":
                    max_threat_level = "CRITICAL"
                elif threat_level == "SUSPICIOUS" and max_threat_level != "CRITICAL":
                    max_threat_level = "SUSPICIOUS"

                if threat_level in ["CRITICAL", "SUSPICIOUS"]: anomalous_count += 1

                # Gom số liệu Zone 2 (Trích xuất từ timeline bị nén)
                source_ip = case.get("source_ip", "Unknown")
                ip_counts[source_ip] = ip_counts.get(source_ip, 0) + case.get("total_raw_events", 0)

                for event in case.get("timeline", []):
                    if event.get("layer1_flagged"):
                        l1_alerts_count += 1
                        for alert_type in event.get("layer1_alerts", []):
                            waf_vectors[alert_type] = waf_vectors.get(alert_type, 0) + 1

        dashboard_data["zone1_metrics"] = {
            "total_events": total_events,
            "l1_blocks": l1_alerts_count,
            "anomalous_sessions": anomalous_count,
            "max_threat": max_threat_level
        }

        dashboard_data["zone2_waf"]["attack_vectors"] = waf_vectors
        # Lấy top 10 IP bắn nhiều request nhất
        dashboard_data["zone2_waf"]["top_ips"] = dict(
            sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:10])

        dashboard_data["zone4_incidents"] = sorted(incidents, key=lambda x: x.get("max_statistical_score", 0),
                                                   reverse=True)

        # 3. Đọc file Machine Learning cho Zone 3 (Scatter Plot)
        try:
            if os.path.exists(self.paths["stat_scores"]) and os.path.exists(self.paths["seq_scores"]):
                df_stat = pd.read_csv(self.paths["stat_scores"])
                df_seq = pd.read_csv(self.paths["seq_scores"])
                df_merged = pd.merge(df_stat, df_seq, on=['session_id', 'parent_tracking_id'], how='inner')

                scatter_list = []
                for _, row in df_merged.iterrows():
                    scatter_list.append({
                        "session_id": row["session_id"],
                        "ip": row["parent_tracking_id"].split("_")[0],
                        "stat_score": row["statistical_threat_score"],
                        "seq_score": row["markov_threat_score"],
                        "label": row["statistical_threat_level"]
                    })
                dashboard_data["zone3_ml"]["scatter_data"] = scatter_list
        except Exception as e:
            print(f"Lỗi khi đọc biểu đồ Zone 3: {e}")

        return dashboard_data