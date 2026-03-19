import os
import json
import pandas as pd
from typing import Callable, Dict, List, Any
import streamlit as st
from datetime import datetime

from data_management.profile_manager import ProfileManager
from parser.parser_class import WebServerLogParser
from run_layer1 import Layer1Runner
from behaviour_layer.sessionizer import StatefulStreamingEngine
from behaviour_layer.machine_learning.statistical_models import Layer2AnomalyEnsemble
from behaviour_layer.machine_learning.sequential_model import MarkovSequentialEngine
from final_layer.correlator import DataCorrelator


class WebserverBridge:
    def __init__(self, profile_name: str, base_data_dir: str = "./webserver_module_AIT/module_data"):
        self.profile_name = profile_name
        self.profile_manager = ProfileManager(base_data_dir=base_data_dir)

        if profile_name not in self.profile_manager.get_all_profiles():
            self.profile_manager.create_profile(profile_name)

        self.profile_dir = os.path.join(base_data_dir, profile_name)
        self.raw_logs_dir = os.path.join(self.profile_dir, "raw_logs")
        self.models_dir = os.path.join(self.profile_dir, "models")
        self.results_dir = os.path.join(self.profile_dir, "results")

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
            "markov_model": os.path.join(self.models_dir, "markov_model.json")
        }

    def has_baseline(self) -> bool:
        stat_model_path = os.path.join(self.models_dir, "isolation_forest.joblib")
        seq_model_path = os.path.join(self.models_dir, "markov_model.json")
        return os.path.exists(stat_model_path) and os.path.exists(seq_model_path)

    def update_ai_thresholds(self, sensitivity: str):
        config_path = os.path.join(self.models_dir, "alert_config.json")
        data = {
            "suspicious_threshold": 60,
            "critical_threshold": 80
        }
        if sensitivity == "low":
            data = {"suspicious_threshold": 70, "critical_threshold": 95}
        elif sensitivity == "high":
            data = {"suspicious_threshold": 40, "critical_threshold": 60}

        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(data, f)

    def process_uploads(self, uploaded_files: List, operation_mode: str, time_window=None) -> List[Dict]:
        ingested_metadata = []
        for file in uploaded_files:
            try:
                record = self.profile_manager.ingest_file(
                    profile_name=self.profile_name,
                    uploaded_file=file,
                    operation_mode=operation_mode,
                    time_window=time_window
                )
                ingested_metadata.append(record)
            except Exception as e:
                st.error(f"❌ {e}")
        return ingested_metadata

    def run_full_pipeline(self, status_callback: Callable[[str, int], None] = None) -> bool:
        def update_ui(msg, pct):
            if status_callback: status_callback(msg, pct)

        try:
            metadata = self.profile_manager._load_metadata(self.profile_name)
            pending_files = [f for f in metadata if f.get("status") == "pending_orchestration"]

            if not pending_files:
                update_ui("Không có file mới nào cần xử lý.", 100)
                return True

            modes = {f.get("operation_mode") for f in pending_files}
            run_train = "train" in modes or "both" in modes
            run_detect = "detect" in modes or "both" in modes

            update_ui("1/5: Đang bóc tách Log thô (Multi-format Parser)...", 10)
            parser = WebServerLogParser(chunk_size=50000)

            if os.path.exists(self.paths["temp_parsed"]): os.remove(self.paths["temp_parsed"])

            all_files = [f for f in metadata if f.get("status") in ["pending_orchestration", "processed"]]

            for file_rec in all_files:
                parser.process_log_file(
                    filepath=file_rec["physical_path"],
                    log_format=file_rec["log_format"],
                    log_type=file_rec["file_type"],
                    stream_to_disk=True,
                    temp_out=self.paths["temp_parsed"]
                )

            update_ui("1.5/5: Đang sắp xếp dữ liệu theo Dòng thời gian liền mạch...", 25)
            parser.export_to_ndjson(self.paths["parsed_timeline"], from_disk=True, temp_out=self.paths["temp_parsed"])
            if os.path.exists(self.paths["temp_parsed"]): os.remove(self.paths["temp_parsed"])

            l1_runner = Layer1Runner()
            l1_runner.run(self.paths["parsed_timeline"], self.paths["layer1_alerts"], status_callback)

            update_ui("3/5: Đang nhóm Phiên và trích xuất Đặc trưng (Sessionizing)...", 45)
            sessionizer = StatefulStreamingEngine(timeout_minutes=10, max_session_hours=2)
            sessionizer.process_stream(self.paths["layer1_alerts"], self.paths["ml_features"],
                                       self.paths["session_timelines"], status_callback)

            # 🟢 FIX BẢO VỆ ML: Bỏ qua ML nếu không có ml_features được tạo ra
            if not os.path.exists(self.paths["ml_features"]) or os.path.getsize(self.paths["ml_features"]) == 0:
                update_ui("⚠️ Dữ liệu log quá ít/rác để tạo Phiên (Session). Bỏ qua ML.", 100)
                open(self.paths["incidents"], 'w').close() # Tạo file rỗng để không bị lỗi Dashboard
                for f in pending_files: f["status"] = "processed"
                self.profile_manager._save_metadata(self.profile_name, metadata)
                return True

            stat_ensemble = Layer2AnomalyEnsemble()
            seq_engine = MarkovSequentialEngine()

            if run_train:
                update_ui("4/5: [Đào tạo] Đang cập nhật Baseline cho Profile này...", 60)
                stat_ensemble.train_baseline(self.paths["ml_features"], self.paths["stat_scores"], self.models_dir,
                                             status_callback)
                seq_engine.load_model(self.paths["markov_model"])
                seq_engine.train_baseline(self.paths["session_timelines"], status_callback=status_callback)
                seq_engine.save_model(self.paths["markov_model"])

            if run_detect:
                update_ui("4/5: [Phát hiện] Đang chạy AI chấm điểm Dị thường...", 70)
                stat_ensemble.score_live(self.paths["ml_features"], self.paths["stat_scores"], self.models_dir,
                                         status_callback)
                seq_engine.load_model(self.paths["markov_model"])
                seq_engine.score_sessions(self.paths["session_timelines"], self.paths["seq_scores"], status_callback)

            if run_detect:
                correlator = DataCorrelator(
                    stat_csv=self.paths["stat_scores"],
                    seq_csv=self.paths["seq_scores"],
                    timelines_json=self.paths["session_timelines"],
                    output_ndjson=self.paths["incidents"],
                    models_dir=self.models_dir
                )
                correlator.run_correlation(status_callback)

            for f in pending_files: f["status"] = "processed"
            self.profile_manager._save_metadata(self.profile_name, metadata)

            update_ui("Hoàn tất! Đang chuẩn bị dữ liệu hiển thị Dashboard...", 100)
            return True

        except Exception as e:
            import traceback
            update_ui(f"❌ Lỗi hệ thống: {str(e)}", 100)
            print(f"Pipeline Error: {traceback.format_exc()}")
            return False

    def rescan_existing_data(self, operation_mode: str, time_window=None,
                             status_callback: Callable[[str, int], None] = None) -> bool:
        def update_ui(msg, pct):
            if status_callback: status_callback(msg, pct)

        try:
            update_ui("Khởi chạy Rescan: Đang nạp dữ liệu cũ từ hệ thống...", 10)

            run_train = operation_mode in ["train", "both"]
            run_detect = operation_mode in ["detect", "both"]

            if time_window:
                update_ui("Phát hiện bộ lọc thời gian: Khởi động lại luồng Parser...", 15)
                metadata = self.profile_manager._load_metadata(self.profile_name)
                existing_files = [f for f in metadata if f.get("status") in ["pending_orchestration", "processed"]]

                if not existing_files:
                    update_ui("❌ Không có file gốc nào trong Profile để lọc.", 100)
                    return False

                parser = WebServerLogParser(chunk_size=50000)
                if os.path.exists(self.paths["temp_parsed"]): os.remove(self.paths["temp_parsed"])

                for f in existing_files:
                    f["time_window_filter"] = [dt.isoformat() for dt in time_window]

                for file_rec in existing_files:
                    parser.process_log_file(
                        filepath=file_rec["physical_path"],
                        log_format=file_rec["log_format"],
                        log_type=file_rec["file_type"],
                        stream_to_disk=True,
                        temp_out=self.paths["temp_parsed"]
                    )

                update_ui("Đang cắt dữ liệu theo Dòng thời gian...", 25)
                parser.export_to_ndjson(self.paths["parsed_timeline"], from_disk=True,
                                        temp_out=self.paths["temp_parsed"])
                if os.path.exists(self.paths["temp_parsed"]): os.remove(self.paths["temp_parsed"])

                l1_runner = Layer1Runner()
                l1_runner.run(self.paths["parsed_timeline"], self.paths["layer1_alerts"], status_callback)
            else:
                if not os.path.exists(self.paths["layer1_alerts"]):
                    update_ui("❌ Không tìm thấy dữ liệu cũ. Vui lòng Nạp Log Mới trước.", 100)
                    return False

            update_ui("3/5: Đang trích xuất lại Đặc trưng (Sessionizing)...", 30)
            sessionizer = StatefulStreamingEngine(timeout_minutes=15, max_session_hours=2)
            sessionizer.process_stream(self.paths["layer1_alerts"], self.paths["ml_features"],
                                       self.paths["session_timelines"], status_callback)

            # 🟢 FIX BẢO VỆ ML CHO RESCAN
            if not os.path.exists(self.paths["ml_features"]) or os.path.getsize(self.paths["ml_features"]) == 0:
                update_ui("⚠️ Dữ liệu sau khi lọc không đủ để tạo Phiên. Dừng phân tích.", 100)
                open(self.paths["incidents"], 'w').close()
                return True

            stat_ensemble = Layer2AnomalyEnsemble()
            seq_engine = MarkovSequentialEngine()

            if run_train:
                update_ui("4/5: [Đào tạo] Đang cập nhật lại Baseline từ dữ liệu cũ...", 50)
                stat_ensemble.train_baseline(self.paths["ml_features"], self.paths["stat_scores"], self.models_dir,
                                             status_callback)
                seq_engine.load_model(self.paths["markov_model"])
                seq_engine.train_baseline(self.paths["session_timelines"], status_callback=status_callback)
                seq_engine.save_model(self.paths["markov_model"])

            if run_detect:
                update_ui("4/5: [Phát hiện] Đang áp dụng Threshold mới để chấm điểm...", 70)
                stat_ensemble.score_live(self.paths["ml_features"], self.paths["stat_scores"], self.models_dir,
                                         status_callback)
                seq_engine.load_model(self.paths["markov_model"])
                seq_engine.score_sessions(self.paths["session_timelines"], self.paths["seq_scores"],
                                          status_callback)

            if run_detect:
                update_ui("5/5: [Correlator] Đang kết xuất báo cáo Sự cố cuối cùng...", 85)
                correlator = DataCorrelator(
                    stat_csv=self.paths["stat_scores"],
                    seq_csv=self.paths["seq_scores"],
                    timelines_json=self.paths["session_timelines"],
                    output_ndjson=self.paths["incidents"],
                    models_dir=self.models_dir
                )
                correlator.run_correlation(status_callback)

            if time_window:
                metadata = self.profile_manager._load_metadata(self.profile_name)
                for f in metadata:
                    if f.get("status") in ["pending_orchestration", "processed"]:
                        f["time_window_filter"] = [dt.isoformat() for dt in time_window]
                self.profile_manager._save_metadata(self.profile_name, metadata)

            update_ui("Hoàn tất Quét lại!", 100)
            return True

        except Exception as e:
            import traceback
            update_ui(f"❌ Lỗi khi Rescan: {str(e)}", 100)
            print(f"Rescan Error: {traceback.format_exc()}")
            return False

    def delete_specific_files(self, file_ids: List[str]):
        metadata = self.profile_manager._load_metadata(self.profile_name)
        new_metadata = []
        for file in metadata:
            if file.get("file_id") in file_ids:
                physical_path = file.get("physical_path")
                if physical_path and os.path.exists(physical_path):
                    os.remove(physical_path)
            else:
                file["status"] = "pending_orchestration"
                new_metadata.append(file)

        self.profile_manager._save_metadata(self.profile_name, new_metadata)

        # 🟢 NẾU XÓA HẾT FILE -> DỌN SẠCH PROFILE NHƯ LÚC MỚI TẠO
        if not new_metadata:
            import shutil
            shutil.rmtree(self.models_dir, ignore_errors=True)
            shutil.rmtree(self.results_dir, ignore_errors=True)
            os.makedirs(self.models_dir, exist_ok=True)
            os.makedirs(self.results_dir, exist_ok=True)
        else:
            for path in self.paths.values():
                if os.path.exists(path):
                    os.remove(path)

    def compile_dashboard_data(self, display_time_window=None) -> Dict[str, Any]:
        dashboard_data = {
            "zone1_metrics": {"total_events": 0, "l1_blocks": 0, "anomalous_sessions": 0, "normal_sessions": 0, "critical_sessions": 0, "suspicious_sessions": 0, "max_threat": "NORMAL"},
            "zone2_waf": {"attack_vectors": {}, "top_ips": {}, "top_uris": {}, "geo_distribution": {}},
            "zone3_ml": {"scatter_data": [], "timeline_data": []},
            "zone4_incidents": []
        }

        if not os.path.exists(self.paths["incidents"]):
            return dashboard_data

        ip_to_country = {}
        if os.path.exists(self.paths["ml_features"]):
            try:
                df_features = pd.read_csv(self.paths["ml_features"])
                if 'source_ip' in df_features.columns and 'geo_country' in df_features.columns:
                    ip_to_country = dict(zip(df_features['source_ip'], df_features['geo_country']))
            except Exception: pass

        incidents = []
        total_events = l1_alerts_count = 0
        normal_count = suspicious_count = critical_count = 0
        max_threat_level = "NORMAL"

        waf_vectors = {}
        ip_counts = {}
        uri_counts = {}
        geo_counts = {}
        timeline_data = []

        with open(self.paths["incidents"], 'r', encoding='utf-8') as f:
            for line in f:
                case = json.loads(line.strip())

                if display_time_window and case.get("timeline"):
                    session_start_str = case["timeline"][0].get("@timestamp")
                    session_end_str = case["timeline"][-1].get("@timestamp")
                    try:
                        s_start = datetime.fromisoformat(session_start_str.replace("Z", "+00:00")).replace(tzinfo=None)
                        s_end = datetime.fromisoformat(session_end_str.replace("Z", "+00:00")).replace(tzinfo=None)
                        if s_end < display_time_window[0] or s_start > display_time_window[1]: continue
                    except Exception: pass

                incidents.append(case)
                total_events += case.get("total_raw_events", 0)
                threat_level = case.get("overall_threat_level", "NORMAL")

                if threat_level == "CRITICAL":
                    max_threat_level = "CRITICAL"
                    critical_count += 1
                elif threat_level == "SUSPICIOUS":
                    if max_threat_level != "CRITICAL": max_threat_level = "SUSPICIOUS"
                    suspicious_count += 1
                else:
                    normal_count += 1

                source_ip = case.get("source_ip", "Unknown")
                ip_counts[source_ip] = ip_counts.get(source_ip, 0) + case.get("total_raw_events", 0)

                country = ip_to_country.get(source_ip, "Unknown")
                if country and country not in ["Unknown", "LOCAL"]:
                    geo_counts[country] = geo_counts.get(country, 0) + case.get("total_raw_events", 0)

                if case.get("timeline"):
                    start_time = case["timeline"][0].get("@timestamp")
                    if start_time:
                        timeline_data.append({
                            "timestamp": start_time,
                            "threat_score": case.get("max_statistical_score", 0),
                            "threat_level": threat_level
                        })

                for event in case.get("timeline", []):
                    if event.get("layer1_flagged"):
                        l1_alerts_count += 1
                        for alert_type in event.get("layer1_alerts", []):
                            waf_vectors[alert_type] = waf_vectors.get(alert_type, 0) + 1

                        uri = event.get("uri_path")
                        if uri: uri_counts[uri] = uri_counts.get(uri, 0) + 1

        total_sessions = len(incidents)
        dashboard_data["zone1_metrics"] = {
            "total_events": total_events,
            "l1_blocks": l1_alerts_count,
            "anomalous_sessions": suspicious_count + critical_count,
            "normal_sessions": normal_count,
            "suspicious_sessions": suspicious_count,
            "critical_sessions": critical_count,
            "max_threat": max_threat_level
        }

        dashboard_data["zone2_waf"]["attack_vectors"] = waf_vectors
        dashboard_data["zone2_waf"]["top_ips"] = dict(sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:10])
        dashboard_data["zone2_waf"]["top_uris"] = dict(sorted(uri_counts.items(), key=lambda item: item[1], reverse=True)[:10])
        dashboard_data["zone2_waf"]["geo_distribution"] = geo_counts
        dashboard_data["zone3_ml"]["timeline_data"] = timeline_data
        dashboard_data["zone4_incidents"] = sorted(incidents, key=lambda x: x.get("max_statistical_score", 0), reverse=True)

        try:
            if os.path.exists(self.paths["stat_scores"]) and os.path.exists(self.paths["seq_scores"]):
                df_stat = pd.read_csv(self.paths["stat_scores"])
                df_seq = pd.read_csv(self.paths["seq_scores"])
                df_merged = pd.merge(df_stat, df_seq, on=['session_id', 'parent_tracking_id'], how='inner')

                config_path = os.path.join(self.models_dir, "alert_config.json")
                sus_thresh, crit_thresh = 50, 80
                if os.path.exists(config_path):
                    with open(config_path, 'r', encoding='utf-8') as f:
                        cfg = json.load(f)
                        sus_thresh = cfg.get("suspicious_threshold", 60)
                        crit_thresh = cfg.get("critical_threshold", 80)

                valid_parent_ids = {case["incident_tracking_id"] for case in incidents}
                scatter_list = []
                for _, row in df_merged.iterrows():
                    if row["parent_tracking_id"] not in valid_parent_ids: continue
                    s_score = row.get("statistical_threat_score", 0)
                    m_score = row.get("markov_threat_score", 0)
                    max_ai = max(s_score, m_score)
                    label = "CRITICAL" if max_ai >= crit_thresh else ("SUSPICIOUS" if max_ai >= sus_thresh else "NORMAL")

                    scatter_list.append({
                        "session_id": row["session_id"],
                        "ip": row["parent_tracking_id"].split("_")[0],
                        "stat_score": s_score,
                        "seq_score": m_score,
                        "label": label
                    })
                dashboard_data["zone3_ml"]["scatter_data"] = scatter_list
        except Exception as e:
            print(f"Lỗi khi đọc biểu đồ Zone 3: {e}")

        return dashboard_data