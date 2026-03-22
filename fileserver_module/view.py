"""
=============================================================================
File Server UEBA — Streamlit View
=============================================================================

Provides the ``render_page()`` entry-point consumed by the SOC platform
router (app.py).  Follows the same 3-tab pattern as the webserver module
via ``core.shared_ui.render_standard_module_layout``.
"""

import os
import sys

# Ensure fileserver_module sibling imports work
_MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
if _MODULE_DIR not in sys.path:
    sys.path.insert(0, _MODULE_DIR)

import streamlit as st
import plotly.express as px
import pandas as pd
from datetime import datetime

from core.shared_ui import render_standard_module_layout
from fileserver_module.backend_bridge import FileServerBridge
from fileserver_module.llm_advisor import FileServerLLMAdvisor
from fileserver_module.collect_logs import (
    is_admin,
    check_audit_policy,
    enable_audit_policy,
    collect_via_powershell,
    collect_via_python,
    TARGET_EVENT_IDS,
    EXTENDED_EVENT_IDS,
)


# =====================================================================
# 1. Dashboard Tab
# =====================================================================

def render_dashboard(data: dict):
    """Render the File Server UEBA dashboard."""
    if not data or not data.get("user_results"):
        st.warning(
            "Chưa có dữ liệu phân tích. Vui lòng sang tab "
            "'📂 Tải lên & Cấu hình' để nạp Log."
        )
        return

    # --- 1.1  Global Metrics ---
    st.markdown("### 📊 1. Chỉ số Tổng quan")
    total_events = data.get("total_events", 0)
    total_users = data.get("total_users", 0)
    time_window = data.get("time_window", "?")
    span_min = data.get("data_span_minutes", 0)

    user_results = data["user_results"]
    analyzed = [u for u in user_results if u["status"] == "analyzed"]
    skipped  = [u for u in user_results if u["status"] == "skipped"]
    total_anomalies = sum(u["anomaly_count"] for u in analyzed)
    max_score = max((u["max_score"] for u in analyzed), default=0)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Tổng Events", f"{total_events:,}")
    c2.metric("Người dùng", f"{total_users}")
    c3.metric("Cửa sổ Dị thường", f"{total_anomalies}")
    c4.metric("Điểm cao nhất", f"{max_score:.1f}/100")
    threat = "🔴 CRITICAL" if max_score >= 80 else ("🟡 WARNING" if max_score >= 50 else "🟢 NORMAL")
    c5.metric("Mức Đe Dọa", threat)

    st.caption(
        f"⏱️ Dữ liệu trải dài {span_min:.0f} phút — "
        f"Cửa sổ phân tích: **{time_window}** — "
        f"Bỏ qua {len(skipped)} user (dữ liệu quá ít)"
    )
    st.markdown("<br>", unsafe_allow_html=True)

    # --- 1.2  Per-user results table ---
    st.markdown("### 👤 2. Kết quả theo Người dùng")

    table_rows = []
    for u in user_results:
        risk = ""
        if u["status"] == "skipped":
            risk = "⏭️ Bỏ qua"
        elif u["max_score"] >= 80:
            risk = "🔴 CRITICAL"
        elif u["max_score"] >= 50:
            risk = "🟡 WARNING"
        else:
            risk = "🟢 NORMAL"
        table_rows.append({
            "Người dùng": u["user"],
            "Cửa sổ": u["total_windows"],
            "Dị thường": u["anomaly_count"],
            "Điểm TB": u["avg_score"],
            "Điểm Max": u["max_score"],
            "Rủi ro": risk,
        })

    df_table = pd.DataFrame(table_rows)
    selection = st.dataframe(
        df_table,
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
    )
    st.markdown("<br>", unsafe_allow_html=True)

    # --- 1.3  Charts ---
    if analyzed:
        st.markdown("### 📈 3. Biểu đồ Phân tích")
        col_bar, col_scatter = st.columns(2)

        with col_bar:
            bar_df = pd.DataFrame([
                {"User": u["user"], "Max Score": u["max_score"], "Avg Score": u["avg_score"]}
                for u in analyzed
            ]).sort_values("Max Score", ascending=False)
            fig_bar = px.bar(
                bar_df, x="User", y=["Max Score", "Avg Score"],
                barmode="group",
                title="Điểm Dị thường theo Người dùng",
                color_discrete_sequence=["#EF553B", "#636EFA"],
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        with col_scatter:
            scatter_rows = []
            for u in analyzed:
                for s in u.get("scores", []):
                    scatter_rows.append({
                        "User": u["user"],
                        "Time Window": s["time_window"],
                        "Score": s["anomaly_score"],
                        "Anomaly": "🔴 Yes" if s["is_anomaly"] else "🟢 No",
                    })
            if scatter_rows:
                sdf = pd.DataFrame(scatter_rows)
                fig_sc = px.strip(
                    sdf, x="User", y="Score", color="Anomaly",
                    color_discrete_map={"🔴 Yes": "#EF553B", "🟢 No": "#00CC96"},
                    title="Phân bố Điểm Dị thường",
                )
                fig_sc.add_hline(y=80, line_dash="dash", line_color="red", opacity=0.4)
                fig_sc.add_hline(y=50, line_dash="dash", line_color="orange", opacity=0.4)
                st.plotly_chart(fig_sc, use_container_width=True)

    # --- 1.4  Selected user detail ---
    selected_user_data = None
    if selection.selection.rows:
        sel_idx = selection.selection.rows[0]
        sel_user_name = df_table.iloc[sel_idx]["Người dùng"]
        selected_user_data = next(
            (u for u in user_results if u["user"] == sel_user_name), None
        )

    if selected_user_data and selected_user_data["status"] == "analyzed":
        st.divider()
        st.markdown(f"### 🔍 Chi tiết: `{selected_user_data['user']}`")

        # Score timeline
        scores = selected_user_data.get("scores", [])
        if scores:
            sdf = pd.DataFrame(scores)
            sdf["time_window"] = pd.to_datetime(sdf["time_window"], errors="coerce")
            color_map = {True: "#EF553B", False: "#00CC96"}
            fig_line = px.scatter(
                sdf, x="time_window", y="anomaly_score",
                color="is_anomaly", color_discrete_map=color_map,
                title="Điểm Dị thường theo Thời gian",
                labels={"time_window": "Thời gian", "anomaly_score": "Điểm"},
            )
            fig_line.update_traces(mode="lines+markers")
            fig_line.add_hline(y=80, line_dash="dash", line_color="red", opacity=0.4)
            st.plotly_chart(fig_line, use_container_width=True)

        # Feature importance
        top_feats = selected_user_data.get("top_features", [])
        if top_feats:
            st.markdown("**🔬 Top 5 Đặc trưng Bất thường nhất (Z-score):**")
            feat_df = pd.DataFrame(top_feats)
            feat_df.columns = ["Đặc trưng", "Z-score", "Baseline Mean", "Baseline Std", "Giá trị hiện tại"]
            st.dataframe(feat_df, use_container_width=True, hide_index=True)


# =====================================================================
# 2. LLM / AI Analysis Tab
# =====================================================================

def render_llm_tab(data: dict):
    """AI-powered per-user threat analysis with LLM summaries."""
    if not data or not data.get("user_results"):
        st.info("Chưa có dữ liệu để phân tích. Vui lòng nạp Log trước.")
        return

    user_results = data["user_results"]
    analyzed = [u for u in user_results if u["status"] == "analyzed"]

    if not analyzed:
        st.warning("Không có người dùng nào đã được phân tích. Vui lòng nạp và chạy phân tích trước.")
        return

    st.markdown("#### 📋 Danh sách Người dùng & Phân tích AI")

    # Build display table sorted by risk (highest first)
    table_rows = []
    for u in analyzed:
        if u["max_score"] >= 80:
            risk = "🔴 CRITICAL"
        elif u["max_score"] >= 50:
            risk = "🟡 WARNING"
        else:
            risk = "🟢 NORMAL"
        table_rows.append({
            "Người dùng": u["user"],
            "Rủi ro": risk,
            "Điểm Max": u["max_score"],
            "Điểm TB": u["avg_score"],
            "Cửa sổ Dị thường": f"{u['anomaly_count']}/{u['total_windows']}",
        })

    df_table = pd.DataFrame(table_rows)
    # Sort: CRITICAL first, then WARNING, then NORMAL
    risk_order = {"🔴 CRITICAL": 0, "🟡 WARNING": 1, "🟢 NORMAL": 2}
    df_table["_sort"] = df_table["Rủi ro"].map(risk_order)
    df_table = df_table.sort_values(["_sort", "Điểm Max"], ascending=[True, False]).drop(columns=["_sort"])

    st.markdown(
        "💡 *Mẹo: Click chọn một dòng để xem chi tiết và yêu cầu AI phân tích.*"
    )

    selection = st.dataframe(
        df_table.reset_index(drop=True),
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
    )
    st.divider()

    # --- Selected user detail ---
    selected_user_data = None
    if selection.selection.rows:
        sel_idx = selection.selection.rows[0]
        sel_user_name = df_table.iloc[sel_idx]["Người dùng"]
        selected_user_data = next(
            (u for u in analyzed if u["user"] == sel_user_name), None
        )

    if not selected_user_data:
        st.info("👆 Chọn một người dùng từ bảng trên để xem phân tích chi tiết.")
        return

    user = selected_user_data["user"]
    max_score = selected_user_data["max_score"]
    if max_score >= 80:
        threat_icon = "🔴"
        threat_label = "CRITICAL"
    elif max_score >= 50:
        threat_icon = "🟡"
        threat_label = "WARNING"
    else:
        threat_icon = "🟢"
        threat_label = "NORMAL"

    st.markdown(f"### 🔍 Phân tích Chuyên sâu: `{user}` {threat_icon} {threat_label}")

    # --- AI Summary Section (above data table) ---
    st.markdown("##### 🤖 Phân tích AI cho Nguồn Nguy hiểm")

    api_key = st.session_state.get("llm_api_key", "")
    provider = st.session_state.get("llm_provider", "nvidia")
    model = st.session_state.get("llm_model", "meta/llama3-70b-instruct")

    if st.button("Phân tích với LLM", type="primary", key="fs_llm_analyze"):
        if not api_key:
            st.error("Vui lòng sang tab '📂 Tải lên & Cấu hình' nhập LLM API Key trước khi sử dụng AI.")
        else:
            with st.spinner(f"Đang gửi dữ liệu đến {provider.upper()} để phân tích..."):
                advisor = FileServerLLMAdvisor()
                analysis_result = advisor.analyze_user(
                    user_result=selected_user_data,
                    provider=provider,
                    model=model,
                    api_key=api_key,
                )
                st.success("Phân tích hoàn tất!")
                st.markdown("### 📝 Báo cáo từ AI:")
                st.info(analysis_result)

    st.divider()

    # --- Feature Context Table ---
    st.markdown("##### 🔬 Đặc trưng Hành vi Chi tiết")

    feature_values = selected_user_data.get("feature_values", {})
    if feature_values:
        # Group features by category for display
        categories = {
            "📊 Volume / Velocity": [
                "total_read_operations", "total_write_operations",
                "total_delete_operations", "total_events", "read_write_ratio",
            ],
            "🔍 Variety / Context": [
                "distinct_files_accessed", "distinct_processes_used",
                "admin_share_access_count", "lolbin_event_count",
            ],
            "🕐 Spatio-Temporal": [
                "off_hour_activity_ratio", "hour_sin", "hour_cos",
            ],
            "🔑 Authentication": [
                "successful_logon_count", "failed_logon_count",
                "failed_logon_ratio", "distinct_logon_source_ips",
                "explicit_credential_count",
            ],
            "⚙️ Process Execution": [
                "new_process_count", "suspicious_process_count",
                "distinct_parent_processes",
            ],
            "📌 Persistence": [
                "scheduled_task_created_count", "service_installed_count",
            ],
            "🧹 Anti-Forensics": [
                "audit_log_cleared_count", "object_deleted_count",
            ],
            "🌐 Network / Share": [
                "share_session_count", "distinct_shares_accessed",
            ],
        }

        for cat_name, feat_list in categories.items():
            present = [f for f in feat_list if f in feature_values]
            if present:
                with st.expander(cat_name, expanded=(cat_name.startswith("📊"))):
                    feat_rows = []
                    for feat in present:
                        val = feature_values[feat]
                        feat_rows.append({"Đặc trưng": feat, "Giá trị (Max)": val})
                    st.dataframe(
                        pd.DataFrame(feat_rows),
                        use_container_width=True, hide_index=True,
                    )

    # --- Top Z-score deviations ---
    top_feats = selected_user_data.get("top_features", [])
    if top_feats:
        st.markdown("##### ⚠️ Top 5 Đặc trưng Lệch Chuẩn (Z-Score)")
        feat_df = pd.DataFrame(top_feats)
        feat_df.columns = ["Đặc trưng", "Z-score", "Baseline Mean", "Baseline Std", "Giá trị hiện tại"]
        st.dataframe(feat_df, use_container_width=True, hide_index=True)

    # --- Anomaly timeline ---
    scores = selected_user_data.get("scores", [])
    if scores:
        st.markdown("##### 📈 Điểm Dị thường theo Thời gian")
        sdf = pd.DataFrame(scores)
        sdf["time_window"] = pd.to_datetime(sdf["time_window"], errors="coerce")
        color_map = {True: "#EF553B", False: "#00CC96"}
        fig_line = px.scatter(
            sdf, x="time_window", y="anomaly_score",
            color="is_anomaly", color_discrete_map=color_map,
            title="Điểm Dị thường theo Cửa sổ Thời gian",
            labels={"time_window": "Thời gian", "anomaly_score": "Điểm"},
        )
        fig_line.update_traces(mode="lines+markers")
        fig_line.add_hline(y=80, line_dash="dash", line_color="red", opacity=0.4)
        fig_line.add_hline(y=50, line_dash="dash", line_color="orange", opacity=0.4)
        st.plotly_chart(fig_line, use_container_width=True)


# =====================================================================
# 3. Upload & Config Tab
# =====================================================================

def render_upload_and_config(bridge: FileServerBridge, profile_name: str):
    # --- 3.1  Existing files ---
    st.markdown(f"#### 1. Quản lý Dữ liệu: `{profile_name}`")

    col_list, col_del = st.columns([4, 1])
    with col_del:
        if st.button("🗑️ Xóa Profile", type="primary", use_container_width=True):
            bridge.delete_profile()
            st.session_state["fs_profile_deleted"] = True
            st.rerun()

    metadata = bridge._load_metadata()
    if metadata:
        df_files = pd.DataFrame(metadata)
        display_cols = ["file_id", "original_name", "size_bytes", "upload_time", "status"]
        available = [c for c in display_cols if c in df_files.columns]
        disp = df_files[available].copy()
        if "size_bytes" in disp.columns:
            disp["size_bytes"] = (disp["size_bytes"] / 1024).round(1).astype(str) + " KB"
        disp.columns = [
            c.replace("file_id", "ID").replace("original_name", "Tên File")
             .replace("size_bytes", "Dung lượng").replace("upload_time", "Ngày nạp")
             .replace("status", "Trạng thái")
            for c in disp.columns
        ]

        file_sel = st.dataframe(
            disp, use_container_width=True, hide_index=True,
            on_select="rerun", selection_mode="multi-row",
        )

        if file_sel.selection.rows:
            sel_ids = df_files.iloc[file_sel.selection.rows]["file_id"].tolist()
            if st.button(f"🗑️ Xóa {len(sel_ids)} file đã chọn", type="primary"):
                bridge.delete_files(sel_ids)
                st.success("Đã xóa file. Vui lòng chạy lại phân tích nếu cần.")
                st.rerun()
    else:
        st.info("Profile này chưa có file dữ liệu nào.")

    st.divider()

    # --- 3.2  Config ---
    st.markdown("#### 2. Cấu hình Phân tích")
    with st.container(border=True):
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            time_window = st.selectbox(
                "Cửa sổ Thời gian (Time Window):",
                ["1h", "30min", "15min", "5min", "2min", "1min"],
                index=0,
                help="Nếu dữ liệu ngắn, hệ thống sẽ tự động chọn cửa sổ nhỏ hơn.",
            )
        with col_c2:
            contamination = st.slider(
                "Tỷ lệ Dị thường (Contamination):",
                min_value=0.01, max_value=0.30, value=0.05, step=0.01,
                help="Tỷ lệ dự kiến dữ liệu bất thường trong tập huấn luyện.",
            )

        st.markdown("---")
        st.markdown("**Cấu hình LLM (cho tab Chuyên gia AI):**")
        col_llm1, col_llm2 = st.columns(2)
        with col_llm1:
            llm_provider = st.selectbox("Nhà cung cấp LLM:", ["nvidia", "openrouter", "google"], key="fs_llm_provider")
            llm_model = st.text_input("Tên Model:", value="meta/llama3-70b-instruct", key="fs_llm_model")
        with col_llm2:
            llm_api_key = st.text_input("API Key:", type="password", key="fs_llm_api_key")

        st.session_state["llm_provider"] = llm_provider
        st.session_state["llm_model"] = llm_model
        st.session_state["llm_api_key"] = llm_api_key

    st.divider()

    # --- 3.3  Upload ---
    st.markdown("#### 3. Nạp Log Mới")
    st.caption("Hỗ trợ: `.json` (PowerShell export), `.csv` (Event Viewer), `.evtx` (raw)")

    if "fs_uploader_key" not in st.session_state:
        st.session_state["fs_uploader_key"] = str(datetime.now())

    uploaded_files = st.file_uploader(
        "Kéo thả file Windows Event Log:",
        accept_multiple_files=True,
        type=["json", "csv", "evtx"],
        key=st.session_state["fs_uploader_key"],
    )

    if uploaded_files:
        if st.button("🚀 Nạp Dữ Liệu & Bắt Đầu Phân Tích", type="primary", use_container_width=True):
            # Ingest files
            for uf in uploaded_files:
                try:
                    bridge.ingest_file(uf)
                except ValueError as e:
                    st.error(f"❌ {e}")

            # Run pipeline
            progress_bar = st.progress(0)
            status_text = st.empty()

            def ui_cb(msg, pct):
                status_text.text(msg)
                progress_bar.progress(min(pct, 100) / 100.0)

            success = bridge.run_pipeline(
                time_window=time_window,
                contamination=contamination,
                status_callback=ui_cb,
            )
            if success:
                st.success("Hoàn tất! Chuyển sang tab Dashboard để xem kết quả.")
                progress_bar.empty()
                status_text.empty()
                st.session_state["fs_uploader_key"] = str(datetime.now())
                st.rerun()

    # --- 3.4  Re-run analysis ---
    st.divider()
    st.markdown("#### 4. Chạy lại Phân tích (Rescan)")
    if bridge.has_results() or metadata:
        if st.button("🔁 Chạy lại Phân tích với Cấu hình mới", use_container_width=True):
            progress_bar = st.progress(0)
            status_text = st.empty()

            def ui_cb2(msg, pct):
                status_text.text(msg)
                progress_bar.progress(min(pct, 100) / 100.0)

            success = bridge.run_pipeline(
                time_window=time_window,
                contamination=contamination,
                status_callback=ui_cb2,
            )
            if success:
                st.success("Hoàn tất! Chuyển sang tab Dashboard để xem kết quả.")
                progress_bar.empty()
                status_text.empty()
                st.rerun()

    # --- 3.5  Collect logs from local machine ---
    st.divider()
    st.markdown("#### 5. 🔍 Thu thập Log từ Máy chủ (Windows Event Log)")
    st.caption(
        "Thu thập trực tiếp Windows Security Event Log từ máy đang chạy. "
        "Yêu cầu quyền **Administrator** để đọc Security log."
    )

    # Audit policy status
    with st.expander("📋 Kiểm tra Audit Policy hiện tại", expanded=False):
        admin_status = is_admin()
        if admin_status:
            st.success("✅ Đang chạy với quyền Administrator.")
        else:
            st.warning(
                "⚠️ Không có quyền Administrator. Một số tính năng có thể bị hạn chế.\n\n"
                "Để thu thập Security log, hãy chạy Streamlit với quyền Admin:"
                "\n```\nRun PowerShell as Administrator → streamlit run app.py\n```"
            )

        if st.button("🔄 Kiểm tra Audit Policy", key="fs_check_audit"):
            policy = check_audit_policy()
            if policy:
                for subcategory, setting in policy.items():
                    status_icon = "✅" if "success" in setting.lower() else "⚠️"
                    st.write(f"{status_icon} **{subcategory}**: {setting}")
            else:
                st.info("Không thể kiểm tra Audit Policy (có thể thiếu quyền).")

        if admin_status:
            if st.button("🔧 Tự động Bật Audit Policy", key="fs_enable_audit", type="secondary"):
                with st.spinner("Đang bật Audit Policy..."):
                    success = enable_audit_policy()
                if success:
                    st.success("Đã bật Audit Policy cho File System, File Share, và Detailed File Share.")
                else:
                    st.error("Có lỗi khi bật một số Audit Policy. Kiểm tra console để biết chi tiết.")

    # Collection settings
    with st.container(border=True):
        col_m1, col_m2, col_m3 = st.columns(3)
        with col_m1:
            collect_method = st.selectbox(
                "Phương pháp thu thập:",
                ["powershell", "python"],
                index=0,
                format_func=lambda x: "PowerShell (Khuyến nghị)" if x == "powershell" else "Python (pywin32)",
                key="fs_collect_method",
            )
        with col_m2:
            collect_days = st.number_input(
                "Số ngày thu thập:",
                min_value=1, max_value=365, value=7, step=1,
                key="fs_collect_days",
                help="Thu thập log từ N ngày gần nhất tính từ hiện tại.",
            )
        with col_m3:
            collect_extended = st.checkbox(
                "Thu thập mở rộng (all 13 Event IDs)",
                value=True,
                key="fs_collect_extended",
                help=(
                    f"Core: {', '.join(str(e) for e in sorted(TARGET_EVENT_IDS))}\n\n"
                    f"Extended thêm: Authentication (4624/4625/4648), Process (4688), "
                    f"Persistence (4698/7045), Anti-Forensics (1102)"
                ),
            )

        # Collect button
        if st.button(
            "📥 Thu thập Log & Tự động Nạp vào Hệ thống",
            type="primary",
            use_container_width=True,
            key="fs_collect_btn",
        ):
            # Output path inside the profile's raw_logs dir
            ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_filename = f"collected_{ts_str}.json"
            output_path = os.path.join(bridge.raw_logs_dir, output_filename)

            with st.spinner(f"Đang thu thập {collect_days} ngày log bằng {collect_method.upper()}..."):
                try:
                    if collect_method == "powershell":
                        result_path = collect_via_powershell(
                            days=collect_days,
                            output_path=output_path,
                            extended=collect_extended,
                        )
                    else:
                        result_path = collect_via_python(
                            days=collect_days,
                            output_path=output_path,
                            extended=collect_extended,
                        )
                except Exception as e:
                    st.error(f"❌ Lỗi thu thập: {e}")
                    result_path = None

            if result_path and os.path.exists(result_path):
                file_size = os.path.getsize(result_path)
                if file_size > 0:
                    # Register in profile metadata
                    import hashlib
                    with open(result_path, "rb") as rf:
                        file_hash = hashlib.md5(rf.read()).hexdigest()

                    metadata = bridge._load_metadata()
                    record = {
                        "file_id": f"fs_{file_hash[:8]}_{ts_str}",
                        "original_name": output_filename,
                        "physical_path": result_path,
                        "file_hash": file_hash,
                        "size_bytes": file_size,
                        "upload_time": datetime.now().isoformat(),
                        "status": "pending",
                        "source": f"local_collect_{collect_method}",
                    }
                    metadata.append(record)
                    bridge._save_metadata(metadata)

                    st.success(
                        f"✅ Thu thập thành công! "
                        f"File: `{output_filename}` ({file_size / 1024:.1f} KB).\n\n"
                        f"File đã được tự động nạp vào Profile. "
                        f"Nhấn **'🚀 Nạp Dữ Liệu & Bắt Đầu Phân Tích'** hoặc "
                        f"**'🔁 Chạy lại Phân tích'** ở trên để bắt đầu phân tích."
                    )
                    st.rerun()
                else:
                    st.warning(
                        "⚠️ File thu thập rỗng. Không tìm thấy Event nào phù hợp.\n\n"
                        "Kiểm tra:\n"
                        "1. Script đang chạy với quyền Administrator\n"
                        "2. Audit Policy đã được bật (dùng nút 'Tự động Bật Audit Policy' ở trên)\n"
                        "3. SACL đã được cấu hình trên thư mục cần giám sát"
                    )
            elif result_path and result_path.endswith(".ps1"):
                st.info(
                    f"📜 PowerShell script đã được tạo tại:\n`{result_path}`\n\n"
                    f"Chạy thủ công bằng cách mở PowerShell (Admin) và chạy:\n"
                    f"```\npowershell -ExecutionPolicy Bypass -File \"{result_path}\"\n```"
                )
            else:
                st.error("❌ Không thể thu thập log. Kiểm tra console để biết chi tiết.")


# =====================================================================
# 4. Main render_page() — entry point for app.py
# =====================================================================

def render_page():
    """Called by app.py's dynamic module loader."""

    # Handle profile deletion
    if st.session_state.get("fs_profile_deleted"):
        st.success("Đã xóa Profile thành công.")
        st.session_state["fs_profile_deleted"] = False
        st.session_state["fs_selected_profile"] = "Default_Tenant"

    # --- Profile selector ---
    st.markdown("### 🏢 Quản lý Phiên làm việc (Tenant Workspace)")

    existing_profiles = FileServerBridge.get_all_profiles()
    col_prof, col_new = st.columns([3, 1])

    with col_prof:
        if not existing_profiles:
            existing_profiles = ["Default_Tenant"]
            FileServerBridge.create_profile("Default_Tenant")

        current = st.session_state.get("fs_selected_profile", existing_profiles[0])
        sel_idx = existing_profiles.index(current) if current in existing_profiles else 0
        selected_profile = st.selectbox(
            "📍 Hồ sơ đang theo dõi:", options=existing_profiles, index=sel_idx,
            key="fs_profile_select",
        )
        st.session_state["fs_selected_profile"] = selected_profile

    with col_new:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.popover("➕ Tạo Hồ sơ mới"):
            new_name = st.text_input("Nhập tên Hồ sơ:", key="fs_new_profile_name")
            if st.button("Tạo ngay", key="fs_create_profile") and new_name:
                FileServerBridge.create_profile(new_name)
                st.session_state["fs_selected_profile"] = new_name
                st.rerun()

    st.divider()

    bridge = FileServerBridge(profile_name=selected_profile)
    dashboard_data = bridge.compile_dashboard_data()

    render_standard_module_layout(
        module_name="File Server APT Hunter (UEBA)",
        module_description="Phân tích hành vi người dùng trên File Server bằng Isolation Forest. Phát hiện ransomware, data exfiltration, và insider threat.",
        render_dashboard_func=lambda: render_dashboard(dashboard_data),
        run_llm_func=lambda: render_llm_tab(dashboard_data),
        render_upload_func=lambda: render_upload_and_config(bridge, selected_profile),
    )


if __name__ == "__main__":
    render_page()
