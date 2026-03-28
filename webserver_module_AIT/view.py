import os
import sys
from datetime import datetime
import urllib.parse
import base64

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import streamlit as st
import plotly.express as px
import pandas as pd
import gc
import re

from core.shared_ui import render_standard_module_layout
from backend_bridge import WebserverBridge
from final_layer.llm_advisor import LLMAdvisor
from data_management.profile_manager import ProfileManager


def render_dashboard(dashboard_data: dict):
    if not dashboard_data or not dashboard_data.get("zone4_incidents"):
        st.warning("Chưa có dữ liệu phân tích cho Hồ sơ này. Vui lòng sang tab 'Tải lên & Cấu hình' để nạp Log.")
        return

    st.markdown("### 📊 1. Chỉ số Tổng quan (Global Metrics)")
    metrics = dashboard_data.get("zone1_metrics", {})

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.metric(label="Tổng Số Logs Xử Lý", value=f"{metrics.get('total_events', 0):,}")
    with col2:
        st.metric(label="Payload Bị Chặn", value=f"{metrics.get('l1_blocks', 0):,}")
    with col3:
        st.metric(label="Phiên Bất Thường (AI)", value=f"{metrics.get('anomalous_sessions', 0):,}")
    with col4:
        st.metric(label="Phiên Sạch (NORMAL)", value=f"{metrics.get('normal_sessions', 0):,}")
    with col5:
        threat = metrics.get('max_threat', 'NORMAL')
        color = "🔴" if threat == "CRITICAL" else ("🟡" if threat == "SUSPICIOUS" else "🟢")
        st.metric(label="Mức Độ Đe Dọa", value=f"{color} {threat}")
    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("### 🛡️ 2. Bề mặt Tấn công (Dựa trên WAF Regex)")
    waf_data = dashboard_data.get("zone2_waf", {})
    col2_1, col2_2 = st.columns(2)
    with col2_1:
        geo_data = waf_data.get("geo_distribution", {})
        if geo_data:
            df_geo = pd.DataFrame(list(geo_data.items()), columns=['Country', 'Requests'])
            fig_map = px.choropleth(df_geo, locations="Country", locationmode="country names", color="Requests",
                                    color_continuous_scale="Reds", title="Bản đồ Phân bổ Nguồn Tấn công")
            fig_map.update_layout(geo=dict(showframe=False, showcoastlines=True, projection_type='equirectangular'))
            st.plotly_chart(fig_map, use_container_width=True)
        else:
            st.info("Chưa có dữ liệu Bản đồ Geo-IP (Không phát hiện Public IP).")

    with col2_2:
        vectors = waf_data.get("attack_vectors", {})
        if vectors:
            fig_pie = px.pie(names=list(vectors.keys()), values=list(vectors.values()), title="Tỷ lệ Các loại Tấn công",
                             hole=0.4, color_discrete_sequence=px.colors.sequential.RdBu)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("Không ghi nhận đòn tấn công tĩnh nào từ WAF.")

    col2_3, col2_4 = st.columns(2)
    with col2_3:
        top_ips = waf_data.get("top_ips", {})
        if top_ips:
            fig_bar_ip = px.bar(x=list(top_ips.keys()), y=list(top_ips.values()), title="Top 10 IP Tấn công",
                                labels={'x': 'Địa chỉ IP', 'y': 'Số lượng Request'}, color=list(top_ips.values()),
                                color_continuous_scale="Reds")
            st.plotly_chart(fig_bar_ip, use_container_width=True)
    with col2_4:
        top_uris = waf_data.get("top_uris", {})
        if top_uris:
            fig_bar_uri = px.bar(x=list(top_uris.values()), y=list(top_uris.keys()), orientation='h',
                                 title="Top 10 Đích ngắm (URIs)",
                                 labels={'x': 'Số lượng Request', 'y': 'Đường dẫn (URI)'})
            fig_bar_uri.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_bar_uri, use_container_width=True)
    st.markdown("<br>", unsafe_allow_html=True)

    st.markdown("### 🧠 3. Phân tích Hành vi (AI/ML)")
    color_map = {"NORMAL": "#00CC96", "SUSPICIOUS": "#FFA15A", "CRITICAL": "#EF553B"}

    col_empty_left, col_pie_center, col_empty_right = st.columns([1, 2, 1])
    with col_pie_center:
        session_counts = {
            "NORMAL": metrics.get("normal_sessions", 0),
            "SUSPICIOUS": metrics.get("suspicious_sessions", 0),
            "CRITICAL": metrics.get("critical_sessions", 0)
        }
        session_counts = {k: v for k, v in session_counts.items() if v > 0}

        if session_counts:
            df_pie_session = pd.DataFrame(list(session_counts.items()), columns=['Mức độ', 'Số lượng'])
            fig_pie_session = px.pie(df_pie_session, names='Mức độ', values='Số lượng',
                                     color='Mức độ', color_discrete_map=color_map,
                                     title="Tỷ lệ Phân loại Phiên", hole=0.4)
            st.plotly_chart(fig_pie_session, use_container_width=True)
        else:
            st.info("Chưa có dữ liệu phân loại Phiên.")

    st.markdown("<br>", unsafe_allow_html=True)

    col3_1, col3_2 = st.columns(2)

    with col3_1:
        scatter_data = dashboard_data.get("zone3_ml", {}).get("scatter_data", [])
        if scatter_data:
            df_scatter = pd.DataFrame(scatter_data)
            fig_scatter = px.scatter(df_scatter, x="stat_score", y="seq_score", color="label",
                                     color_discrete_map=color_map, hover_data=["ip", "session_id"],
                                     title="Phân tích Điểm Dị thường",
                                     labels={"stat_score": "Isolation Forest", "seq_score": "Markov Score",
                                             "label": "Mức độ"})
            fig_scatter.add_hline(y=50, line_dash="dash", line_color="gray", opacity=0.5)
            fig_scatter.add_vline(x=50, line_dash="dash", line_color="gray", opacity=0.5)
            st.plotly_chart(fig_scatter, use_container_width=True)
        else:
            st.info("Chưa có đủ dữ liệu Scatter Plot.")

    with col3_2:
        timeline_data = dashboard_data.get("zone3_ml", {}).get("timeline_data", [])
        if timeline_data:
            df_time = pd.DataFrame(timeline_data)
            df_time['timestamp'] = pd.to_datetime(df_time['timestamp'], errors='coerce')
            df_time = df_time.dropna(subset=['timestamp']).sort_values('timestamp')
            fig_line = px.scatter(df_time, x="timestamp", y="threat_score", color="threat_level",
                                  color_discrete_map=color_map, title="Rủi ro theo Dòng Thời gian",
                                  labels={"timestamp": "Thời gian", "threat_score": "Điểm Dị thường",
                                          "threat_level": "Mức độ"})
            fig_line.update_traces(mode='lines+markers', line=dict(color="rgba(200,200,200,0.5)"))
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("Chưa có dữ liệu chuỗi thời gian cho Line Chart.")


def try_decode_payload(raw_uri):
    """
    Attempts to URL decode and Base64 decode payloads for display in the View.
    """
    if not raw_uri or raw_uri == "N/A":
        return ""

    current = raw_uri
    for _ in range(3):
        decoded = urllib.parse.unquote(current)
        if decoded == current: break
        current = decoded

    b64_match = re.search(r'WyJ[A-Za-z0-9+/]+', current)
    if b64_match:
        b64_str = b64_match.group(0)
        try:
            pad_len = (4 - len(b64_str) % 4) % 4
            padded = b64_str + "=" * pad_len
            decoded_b64 = base64.b64decode(padded).decode('ascii', errors='ignore')
            return f"[Decoded B64]: {decoded_b64}"
        except:
            pass

    if current != raw_uri:
        return f"[Decoded URL]: {current}"

    return ""


def format_timeline_to_df(timeline_data: list) -> pd.DataFrame:
    formatted_data = []

    CRITICAL_WAFS = {"SQLi", "XSS", "RCE", "RCE_Execution_Output", "LFI", "SSRF"}

    for event in timeline_data:

        if event.get("event_type") == "COMPRESSED_BULK_ACTION":
            formatted_data.append({
                "Thời gian (Khoảng)": f"{event.get('start_time', '')[:19]} ➔ {event.get('end_time', '')[11:19]}",
                "Phân loại": "HÀNH VI LẶP LẠI (RLE)",
                "Loại Tấn Công (WAF)": "N/A",
                "Chi tiết (Decode/Lỗi)": event.get("summary", ""),
                "Đích ngắm (URI)": event.get("uri_path", ""),
                "Trạng thái": f"Lặp lại {event.get('count', 0)} lần",
                "Mã Code": str(event.get("status_code", "N/A")),
                "Host (VHost)": "N/A",
                "Kích thước (Bytes)": "N/A",
                "User Agent": "N/A",
                "Log thô": ""
            })

        else:
            wafs = event.get("layer1_alerts", [])
            alert_str = ", ".join(wafs) if wafs else ""
            status_code = str(event.get("status_code", ""))

            uri_path = event.get("uri_path", "")
            uri_query = event.get("uri_query", "")
            raw_message = event.get("raw_message", "")
            user_agent = event.get("user_agent")
            bytes_sent = event.get("bytes_sent")
            vhost = event.get("vhost")

            full_uri = uri_path
            if uri_query and uri_path:
                full_uri = f"{uri_path}?{uri_query}"

            error_msg = event.get("error_message", "")
            is_error_log = event.get("event_source") in ["apache_error", "nginx_error"]

            if not full_uri and error_msg:
                match = re.search(r'(/[\w\-\.\/]+)', error_msg)
                if match:
                    full_uri = f"(Từ log lỗi) {match.group(1)}"
                else:
                    full_uri = "N/A"

            categories = []
            is_critical_waf = any(w in CRITICAL_WAFS for w in wafs)

            if is_critical_waf:
                categories.append("🔥 WAF NGHIÊM TRỌNG")
            elif wafs:
                categories.append("🚨 WAF BÁO ĐỘNG")

            if status_code.startswith(("4", "5")) or is_error_log:
                categories.append("⚠️ LỖI CLIENT/SERVER")

            if not categories:
                category = "BÌNH THƯỜNG"
            else:
                category = " | ".join(categories)

            http_method = event.get("http_method")
            if not http_method:
                http_method = "INTERNAL" if is_error_log else "N/A"

            # Integrate Error Message or Decode Payload
            decoded_info = ""
            if error_msg:
                decoded_info = f"[Lỗi Máy Chủ]: {error_msg}"
            else:
                decoded_info = try_decode_payload(full_uri)

            # 🟢 REORDERED COLUMNS FOR UX
            formatted_data.append({
                "Thời gian (Khoảng)": event.get("@timestamp", "")[:19].replace("T", " "),
                "Phân loại": category,
                "Loại Tấn Công (WAF)": alert_str if alert_str else "N/A",
                "Chi tiết (Decode/Lỗi)": decoded_info,
                "Đích ngắm (URI)": full_uri,
                "Trạng thái": http_method,
                "Mã Code": status_code if status_code != "None" else "N/A",
                "Host (VHost)": vhost if vhost else "N/A",
                "Kích thước (Bytes)": str(int(bytes_sent)) if bytes_sent is not None else "N/A",
                "User Agent": user_agent if user_agent and user_agent != "-" else "N/A",
                "Log thô": raw_message
            })

    return pd.DataFrame(formatted_data)


def run_llm_advisor(dashboard_data: dict):
    incidents = dashboard_data.get("zone4_incidents", [])
    if not incidents:
        st.success("Chưa có dữ liệu phân tích cho Hồ sơ này. Vui lòng sang tab 'Tải lên & Cấu hình' để nạp Log.")
        return

    st.markdown("#### Danh sách Phiên truy cập & Phân tích AI")

    flat_incidents = []
    for inc in incidents:
        base_info = {
            "ID Sự Cố": inc.get("incident_tracking_id"),
            "IP Nguồn": inc.get("source_ip"),
            "Mức Đe Dọa": inc.get("overall_threat_level"),
            "Cảnh báo WAF L1": " | ".join(inc.get("layer1_alerts", [])),
            "Lý do Stat AI": " | ".join(inc.get("statistical_anomaly_reasons", [])),
            "Điểm Stat": inc.get("max_statistical_score"),
            "Lý do Markov AI": " | ".join(inc.get("sequential_anomaly_reasons", [])),
            "Điểm Markov": inc.get("max_markov_score"),
            "Số Request": inc.get("total_raw_events"),
            "Chuỗi Hành Vi": inc.get("sequence_chain")
        }

        stats = inc.get("stats_context", {})
        if stats:
            for key, val in stats.items():
                if key.endswith("_rate") or key.endswith("_ratio"):
                    val_str = f"{float(val) * 100:.1f}%"
                elif isinstance(val, float):
                    val_str = f"{val:.2f}"
                else:
                    val_str = str(val)
                base_info[key] = val_str

        flat_incidents.append(base_info)

    display_df = pd.DataFrame(flat_incidents)

    col_filter, col_export = st.columns([3, 1])
    with col_filter:
        show_normal = st.checkbox("🟢 Hiển thị cả các phiên traffic bình thường (NORMAL)", value=False)
    with col_export:
        csv_data = display_df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Xuất Báo cáo CSV", data=csv_data, file_name="soc_incidents_report.csv", mime="text/csv",
                           use_container_width=True)

    if not show_normal:
        display_df = display_df[display_df["Mức Đe Dọa"] != "NORMAL"]

    st.markdown(
        "💡 *Mẹo: Giải thích AI (XAI) - Các ô được bôi màu Đỏ nhạt/Cam là nguyên nhân cốt lõi khiến AI đánh dấu phiên truy cập này là bất thường.*")

    def highlight_session_cells(row):
        styles = [''] * len(row)
        stat_reason = str(row.get('Lý do Stat AI', ''))
        seq_reason = str(row.get('Lý do Markov AI', ''))

        for i, col in enumerate(row.index):
            if col != 'Lý do Stat AI' and col in stat_reason:
                styles[i] = 'background-color: rgba(255, 99, 71, 0.4); border: 1px solid red;'
            if col == 'Chuỗi Hành Vi' and seq_reason:
                styles[i] = 'background-color: rgba(255, 165, 0, 0.4); border: 1px solid orange;'
        return styles

    styled_display_df = display_df.style.apply(highlight_session_cells, axis=1)

    selection_event = st.dataframe(styled_display_df, use_container_width=True, hide_index=True, on_select="rerun",
                                   selection_mode="single-row")
    st.divider()

    selected_case = None
    if selection_event.selection.rows:
        selected_idx = selection_event.selection.rows[0]
        selected_id = display_df.iloc[selected_idx]["ID Sự Cố"]
        selected_case = next((inc for inc in incidents if inc['incident_tracking_id'] == selected_id), None)

    if selected_case:
        st.markdown(f"#### 🔍 Điều tra Chuyên sâu: `{selected_case['source_ip']}`")
        st.markdown("**Dòng thời gian Sự kiện (Nhanh & Hỗ trợ cuộn vô hạn/Tìm kiếm)**")

        df_timeline = format_timeline_to_df(selected_case.get("timeline", []))

        # Smart filter
        show_alerts_only = st.checkbox("🎯 Chỉ hiển thị các dòng log CÓ CẢNH BÁO HOẶC LỖI (Lọc rác/Scanner Bot)",
                                       value=False)

        if show_alerts_only:
            def is_alert_or_anomaly(row):
                if row["Phân loại"] not in ["BÌNH THƯỜNG", "HÀNH VI LẶP LẠI (RLE)"] and "🚨 WAF BÁO ĐỘNG" not in row[
                    "Phân loại"]:
                    return True
                if "🔥 WAF NGHIÊM TRỌNG" in row["Phân loại"]:
                    return True
                if row["Loại Tấn Công (WAF)"] != "N/A" and "Scanner_Bot" not in row["Loại Tấn Công (WAF)"]:
                    return True
                return False

            mask = df_timeline.apply(is_alert_or_anomaly, axis=1)
            df_timeline = df_timeline[mask]

        # 🟢 NATIVE STREAMLIT COMPONENT FOR MAX PERFORMANCE & INFINITE SCROLL
        st.dataframe(df_timeline, use_container_width=True, hide_index=True)

        st.markdown("##### 🤖 Yêu cầu AI Giải thích Mã độc")
        api_key = st.session_state.get("llm_api_key", "")
        provider = st.session_state.get("llm_provider", "nvidia")
        model = st.session_state.get("llm_model", "meta/llama3-70b-instruct")

        if st.button("Phân tích với LLM", type="primary"):
            if not api_key:
                st.error("Vui lòng sang tab 'Tải lên & Cấu hình' nhập LLM API Key trước khi sử dụng AI.")
            else:
                with st.spinner(f"Đang gửi dữ liệu đến {provider.upper()} để phân tích..."):
                    advisor = LLMAdvisor()
                    analysis_result = advisor.analyze_session(case_file=selected_case, provider=provider, model=model,
                                                              api_key=api_key)
                    st.success("Phân tích hoàn tất!")
                    st.markdown("### Báo cáo từ AI:")
                    st.info(analysis_result)


@st.dialog("⚠️ Xác nhận Xóa Toàn bộ Profile")
def confirm_delete_profile(bridge):
    st.warning(
        f"Bạn có chắc chắn muốn xóa toàn bộ dữ liệu của Profile `{bridge.profile_name}` không? Thao tác này không thể hoàn tác.")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("✅ Đồng ý Xóa", type="primary", use_container_width=True):
            import shutil
            shutil.rmtree(bridge.profile_dir, ignore_errors=True)
            st.session_state['profile_deleted'] = True
            st.rerun()
    with col2:
        if st.button("❌ Hủy bỏ", use_container_width=True):
            st.rerun()


@st.dialog("⚠️ Xác nhận Xóa File")
def confirm_delete_files(file_ids):
    st.warning(
        f"Bạn chuẩn bị xóa {len(file_ids)} file khỏi Profile. Việc này sẽ tự động kích hoạt quá trình Quét lại toàn bộ hệ thống dựa trên cấu hình hiện tại để làm sạch Baseline.")
    if st.button("Xác nhận Xóa & Quét lại", type="primary", use_container_width=True):
        st.session_state["do_delete_files"] = file_ids
        st.rerun()


def render_page():
    if st.session_state.get('profile_deleted'):
        st.success("Đã xóa Profile thành công.")
        st.session_state['profile_deleted'] = False
        st.session_state['selected_profile'] = "Default_Tenant"

    st.markdown("### 🏢 Quản lý Phiên làm việc (Tenant Workspace)")
    pm = ProfileManager()
    existing_profiles = pm.get_all_profiles()

    col_prof, col_new = st.columns([3, 1])
    with col_prof:
        if not existing_profiles:
            existing_profiles = ["Default_Tenant"]
            pm.create_profile("Default_Tenant")

        sel_idx = existing_profiles.index(
            st.session_state.get('selected_profile', existing_profiles[0])) if st.session_state.get(
            'selected_profile') in existing_profiles else 0
        selected_profile = st.selectbox("📍 Hồ sơ đang theo dõi:", options=existing_profiles, index=sel_idx)
        st.session_state['selected_profile'] = selected_profile

    with col_new:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.popover("➕ Tạo Hồ sơ mới"):
            new_prof_name = st.text_input("Nhập tên Hồ sơ:")
            if st.button("Tạo ngay") and new_prof_name:
                pm.create_profile(new_prof_name)
                st.session_state['selected_profile'] = new_prof_name
                st.rerun()

    st.divider()

    st.markdown("**Hiển thị Dữ liệu theo Thời gian:**")
    use_display_time_filter = st.checkbox("⏳ Chỉ xem các Sự cố hoạt động trong khoảng thời gian cụ thể")
    display_time_window = None
    if use_display_time_filter:
        display_date_range = st.date_input("Chọn ngày Bắt đầu & Kết thúc:", value=[])
        if len(display_date_range) == 2:
            display_time_window = (
                datetime.combine(display_date_range[0], datetime.min.time()),
                datetime.combine(display_date_range[1], datetime.max.time())
            )

    bridge = WebserverBridge(profile_name=selected_profile)
    dashboard_data = bridge.compile_dashboard_data(display_time_window=display_time_window)

    def render_upload_and_config():
        st.markdown(f"#### 1. Quản lý Dữ liệu đã nạp: `{selected_profile}`")
        col_list, col_del_all = st.columns([4, 1])
        with col_del_all:
            if st.button("🗑️ Xóa toàn bộ Profile", type="primary", use_container_width=True):
                confirm_delete_profile(bridge)

        metadata = pm._load_metadata(selected_profile)
        if metadata:
            df_files = pd.DataFrame(metadata)
            display_files = df_files[
                ["file_id", "original_name", "file_type", "log_format", "size_bytes", "upload_time",
                 "min_timestamp_str", "max_timestamp_str"]].copy()
            display_files["size_bytes"] = (display_files["size_bytes"] / (1024 * 1024)).round(2).astype(str) + " MB"
            display_files.columns = ["ID File", "Tên File", "Loại", "Định dạng", "Dung lượng", "Ngày nạp",
                                     "Log từ ngày", "Log đến ngày"]

            st.markdown("Danh sách các file hiện có trong Profile (Hỗ trợ chọn nhiều dòng):")
            file_selection = st.dataframe(display_files, use_container_width=True, hide_index=True, on_select="rerun",
                                          selection_mode="multi-row")

            if file_selection.selection.rows:
                sel_indices = file_selection.selection.rows
                sel_file_ids = display_files.iloc[sel_indices]["ID File"].tolist()

                is_deleting_all = len(sel_file_ids) == len(display_files)
                btn_text = f"🗑️ Xóa {len(sel_file_ids)} file đã chọn"
                btn_text += " (Reset Profile)" if is_deleting_all else " & Quét lại Hệ thống"

                if st.button(btn_text, type="primary"):
                    bridge.delete_specific_files(sel_file_ids)

                    if is_deleting_all:
                        st.success("Đã xóa sạch các file. Hồ sơ đã được trả về trạng thái trống!")
                        st.rerun()
                    else:
                        st.info(
                            f"Đang xóa {len(sel_file_ids)} file, tính toán lại Baseline và quét lại các file còn lại...")
                        progress_bar = st.progress(0)
                        status_text = st.empty()

                        def ui_cb(msg, pct):
                            status_text.text(msg)
                            progress_bar.progress(pct / 100.0)

                        bridge.rescan_existing_data(
                            operation_mode=st.session_state.get('operation_mode', 'both'),
                            time_window=None,
                            status_callback=ui_cb
                        )

                        st.success(f"Đã xóa file và cập nhật hệ thống thành công!")
                        st.rerun()
        else:
            st.info("Profile này hiện chưa có file dữ liệu nào.")

        st.divider()

        st.markdown("#### 2. Cấu hình Hệ thống (Dành cho Chuyên gia)")
        with st.container(border=True):
            col_cfg1, col_cfg2 = st.columns(2)

            has_base = bridge.has_baseline()
            mode_options = ["both", "detect", "train"] if has_base else ["both", "train"]

            with col_cfg1:
                operation_mode = st.selectbox(
                    "Chế độ Hoạt động của ML:",
                    mode_options,
                    index=0,
                    format_func=lambda x: {"both": "Vừa Huấn luyện vừa Phát hiện", "detect": "Chỉ Phát hiện (Detect)",
                                           "train": "Chỉ Huấn luyện (Train)"}[x]
                )

                st.session_state['operation_mode'] = operation_mode

                if not has_base:
                    st.caption("⚠️ *Hồ sơ này chưa có mô hình Baseline, hệ thống bắt buộc phải kèm chế độ Huấn luyện.*")

                ai_sensitivity = st.select_slider(
                    "Độ nhạy cảnh báo tầng ML (Threshold Tuning):",
                    options=["Thấp (Ít cảnh báo giả)", "Tiêu chuẩn", "Cao (Bắt mọi bất thường)"],
                    value="Tiêu chuẩn"
                )

            with col_cfg2:
                llm_provider = st.selectbox("Nhà cung cấp LLM:", ["nvidia", "openrouter", "google"])
                llm_model = st.text_input("Tên Model:", value="meta/llama3-70b-instruct")
                llm_api_key = st.text_input("API Key:", type="password")

            st.session_state["llm_provider"] = llm_provider
            st.session_state["llm_model"] = llm_model
            st.session_state["llm_api_key"] = llm_api_key

            sensitivity_map = {"Thấp (Ít cảnh báo giả)": "low", "Tiêu chuẩn": "medium",
                               "Cao (Bắt mọi bất thường)": "high"}
            selected_sensitivity = sensitivity_map[ai_sensitivity]

            st.markdown("---")
            st.markdown("**Quét lại dữ liệu với khoảng thời gian mới**")
            use_rescan_time_filter = st.checkbox("⏳ Cắt Log theo khoảng thời gian (Khi Rescan)")
            rescan_time_window = None
            if use_rescan_time_filter:
                rescan_date_range = st.date_input("Chọn ngày Bắt đầu & Kết thúc (Rescan):", value=[])
                if len(rescan_date_range) == 2:
                    rescan_time_window = (datetime.combine(rescan_date_range[0], datetime.min.time()),
                                          datetime.combine(rescan_date_range[1], datetime.max.time()))

            if st.button("🔁 Lưu Cấu hình & Chạy lại Phân tích (Rescan)", type="secondary", use_container_width=True):
                bridge.update_ai_thresholds(selected_sensitivity)
                progress_bar = st.progress(0)
                status_text = st.empty()

                def ui_callback(message, percent):
                    status_text.text(message)
                    progress_bar.progress(percent / 100.0)

                success = bridge.rescan_existing_data(operation_mode, time_window=rescan_time_window,
                                                      status_callback=ui_callback)
                if success:
                    st.success("Hoàn tất quét lại dữ liệu! Hãy sang Tab Dashboard để xem kết quả.")
                    progress_bar.empty()
                    status_text.empty()
                    st.rerun()

        st.divider()

        st.markdown(f"#### 3. Nạp Log Mới cho hệ thống")
        use_time_filter = st.checkbox("⏳ Cắt Log theo khoảng thời gian (Khi nạp file mới)")
        time_window = None
        if use_time_filter:
            date_range = st.date_input("Chọn ngày Bắt đầu & Kết thúc (Upload):", value=[])
            if len(date_range) == 2:
                time_window = (datetime.combine(date_range[0], datetime.min.time()),
                               datetime.combine(date_range[1], datetime.max.time()))

        if "uploader_key" not in st.session_state:
            st.session_state["uploader_key"] = str(datetime.now())

        uploaded_files = st.file_uploader(
            "Kéo thả các file Web Log (Hỗ trợ tự nhận diện định dạng Nginx/Apache):",
            accept_multiple_files=True,
            type=None,
            key=st.session_state["uploader_key"]
        )

        if uploaded_files:
            if st.button("🚀 Nạp Dữ Liệu Mới & Bắt Đầu Phân Tích", use_container_width=True, type="primary"):
                bridge.update_ai_thresholds(selected_sensitivity)
                bridge.process_uploads(uploaded_files, operation_mode, time_window=time_window)
                progress_bar = st.progress(0)
                status_text = st.empty()

                def ui_callback(message, percent):
                    status_text.text(message)
                    progress_bar.progress(percent / 100.0)

                success = bridge.run_full_pipeline(status_callback=ui_callback)
                if success:
                    st.success("Hoàn tất! Hãy chuyển sang Tab 'Dashboard Giám sát' để xem kết quả.")
                    progress_bar.empty()
                    status_text.empty()
                    st.session_state["uploader_key"] = str(datetime.now())
                    st.rerun()

    render_standard_module_layout(
        module_name="Web Server APT Hunter",
        module_description="Hệ thống Phát hiện APT trên Web Server. Kết hợp WAF lai, Học máy Hành vi và Phân tích LLM.",
        render_dashboard_func=lambda: render_dashboard(dashboard_data),
        run_llm_func=lambda: run_llm_advisor(dashboard_data),
        render_upload_func=render_upload_and_config
    )


if __name__ == "__main__":
    render_page()