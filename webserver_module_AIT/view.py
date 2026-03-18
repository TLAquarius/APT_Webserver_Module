import os
import sys
from datetime import datetime

current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

import streamlit as st
import plotly.express as px
import pandas as pd
import gc

from core.shared_ui import render_standard_module_layout
from backend_bridge import WebserverBridge
from final_layer.llm_advisor import LLMAdvisor
from data_management.profile_manager import ProfileManager


def render_dashboard(dashboard_data: dict):
    if not dashboard_data or not dashboard_data.get("zone4_incidents"):
        st.warning("Chưa có dữ liệu phân tích cho Hồ sơ này. Vui lòng sang tab 'Tải lên & Cấu hình' để nạp Log.")
        return

    # ==========================================
    # 🟢 ZONE 1: HIGH-LEVEL METRICS
    # ==========================================
    st.markdown("### 📊 1. Chỉ số Tổng quan (Global Metrics)")
    metrics = dashboard_data.get("zone1_metrics", {})

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(label="Tổng Số Logs Đã Xử Lý", value=f"{metrics.get('total_events', 0):,}")
    with col2:
        st.metric(label="Payload Bị Chặn (WAF)", value=f"{metrics.get('l1_blocks', 0):,}")
    with col3:
        st.metric(label="Phiên Dị Thường (AI)", value=f"{metrics.get('anomalous_sessions', 0):,}")
    with col4:
        threat = metrics.get('max_threat', 'NORMAL')
        color = "🔴" if threat == "CRITICAL" else ("🟡" if threat == "SUSPICIOUS" else "🟢")
        st.metric(label="Mức Độ Đe Dọa Hiện Tại", value=f"{color} {threat}")

    st.markdown("<br>", unsafe_allow_html=True)

    # ==========================================
    # 🟡 ZONE 2: THREAT LANDSCAPE (WAF LAYER 1)
    # ==========================================
    st.markdown("### 🛡️ 2. Bề mặt Tấn công (Dựa trên WAF Regex)")
    waf_data = dashboard_data.get("zone2_waf", {})

    # --- ROW 1: Geo Map & Attack Vectors ---
    col2_1, col2_2 = st.columns(2)
    with col2_1:
        geo_data = waf_data.get("geo_distribution", {})
        if geo_data:
            df_geo = pd.DataFrame(list(geo_data.items()), columns=['Country', 'Requests'])
            fig_map = px.choropleth(
                df_geo, locations="Country", locationmode="country names",
                color="Requests", color_continuous_scale="Reds",
                title="Bản đồ Phân bổ Nguồn Tấn công"
            )
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

    # --- ROW 2: Top IPs & Top URIs ---
    col2_3, col2_4 = st.columns(2)
    with col2_3:
        top_ips = waf_data.get("top_ips", {})
        if top_ips:
            fig_bar_ip = px.bar(x=list(top_ips.keys()), y=list(top_ips.values()), title="Top 10 IP Tấn công nhiều nhất",
                                labels={'x': 'Địa chỉ IP', 'y': 'Số lượng Request'}, color=list(top_ips.values()),
                                color_continuous_scale="Reds")
            st.plotly_chart(fig_bar_ip, use_container_width=True)
        else:
            st.info("Không có dữ liệu IP tấn công.")

    with col2_4:
        top_uris = waf_data.get("top_uris", {})
        if top_uris:
            fig_bar_uri = px.bar(x=list(top_uris.values()), y=list(top_uris.keys()), orientation='h',
                                 title="Top 10 Đích ngắm (URIs) bị tấn công nhiều nhất",
                                 labels={'x': 'Số lượng Request', 'y': 'Đường dẫn (URI)'})
            fig_bar_uri.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_bar_uri, use_container_width=True)
        else:
            st.info("Không có dữ liệu đích ngắm URI.")

    st.markdown("<br>", unsafe_allow_html=True)

    # ==========================================
    # 🟠 ZONE 3: MACHINE LEARNING BEHAVIORAL ANALYTICS
    # ==========================================
    st.markdown("### 🧠 3. Phân tích Hành vi (AI/ML)")
    color_map = {"NORMAL": "#00CC96", "SUSPICIOUS": "#FFA15A", "CRITICAL": "#EF553B"}

    col3_1, col3_2 = st.columns(2)

    with col3_1:
        scatter_data = dashboard_data.get("zone3_ml", {}).get("scatter_data", [])
        if scatter_data:
            df_scatter = pd.DataFrame(scatter_data)
            fig_scatter = px.scatter(
                df_scatter, x="stat_score", y="seq_score", color="label", color_discrete_map=color_map,
                hover_data=["ip", "session_id"], title="Phân tích Điểm Dị thường (Kẻ thù lẩn khuất)",
                labels={"stat_score": "Isolation Forest Score", "seq_score": "Markov Chain Score", "label": "Mức độ"}
            )
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

            fig_line = px.scatter(
                df_time, x="timestamp", y="threat_score", color="threat_level",
                color_discrete_map=color_map, title="Mức độ Rủi ro theo Dòng Thời gian",
                labels={"timestamp": "Thời gian", "threat_score": "Điểm Dị thường", "threat_level": "Mức độ"}
            )
            fig_line.update_traces(mode='lines+markers', line=dict(color="rgba(200,200,200,0.5)"))
            st.plotly_chart(fig_line, use_container_width=True)
        else:
            st.info("Chưa có dữ liệu chuỗi thời gian cho Line Chart.")


def run_llm_advisor(dashboard_data: dict):
    incidents = dashboard_data.get("zone4_incidents", [])
    if not incidents:
        st.success("Chưa có dữ liệu phân tích cho Hồ sơ này. Vui lòng sang tab 'Tải lên & Cấu hình' để nạp Log.")
        return

    st.markdown("#### Danh sách Phiên truy cập")
    df_incidents = pd.DataFrame(incidents)

    # Thêm ID và thông số Nén để người dùng nắm rõ mức độ
    display_df = df_incidents[
        ["incident_tracking_id", "source_ip", "overall_threat_level", "max_statistical_score", "max_markov_score", "total_raw_events", "sequence_chain"]
    ].copy()
    display_df.columns = ["ID Sự Cố", "IP Nguồn", "Mức Đe Dọa", "Điểm Stat", "Điểm Markov", "Số Request", "Chuỗi Hành Vi"]

    col_filter, col_export = st.columns([3, 1])
    with col_filter:
        show_normal = st.checkbox("🟢 Hiển thị cả các phiên traffic bình thường (NORMAL)", value=False)
    with col_export:
        csv_data = display_df.to_csv(index=False).encode('utf-8')
        st.download_button("📥 Xuất Báo cáo CSV", data=csv_data, file_name="soc_incidents_report.csv", mime="text/csv",
                           use_container_width=True)

    if not show_normal:
        display_df = display_df[display_df["Mức Đe Dọa"] != "NORMAL"]

    st.markdown("💡 *Mẹo: Click chọn trực tiếp vào một dòng trong bảng dưới đây để xem chi tiết và yêu cầu AI phân tích.*")

    # 🟢 BIẾN DATAFRAME THÀNH BẢNG TƯƠNG TÁC ĐƯỢC (Clickable Row)
    selection_event = st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        on_select="rerun",           # Render lại giao diện khi có người click
        selection_mode="single-row"  # Chỉ cho phép chọn 1 dòng
    )

    st.divider()

    # Bắt sự kiện Click và tìm Object Incident tương ứng
    selected_case = None
    if selection_event.selection.rows:
        selected_idx = selection_event.selection.rows[0]
        selected_id = display_df.iloc[selected_idx]["ID Sự Cố"]
        selected_case = next((inc for inc in incidents if inc['incident_tracking_id'] == selected_id), None)

    if selected_case:
        st.markdown(f"#### 🔍 Điều tra Chuyên sâu: `{selected_case['source_ip']}`")
        with st.expander("Xem Dòng thời gian Raw Logs (Đã nén RLE)", expanded=False):
            st.json(selected_case.get("timeline", []))

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
                    analysis_result = advisor.analyze_session(
                        case_file=selected_case, provider=provider, model=model, api_key=api_key
                    )
                    st.success("Phân tích hoàn tất!")
                    st.markdown("### Báo cáo từ AI:")
                    st.info(analysis_result)


def render_page():
    # ---------------------------------------------------------
    # 1. TRÌNH CHỌN PROFILE TỔNG (GLOBAL PROFILE SELECTOR)
    # ---------------------------------------------------------
    st.markdown("### 🏢 Quản lý Phiên làm việc (Tenant Workspace)")
    pm = ProfileManager()
    existing_profiles = pm.get_all_profiles()

    col_prof, col_new = st.columns([3, 1])
    with col_prof:
        if not existing_profiles:
            existing_profiles = ["Default_Tenant"]
            pm.create_profile("Default_Tenant")

        selected_profile = st.selectbox(
            "📍 Hồ sơ đang theo dõi:",
            options=existing_profiles,
            help="Chọn công ty/hệ thống để xem báo cáo hoặc nạp thêm log."
        )
    with col_new:
        st.markdown("<br>", unsafe_allow_html=True)
        with st.popover("➕ Tạo Hồ sơ mới"):
            new_prof_name = st.text_input("Nhập tên Hồ sơ:")
            if st.button("Tạo ngay") and new_prof_name:
                pm.create_profile(new_prof_name)
                st.rerun()

    st.divider()

    # Khởi tạo Bridge để lấy dữ liệu
    bridge = WebserverBridge(profile_name=selected_profile)
    dashboard_data = bridge.compile_dashboard_data()

    # ---------------------------------------------------------
    # 2. HÀM RENDER TAB UPLOAD & CẤU HÌNH (Giao cho Tab 3)
    # ---------------------------------------------------------
    def render_upload_and_config():
        col_btn1, col_btn2 = st.columns([1, 4])
        with col_btn1:
            if st.button("🗑️ Xóa sạch dữ liệu Profile này", type="secondary", use_container_width=True):
                for root, dirs, files in os.walk(bridge.profile_dir, topdown=False):
                    for name in files:
                        os.remove(os.path.join(root, name))
                st.success("Đã xóa toàn bộ log và báo cáo. Vui lòng tải lại trang.")
                gc.collect()

        st.markdown(f"#### 1. Nạp Log cho hệ thống: `{selected_profile}`")

        with st.popover("⚙️ Hiệu chỉnh Nạp Log & Cấu hình"):
            st.markdown("**Cấu hình Pipeline**")
            operation_mode = st.selectbox(
                "Chế độ Hoạt động:",
                ["both", "detect", "train"],
                format_func=lambda x: {"both": "Vừa Huấn luyện vừa Phát hiện", "detect": "Chỉ Phát hiện (Detect)",
                                       "train": "Chỉ Huấn luyện (Train)"}[x]
            )

            use_time_filter = st.checkbox("⏳ Cắt Log theo khoảng thời gian (Time Window)")
            time_window = None
            if use_time_filter:
                date_range = st.date_input("Chọn ngày Bắt đầu & Kết thúc:", value=[])
                if len(date_range) == 2:
                    time_window = (
                        datetime.combine(date_range[0], datetime.min.time()),
                        datetime.combine(date_range[1], datetime.max.time())
                    )

            ai_sensitivity = st.select_slider(
                "Độ nhạy cảnh báo AI:",
                options=["Thấp (Ít cảnh báo giả)", "Tiêu chuẩn", "Cao (Bắt mọi bất thường)"],
                value="Tiêu chuẩn"
            )
            sensitivity_map = {"Thấp (Ít cảnh báo giả)": "low", "Tiêu chuẩn": "medium",
                               "Cao (Bắt mọi bất thường)": "high"}
            selected_sensitivity = sensitivity_map[ai_sensitivity]

            st.divider()
            st.markdown("**Cấu hình AI (LLM)**")
            llm_provider = st.selectbox("Nhà cung cấp:", ["nvidia", "openrouter", "google"])
            llm_model = st.text_input("Tên Model:", value="meta/llama3-70b-instruct")
            llm_api_key = st.text_input("API Key:", type="password")

            st.session_state["llm_provider"] = llm_provider
            st.session_state["llm_model"] = llm_model
            st.session_state["llm_api_key"] = llm_api_key

        uploaded_files = st.file_uploader(
            "Kéo thả các file Web Log (Hỗ trợ tự nhận diện định dạng Nginx/Apache):",
            accept_multiple_files=True,
            type=None
        )

        if uploaded_files:
            if st.button("🚀 Bắt đầu Phân tích Chuyên sâu", use_container_width=True, type="primary"):
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
                    st.rerun()

    # ---------------------------------------------------------
    # 3. GỌI BỘ KHUNG CHUẨN ĐỂ VẼ GIAO DIỆN
    # ---------------------------------------------------------
    render_standard_module_layout(
        module_name="Web Server APT Hunter",
        module_description="Hệ thống Phát hiện APT trên Web Server. Kết hợp WAF lai, Học máy Hành vi và Phân tích LLM.",
        render_dashboard_func=lambda: render_dashboard(dashboard_data),
        run_llm_func=lambda: run_llm_advisor(dashboard_data),
        render_upload_func=render_upload_and_config
    )

if __name__ == "__main__":
    render_page()