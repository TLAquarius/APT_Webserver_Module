import streamlit as st
import plotly.express as px
import pandas as pd

# Trích xuất bộ khung UI chung và Nhạc trưởng Backend
from core.shared_ui import render_standard_module_layout
from webserver_module_AIT.backend_bridge import WebserverBridge
from webserver_module_AIT.final_layer.llm_advisor import LLMAdvisor


def render_dashboard(dashboard_data: dict):
    """
    Render Khu vực 1, 2 và 3 của Dashboard.
    Hàm này được gọi tự động bởi shared_ui.py sau khi có dữ liệu.
    """
    if not dashboard_data:
        st.warning("Không có dữ liệu Dashboard để hiển thị. Vui lòng kiểm tra lại quá trình phân tích.")
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
    vectors = waf_data.get("attack_vectors", {})
    top_ips = waf_data.get("top_ips", {})

    col2_1, col2_2 = st.columns(2)
    with col2_1:
        if vectors:
            fig_pie = px.pie(
                names=list(vectors.keys()),
                values=list(vectors.values()),
                title="Tỷ lệ Các loại Tấn công",
                hole=0.4,
                color_discrete_sequence=px.colors.sequential.RdBu
            )
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.info("Không ghi nhận đòn tấn công tĩnh nào từ WAF.")

    with col2_2:
        if top_ips:
            fig_bar = px.bar(
                x=list(top_ips.keys()),
                y=list(top_ips.values()),
                title="Top 10 IP Tấn công nhiều nhất",
                labels={'x': 'Địa chỉ IP', 'y': 'Số lượng Request'},
                color=list(top_ips.values()),
                color_continuous_scale="Reds"
            )
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.info("Không có dữ liệu IP tấn công.")

    st.markdown("<br>", unsafe_allow_html=True)

    # ==========================================
    # 🟠 ZONE 3: MACHINE LEARNING BEHAVIORAL ANALYTICS
    # ==========================================
    st.markdown("### 🧠 3. Phân tích Hành vi (AI/ML)")
    scatter_data = dashboard_data.get("zone3_ml", {}).get("scatter_data", [])

    if scatter_data:
        df_scatter = pd.DataFrame(scatter_data)

        # Ánh xạ màu sắc theo nhãn
        color_map = {"NORMAL": "#00CC96", "SUSPICIOUS": "#FFA15A", "CRITICAL": "#EF553B"}

        fig_scatter = px.scatter(
            df_scatter,
            x="stat_score",
            y="seq_score",
            color="label",
            color_discrete_map=color_map,
            hover_data=["ip", "session_id"],
            title="Biểu đồ Tương quan Hành vi: Phân tích Kẻ thù lẩn khuất (APT)",
            labels={
                "stat_score": "Điểm Bất thường Thống kê (Isolation Forest)",
                "seq_score": "Điểm Bất thường Chuỗi (Markov Chain)",
                "label": "Mức độ Đe dọa"
            }
        )

        # Vẽ 2 đường chéo chia vùng rủi ro
        fig_scatter.add_hline(y=50, line_dash="dash", line_color="gray", opacity=0.5)
        fig_scatter.add_vline(x=50, line_dash="dash", line_color="gray", opacity=0.5)

        st.plotly_chart(fig_scatter, use_container_width=True)
        st.caption(
            "💡 *Mẹo: Những chấm đỏ nằm ở góc trên cùng bên phải là những phiên truy cập nguy hiểm nhất (Vừa dị thường về nhịp độ, vừa dị thường về trình tự).*")
    else:
        st.info("Chưa có đủ dữ liệu Machine Learning để vẽ biểu đồ.")


def run_llm_advisor(dashboard_data: dict):
    """
    Render Khu vực 4: Bảng Điều tra Sự cố & AI Tham vấn.
    """
    incidents = dashboard_data.get("zone4_incidents", [])
    if not incidents:
        st.success("Hệ thống an toàn. Không có sự cố nào cần điều tra.")
        return

    # 1. Bảng danh sách Sự cố
    st.markdown("#### Danh sách Phiên truy cập")
    df_incidents = pd.DataFrame(incidents)

    # Rút gọn bảng để hiển thị đẹp hơn
    display_df = df_incidents[
        ["source_ip", "overall_threat_level", "max_statistical_score", "max_markov_score", "total_raw_events",
         "sequence_chain"]].copy()
    display_df.columns = ["IP Nguồn", "Mức Đe Dọa", "Điểm Stat", "Điểm Markov", "Số Request", "Chuỗi Hành Vi"]
    st.dataframe(display_df, use_container_width=True)

    st.divider()

    # 2. Bộ lọc chọn Sự cố để Phân tích
    st.markdown("#### 🔍 Điều tra Chuyên sâu (Deep-Dive Forensics)")

    # Tạo list cho selectbox (Chỉ lấy IP và Threat Level)
    incident_options = [f"{inc['source_ip']} (Mức: {inc['overall_threat_level']} - ID: {inc['incident_tracking_id']})"
                        for inc in incidents]
    selected_option = st.selectbox("Chọn một Phiên truy cập để AI phân tích:", incident_options)

    if selected_option:
        # Tìm lại object incident gốc dựa trên ID
        selected_id = selected_option.split("ID: ")[-1].replace(")", "")
        selected_case = next((inc for inc in incidents if inc['incident_tracking_id'] == selected_id), None)

        if selected_case:
            with st.expander("Xem Dòng thời gian Raw Logs (Đã nén RLE)", expanded=False):
                st.json(selected_case.get("timeline", []))

            # 3. Kích hoạt LLM
            st.markdown("##### 🤖 Yêu cầu AI Giải thích Mã độc")

            # Lấy API Key từ Sidebar (Đã được định nghĩa ở hàm main)
            api_key = st.session_state.get("llm_api_key", "")
            provider = st.session_state.get("llm_provider", "nvidia")
            model = st.session_state.get("llm_model", "meta/llama3-70b-instruct")

            if st.button("Phân tích với LLM", type="primary"):
                if not api_key:
                    st.error("Vui lòng nhập LLM API Key ở thanh Sidebar bên trái trước khi sử dụng AI.")
                else:
                    with st.spinner(f"Đang gửi dữ liệu đến {provider.upper()} để phân tích..."):
                        advisor = LLMAdvisor()
                        analysis_result = advisor.analyze_session(
                            case_file=selected_case,
                            provider=provider,
                            model=model,
                            api_key=api_key
                        )
                        st.success("Phân tích hoàn tất!")
                        st.markdown("### Báo cáo từ AI:")
                        st.info(analysis_result)


def render_page():
    """
    Hàm khởi chạy chính của Module Web Server AIT.
    Định nghĩa các Sidebar Config và truyền vào bộ khung shared_ui.
    """
    # ==========================================
    # CẤU HÌNH SIDEBAR ĐẶC THÙ CHO MODULE NÀY
    # ==========================================
    st.sidebar.image("https://img.icons8.com/color/96/000000/web.png", width=60)
    st.sidebar.title("Cấu hình WebServer AIT")

    # 1. Quản lý Tenant / Profile
    profile_name = st.sidebar.text_input("Tên Hồ sơ (Profile / Công ty):", value="Default_Tenant")

    st.sidebar.divider()

    # 2. Cấu hình Nạp dữ liệu
    st.sidebar.subheader("Cấu hình Đầu vào")
    log_format = st.sidebar.selectbox("Định dạng Log:",
                                      ["combined_access", "common_access", "apache_error", "nginx_error"])
    log_type = st.sidebar.selectbox("Loại Log:", ["access", "error"])
    operation_mode = st.sidebar.selectbox("Chế độ Hoạt động:", ["both", "detect", "train"], format_func=lambda x:
    {"both": "Vừa Huấn luyện vừa Phát hiện", "detect": "Chỉ Phát hiện (Detect)", "train": "Chỉ Huấn luyện (Train)"}[x])

    st.sidebar.divider()

    # 3. Cấu hình Trí tuệ Nhân tạo (LLM)
    st.sidebar.subheader("Cấu hình LLM Copilot")
    llm_provider = st.sidebar.selectbox("Nhà cung cấp:", ["nvidia", "openrouter", "google"])
    llm_model = st.sidebar.text_input("Tên Model:", value="meta/llama3-70b-instruct")
    llm_api_key = st.sidebar.text_input("API Key:", type="password")

    # Lưu config LLM vào session_state để hàm run_llm_advisor có thể lấy được
    st.session_state["llm_provider"] = llm_provider
    st.session_state["llm_model"] = llm_model
    st.session_state["llm_api_key"] = llm_api_key

    # ==========================================
    # WRAPPER CHUYỂN TIẾP CHO BACKEND BRIDGE
    # ==========================================
    def process_logs_wrapper(uploaded_files):
        """Đóng gói các cấu hình từ Sidebar và gọi Backend Bridge"""
        bridge = WebserverBridge(profile_name=profile_name)

        # 1. Lưu file xuống ổ cứng (Sử dụng ProfileManager bên trong)
        bridge.process_uploads(uploaded_files, log_type, log_format, operation_mode)

        # 2. Tạo một callback để cập nhật thanh tiến trình của Streamlit
        progress_bar = st.progress(0)
        status_text = st.empty()

        def ui_callback(message, percent):
            status_text.text(message)
            progress_bar.progress(percent / 100.0)

        # 3. Chạy Toàn bộ Pipeline Backend
        success = bridge.run_full_pipeline(status_callback=ui_callback)

        if success:
            progress_bar.empty()
            status_text.empty()
            # 4. Gom dữ liệu kết quả để vẽ Dashboard
            return bridge.compile_dashboard_data()
        else:
            return None

    # ==========================================
    # GỌI BỘ KHUNG GIAO DIỆN CHUNG (SHARED_UI)
    # ==========================================
    render_standard_module_layout(
        module_id="webserver_ait",
        module_name="Web Server APT Hunter",
        module_description="Hệ thống Săn lùng Đe dọa Liên tục Nâng cao (APT) trên bề mặt Web Server. Kết hợp WAF lai, Học máy Hành vi và Phân tích LLM.",
        accepted_file_types=["log", "txt"],
        process_logs_func=process_logs_wrapper,
        render_dashboard_func=render_dashboard,
        run_llm_func=run_llm_advisor
    )


if __name__ == "__main__":
    render_page()