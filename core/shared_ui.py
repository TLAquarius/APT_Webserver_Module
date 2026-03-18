import streamlit as st
import gc


def inject_custom_css():
    """
    Injects custom CSS to unify the look and feel of all modules.
    This creates card-like structures for metrics and standardizes button colors.
    """
    st.markdown(
        """
        <style>
        /* Card styling for metric containers */
        div[data-testid="metric-container"] {
            background-color: #f8f9fa;
            border: 1px solid #e0e0e0;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 2px 2px 5px rgba(0,0,0,0.05);
        }
        /* Primary button styling */
        div.stButton > button:first-child {
            border-radius: 6px;
            font-weight: bold;
        }
        /* Divider styling */
        hr {
            margin-top: 2rem;
            margin-bottom: 2rem;
        }
        </style>
        """,
        unsafe_allow_html=True
    )


def render_standard_module_layout(
        module_id: str,
        module_name: str,
        module_description: str,
        accepted_file_types: list,
        process_logs_func: callable,
        render_dashboard_func: callable,
        run_llm_func: callable
):
    """
    The standard UI skeleton for all SOC modules.

    Args:
        module_id (str): Unique identifier for the module (e.g., "webserver_ait").
        module_name (str): Display name of the module.
        module_description (str): Short description of what the module does.
        accepted_file_types (list): List of allowed file extensions (e.g., ["log", "csv"]).
        process_logs_func (callable): Backend function to process uploaded files.
        render_dashboard_func (callable): Frontend function to draw charts/metrics.
        run_llm_func (callable): Frontend/Backend function to handle LLM interactions.
    """
    # 1. Apply global CSS styles
    inject_custom_css()

    # 2. Render Header
    st.title(f"🛠️ Module: {module_name}")
    st.markdown(f"*{module_description}*")
    st.divider()

    # State keys specifically namespaced for this module to prevent RAM conflicts
    data_key = f"{module_id}_processed_data"

    # ==========================================
    # SECTION 1: DATA INGESTION
    # ==========================================
    st.subheader("1. Tải lên Dữ liệu (Raw Logs)")

    uploaded_files = st.file_uploader(
        "Tải lên một hoặc nhiều tệp log để phân tích:",
        accept_multiple_files=True,
        type=accepted_file_types
    )

    col_btn1, col_btn2 = st.columns([1, 4])

    with col_btn1:
        # Provide a manual memory clearance button
        if st.button("🗑️ Xóa Dữ liệu & Giải phóng RAM", use_container_width=True):
            if data_key in st.session_state:
                del st.session_state[data_key]
                gc.collect()  # Force OS to reclaim memory immediately
            st.success("Đã giải phóng bộ nhớ thành công.")
            st.rerun()

    # If files are uploaded and data hasn't been processed yet
    if uploaded_files and data_key not in st.session_state:
        st.info(f"Đã nạp {len(uploaded_files)} tệp. Sẵn sàng xử lý.")

        if st.button("🚀 Bắt đầu Phân tích Chuyên sâu", use_container_width=True, type="primary"):
            # st.spinner keeps the UI responsive (non-blocking feel) while backend runs
            with st.spinner("Đang xử lý log qua các tầng Regex, Học máy và Dung hợp dữ liệu... Vui lòng đợi."):
                try:
                    # Execute the module-specific backend logic
                    result_data = process_logs_func(uploaded_files)

                    # Store result in session state to persist across reruns
                    st.session_state[data_key] = result_data
                    st.success("Phân tích hoàn tất thành công!")
                except Exception as e:
                    st.error(f"Đã xảy ra lỗi trong quá trình xử lý: {e}")

    st.divider()

    # ==========================================
    # SECTION 2 & 3: DASHBOARD & LLM ADVISOR
    # Only render these if data has been successfully processed and exists in RAM
    # ==========================================
    if data_key in st.session_state and st.session_state[data_key] is not None:
        processed_data = st.session_state[data_key]

        st.subheader("2. Dashboard Giám sát & Phân tích")
        # Execute the module-specific dashboard rendering
        render_dashboard_func(processed_data)

        st.divider()

        st.subheader("3. 🤖 Chuyên gia Trí tuệ Nhân tạo (LLM Advisor)")
        st.info("Sử dụng LLM nhận thức ngữ cảnh để phân tích chuỗi hành vi và cung cấp báo cáo bằng ngôn ngữ tự nhiên.")
        # Execute the module-specific LLM logic
        run_llm_func(processed_data)

    elif not uploaded_files:
        st.caption("Vui lòng tải lên các tệp log để mở khóa tính năng Dashboard và Chuyên gia AI.")