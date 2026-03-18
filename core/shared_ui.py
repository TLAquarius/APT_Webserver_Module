import streamlit as st

def inject_custom_css():
    st.markdown(
        """
        <style>
        div[data-testid="metric-container"] {
            background-color: #f8f9fa;
            border: 1px solid #e0e0e0;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 2px 2px 5px rgba(0,0,0,0.05);
        }
        div.stButton > button:first-child {
            border-radius: 6px;
            font-weight: bold;
        }
        hr { margin-top: 2rem; margin-bottom: 2rem; }
        </style>
        """,
        unsafe_allow_html=True
    )

def render_standard_module_layout(
        module_name: str,
        module_description: str,
        render_dashboard_func: callable,
        run_llm_func: callable,
        render_upload_func: callable
):
    """
    Bộ khung dùng chung cho mọi Module.
    Thiết kế 3 Tab ngang: [Dashboard] | [AI LLM] | [Tải lên Dữ liệu]
    """
    inject_custom_css()

    st.subheader(f"🛠️ {module_name}")
    st.caption(f"_{module_description}_")
    st.markdown("<br>", unsafe_allow_html=True)

    # ==========================================
    # CẤU TRÚC 3 TABS LỚN HÀNG NGANG
    # ==========================================
    tab_dashboard, tab_llm, tab_upload = st.tabs([
        "📊 1. Dashboard Giám sát",
        "🤖 2. Chuyên gia AI (LLM)",
        "📂 3. Tải lên & Cấu hình"
    ])

    with tab_dashboard:
        render_dashboard_func()

    with tab_llm:
        st.info("Sử dụng LLM nhận thức ngữ cảnh để phân tích chuỗi hành vi và cung cấp báo cáo bằng ngôn ngữ tự nhiên.")
        run_llm_func()

    with tab_upload:
        render_upload_func()