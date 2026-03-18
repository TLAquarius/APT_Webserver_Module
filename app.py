import streamlit as st
import importlib
import gc

# =====================================================================
# 1. PAGE CONFIGURATION (Must be the first Streamlit command)
# =====================================================================
st.set_page_config(
    page_title="SOC APT Hunter Platform",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# =====================================================================
# 2. MODULE REGISTRY
# Allows team members to easily plug their modules into the system.
# =====================================================================
MODULES_REGISTRY = {
    "🏠 Giới thiệu (Home)": {
        "type": "home",
        "description": "Trang chủ giới thiệu hệ thống SOC."
    },
    "🌐 Phân tích Web Server (AIT)": {
        "type": "app",
        "path": "webserver_module_AIT.view",  # Points to the view.py file in your folder
        "status": "ready"
    },
    "🗄️ Phân tích Database (Thành viên A)": {
        "type": "app",
        "path": "database_module_XYZ.view",  # Points to Member A's folder
        "status": "developing"  # Change to "ready" when coding is finished
    },
    "📡 Phân tích Network (Thành viên B)": {
        "type": "app",
        "path": "network_module_ABC.view",
        "status": "developing"
    }
}


# =====================================================================
# 3. MEMORY MANAGEMENT & MULTITHREADING FUNCTIONS
# =====================================================================
def clear_memory_on_tab_switch(new_tab_name):
    """
    Free up RAM immediately when the user switches to another tab.
    Clear heavy DataFrames and Raw Logs stored in Session State.
    """
    if "current_active_tab" not in st.session_state:
        st.session_state.current_active_tab = new_tab_name
        return

    # If a tab switch is detected
    if st.session_state.current_active_tab != new_tab_name:
        # Filter out safe keys (do not delete)
        safe_keys = ["current_active_tab", "user_settings"]

        # Delete all temporary variables of the old module
        keys_to_delete = [k for k in st.session_state.keys() if k not in safe_keys]
        for k in keys_to_delete:
            del st.session_state[k]

        # Force Python to collect garbage (Actual RAM release)
        gc.collect()

        # Update the current tab state
        st.session_state.current_active_tab = new_tab_name


def load_module_dynamically(module_path):
    """
    Lazy Loading Technique: Instead of static imports at the top of the file
    causing high RAM usage, this function only imports the module's code
    when the user actually clicks on it.
    """
    try:
        # Dynamically import the module using importlib
        module = importlib.import_module(module_path)
        return module
    except ImportError as e:
        st.error(
            f"❌ Lỗi tải module `{module_path}`: Có thể thư mục hoặc file `view.py` chưa tồn tại.\n\nChi tiết lỗi: {e}")
        return None
    except Exception as e:
        st.error(f"❌ Lỗi thực thi bên trong module `{module_path}`: {e}")
        return None


# =====================================================================
# 4. COMMON UI (SIDEBAR ROUTER)
# =====================================================================
def main():
    # --- Build the left sidebar ---
    st.sidebar.title("🛡️ SOC PLATFORM")
    st.sidebar.markdown("Hệ thống Phát hiện APT Toàn diện")
    st.sidebar.divider()

    # Get the list of module names from the Registry
    module_names = list(MODULES_REGISTRY.keys())

    # Module selection widget
    selected_tab = st.sidebar.radio("📌 Điều hướng:", module_names)

    # Trigger RAM cleanup before loading the new page
    clear_memory_on_tab_switch(selected_tab)

    st.sidebar.divider()
    st.sidebar.info("🎓 Đồ án tốt nghiệp\n\nNhóm phát triển: ...")

    # --- Routing (Display redirection) ---
    module_info = MODULES_REGISTRY[selected_tab]

    # Handle the Home page separately (Avoid creating an extra folder)
    if module_info["type"] == "home":
        render_home_page()

    # Handle loading the actual Analysis Modules
    elif module_info["type"] == "app":
        if module_info.get("status") == "ready":
            # Start Lazy Loading the module's code
            view_module = load_module_dynamically(module_info["path"])

            if view_module and hasattr(view_module, "render_page"):
                # Call the render_page() function from the corresponding module's view.py file
                view_module.render_page()
            else:
                st.warning(
                    "⚠️ Module đã được import nhưng không tìm thấy hàm `render_page()`. Yêu cầu thành viên nhóm kiểm tra lại file `view.py`.")
        else:
            # Placeholder UI for modules under construction
            st.title(selected_tab)
            st.info("🚧 Module này đang trong quá trình phát triển (Under Construction).")


# =====================================================================
# 5. HOME PAGE (Placed directly here for convenience)
# =====================================================================
def render_home_page():
    st.title("🛡️ SOC APT Hunter Platform")
    st.markdown("### Trung tâm Giám sát và Điều tra Sự cố An ninh Mạng")

    st.write("""
    Chào mừng đến với hệ thống SOC. Hệ thống này áp dụng kiến trúc Micro-module, 
    cho phép phân tích chuyên sâu đa bề mặt (Web, Database, Network) bằng cách kết hợp:

    * **Deterministic Rules (Tầng 1):** Bắt quả tang qua chữ ký (Signatures).
    * **Machine Learning (Tầng 2 & 3):** Tìm kiếm dị thường (Isolation Forest, Markov Chain).
    * **Generative AI (Tầng 4):** Tham vấn bằng Mô hình ngôn ngữ lớn (LLM).

    👈 **Vui lòng chọn một Module phân tích ở thanh công cụ bên trái để bắt đầu.**
    """)

    # You can insert the overall system architecture diagram for the entire team here
    # st.image("đường_dẫn_ảnh_sơ_đồ_kiến_trúc.png", use_container_width=True)


# =====================================================================
# RUN THE APPLICATION
# =====================================================================
if __name__ == "__main__":
    main()