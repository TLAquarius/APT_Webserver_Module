import streamlit as st
import importlib
import gc

# =====================================================================
# 1. PAGE CONFIGURATION
# =====================================================================
st.set_page_config(
    page_title="SOC APT Hunter Platform",
    layout="wide",
    page_icon="🛡️",
    initial_sidebar_state="expanded"
)

# =====================================================================
# 2. MODULE REGISTRY
# =====================================================================
MODULES_REGISTRY = {
    "🏠 Giới thiệu (Home)": {
        "type": "home",
        "description": "Trang chủ giới thiệu hệ thống SOC."
    },
    "🌐 Phân tích Web Server (AIT)": {
        "type": "app",
        "path": "webserver_module_AIT.view",
        "status": "ready"
    },
    "🗄️ Phân tích Database": {
        "type": "app",
        "path": "database_module_XYZ.view",
        "status": "developing"
    },
    "📡 Phân tích Network": {
        "type": "app",
        "path": "network_module_ABC.view",
        "status": "developing"
    }
}


# =====================================================================
# 3. MEMORY MANAGEMENT
# =====================================================================
def clear_memory_on_tab_switch(new_tab_name):
    if "current_active_tab" not in st.session_state:
        st.session_state.current_active_tab = new_tab_name
        return

    if st.session_state.current_active_tab != new_tab_name:
        safe_keys = ["current_active_tab", "user_settings"]
        keys_to_delete = [k for k in st.session_state.keys() if k not in safe_keys]
        for k in keys_to_delete:
            del st.session_state[k]

        gc.collect()
        st.session_state.current_active_tab = new_tab_name


def load_module_dynamically(module_path):
    try:
        module = importlib.import_module(module_path)
        return module
    except ImportError as e:
        st.error(f"❌ Lỗi tải module `{module_path}`: {e}")
        return None
    except Exception as e:
        st.error(f"❌ Lỗi thực thi bên trong module `{module_path}`: {e}")
        return None


# =====================================================================
# 4. COMMON UI (HORIZONTAL ROUTER)
# =====================================================================
def main():
    # --- Sidebar (Chỉ để thông tin phụ) ---
    st.sidebar.title("🛡️ SOC PLATFORM")
    st.sidebar.markdown("Hệ thống Phát hiện APT Toàn diện")
    st.sidebar.divider()
    st.sidebar.info("🎓 Đồ án tốt nghiệp\n\nKiến trúc Micro-module mở rộng.")

    # --- Main Body: Horizontal Navigation ---
    st.title("🛡️ SOC APT Hunter Platform")

    module_names = list(MODULES_REGISTRY.keys())

    # Render Tab ngang như E-commerce
    selected_tab = st.radio(
        "📌 Menu Điều hướng:",
        module_names,
        horizontal=True,
        label_visibility="collapsed"
    )

    clear_memory_on_tab_switch(selected_tab)
    st.markdown("---")  # Divider ngang

    # --- Routing ---
    module_info = MODULES_REGISTRY[selected_tab]

    if module_info["type"] == "home":
        render_home_page()
    elif module_info["type"] == "app":
        if module_info.get("status") == "ready":
            view_module = load_module_dynamically(module_info["path"])
            if view_module and hasattr(view_module, "render_page"):
                view_module.render_page()
            else:
                st.warning("⚠️ Module đã import nhưng không có hàm `render_page()`.")
        else:
            st.info("🚧 Module này đang trong quá trình phát triển (Under Construction).")


# =====================================================================
# 5. HOME PAGE
# =====================================================================
def render_home_page():
    st.markdown("### Trung tâm Giám sát và Điều tra Sự cố An ninh Mạng")
    st.write("""
    Hệ thống áp dụng kiến trúc Micro-module, phân tích chuyên sâu đa bề mặt bằng cách kết hợp:
    * **Deterministic Rules (Tầng 1):** Bắt quả tang qua Signatures.
    * **Machine Learning (Tầng 2 & 3):** Tìm kiếm dị thường (Isolation Forest, Markov Chain).
    * **Generative AI (Tầng 4):** Tham vấn bằng Mô hình ngôn ngữ lớn (LLM).

    👆 **Vui lòng chọn một Module trên thanh Menu ngang để bắt đầu.**
    """)


if __name__ == "__main__":
    main()