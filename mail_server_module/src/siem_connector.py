from elasticsearch import Elasticsearch

def connect_siem(host="http://127.0.0.1:9200"):
    """Tạo kết nối đến Elasticsearch"""
    print("[*] Đang kết nối tới CSDL Elasticsearch (SIEM)...")
    try:
        es = Elasticsearch(hosts=[host])
        info = es.info()
        print(f"    [+] Kết nối thành công! Elasticsearch phiên bản: {info['version']['number']}")
        return es
    except Exception as e:
        print(f"    [!] LỖI KẾT NỐI MẠNG: {e}")
        return None

def push_to_siem(es_client, index_name, document):
    """Đẩy một tài liệu lên Elasticsearch (Hỗ trợ cả Email và Log)"""
    # Lấy tên định danh an toàn: Ưu tiên file_name (của Email), nếu không có thì lấy alert_type (của Log)
    doc_name = document.get('file_name', document.get('alert_type', 'Unknown Document'))
    
    try:
        res = es_client.index(
            index=index_name, 
            document=document,
            refresh=True  # Ép dữ liệu hiện lên Kibana ngay lập tức
        )
        print(f"    [+] Đã đẩy báo cáo '{doc_name}' lên SIEM (ID: {res['_id']})")
    except Exception as e:
        print(f"    [!] Lỗi từ Elasticsearch khi đẩy '{doc_name}': {e}")