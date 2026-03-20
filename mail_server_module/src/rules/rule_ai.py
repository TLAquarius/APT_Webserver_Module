# src/rules/rule_ai.py
from ai.feature_extractor import extract_features, get_feature_names
from ai.model_manager import AnomalyDetector

# Khởi tạo Trợ lý AI (Nó sẽ tự động tìm file .pkl trên ổ cứng để load)
ai_detector = AnomalyDetector()

# Bộ đệm dành cho lần chạy đầu tiên (nếu chưa có file mô hình)
WARM_UP_SAMPLES = 500
buffer_data = []

def check_ai_anomaly(log_data):
    """Đầu dò AI tích hợp vào Pipeline của SIEM"""
    global buffer_data
    
    features = extract_features(log_data)
    feature_names = get_feature_names()

    # Xử lý nếu mô hình CHƯA ĐƯỢC HỌC (Lần đầu tiên chạy toàn bộ hệ thống)
    if not ai_detector.is_trained:
        buffer_data.append(features)
        if len(buffer_data) >= WARM_UP_SAMPLES:
            ai_detector.train(buffer_data, feature_names)
            buffer_data.clear() # Xóa bộ đệm cho nhẹ RAM
        return None

    # Xử lý khi mô hình ĐÃ SẴN SÀNG (Dự đoán trực tiếp)
    is_anomaly, score = ai_detector.predict(features, feature_names)
    
    if is_anomaly:
        return {
            "alert_type": "AI Anomaly Detection",
            "severity": "CRITICAL",
            "source_ip": log_data.get('ip', 'Unknown'),
            "target_user": log_data.get('user', 'Unknown'),
            "description": f"Hành vi vi tế bất thường (Anomaly Score: {score:.2f}). Đặc trưng: Giờ {features[0]}, DV {features[1]}, KQ {features[2]}."
        }
        
    return None