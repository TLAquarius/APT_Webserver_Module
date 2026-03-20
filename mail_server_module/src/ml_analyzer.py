import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import make_pipeline

# 1. TẬP DỮ LIỆU HUẤN LUYỆN (MINI-DATASET)
# 1 = Độc hại / Lừa đảo (BEC/Phishing)
# 0 = Bình thường (Safe)
TRAIN_DATA = [
    # Mẫu lừa đảo (Tiếng Anh & Tiếng Việt)
    ("Urgent: Please process this wire transfer immediately", 1),
    ("Your account will be suspended. Click here to verify", 1),
    ("Khẩn cấp: Yêu cầu kế toán chuyển khoản ngay hóa đơn này", 1),
    ("Tôi đang họp không nghe máy được, chuyển gấp cho đối tác 50 triệu", 1),
    ("Vui lòng cập nhật thông tin tài khoản ngân hàng của bạn", 1),
    ("Kindly pay the attached invoice to avoid penalty", 1),
    ("Xác minh mật khẩu email của bạn ngay lập tức", 1),
    
    # Mẫu bình thường
    ("Hẹn anh chiều nay 3h họp dự án nhé", 0),
    ("Gửi sếp báo cáo tiến độ tuần này", 0),
    ("Here is the meeting minutes from yesterday", 0),
    ("Cảm ơn bạn đã phản hồi, mình sẽ xem xét", 0),
    ("Chúc mọi người cuối tuần vui vẻ", 0),
    ("Please find the attached project timeline", 0)
]

# Tách dữ liệu thành Text (X) và Nhãn (y)
texts, labels = zip(*TRAIN_DATA)

def train_model():
    """Huấn luyện mô hình Phân loại văn bản"""
    # Sử dụng TF-IDF để biến đổi chữ thành ma trận số, sau đó dùng thuật toán Naive Bayes
    model = make_pipeline(TfidfVectorizer(ngram_range=(1, 2)), MultinomialNB())
    model.fit(texts, labels)
    return model

# Khởi tạo mô hình (Train ngay khi module được import)
print("[*] Đang nạp mô hình Học máy AI (NLP)...")
ai_model = train_model()

def analyze_email_content(body_text):
    """
    Đưa nội dung email vào mô hình để dự đoán xác suất lừa đảo.
    Trả về điểm từ 0 -> 100
    """
    if not body_text or len(body_text.strip()) < 10:
        return {"status": "Skipped", "score": 0, "message": "Nội dung quá ngắn để phân tích"}

    # Dự đoán xác suất (Probability)
    probs = ai_model.predict_proba([body_text])[0]
    
    # probs[1] là xác suất rơi vào nhãn 1 (Độc hại)
    phishing_prob = probs[1] * 100 

    if phishing_prob >= 60:
        return {
            "status": "Suspicious",
            "score": int(phishing_prob),
            "message": f"Nghi ngờ lừa đảo BEC/Phishing (Độ tin cậy: {int(phishing_prob)}%)"
        }
    else:
        return {
            "status": "Clean",
            "score": int(phishing_prob),
            "message": f"Văn phong bình thường (Rủi ro: {int(phishing_prob)}%)"
        }

# --- TEST ĐỘC LẬP ---
if __name__ == "__main__":
    test_text_1 = "Kế toán trưởng chú ý, hãy thanh toán gấp hóa đơn này cho đối tác."
    print("Test 1:", analyze_email_content(test_text_1))
    
    test_text_2 = "File báo cáo mình để trên drive, bạn check nhé."
    print("Test 2:", analyze_email_content(test_text_2))