import os
import requests
from dotenv import load_dotenv
import json

load_dotenv()


class LLMClient:
    """Generic LLM Client for Google Gemini."""

    def __init__(self, model: str = "gemini-2.5-flash"):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("Missing GEMINI_API_KEY in environment.")

        # Gemini official API endpoint
        self.api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
        self.model = model
        self.headers = {
            "Content-Type": "application/json"
        }

    def analyze_logs(self, csv_text: str, temperature: float = 0.3):
        """
        Send entire CSV log to Gemini for analysis.
        Expect Gemini to return a JSON array with analysis for each row.
        """
        prompt = f"""
        You are a cybersecurity analyst can view both Vietnamese and English logs.
        You are given a security log in CSV format.

        Your task:
        1. Analyze each log entry carefully.
        2. For each or multiple related rows, determine:
           - entry: list of entries' timestamp (or ID) that related or need noting 
           - summary: explanation of the events
           - suspicious: "yes" or "no"
           - risk_type: what type of security risk the event likely to be (e.g Privilege Escalation, malware injection,...)
           - severity: "low", "medium", or "high"
           - action: "keep tracking", "need inspect", "block" or other action to do next
           - next_prediction: describe what the attacker, system or event is likely to do next
        3. Give the answer in the Vietnamese natural language. Example:
        Return your answer as a JSON array (no explanations), like:
        [
          {{"entry": ["2025-09-26T15:00:05Z", "2025-09-26T15:01:00Z",...] or ["id1", "id3", "id9"],
          "summary": "Người dùng có IP xxxx đã đổi thành quyền admin và download lượng file lớn bất thường (2GB)",
          "suspicious": "Có" or "Không",
          "risk_type": "Có thể là hành động khai thác dữ liệu trái phép (Data Exfiltration) bằng cách leo thang phân quyền (Privilege Escalation)",
          "severity": "Cao",
          "action": "Lặp tức chặn quyền và điều tra",
          "next_prediction": "Người dùng IP xxxx có thể sẽ tiếp tục tấn công"
          }},
          ...
        ]
        ----------------
        Input Log (CSV):
        {csv_text}
        Output:
        """

        payload = {
            "contents": [
                {"parts": [{"text": prompt}]}
            ],
            "generationConfig": {"temperature": temperature}
        }

        response = requests.post(
            f"{self.api_url}?key={self.api_key}",
            headers=self.headers,
            json=payload
        )

        if response.status_code != 200:
            print("Error:", response.status_code)
            print(response.text)
            response.raise_for_status()

        result = response.json()

        # Extract the generated text
        try:
            content = result["candidates"][0]["content"]["parts"][0]["text"].strip()
        except (KeyError, IndexError):
            raise ValueError(f"Unexpected response format: {json.dumps(result, indent=2)}")

        return self._parse_json(content)

    def _parse_json(self, content: str):
        """Safely extract JSON array from model output."""
        start = content.find("[")
        end = content.rfind("]") + 1
        json_str = content[start:end]
        try:
            return json.loads(json_str)
        except Exception as e:
            print("Failed to parse LLM output.")
            print("Raw content:", content)
            raise e
