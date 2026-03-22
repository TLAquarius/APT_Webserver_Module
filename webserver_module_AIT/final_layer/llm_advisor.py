import json
import requests


class LLMAdvisor:
    def __init__(self):
        self.GOOGLE_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        self.OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
        self.NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

    def _extract_multi_anchor_blast_radius(self, timeline, max_logs=70, window_per_anchor=15):
        total_len = len(timeline)
        if total_len <= max_logs: return timeline

        anchor_indices = []
        for i, event in enumerate(timeline):
            if event.get('layer1_flagged') or event.get('status_code') in [500, 502, 503, 504]:
                anchor_indices.append(i)

        if not anchor_indices: anchor_indices = [0, total_len - 1]

        indices_to_keep = set()
        for anchor in anchor_indices:
            start = max(0, anchor - window_per_anchor)
            end = min(total_len, anchor + window_per_anchor + 1)
            indices_to_keep.update(range(start, end))

        sorted_indices = sorted(list(indices_to_keep))[:max_logs]
        return [timeline[i] for i in sorted_indices]

    def _build_prompt(self, case_file):
        prompt = (
            "You are a Senior Threat Hunter and APT (Advanced Persistent Threat) Expert. Review this session profile.\n"
            "WARNING: APTs often hide in plain sight using 'benign' HTTP 200 requests. Do NOT just look for obvious SQLi/XSS payloads.\n"
            "You MUST analyze BOTH the Statistical Context, the Temporal Timeline, and the session's stats to detect:\n"
            "1. Automated Scanners / Fuzzing (High Request/Min, Request/Sec, High 404 Rate, multiple User-Agents).\n"
            "2. C2 Beaconing (rhythmic, periodic requests).\n"
            "3. Path Traversal or LFI (High unique path ratio, deep URI depths).\n"
            "4. Exploitation of suspicious extensions (.env, .bak, .php).\n"
            "5. Data Exfiltration (High max_resp_bytes or avg_payload_bytes).\n"
            "7. Time-based attacks type\n"
            "6. And other type of anomalies (high total request number, long session)\n\n"
            "Your job is to look at the profile, verify if it's an actual exploit or scanning tool, "
            "explain the attacker's methodology, and determine if this is a True Attack or benign.\n"
            "Answer precisely, shortly and go straight to the point in Vietnamese.\n\n"
        )

        prompt += "[1. GENERAL PROFILE]\n"
        prompt += f"Entity ID: {case_file.get('incident_tracking_id', 'UNKNOWN')}\n"
        prompt += f"Threat Level: {case_file.get('overall_threat_level', 'NORMAL')} (Stat Score: {case_file.get('max_statistical_score', 0)}, Markov Score: {case_file.get('max_markov_score', 0)})\n"
        prompt += f"Behavioral Chain: {case_file.get('sequence_chain', '')}\n\n"

        # 🟢 IN TOÀN BỘ CÁC FEATURE ĐỂ CUNG CẤP NGỮ CẢNH ĐẦY ĐỦ CHO LLM
        stats = case_file.get('stats_context', {})
        if stats:
            prompt += "[2. FULL STATISTICAL BEHAVIOR CONTEXT]\n"
            prompt += "The following are aggregated statistical features extracted by ML Sessionizer for this IP:\n"
            for feature_name, value in stats.items():
                prompt += f"- {feature_name}: {value}\n"
            prompt += "\n"

        full_timeline = case_file.get('timeline', [])
        if not full_timeline: return prompt + "No timeline data available."

        sampled_timeline = self._extract_multi_anchor_blast_radius(full_timeline)
        prompt += "[3. TIMELINE & RAW LOG SAMPLES]\n"
        prompt += f"Note: Showing the {len(sampled_timeline)} most critical events surrounding the anomalies:\n\n"

        for event in sampled_timeline:
            if event.get("event_type") == "COMPRESSED_BULK_ACTION":
                prompt += f"[{event.get('start_time')} to {event.get('end_time')}] BULK ACTION: {event.get('count')} requests to {event.get('uri_path')} (Status {event.get('status_code')})\n"
            else:
                if event.get('layer1_flagged'):
                    alerts = ", ".join(event.get('layer1_alerts', []))
                    prompt += f"\n[! WAF ALERT TRIGGERED: {alerts} !] -> RAW LOG:\n"
                    clean_event = {k: v for k, v in event.items() if k not in ['raw_response_body']}
                    prompt += f"{json.dumps(clean_event, indent=2)}\n\n"
                elif event.get('status_code') in [500, 502, 503]:
                    prompt += f"-> RAW ERROR LOG:\n{json.dumps(event, separators=(',', ':'))}\n"
                else:
                    timestamp = event.get('@timestamp', '')
                    method = event.get('http_method', 'GET')
                    uri = event.get('uri_path', '/')
                    status = event.get('status_code', '000')
                    body = event.get('request_body', '')

                    log_str = f"[{timestamp}] {method} {uri} -> {status}"
                    if body: log_str += f" | BODY: {body}"
                    prompt += log_str + "\n"

        return prompt

    def _call_openai_compatible(self, url, prompt, model, api_key):
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        if "openrouter" in url:
            headers["HTTP-Referer"] = "https://github.com/your-repo/apt-hunter"
            headers["X-Title"] = "APT Hunter System"

        payload = {
            "model": model,
            "messages": [
                {"role": "system", "content": "You are a direct cybersecurity AI."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.08
        }

        try:
            response = requests.post(url, headers=headers, json=payload)
            if response.status_code == 200:
                return response.json()["choices"][0]["message"]["content"]
            return f"API Error {response.status_code}: {response.text}"
        except Exception as e:
            return f"Connection Error: {e}"

    def _call_google(self, prompt, model, api_key):
        url = self.GOOGLE_URL.format(model=model, api_key=api_key)
        headers = {"Content-Type": "application/json"}

        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.08}
        }

        try:
            response = requests.post(url, headers=headers, json=payload)
            if response.status_code == 200:
                return response.json()["candidates"][0]["content"]["parts"][0]["text"]
            return f"API Error {response.status_code}: {response.text}"
        except Exception as e:
            return f"Connection Error: {e}"

    def analyze_session(self, case_file, provider, model, api_key):
        if not api_key: return "[-] Vui lòng cung cấp API Key trong phần Cài đặt."

        prompt = self._build_prompt(case_file)
        if provider.lower() == "openrouter":
            return self._call_openai_compatible(self.OPENROUTER_URL, prompt, model, api_key)
        elif provider.lower() == "nvidia":
            return self._call_openai_compatible(self.NVIDIA_URL, prompt, model, api_key)
        elif provider.lower() == "google":
            return self._call_google(prompt, model, api_key)
        else:
            return "[-] Error: Unknown provider."