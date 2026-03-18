import json
import requests


class LLMAdvisor:
    def __init__(self):
        # API Endpoints
        self.GOOGLE_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        self.OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
        self.NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

    def _extract_multi_anchor_blast_radius(self, timeline, max_logs=70, window_per_anchor=15):
        """
        Extracts up to `max_logs` from the timeline by identifying critical 'Anchors'
        and grabbing the surrounding context logs. Merges overlapping windows.
        """
        total_len = len(timeline)
        if total_len <= max_logs:
            # If the session is small enough, just send the whole thing.
            return timeline

        anchor_indices = []

        # 1. Identify all critical points of interest
        for i, event in enumerate(timeline):
            if event.get('layer1_flagged'):
                anchor_indices.append(i)
            elif event.get('status_code') in [500, 502, 503, 504]:
                anchor_indices.append(i)

        # If no anchors found, anchor to the start and end
        if not anchor_indices:
            anchor_indices = [0, total_len - 1]

        # 2. Calculate windows around anchors
        indices_to_keep = set()
        for anchor in anchor_indices:
            start = max(0, anchor - window_per_anchor)
            end = min(total_len, anchor + window_per_anchor + 1)
            indices_to_keep.update(range(start, end))

        # 3. Sort and enforce the max_logs cap
        sorted_indices = sorted(list(indices_to_keep))

        if len(sorted_indices) > max_logs:
            sorted_indices = sorted_indices[:max_logs]

        # 4. Extract the logs
        sampled_timeline = [timeline[i] for i in sorted_indices]

        return sampled_timeline

    def _build_prompt(self, case_file):
        """
        Converts the JSON case file into a highly compressed text prompt,
        injecting raw log samples using Multi-Anchor extraction.
        """
        prompt = (
            "You are a Senior Threat Hunter and APT (Advanced Persistent Threat) Expert. Review this session profile.\n"
            "WARNING: APTs often hide in plain sight using 'benign' HTTP 200 requests. Do NOT just look for obvious SQLi/XSS payloads.\n"
            "You MUST analyze the TEMPORAL TIMELINE (the timestamps between requests) to detect:\n"
            "1. C2 Beaconing (automated, rhythmic, or periodic requests like polling admin-ajax.php every few minutes).\n"
            "2. Low-and-slow data exfiltration or automated reconnaissance.\n"
            "3. Evasion attempts masking as normal internal traffic.\n\n"
            "Your job is to look at the raw log samples, verify if an actual exploit or automated C2 beaconing occurred, "
            "explain the attacker's methodology, and determine if this is a True Attack or benign. "
            "Always suspicious, if it show any sight of attack/exploit/anomalies no matter if it's APT or not, then please say so. "
            "Never underrate the alert.\n\n"
            "Answer precisely, shortly and go straight to the point in Vietnamese.\n\n"
        )

        # 1. The Executive Summary (Layer 2 Context)
        prompt += "[EVENTS PROFILE]\n"
        prompt += f"Entity ID: {case_file.get('incident_tracking_id', 'UNKNOWN')}\n"
        prompt += f"Statistical Threat Level: {case_file.get('overall_threat_level', 'NORMAL')} (Score: {case_file.get('max_statistical_score', 0)})\n"
        prompt += f"Markov Sequence Score: {case_file.get('max_markov_score', 0)}/100\n"
        prompt += f"Behavioral Chain: {case_file.get('sequence_chain', '')}\n\n"

        # 2. Representative Timeline & Raw Samples
        full_timeline = case_file.get('timeline', [])

        if not full_timeline:
            return prompt + "No timeline data available."

        sampled_timeline = self._extract_multi_anchor_blast_radius(full_timeline)

        prompt += "[TIMELINE & RAW LOG SAMPLES]\n"
        prompt += f"Note: Timeline contains {len(full_timeline)} total events. Showing the {len(sampled_timeline)} most critical events surrounding the anomalies:\n\n"

        prompt += "--- Session Start ---\n"
        prompt += f"{json.dumps(sampled_timeline[0], separators=(',', ':'))}\n\n"

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
                    prompt += f"[{timestamp}] {method} {uri} -> {status}\n"

        if len(sampled_timeline) > 1:
            prompt += "\n--- Session End ---\n"
            prompt += f"{json.dumps(sampled_timeline[-1], separators=(',', ':'))}\n"

        return prompt

    def _call_openai_compatible(self, url, prompt, model, api_key):
        """Helper for OpenRouter and NVIDIA, which both use the OpenAI REST format."""
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }

        # OpenRouter specific optional header for app rankings
        if "openrouter" in url:
            headers["HTTP-Referer"] = "https://github.com/your-repo/apt-hunter"
            headers["X-Title"] = "APT Hunter System"

        payload = {
            "model": model,
            "messages": [
                {"role": "system",
                 "content": "You are a direct, highly technical cybersecurity AI. Do not use pleasantries."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.08  # Low temperature for analytical consistency
        }

        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            return response.json()["choices"][0]["message"]["content"]
        else:
            return f"API Error {response.status_code}: {response.text}"

    def _call_google(self, prompt, model, api_key):
        """Helper for Google Gemini's specific REST format."""
        url = self.GOOGLE_URL.format(model=model, api_key=api_key)
        headers = {"Content-Type": "application/json"}

        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }],
            "generationConfig": {
                "temperature": 0.08
            }
        }

        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            return response.json()["candidates"][0]["content"]["parts"][0]["text"]
        else:
            return f"API Error {response.status_code}: {response.text}"

    def analyze_session(self, case_file, provider, model, api_key):
        """
        Main entry point. Pass a dictionary case_file from your ndjson,
        select your provider, and get the analysis.
        """
        print(f"[*] Formatting prompt for {provider} ({model})...")
        prompt = self._build_prompt(case_file)

        print("[*] Dispatching request to LLM API...")

        if provider.lower() == "openrouter":
            return self._call_openai_compatible(self.OPENROUTER_URL, prompt, model, api_key)

        elif provider.lower() == "nvidia":
            return self._call_openai_compatible(self.NVIDIA_URL, prompt, model, api_key)

        elif provider.lower() == "google":
            return self._call_google(prompt, model, api_key)

        else:
            return "[-] Error: Unknown provider. Choose 'openrouter', 'nvidia', or 'google'."


# ==========================================
# TEST SCRIPT
# ==========================================
if __name__ == "__main__":
    # 1. We mock loading a single case file from our ndjson
    test_case_file = {
        "incident_tracking_id": "192.168.1.100_20241010",
        "overall_threat_level": "CRITICAL",
        "max_statistical_score": 100,
        "max_markov_score": 98.5,
        "sequence_chain": "STATIC_ASSET | L1_ALERT | SHELL_EXECUTION",
        "timeline": [
            {"@timestamp": "2024-10-10T08:14:00Z", "http_method": "GET", "uri_path": "/index.php", "status_code": 200},
            {"@timestamp": "2024-10-10T08:14:05Z", "http_method": "POST", "uri_path": "/upload.php", "status_code": 200,
             "layer1_flagged": True, "layer1_alerts": ["Suspicious_File_Upload"]},
            {"@timestamp": "2024-10-10T08:14:10Z", "http_method": "GET", "uri_path": "/uploads/shell.php?cmd=whoami",
             "status_code": 200, "layer1_flagged": True, "layer1_alerts": ["RCE_Execution_Output"]}
        ]
    }

    advisor = LLMAdvisor()

    # --- INSTRUCTIONS TO TEST ---
    # Put your real API key here to test the specific provider you want.
    PROVIDER = "nvidia"  # Options: "google", "openrouter", "nvidia"
    MODEL = "openai/gpt-oss-120b"  # Replace with actual target model
    API_KEY = "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"

    if API_KEY != "YOUR_API_KEY_HERE" and API_KEY != "":
        result = advisor.analyze_session(test_case_file, PROVIDER, MODEL, API_KEY)
        print("\n=== LLM ANALYSIS REPORT ===\n")
        print(result)
    else:
        print("[-] Please enter an API key in the script to test the LLM connection.")