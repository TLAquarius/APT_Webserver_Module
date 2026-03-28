import json
import requests


class LLMAdvisor:
    def __init__(self):
        """
        Initializes the LLM Advisor with API endpoints for various providers.
        """
        self.GOOGLE_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={api_key}"
        self.OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
        self.NVIDIA_URL = "https://integrate.api.nvidia.com/v1/chat/completions"

    def _truncate_event(self, event_dict, max_len=512):
        """
        Truncates long string values in an event dictionary to prevent LLM token limit crashes.
        """
        safe_dict = {}
        for k, v in event_dict.items():
            if isinstance(v, str) and len(v) > max_len:
                safe_dict[k] = v[:max_len] + f"... [TRUNCATED {len(v)} chars]"
            else:
                safe_dict[k] = v
        return safe_dict

    def _extract_multi_anchor_blast_radius(self, timeline, max_logs=70, window_per_anchor=15):
        """
        Selects critical timeline segments by anchoring on L1 alerts, errors, and ML-identified anomalies.
        """
        total_len = len(timeline)
        if total_len <= max_logs: return timeline

        anchor_indices = []
        suspicious_exts = ['.bak', '.env', '.sql', '.git', '.old', '.log', '.sh', '.zip', '.tar.gz', '.inc', '.php']

        for i, event in enumerate(timeline):
            uri = str(event.get('uri_path', '')).lower()
            is_suspicious_ext = any(ext in uri for ext in suspicious_exts)
            heavy_payload = int(event.get('bytes_sent', 0)) > 500000
            status = event.get('status_code', 200)

            if (event.get('layer1_flagged') or
                    status >= 500 or status in [401, 403, 404] or
                    is_suspicious_ext or
                    heavy_payload):
                anchor_indices.append(i)

        if not anchor_indices:
            anchor_indices = [0, total_len - 1]

        indices_to_keep = set()
        for anchor in anchor_indices:
            start = max(0, anchor - window_per_anchor)
            end = min(total_len, anchor + window_per_anchor + 1)
            indices_to_keep.update(range(start, end))

        sorted_indices = sorted(list(indices_to_keep))[:max_logs]
        return [timeline[i] for i in sorted_indices]

    def _build_prompt(self, case_file):
        """
        Constructs the final text prompt sent to the LLM, incorporating statistics, ML reasons, and truncated timelines.
        """
        prompt = (
            "You are a Senior Threat Hunter and APT Expert. Review this session profile.\n"
            "WARNING: APTs often hide in plain sight using 'benign' HTTP 200 requests.\n"
            "You MUST analyze the AI Anomaly Reasons, the Statistical Context, and the Timeline to detect:\n"
            "1. Automated Scanners / Fuzzing (High Request/Min, High 404 Rate, multiple User-Agents).\n"
            "2. C2 Beaconing (rhythmic, periodic requests).\n"
            "3. Path Traversal or LFI (High unique path ratio, deep URI depths).\n"
            "4. Exploitation of suspicious extensions (.env, .bak, .php).\n"
            "5. Data Exfiltration (High max_resp_bytes or avg_payload_bytes).\n"
            "Your job is to verify if it's an actual exploit or scanning tool, explain the methodology, and determine if it is a True Attack or benign.\n"
            "Answer precisely, shortly and go straight to the point in Vietnamese.\n\n"
        )

        prompt += "[1. GENERAL PROFILE]\n"
        prompt += f"Entity ID: {case_file.get('incident_tracking_id', 'UNKNOWN')}\n"
        prompt += f"Threat Level: {case_file.get('overall_threat_level', 'NORMAL')} (Stat Score: {case_file.get('max_statistical_score', 0)}, Markov Score: {case_file.get('max_markov_score', 0)})\n"

        stat_reasons = case_file.get('statistical_anomaly_reasons', [])
        seq_reasons = case_file.get('sequential_anomaly_reasons', [])

        if stat_reasons:
            prompt += f"Statistical AI Flags: {' | '.join(stat_reasons)}\n"
        if seq_reasons:
            prompt += f"Sequential AI Flags: {' | '.join(seq_reasons)}\n"

        prompt += f"Behavioral Chain: {case_file.get('sequence_chain', '')}\n\n"

        stats = case_file.get('stats_context', {})
        if stats:
            prompt += "[2. FULL STATISTICAL BEHAVIOR CONTEXT]\n"
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
                    safe_event = self._truncate_event(clean_event)
                    prompt += f"{json.dumps(safe_event, indent=2)}\n\n"
                elif event.get('status_code') in [401, 403, 404, 500, 502, 503, 504]:
                    prompt += f"-> RAW ERROR LOG:\n{json.dumps(self._truncate_event(event), separators=(',', ':'))}\n"
                else:
                    timestamp = event.get('@timestamp', '')
                    method = event.get('http_method', 'GET')
                    uri = event.get('uri_path', '/')
                    status = event.get('status_code', '000')
                    body = str(event.get('request_body', ''))

                    log_str = f"[{timestamp}] {method} {uri} -> {status}"
                    if body:
                        safe_body = body[:512] + "...[TRUNCATED]" if len(body) > 512 else body
                        log_str += f" | BODY: {safe_body}"
                    prompt += log_str + "\n"

        return prompt

    def _call_openai_compatible(self, url, prompt, model, api_key):
        """
        Executes a synchronous POST request to OpenAI-compatible LLM APIs.
        """
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
        """
        Executes a synchronous POST request to the Google Gemini API.
        """
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
        """
        Routes the session analysis request to the designated LLM provider.
        """
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