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

    def _truncate_event(self, event_dict, max_len=2000):
        """
        Truncates excessively long payloads to prevent memory crashes, but keeps enough
        context (2000 chars) for the LLM to analyze the exact payload.
        """
        safe_dict = {}
        for k, v in event_dict.items():
            if isinstance(v, str) and len(v) > max_len:
                safe_dict[k] = v[:max_len] + f"... [TRUNCATED {len(v)} chars]"
            else:
                safe_dict[k] = v
        return safe_dict

    def _extract_smart_blast_radius(self, timeline, stat_reasons, max_events=150, window=10):
        """
        ML-Steered Weighted Anchor Logic (Multi-Point Context Extraction):
        Uses the IQR anomaly reasons from the Statistical Layer to hunt for the
        specific logs that caused the anomaly, extracting windows around each anchor.
        """
        if len(timeline) <= max_events:
            return timeline

        combined_ml_reasons = " ".join(stat_reasons).lower()
        scored_events = []

        for i, event in enumerate(timeline):
            score = 0

            try:
                status = int(event.get('status_code') or 200)
            except (ValueError, TypeError):
                status = 200

            is_waf_flagged = event.get('layer1_flagged', False)
            uri = str(event.get('uri_path', '')).lower()
            method = event.get('http_method', 'GET')

            try:
                bytes_sent = int(event.get('bytes_sent') or 0)
            except (ValueError, TypeError):
                bytes_sent = 0

            if event.get("event_type") == "COMPRESSED_BULK_ACTION":
                score += 50

            if is_waf_flagged:
                if status in [200, 201, 301, 302]:
                    score += 1500
                elif status >= 500:
                    score += 500
                else:
                    score += 100

            if status >= 500:
                score += 50
            elif status in [401, 403]:
                score += 10

            if "error_404_rate" in combined_ml_reasons and status == 404:
                score += 200

            if "error_401_rate" in combined_ml_reasons and status == 401:
                score += 200

            if (
                    "max_resp_bytes" in combined_ml_reasons or "avg_payload_bytes" in combined_ml_reasons) and bytes_sent > 100000:
                score += 300

            if "suspicious_ext_rate" in combined_ml_reasons:
                suspicious_exts = ['.bak', '.env', '.sql', '.git', '.old', '.log', '.sh', '.zip', '.tar.gz', '.inc',
                                   '.php']
                if any(ext in uri for ext in suspicious_exts):
                    score += 250

            if "auth_attempt_rate" in combined_ml_reasons:
                if any(kw in uri for kw in ['login', 'admin', 'auth', 'signin']):
                    score += 200

            if "avg_uri_depth" in combined_ml_reasons and uri.count('/') >= 4:
                score += 200

            if "rare_method_rate" in combined_ml_reasons and method not in ['GET', 'POST', 'HEAD']:
                score += 200

            scored_events.append((i, score))

        top_anchors = [idx for idx, score in sorted(scored_events, key=lambda x: x[1], reverse=True) if score > 0]

        if not top_anchors:
            return timeline[-max_events:]

        indices_to_keep = set()
        for anchor in top_anchors:
            if len(indices_to_keep) >= max_events:
                break
            start = max(0, anchor - window)
            end = min(len(timeline), anchor + window + 1)
            indices_to_keep.update(range(start, end))

        sorted_indices = sorted(list(indices_to_keep))[:max_events]
        return [timeline[i] for i in sorted_indices]

    def _build_prompt(self, case_file):
        """
        Constructs a strict, XML-tagged prompt forcing the LLM into a structured analytical framework.
        """
        prompt = (
            "You are a Senior Security Operations Center (SOC) Lead Analyst.\n"
            "Analyze the following incident report. Do NOT hallucinate or invent data. "
            "Only use the provided <DATA_CONTEXT>.\n\n"
            "Your objective is to determine:\n"
            "1. Attack Type: What is the attacker trying to do? (e.g., Reconnaissance, SQLi, Data Exfiltration).\n"
            "2. Exploit Success Evaluation: Did the attack succeed? (Look carefully at HTTP Status codes for WAF alerts. 200=Potential Success, 403=Blocked, 404=Failed).\n"
            "3. Actionable Recommendation: What should the firewall/sysadmin team do immediately?\n\n"
            "Respond in Vietnamese. Be highly technical, precise, and concise.\n\n"
        )

        prompt += "<DATA_CONTEXT>\n"
        prompt += "<GENERAL_PROFILE>\n"
        prompt += f"Incident ID: {case_file.get('incident_tracking_id', 'UNKNOWN')}\n"
        prompt += f"Overall Threat Level: {case_file.get('overall_threat_level', 'NORMAL')}\n"
        prompt += f"Statistical AI Score: {case_file.get('max_statistical_score', 0)}\n"
        prompt += f"Sequential (Markov) AI Score: {case_file.get('max_markov_score', 0)}\n"
        prompt += "</GENERAL_PROFILE>\n\n"

        prompt += "<AI_DETECTION_REASONS>\n"
        stat_reasons = case_file.get('statistical_anomaly_reasons', [])
        seq_reasons = case_file.get('sequential_anomaly_reasons', [])
        if stat_reasons: prompt += f"- Statistical Deviations: {' | '.join(stat_reasons)}\n"
        if seq_reasons: prompt += f"- Behavioral Sequence: {' | '.join(seq_reasons)}\n"
        prompt += f"- Markov Chain Summary: {case_file.get('sequence_chain', '')}\n"
        prompt += "</AI_DETECTION_REASONS>\n\n"

        stats = case_file.get('stats_context', {})
        if stats:
            prompt += "<STATISTICAL_METRICS>\n"
            for feature_name, value in stats.items():
                prompt += f"{feature_name}: {value}\n"
            prompt += "</STATISTICAL_METRICS>\n\n"

        full_timeline = case_file.get('timeline', [])
        if not full_timeline:
            return prompt + "</DATA_CONTEXT>\nNo timeline data available."

        sampled_timeline = self._extract_smart_blast_radius(full_timeline, stat_reasons)

        prompt += f"<TIMELINE_SAMPLES> (Showing {len(sampled_timeline)} critical chronological events)\n"

        for event in sampled_timeline:
            if event.get("event_type") == "COMPRESSED_BULK_ACTION":
                prompt += f"[{event.get('start_time')} -> {event.get('end_time')}] [BULK NOISE] {event.get('count')} automated requests to {event.get('uri_path')} (Status {event.get('status_code')})\n"
            else:
                timestamp = event.get('@timestamp', '')
                method = event.get('http_method', 'GET')
                uri = event.get('uri_path', '/')

                try:
                    status = int(event.get('status_code') or 0)
                except (ValueError, TypeError):
                    status = 0

                if event.get('layer1_flagged'):
                    alerts = ", ".join(event.get('layer1_alerts', []))
                    clean_event = {k: v for k, v in event.items() if k not in ['raw_response_body']}
                    safe_event = self._truncate_event(clean_event)
                    prompt += f"[{timestamp}] [🔥 WAF ALERT: {alerts}] {method} {uri} -> Status: {status}\n"
                    prompt += f"      Payload Context: {json.dumps(safe_event)}\n"
                elif status in [401, 403, 404, 500, 502, 503, 504]:
                    prompt += f"[{timestamp}] [⚠️ ERROR] {method} {uri} -> Status: {status}\n"
                else:
                    body = str(event.get('request_body', ''))
                    log_str = f"[{timestamp}] [INFO] {method} {uri} -> Status: {status}"
                    if body and body != 'None':
                        safe_body = body[:200] + "..." if len(body) > 200 else body
                        log_str += f" | Body: {safe_body}"
                    prompt += log_str + "\n"

        prompt += "</TIMELINE_SAMPLES>\n"
        prompt += "</DATA_CONTEXT>\n\n"
        prompt += "Based on the <DATA_CONTEXT> above, provide your final assessment."

        return prompt

    def _call_openai_compatible(self, url, prompt, model, api_key):
        """
        Executes a synchronous POST request to OpenAI-compatible LLM APIs.
        """
        headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
        if "openrouter" in url:
            headers["HTTP-Referer"] = "https://github.com/your-repo/apt-hunter"
            headers["X-Title"] = "Web Log Anomaly Detection"

        payload = {
            "model": model,
            "messages": [
                {"role": "system",
                 "content": "You are a direct cybersecurity AI. Obey all instructions strictly. Do not invent data."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.05
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
            "generationConfig": {"temperature": 0.05}
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