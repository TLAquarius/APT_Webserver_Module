import json
import os
import collections


class AITPipelineEvaluator:
    """
    Line-by-Line deterministic evaluator for the AIT Dataset.
    Tracks False Positives, True Positives, and aggregates False Negatives.
    """

    def __init__(self):
        # Dictionary format: {("host_name", "log_type", line_number): ["list", "of", "labels"]}
        self.ground_truth = {}

        self.results = {
            "Total_Logs_Evaluated": 0,
            "Total_Alerts_Fired": 0,
            "True_Positives": 0,
            "False_Positives": 0,
            "False_Negatives": 0,  # NEW: Explicitly tracking missed attacks
            "L1_Caught_Webshell": 0,
            "Deferred_to_Layer2": 0
        }

        # Detailed tracking lists
        self.false_positives_details = []
        self.true_positives_details = []
        self.deferred_label_counter = collections.Counter()

    def load_ait_labels(self, base_label_dir):
        """Recursively scans the label directory and maps exact line numbers."""
        print(f"[*] Scanning AIT Labels in: {base_label_dir}")
        loaded_count = 0

        for root, dirs, files in os.walk(base_label_dir):
            for filename in files:
                # FIX: Safely determine the log type regardless of how the label file is named
                if "access" in filename:
                    log_type = "access.log"
                elif "error" in filename:
                    log_type = "error.log"
                else:
                    continue

                filepath = os.path.join(root, filename)

                host_name = "unknown"
                if "intranet_server" in filepath:
                    host_name = "intranet_server"
                elif "webserver" in filepath:
                    host_name = "webserver"
                elif "cloud_share" in filepath:
                    host_name = "cloud_share"

                with open(filepath, 'r', encoding='utf-8') as f:
                    for line in f:
                        if not line.strip(): continue
                        try:
                            data = json.loads(line)
                            line_num = data.get("line")
                            labels = data.get("labels", [])

                            # Use the normalized log_type instead of the literal filename
                            self.ground_truth[(host_name, log_type, line_num)] = labels
                            loaded_count += 1
                        except Exception:
                            pass

        print(f"[+] Successfully loaded {loaded_count:,} exact attack lines from Ground Truth.")

    def _parse_event_id(self, event_id):
        """Extracts the line number and normalizes the log type from the parser's event_id."""
        try:
            parts = event_id.rsplit('_', 1)
            line_num = int(parts[1])

            # FIX: Normalize to match the ground truth dictionary keys
            log_type = "access.log" if "acc_" in event_id else "error.log"
            return log_type, line_num
        except Exception:
            return None, None

    def evaluate_layer1(self, layer1_json_path):
        print(f"\n[*] Cross-Referencing Layer 1 Output: {layer1_json_path}")

        with open(layer1_json_path, 'r', encoding='utf-8') as f:
            for line in f:
                if not line.strip(): continue
                self.results["Total_Logs_Evaluated"] += 1

                record = json.loads(line)

                host_name = record.get('host_name')
                event_id = record.get('event_id')
                log_type, line_num = self._parse_event_id(event_id)

                is_flagged_by_l1 = record.get('layer1_flagged', False)
                l1_alerts_triggered = record.get('layer1_alerts', [])

                # Check Ground Truth using the normalized keys
                is_actual_attack = (host_name, log_type, line_num) in self.ground_truth
                attack_labels = self.ground_truth.get((host_name, log_type, line_num), [])

                # Create a clean URI for reporting
                uri = f"{record.get('uri_path', '')}?{record.get('uri_query', '')}"

                if is_flagged_by_l1:
                    self.results["Total_Alerts_Fired"] += 1

                    if is_actual_attack:
                        self.results["True_Positives"] += 1
                        if "webshell_cmd" in attack_labels or "foothold" in attack_labels:
                            self.results["L1_Caught_Webshell"] += 1

                        # Store a few TP details just to verify
                        if len(self.true_positives_details) < 10:
                            self.true_positives_details.append({
                                "labels": attack_labels,
                                "l1_tags": l1_alerts_triggered,
                                "uri": uri,
                                "raw": record.get('raw_message', '')[:50]  # Snippet for verification
                            })
                    else:
                        self.results["False_Positives"] += 1
                        # Store ALL False Positives so we can fix the WAF engine
                        self.false_positives_details.append({
                            "host": host_name,
                            "ip": record.get('source_ip'),
                            "l1_tags": l1_alerts_triggered,
                            "uri": uri,
                            "ua": record.get('user_agent', '')
                        })

                else:  # Layer 1 did NOT flag this
                    if is_actual_attack:
                        self.results["False_Negatives"] += 1
                        self.results["Deferred_to_Layer2"] += 1
                        # Count what kind of attacks we are deferring
                        for label in attack_labels:
                            self.deferred_label_counter[label] += 1

    def print_report(self):
        total = self.results["Total_Logs_Evaluated"]
        flagged = self.results["Total_Alerts_Fired"]
        tp = self.results["True_Positives"]
        fp = self.results["False_Positives"]
        fn = self.results["False_Negatives"]
        deferred = self.results["Deferred_to_Layer2"]
        l1_critical = self.results["L1_Caught_Webshell"]

        precision = (tp / flagged * 100) if flagged > 0 else 0
        recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0

        print("\n" + "=" * 60)
        print(" LAYER 1: EXACT LINE-BY-LINE EVALUATION")
        print("=" * 60)
        print(f"Total Logs Evaluated       : {total:,}")
        print(f"Total Alerts Fired (L1)    : {flagged:,}")
        print("-" * 60)
        print(f"TRUE POSITIVES (Matches)   : {tp:,}")
        print(f"  -> Caught Web Shell / RCE: {l1_critical:,}")
        print(f"FALSE POSITIVES (Noise)    : {fp:,}")
        print(f"FALSE NEGATIVES (Missed)   : {fn:,}")
        print("-" * 60)
        print(f"LAYER 1 PRECISION          : {precision:.2f}% (How often alerts are real attacks)")
        print(f"LAYER 1 RECALL             : {recall:.2f}% (How many total attacks L1 caught)")

        print("\n=== THE 25 FALSE POSITIVES (Why did L1 fail?) ===")
        if not self.false_positives_details:
            print("  None! Perfect Precision.")
        else:
            for i, fp_log in enumerate(self.false_positives_details[:25]):  # Print up to 25 FPs
                print(f"  [{i + 1}] Tagged as {fp_log['l1_tags']} | IP: {fp_log['ip']}")
                print(f"      URI: {fp_log['uri']}")
                print(f"      UA : {fp_log['ua']}\n")

        print("\n=== LAYER 2 HANDOFF EXPECTATION ===")
        print(f"Logs deferred to Layer 2   : {deferred:,}")
        print("Breakdown of missed attacks (What Layer 2 must catch):")
        for label, count in self.deferred_label_counter.most_common(15):
            print(f"  -> {label}: {count:,} events missed by L1")

        print("\n=== SAMPLE TRUE POSITIVES (L1 Success) ===")
        for tp_log in self.true_positives_details[:3]:
            print(f"  [+] Ground Truth: {tp_log['labels']} -> L1 Tagged: {tp_log['l1_tags']}")
            print(f"      URI: {tp_log['uri']}")
            print(f"      RAW: {tp_log['raw']}...\n")
        print("=" * 60)


if __name__ == "__main__":
    # 1. Point to your master labels directory
    LABEL_DIR = r"D:\Download\Do_an_tot_nghiep\dataset\russellmitchell\labels"

    # 2. Point to your Unified Engine output
    L1_OUTPUT = "layer1_tagged_timeline.json"

    evaluator = AITPipelineEvaluator()

    if os.path.exists(LABEL_DIR):
        evaluator.load_ait_labels(LABEL_DIR)
        evaluator.evaluate_layer1(L1_OUTPUT)
        evaluator.print_report()
    else:
        print(f"[-] Label directory not found: {LABEL_DIR}")