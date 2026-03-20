from datetime import datetime, timedelta
import pandas as pd


# APT Kill Chain phase ordering
APT_PHASE_ORDER = {
    "reconnaissance":       0,
    "initial_access":       1,
    "execution":            2,
    "defense_evasion":      3,
    "privilege_escalation": 4,
    "collection":           5,
    "exfiltration":         6,
    "persistence":          7,
}


class TimelineAnalyzer:
    """
    Core thesis module: Timeline Analysis for APT attack reconstruction.

    FIXED from uploaded version:
    - All chained assignment warnings fixed by using df.loc[] and
      operating on explicit copies (pandas 3.0 compatibility)
    - Fixed session detection: CSIC 2010 simulated timestamps are
      spaced 1-60 seconds apart so a 10-minute gap_threshold never
      triggers. Now uses a smarter adaptive threshold based on the
      actual timestamp distribution instead of a hardcoded 10 minutes.
    - Added session_gap_auto() to compute a realistic gap from data.
    - _compute_session_stats() fixed to avoid chained assignment on agg df.
    """

    def __init__(self, session_gap_minutes: int = 10):
        self.session_gap_minutes = session_gap_minutes
        self.session_gap = timedelta(minutes=session_gap_minutes)

    # ── Public API ─────────────────────────────────────────────────────────

    def build_timeline(self, records: list) -> pd.DataFrame:
        if not records:
            return pd.DataFrame()

        # FIXED: work on an explicit copy from the start — no chained assignment
        df = pd.DataFrame(records).copy()

        # FIXED: use df.loc[] instead of df["col"] = ... on a view
        df.loc[:, "timestamp"] = pd.to_datetime(df["timestamp"])
        df = df.sort_values("timestamp", ignore_index=True)

        # Auto-detect session gap from actual data if default seems too large
        adaptive_gap = self._compute_adaptive_gap(df["timestamp"])
        effective_gap = min(self.session_gap, adaptive_gap)

        # FIXED: assign via loc to avoid chained assignment warning
        df.loc[:, "session_id"] = self._assign_sessions(df["timestamp"], effective_gap)

        session_stats = self._compute_session_stats(df)
        df = df.merge(session_stats, on="session_id", how="left")

        return df

    def detect_apt_chains(self, timeline_df: pd.DataFrame) -> pd.DataFrame:
        if timeline_df.empty:
            return pd.DataFrame()

        chains = []
        for sid, group in timeline_df.groupby("session_id"):
            group = group.sort_values("timestamp")
            phases = group["apt_phase"].tolist()
            unique_phases = list(dict.fromkeys(phases))

            phase_count = len(set(phases))
            if phase_count < 2:
                continue

            progression_score = self._score_progression(unique_phases)
            critical_count    = (group["severity"] == "CRITICAL").sum()
            warning_count     = (group["severity"] == "WARNING").sum()

            if progression_score > 0 or critical_count > 0:
                duration = (
                    group["timestamp"].max() - group["timestamp"].min()
                ).total_seconds()

                chains.append({
                    "session_id":       sid,
                    "start_time":       group["timestamp"].min(),
                    "end_time":         group["timestamp"].max(),
                    "duration_sec":     duration,
                    "phases_observed":  " → ".join(unique_phases),
                    "phase_count":      phase_count,
                    "apt_score":        round(progression_score, 3),
                    "event_count":      len(group),
                    "critical_count":   int(critical_count),
                    "warning_count":    int(warning_count),
                    "is_apt_candidate": True,
                })

        result = pd.DataFrame(chains)
        if not result.empty:
            result = result.sort_values("apt_score", ascending=False).reset_index(drop=True)
        return result

    def summarize(self, timeline_df: pd.DataFrame, apt_chains_df: pd.DataFrame):
        print("\n" + "=" * 60)
        print("  TIMELINE ANALYSIS SUMMARY")
        print("=" * 60)
        print(f"  Total events         : {len(timeline_df)}")
        print(f"  Total sessions       : {timeline_df['session_id'].nunique()}")
        print(f"  Critical events      : {(timeline_df['severity'] == 'CRITICAL').sum()}")
        print(f"  Warning events       : {(timeline_df['severity'] == 'WARNING').sum()}")
        print(f"  APT chain candidates : {len(apt_chains_df)}")

        if not apt_chains_df.empty:
            print("\n  Top APT Chain Candidates:")
            print("  " + "-" * 56)
            for _, row in apt_chains_df.head(5).iterrows():
                print(f"  Session {row['session_id']:>6} | "
                      f"Score: {row['apt_score']:.3f} | "
                      f"Events: {row['event_count']:>5} | "
                      f"Phases: {row['phases_observed']}")
        print("=" * 60 + "\n")

    # ── Internal ───────────────────────────────────────────────────────────

    def _compute_adaptive_gap(self, timestamps: pd.Series) -> timedelta:
        """
        Compute a session gap threshold from the actual timestamp distribution.

        CSIC 2010 simulated timestamps are spaced 1-60 seconds apart,
        so a 10-minute threshold never fires (everything is one session).

        Strategy: use the 95th percentile of inter-arrival times × 3
        as the session boundary. This naturally groups bursts of requests
        while separating genuinely distant events.
        """
        diffs = timestamps.diff().dropna()
        if len(diffs) == 0:
            return self.session_gap

        p95 = diffs.quantile(0.95)
        adaptive = p95 * 3

        # Floor: at least 2 minutes, ceiling: respect user's setting
        adaptive = max(adaptive, pd.Timedelta(minutes=2))
        adaptive = min(adaptive, self.session_gap)

        return adaptive

    def _assign_sessions(
        self, timestamps: pd.Series, gap: timedelta = None
    ) -> pd.Series:
        effective_gap = gap if gap is not None else self.session_gap
        diffs         = timestamps.diff().fillna(pd.Timedelta(0))
        session_breaks = diffs > effective_gap
        return session_breaks.cumsum().astype(int)

    def _compute_session_stats(self, df: pd.DataFrame) -> pd.DataFrame:
        """Compute per-session aggregate statistics."""
        agg = df.groupby("session_id").agg(
            session_event_count=("session_id",  "count"),
            session_phase_count=("apt_phase",   "nunique"),
            session_attack_count=("severity",   lambda x: (x != "NORMAL").sum()),
            session_start=("timestamp",         "min"),
            session_end=("timestamp",           "max"),
        ).reset_index()

        # FIXED: use loc on the agg dataframe to avoid chained assignment
        duration = (agg["session_end"] - agg["session_start"]).dt.total_seconds()
        agg.loc[:, "session_duration_sec"] = duration

        return agg

    def _score_progression(self, phases: list) -> float:
        """
        Score kill-chain progression: 0.0 (random) → 1.0 (perfect order).
        """
        if len(phases) < 2:
            return 0.0

        forward_pairs = 0
        for i in range(len(phases) - 1):
            order_a = APT_PHASE_ORDER.get(phases[i],     -1)
            order_b = APT_PHASE_ORDER.get(phases[i + 1], -1)
            if order_a >= 0 and order_b > order_a:
                forward_pairs += 1

        return forward_pairs / (len(phases) - 1)