import pandas as pd
import numpy as np

class FeatureEngineer:

    @staticmethod
    def add_ratio_features(df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()

        raw_packets = df["Packets"]
        raw_bytes = df["Bytes"]

        df["byte_ratio"] = np.log1p(df["Bytes Sent"]) - np.log1p(df["Bytes Received"])
        df["packet_ratio"] = np.log1p(df["pkts_sent"]) - np.log1p(df["pkts_received"])

        df["bytes_per_packet"] = np.log1p(raw_bytes / (raw_packets + 1))
        df["connection_intensity"] = np.log1p(raw_packets / (df["Elapsed Time (sec)"] + 1))

        df["Bytes"] = np.log1p(raw_bytes)
        df["Packets"] = np.log1p(raw_packets)
        df["Elapsed Time (sec)"] = np.log1p(df["Elapsed Time (sec)"])

        df["byte_rate"] = np.log1p(
            raw_bytes / (df["Elapsed Time (sec)"] + 1)
        )

        return df