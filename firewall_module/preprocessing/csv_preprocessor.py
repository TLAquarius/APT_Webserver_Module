import pandas as pd
from sklearn.preprocessing import StandardScaler

class CSVPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()

        self.feature_columns = [
            "Source Port",
            "Destination Port",
            "NAT Source Port",
            "NAT Destination Port",
            "Bytes",
            "Bytes Sent",
            "Bytes Received",
            "Packets",
            "Elapsed Time (sec)",
            "pkts_sent",
            "pkts_received",
            "byte_ratio",
            "packet_ratio",
            "bytes_per_packet",
            "connection_intensity",
            "byte_rate"
        ]

    def _basic_cleaning(self, df: pd.DataFrame) -> pd.DataFrame:
        df = df.copy()
        df.columns = df.columns.str.strip()

        drop_cols = [
            "Action",
            "Source IP",
            "Destination IP",
            "SessionID",
            "Timestamp",
            "Label"
        ]

        for col in drop_cols:
            if col in df.columns:
                df = df.drop(columns=[col])

        numeric_cols = df.select_dtypes(include=["int64", "float64"]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0)

        return df

    def fit_transform(self, df: pd.DataFrame):
        df = self._basic_cleaning(df)
    
        X = df[self.feature_columns]
        X_scaled = self.scaler.fit_transform(X)

        return X_scaled

    def transform(self, df: pd.DataFrame):
        df = self._basic_cleaning(df)

        X = df[self.feature_columns]
        X_scaled = self.scaler.transform(X)

        return X_scaled