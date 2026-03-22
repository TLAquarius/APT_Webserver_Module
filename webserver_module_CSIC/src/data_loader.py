import re
from datetime import datetime, timedelta
import random


# CSIC 2010 dataset structure:
#   normalTrafficTraining.txt  → label 0  (normal, used for training)
#   normalTrafficTest.txt      → label 0  (normal, used for testing)
#   anomalousTrafficTest.txt   → label 1  (attacks, used for testing)
#
# Pass label=0 when loading normal files, label=1 for the attack file.

HTTP_METHODS = ("GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ")


class CSICDataLoader:
    """
    Loads raw HTTP request blocks from a CSIC 2010 text file.

    Each record returned is a dict:
        {
            "raw":       str,   # the full raw HTTP request text
            "label":     int,   # 0 = normal, 1 = attack  (-1 = unknown)
            "timestamp": datetime  # simulated timestamp (CSIC has none)
        }
    """

    def __init__(self, file_path: str):
        self.file_path = file_path

    # ------------------------------------------------------------------ #

    def load_raw_requests(
        self,
        label: int = -1,
        limit: int = None,
        seed: int = 42,
    ) -> list[dict]:
        """
        Parameters
        ----------
        label   : 0 for normal traffic files, 1 for anomalous traffic file,
                  -1 if unknown (will still load, just unlabeled).
        limit   : cap the number of records returned (useful for quick tests).
        seed    : random seed for reproducible timestamp simulation.
        """
        raw_blocks = self._split_into_blocks()

        if limit:
            raw_blocks = raw_blocks[:limit]

        timestamps = self._simulate_timestamps(len(raw_blocks), seed=seed)

        records = []
        for raw, ts in zip(raw_blocks, timestamps):
            records.append({
                "raw":       raw,
                "label":     label,
                "timestamp": ts,
            })

        return records

    # ------------------------------------------------------------------ #

    def _split_into_blocks(self) -> list[str]:
        """
        Split the file into individual HTTP request strings.
        A new request is detected when a line starts with an HTTP method.
        Uses errors="replace" so encoded attack bytes are never silently lost.
        """
        blocks = []
        current: list[str] = []

        with open(self.file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if line.startswith(HTTP_METHODS):
                    if current:
                        blocks.append("".join(current))
                    current = [line]
                else:
                    current.append(line)

        if current:
            blocks.append("".join(current))

        return blocks

    def _simulate_timestamps(
        self, n: int, seed: int = 42
    ) -> list[datetime]:
        """
        CSIC 2010 has no real timestamps. We simulate a realistic distribution:
        - Requests arrive over several days
        - Inter-arrival time is random (1–60 seconds), mimicking HTTP browsing
        """
        rng = random.Random(seed)
        base = datetime(2010, 6, 1, 8, 0, 0)
        timestamps = []
        current = base
        for _ in range(n):
            timestamps.append(current)
            current += timedelta(seconds=rng.randint(1, 60))
        return timestamps
