import os
from typing import List, Dict, Any
import logging
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from pathlib import Path

# Project imports
from src.packet_analysis.config import Config
from src.packet_analysis.services.pcap_extractor import PARQUET_COLUMNS


def analyze_playback_data(results: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
    """
    - Process raw playback packet data
    - Extract relevant metrics and statistics
    - Return analyzed results
    """
    parquet_file_path = results[0]
    sorted_df = pd.read_parquet(parquet_file_path, columns=PARQUET_COLUMNS)

    # Write parquet file
    Path(options['task_result_path']).mkdir(parents=True, exist_ok=True)
    result_parquet_file_path = os.path.join(
        options['task_result_path'],
        f"extracted_data_{options['pcap_info_idx']}_playback.parquet"
    )
    table = pa.Table.from_pandas(sorted_df, preserve_index=False)
    pq.write_table(table, result_parquet_file_path, compression='snappy')
    return {}
