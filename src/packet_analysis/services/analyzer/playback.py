import os
from typing import List, Dict, Any
import logging
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from pathlib import Path

# Project imports
from src.packet_analysis.config import Config
from src.packet_analysis.services.analyzer.general import general_data_analyzer
from src.packet_analysis.services.pcap_extractor import PARQUET_COLUMNS


def analyze_playback_data(results: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
    """
    - Process raw playback packet data
    - Extract relevant metrics and statistics
    - Return analyzed results
    """
    parquet_file_path = results[0]
    sorted_df = pd.read_parquet(parquet_file_path, columns=PARQUET_COLUMNS)
    # 添加 'No' 列，从 1 开始的序号
    sorted_df.insert(0, 'No', range(1, len(sorted_df) + 1))

    # 若为空表跳过处理
    if sorted_df.empty:
        pass
    else:
        # 获取第一个Sniff_time的时间戳
        first_sniff_time = sorted_df['Sniff_time'].iloc[0]

        # 计算每个Sniff_time相对于第一个Sniff_time的相对时间（以秒为单位）
        sorted_df['Relative_time'] = (sorted_df['Sniff_time'] - first_sniff_time).dt.total_seconds()

    # Write parquet file
    Path(options['task_result_path']).mkdir(parents=True, exist_ok=True)
    result_parquet_file_path = os.path.join(
        options['task_result_path'],
        f"extracted_data_{options['pcap_info_idx']}_playback.parquet"
    )
    table = pa.Table.from_pandas(sorted_df, preserve_index=False)
    pq.write_table(table, result_parquet_file_path, compression='snappy')

    general_analysis_result = general_data_analyzer(sorted_df, options)

    return {
        "parquet_file_path": result_parquet_file_path,
        "general_analysis_result": general_analysis_result,
    }
