import os.path
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import heapq
from datetime import datetime
from collections import defaultdict
import logging

# Project imports - ensure this path is correct relative to where the script runs
from src.packet_analysis.utils.path import classify_path

# Logging
logger = logging.getLogger(__name__)

# --- Define the guaranteed output schema ---
# Using pandas nullable dtypes where appropriate (requires pandas >= 1.0)
# Use 'float64' for numeric columns that can have NaN (like delays, lengths, ratios)
# Use 'string' (pandas StringDtype) for text that can be missing
# Use 'boolean' for True/False/NA
# Use 'Int64' (pandas Int64Dtype) for integers that can be missing
# Adjust dtypes based on your actual data needs (e.g., float32?, specific timestamp?)
ALIGNED_SCHEMA = {
    'No': pd.Int64Dtype(),
    'Path': 'string',
    'Query': 'string',
    'Src_Port': pd.Int64Dtype(),
    'Request_Method': 'string',
    # Production
    'Production_Sniff_time': 'datetime64[ns]',  # Changed to datetime type
    'Production_Relative_time': 'timedelta64[ns]',  # Changed to timedelta
    'Production_Time_since_request': 'timedelta64[ns]',  # Changed to timedelta
    'Production_Processing_delay': 'timedelta64[ns]',  # Changed to timedelta
    'Production_Transmission_delay': 'timedelta64[ns]',  # Changed to timedelta
    'Production_Request_Packet_Length': pd.Int64Dtype(),
    'Production_Response_Packet_Length': pd.Int64Dtype(),
    'Production_Response_Total_Length': pd.Int64Dtype(),
    'Production_Is_zero_window': 'boolean',
    'Production_Is_tcp_reset': 'boolean',
    'Production_Response_Code': pd.Int64Dtype(),
    'Production_Src_Ip': 'string',
    'Production_Dst_Ip': 'string',
    # Back
    'Back_Sniff_time': 'datetime64[ns]',  # Changed to datetime type
    'Back_Relative_time': 'timedelta64[ns]',  # Changed to timedelta
    'Back_Time_since_request': 'timedelta64[ns]',  # Changed to timedelta
    'Back_Processing_delay': 'timedelta64[ns]',  # Changed to timedelta
    'Back_Transmission_delay': 'timedelta64[ns]',  # Changed to timedelta
    'Back_Request_Packet_Length': pd.Int64Dtype(),
    'Back_Response_Packet_Length': pd.Int64Dtype(),
    'Back_Response_Total_Length': pd.Int64Dtype(),
    'Back_Is_zero_window': 'boolean',
    'Back_Is_tcp_reset': 'boolean',
    'Back_Response_Code': pd.Int64Dtype(),
    'Back_Src_Ip': 'string',
    'Back_Dst_Ip': 'string',
    # Analysis
    'Request_type': 'string',
    'Time_since_request_ratio': 'float64',
    'Index_diff': pd.Int64Dtype(),
    'state': 'string'
}


def get_default_value(dtype):
    """根据目标类型返回适当的缺失值"""
    if pd.api.types.is_float_dtype(dtype):
        return np.nan
    elif pd.api.types.is_datetime64_dtype(dtype):
        return pd.NaT
    elif pd.api.types.is_timedelta64_dtype(dtype):
        return pd.NaT
    elif pd.api.types.is_integer_dtype(dtype):
        return pd.NA
    elif pd.api.types.is_bool_dtype(dtype):
        return pd.NA
    elif pd.api.types.is_string_dtype(dtype):
        return pd.NA
    else:
        return pd.NA


def alignment_two_paths(parquet_production_output: str, parquet_back_output: str,
                        alignment_parquet_file_path: str = None) -> pd.DataFrame:
    """
    Aligns packet data from production and back/playback environments based on Path and Query.

    Args:
        parquet_production_output: Path to the production data Parquet file.
        parquet_back_output: Path to the back/playback data Parquet file.
        alignment_parquet_file_path: Optional path to save the aligned data Parquet file.
                                     If None, the file is not saved.

    Returns:
        pandas.DataFrame: A DataFrame containing the aligned data, conforming to
                          the ALIGNED_SCHEMA. Will have the defined columns even if empty.
    """
    start = datetime.now()
    logger.info("Starting alignment...")
    logger.info(f"Production input: {parquet_production_output}")
    logger.info(f"Back input: {parquet_back_output}")
    if alignment_parquet_file_path:
        logger.info(f"Alignment output (file): {alignment_parquet_file_path}")
    else:
        logger.info("Alignment output will be returned as DataFrame only (no file saved).")

    # --- Configuration ---
    MAX_INDEX_DIFFERENCE = 1000
    MATCH_SEARCH_WINDOW = 1000
    LOG_INTERVAL = 5000

    # --- Step 1: Read Data ---
    try:
        production_df = pd.read_parquet(parquet_production_output)
        back_df = pd.read_parquet(parquet_back_output)
        logger.info(f"Loaded production data ({len(production_df)} rows) and back data ({len(back_df)} rows).")
    except Exception as e:
        logger.error(f"Error reading Parquet files: {e}")
        # Return an empty DataFrame conforming to the schema on read error
        empty_df = pd.DataFrame(columns=ALIGNED_SCHEMA.keys()).astype(ALIGNED_SCHEMA)
        return empty_df  # Return empty df consistent with schema

    # --- Step 2: Prepare Back Data Heap ---
    back_heap = []
    for idx, row in back_df.iterrows():
        path = row.get('Path', '')
        query = row.get('Query', '')
        path = '' if pd.isna(path) else str(path)
        query = '' if pd.isna(query) else str(query)
        row_dict = row.to_dict()
        row_dict['Path'] = path
        row_dict['Query'] = query
        # Use pd.NA for missing values where appropriate if source might have them
        # Ensure numeric fields expected later are actually numeric or None/NaN
        for col, dtype in ALIGNED_SCHEMA.items():
            if col.startswith('Back_') and col in row_dict:
                if pd.isna(row_dict[col]):
                    # Convert recognized nulls to appropriate type for schema
                    if pd.api.types.is_integer_dtype(dtype) or \
                            pd.api.types.is_bool_dtype(dtype) or \
                            pd.api.types.is_string_dtype(dtype):
                        row_dict[col] = pd.NA
                    elif pd.api.types.is_float_dtype(dtype):
                        row_dict[col] = np.nan
                # Optional: Add type checks/conversions here if source parquet dtypes are unreliable

        heapq.heappush(back_heap, (row['Sniff_time'], idx, row_dict))
    logger.info(f"Built back data heap with {len(back_heap)} items.")

    # --- Step 3: Initialize Aligned Data Storage ---
    aligned_rows = []

    # --- Step 4: Align Data ---
    processed_count = 0
    match_count = 0
    no_match_count = 0

    for production_index, production_row in production_df.iterrows():
        processed_count += 1
        if processed_count % LOG_INTERVAL == 0:
            elapsed = (datetime.now() - start).total_seconds()
            rate = processed_count / elapsed if elapsed > 0 else 0
            logger.info(
                f"Processing production index: {production_index} ({processed_count}/{len(production_df)}). Rate: {rate:.2f} items/sec.")

        prod_path = production_row.get('Path', '')
        prod_query = production_row.get('Query', '')
        prod_path = '' if pd.isna(prod_path) else str(prod_path)
        prod_query = '' if pd.isna(prod_query) else str(prod_query)

        match_found = False
        best_match_details = None
        temp_unmatched_back_items = []

        search_attempts = 0
        while back_heap and search_attempts < MATCH_SEARCH_WINDOW:
            back_sniff_time, back_index, back_row_dict = heapq.heappop(back_heap)
            search_attempts += 1

            if abs(production_index - back_index) > MAX_INDEX_DIFFERENCE:
                # logger.debug(f"Discarding back_index {back_index} (diff > {MAX_INDEX_DIFFERENCE} from prod_index {production_index})")
                continue

            if prod_path == back_row_dict['Path'] and prod_query == back_row_dict['Query']:
                match_found = True
                best_match_details = (back_sniff_time, back_index, back_row_dict)
                # logger.debug(f"Matched Prod[{production_index}] with Back[{back_index}] on Path/Query: {prod_path}?{prod_query}")
                break
            else:
                temp_unmatched_back_items.append((back_sniff_time, back_index, back_row_dict))

        for item in temp_unmatched_back_items:
            heapq.heappush(back_heap, item)

        # --- Prepare data row for appending ---
        # Initialize with guaranteed keys and NA/NaN values
        # 修改初始化部分
        row_data = {col: get_default_value(dtype) for col, dtype in ALIGNED_SCHEMA.items()}

        # Fill production data (handle potential missing values in source)
        row_data.update({
            'No': production_row.get('No', pd.NA),
            'Path': prod_path,
            'Query': prod_query,
            'Src_Port': production_row.get('Src_Port', pd.NA),
            'Request_Method': str(production_row.get('Request_Method', '')) if pd.notna(
                production_row.get('Request_Method')) else pd.NA,
            'Request_type': classify_path(prod_path),

            'Production_Sniff_time': pd.to_datetime(production_row.get('Sniff_time')) if pd.notna(production_row.get('Sniff_time')) else pd.NaT,
            'Production_Relative_time': pd.to_timedelta(production_row.get('Relative_time'), unit='ns') if pd.notna(production_row.get('Relative_time')) else pd.NaT,
            'Production_Time_since_request': pd.to_timedelta(production_row.get('Time_since_request'), unit='ns') if pd.notna(production_row.get('Time_since_request')) else pd.NaT,
            'Production_Processing_delay': pd.to_timedelta(production_row.get('Processing_delay'), unit='ns') if pd.notna(production_row.get('Processing_delay')) else pd.NaT,
            'Production_Transmission_delay': pd.to_timedelta(production_row.get('Transmission_delay'), unit='ns') if pd.notna(production_row.get('Transmission_delay')) else pd.NaT,
            'Production_Request_Packet_Length': production_row.get('Request_Packet_Length', pd.NA),
            'Production_Response_Packet_Length': production_row.get('Response_Packet_Length', pd.NA),
            'Production_Response_Total_Length': production_row.get('Response_Total_Length', pd.NA),
            'Production_Is_zero_window': production_row.get('Is_zero_window', pd.NA),
            'Production_Is_tcp_reset': production_row.get('Is_tcp_reset', pd.NA),
            'Production_Response_Code': production_row.get('Response_code', pd.NA),
            'Production_Src_Ip': str(production_row.get('Ip_src', '')) if pd.notna(
                production_row.get('Ip_src')) else pd.NA,
            'Production_Dst_Ip': str(production_row.get('Ip_dst', '')) if pd.notna(
                production_row.get('Ip_dst')) else pd.NA,
        })

        if match_found:
            match_count += 1
            back_sniff_time, back_index, back_row_dict = best_match_details

            prod_tsr = row_data['Production_Time_since_request']  # Use already extracted value
            back_tsr = back_row_dict.get('Time_since_request', np.nan)
            time_since_request_ratio = np.nan
            # Ensure both are valid numbers before dividing
            if pd.notna(prod_tsr) and pd.notna(back_tsr) and isinstance(prod_tsr, (int, float)) and isinstance(back_tsr,
                                                                                                               (int,
                                                                                                                float)):
                if abs(prod_tsr) > 1e-9:
                    time_since_request_ratio = back_tsr / prod_tsr
                elif abs(back_tsr) > 1e-9:
                    time_since_request_ratio = 999999
                else:
                    time_since_request_ratio = 1.0  # Or np.nan if 0/0 should be NaN

            # Update row_data with Back Data
            row_data.update({
                'Back_Sniff_time': back_row_dict.get('Sniff_time', np.nan),
                'Back_Relative_time': back_row_dict.get('Relative_time', np.nan),
                'Back_Time_since_request': back_tsr,
                'Back_Processing_delay': back_row_dict.get('Processing_delay', np.nan),
                'Back_Transmission_delay': back_row_dict.get('Transmission_delay', np.nan),
                'Back_Request_Packet_Length': back_row_dict.get('Request_Packet_Length', pd.NA),
                'Back_Response_Packet_Length': back_row_dict.get('Response_Packet_Length', pd.NA),
                'Back_Response_Total_Length': back_row_dict.get('Response_Total_Length', pd.NA),
                'Back_Is_zero_window': back_row_dict.get('Is_zero_window', pd.NA),
                'Back_Is_tcp_reset': back_row_dict.get('Is_tcp_reset', pd.NA),
                'Back_Response_Code': back_row_dict.get('Response_code', pd.NA),
                'Back_Src_Ip': str(back_row_dict.get('Ip_src', '')) if pd.notna(back_row_dict.get('Ip_src')) else pd.NA,
                'Back_Dst_Ip': str(back_row_dict.get('Ip_dst', '')) if pd.notna(back_row_dict.get('Ip_dst')) else pd.NA,

                'Time_since_request_ratio': time_since_request_ratio,
                'Index_diff': production_index - back_index,
                'state': 'success'
            })
        else:
            no_match_count += 1
            # Back_* fields already initialized to NA/NaN
            # Update only state and potentially Index_diff/Ratio if applicable
            row_data['state'] = 'failed'
            # Index_diff and Time_since_request_ratio remain NA/NaN as initialized

        aligned_rows.append(row_data)

    logger.info(f"Finished processing {processed_count} production items.")
    logger.info(f"Alignment results: Success={match_count}, Failed={no_match_count}")
    logger.info(f"Remaining items in back_heap: {len(back_heap)}")

    # --- Step 5: Create Final DataFrame with Guaranteed Schema ---
    if not aligned_rows:
        logger.warning("No aligned data generated. Returning empty DataFrame with defined schema.")
        # Create empty DataFrame directly with the schema
        aligned_df = pd.DataFrame(columns=ALIGNED_SCHEMA.keys()).astype(ALIGNED_SCHEMA)
    else:
        try:
            # Create DataFrame from the list of dictionaries
            aligned_df = pd.DataFrame(aligned_rows)
            logger.info(f"Created aligned DataFrame with {len(aligned_df)} rows.")

            # Ensure all columns exist and enforce schema types
            # Reindex first to add any potentially missing columns (filled with NA/NaN)
            aligned_df = aligned_df.reindex(columns=ALIGNED_SCHEMA.keys())
            # Then cast to the desired types
            aligned_df = aligned_df.astype(ALIGNED_SCHEMA)
            logger.info("DataFrame schema enforced.")

        except Exception as e:
            logger.error(f"Error creating or casting DataFrame: {e}", exc_info=True)
            logger.error("Returning empty DataFrame with defined schema due to error.")
            aligned_df = pd.DataFrame(columns=ALIGNED_SCHEMA.keys()).astype(ALIGNED_SCHEMA)

    # --- Step 6: Save Aligned Data (Optional) ---
    if alignment_parquet_file_path and not aligned_df.empty:  # Avoid saving empty files unless required
        try:
            logger.info("Converting DataFrame to Arrow Table for saving...")
            # PyArrow should handle the pandas nullable types correctly
            table = pa.Table.from_pandas(aligned_df, preserve_index=False)
            pq.write_table(table, alignment_parquet_file_path, compression='snappy')
            logger.info(f"Aligned data saved successfully to: {alignment_parquet_file_path}")
        except Exception as e:
            # Log error but continue to return the DataFrame
            logger.error(f"Error saving aligned data to Parquet: {e}")
            # Optionally: Log column types if ArrowTypeError occurs
            if isinstance(e, pa.ArrowTypeError):
                try:
                    col_name = str(e).split("'")[1]  # Attempt to get column name
                    if col_name in aligned_df.columns:
                        logger.error(
                            f"Data types of problematic column '{col_name}':\n{aligned_df[col_name].apply(type).value_counts()}")
                        logger.error(f"Head of column '{col_name}':\n{aligned_df[col_name].head(20)}")
                except Exception as e_debug:
                    logger.error(f"Could not extract debug info from ArrowTypeError: {e_debug}")

    # --- Timing & Return ---
    end = datetime.now()
    logger.info(f"Alignment module total time: {end - start}")

    # --- Step 7: Return DataFrame ---
    return aligned_df

# Example usage (remove or guard with if __name__ == '__main__':)
# if __name__ == '__main__':
#     print("Running alignment directly (example usage - replace paths)")
#     # Example 1: Save to file and get DataFrame
#     df_result = alignment_two_paths(
#         'path/to/production_output.parquet',
#         'path/to/back_output.parquet',
#         'path/to/aligned_output.parquet' # Provide path to save
#     )
#     print("DataFrame returned (saved to file):")
#     print(df_result.info()) # Show schema and non-null counts

#     # Example 2: Only get DataFrame, don't save file
#     df_result_only = alignment_two_paths(
#         'path/to/production_output.parquet',
#         'path/to/back_output.parquet',
#         None # Pass None to skip saving
#     )
#     print("\nDataFrame returned (not saved to file):")
#     print(df_result_only.info())
