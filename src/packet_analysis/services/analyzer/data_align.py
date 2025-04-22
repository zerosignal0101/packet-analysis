import os.path
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import heapq
from datetime import datetime
from collections import defaultdict
import logging

# Project imports
from src.packet_analysis.utils.path import classify_path

# Logging
logging.basicConfig(level=logging.INFO)  # Ensure logger is configured
logger = logging.getLogger(__name__)


def alignment_two_paths(parquet_production_output: str, parquet_back_output: str, alignment_parquet_file_path: str):
    """
    Aligns packet data from production and back/playback environments based on Path and Query.

    Args:
        parquet_production_output: Path to the production data Parquet file.
        parquet_back_output: Path to the back/playback data Parquet file.
        alignment_parquet_file_path: Path to save the aligned data Parquet file.
    """
    start = datetime.now()
    logger.info("Starting alignment...")
    logger.info(f"Production input: {parquet_production_output}")
    logger.info(f"Back input: {parquet_back_output}")
    logger.info(f"Alignment output: {alignment_parquet_file_path}")

    # --- Configuration ---
    # Max index difference allowed for a potential match
    MAX_INDEX_DIFFERENCE = 1000
    # Max items to check in the back_heap if the first ones don't match the current production item
    MATCH_SEARCH_WINDOW = 1000
    # How often to log progress
    LOG_INTERVAL = 5000

    # --- Step 1: Read Data ---
    try:
        production_df = pd.read_parquet(parquet_production_output)
        back_df = pd.read_parquet(parquet_back_output)
        logger.info(f"Loaded production data ({len(production_df)} rows) and back data ({len(back_df)} rows).")
    except Exception as e:
        logger.error(f"Error reading Parquet files: {e}")
        raise

    # --- Step 2: Prepare Back Data Heap ---
    # Store (Sniff_time, index, row_dict) for efficient searching
    # Using Sniff_time assumes time ordering is somewhat preserved and useful for heap ordering
    back_heap = []
    for idx, row in back_df.iterrows():
        # Ensure Path/Query are strings, handle potential NaN/None from parquet read
        path = row.get('Path', '')
        query = row.get('Query', '')
        path = '' if pd.isna(path) else str(path)
        query = '' if pd.isna(query) else str(query)

        # Convert row to dict once for efficiency
        row_dict = row.to_dict()
        row_dict['Path'] = path  # Store normalized path/query in dict
        row_dict['Query'] = query

        heapq.heappush(back_heap, (row['Sniff_time'], idx, row_dict))
    logger.info(f"Built back data heap with {len(back_heap)} items.")

    # --- Step 3: Initialize Aligned Data Storage ---
    # Using a list of dictionaries is often easier to append to row-by-row
    aligned_rows = []
    # Keep track of matched back indices to avoid reuse (optional, depends on requirement)
    # matched_back_indices = set() # Uncomment if a back packet can only match one production packet

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

        # Ensure Path/Query are strings and handle potential NaN/None
        prod_path = production_row.get('Path', '')
        prod_query = production_row.get('Query', '')
        prod_path = '' if pd.isna(prod_path) else str(prod_path)
        prod_query = '' if pd.isna(prod_query) else str(prod_query)

        match_found = False
        best_match_details = None  # Store (back_sniff_time, back_index, back_row_dict)
        temp_unmatched_back_items = []  # Store items popped but not matched for this prod item

        # Search for a match in the back_heap
        search_attempts = 0
        while back_heap and search_attempts < MATCH_SEARCH_WINDOW:
            back_sniff_time, back_index, back_row_dict = heapq.heappop(back_heap)
            search_attempts += 1

            # --- Matching Criteria ---
            # 1. Check index proximity (optional but helps prune search)
            if abs(production_index - back_index) > MAX_INDEX_DIFFERENCE:
                # This back item is too far from the production item index-wise,
                # Assume it's not a match and discard it permanently from the heap.
                # Adjust this logic if index difference isn't a reliable filter.
                logger.debug(
                    f"Discarding back_index {back_index} (diff > {MAX_INDEX_DIFFERENCE} from prod_index {production_index})")
                continue  # Discard this item and check the next one from heap

            # 2. Check Path and Query match
            if prod_path == back_row_dict['Path'] and prod_query == back_row_dict['Query']:
                # Found a potential match
                # Optional: Check if this back item was already matched
                # if back_index in matched_back_indices:
                #     temp_unmatched_back_items.append((back_sniff_time, back_index, back_row_dict))
                #     continue # Try next item in heap

                match_found = True
                best_match_details = (back_sniff_time, back_index, back_row_dict)
                # matched_back_indices.add(back_index) # Mark as used
                # # Debug
                # logger.debug(
                #     f"Matched Prod[{production_index}] with Back[{back_index}] on Path/Query: {prod_path}?{prod_query}")
                break  # Stop searching for this production item

            else:
                # No match for *this* production item, keep it for potential future matches
                temp_unmatched_back_items.append((back_sniff_time, back_index, back_row_dict))

        # Push back the temporarily popped, non-matching items
        for item in temp_unmatched_back_items:
            heapq.heappush(back_heap, item)

        # --- Prepare data row for appending ---
        row_data = {
            'No': production_row['No'],
            'Path': prod_path,
            'Query': prod_query,
            'Src_Port': production_row['Src_Port'],
            'Request_Method': production_row['Request_Method'],
            'Request_type': classify_path(prod_path),  # Classify based on production path

            # Production Data
            'Production_Sniff_time': production_row['Sniff_time'],
            'Production_Relative_time': production_row['Relative_time'],
            'Production_Time_since_request': production_row['Time_since_request'],
            'Production_Processing_delay': production_row['Processing_delay'],
            'Production_Transmission_delay': production_row['Transmission_delay'],
            'Production_Request_Packet_Length': production_row['Request_Packet_Length'],
            'Production_Response_Packet_Length': production_row['Response_Packet_Length'],
            'Production_Response_Total_Length': production_row['Response_Total_Length'],
            'Production_Is_zero_window': production_row['Is_zero_window'],
            'Production_Is_tcp_reset': production_row['Is_tcp_reset'],
            'Production_Response_Code': production_row['Response_code'],
            'Production_Src_Ip': production_row['Ip_src'],
            'Production_Dst_Ip': production_row['Ip_dst'],
        }

        if match_found:
            match_count += 1
            back_sniff_time, back_index, back_row_dict = best_match_details

            # Calculate Time_since_request_ratio
            prod_tsr = production_row['Time_since_request'].total_seconds()
            back_tsr = back_row_dict['Time_since_request'].total_seconds()
            time_since_request_ratio = np.nan  # Default to NaN
            if pd.notna(prod_tsr) and pd.notna(back_tsr):
                if prod_tsr > 1e-9:  # Avoid division by zero or near-zero
                    time_since_request_ratio = back_tsr / prod_tsr
                elif back_tsr > 1e-9:  # Production was zero, back was not
                    time_since_request_ratio = np.inf  # Or keep NaN, depending on desired meaning
                else:  # Both are zero or very small
                    time_since_request_ratio = 1.0  # Or NaN, depending on meaning

            # Add Back Data
            row_data.update({
                'Back_Sniff_time': back_sniff_time,
                'Back_Relative_time': back_row_dict['Relative_time'],
                'Back_Time_since_request': back_row_dict['Time_since_request'],
                'Back_Processing_delay': back_row_dict['Processing_delay'],
                'Back_Transmission_delay': back_row_dict['Transmission_delay'],
                'Back_Request_Packet_Length': back_row_dict['Request_Packet_Length'],
                'Back_Response_Packet_Length': back_row_dict['Response_Packet_Length'],
                'Back_Response_Total_Length': back_row_dict['Response_Total_Length'],
                'Back_Is_zero_window': back_row_dict['Is_zero_window'],
                'Back_Is_tcp_reset': back_row_dict['Is_tcp_reset'],
                'Back_Response_Code': back_row_dict['Response_code'],
                'Back_Src_Ip': back_row_dict['Ip_src'],
                'Back_Dst_Ip': back_row_dict['Ip_dst'],
                'Time_since_request_ratio': time_since_request_ratio,
                'Index_diff': production_index - back_index,
                'state': 'success'
            })
        else:
            no_match_count += 1
            # Add Null Placeholders for Back Data using None/np.nan
            row_data.update({
                'Back_Sniff_time': None,  # Use None for missing values
                'Back_Relative_time': np.nan,  # np.nan for float columns
                'Back_Time_since_request': np.nan,
                'Back_Processing_delay': np.nan,
                'Back_Transmission_delay': np.nan,
                'Back_Request_Packet_Length': np.nan,  # Assuming these are numeric
                'Back_Response_Packet_Length': np.nan,
                'Back_Response_Total_Length': np.nan,
                'Back_Is_zero_window': None,  # Use None for boolean/int, pandas handles this
                'Back_Is_tcp_reset': None,
                'Back_Response_Code': None,  # Use None if it can be string or int
                'Back_Src_Ip': None,  # Use None for missing strings
                'Back_Dst_Ip': None,
                'Time_since_request_ratio': np.nan,
                'Index_diff': None,  # Use None for missing int
                'state': 'failed'
            })

        aligned_rows.append(row_data)

    logger.info(f"Finished processing {processed_count} production items.")
    logger.info(f"Alignment results: Success={match_count}, Failed={no_match_count}")
    logger.info(f"Remaining items in back_heap: {len(back_heap)}")  # Log unused back items

    # --- Step 5: Save Aligned Data ---
    if not aligned_rows:
        logger.warning("No aligned data generated.")
        # Optionally create an empty parquet file with schema or just return
        # Define schema based on expected types if creating empty file
        # schema = pa.schema([...])
        # empty_table = pa.Table.from_pylist([], schema=schema)
        # pq.write_table(empty_table, alignment_parquet_file_path, compression='snappy')
        end = datetime.now()
        logger.info(f"Alignment module total time: {end - start}")
        return  # Exit if nothing to save

    try:
        # Create DataFrame from the list of dictionaries
        aligned_df = pd.DataFrame(aligned_rows)
        logger.info("Created aligned DataFrame.")

        # Optional: Explicitly define schema for PyArrow for robustness
        # schema = pa.schema([
        #     pa.field('No', pa.int64()),
        #     pa.field('Path', pa.string()),
        #     pa.field('Query', pa.string()),
        #     # ... define all fields with appropriate nullable types ...
        #     pa.field('Back_Sniff_time', pa.timestamp('us')), # Example: specify type
        #     pa.field('Back_Relative_time', pa.float64()),
        #     # ...
        #     pa.field('state', pa.string())
        # ])
        # table = pa.Table.from_pandas(aligned_df, schema=schema, preserve_index=False)

        # Let PyArrow infer schema (should work correctly with None/np.nan)
        table = pa.Table.from_pandas(aligned_df, preserve_index=False)
        logger.info("Converted DataFrame to Arrow Table.")

        pq.write_table(table, alignment_parquet_file_path, compression='snappy')
        logger.info(f"Aligned data saved successfully to: {alignment_parquet_file_path}")

    except pa.ArrowTypeError as e:
        logger.error(f"ArrowTypeError during conversion or saving: {e}")
        logger.error("This might indicate inconsistent data types persisted despite using None/NaN.")
        # Add debugging: print dtypes and head of failing column
        col_name = str(e).split("'")[1]  # Attempt to get column name from error
        if col_name in aligned_df.columns:
            logger.error(f"Data types of column '{col_name}':\n{aligned_df[col_name].apply(type).value_counts()}")
            logger.error(f"Head of column '{col_name}':\n{aligned_df[col_name].head(20)}")
        raise
    except Exception as e:
        logger.error(f"Error saving aligned data to Parquet: {e}")
        raise

    # --- Timing ---
    end = datetime.now()
    logger.info(f"Alignment module total time: {end - start}")

    return aligned_df

# Example usage (remove or guard with if __name__ == '__main__':)
# if __name__ == '__main__':
#     # Create dummy data for testing if needed
#     # ... (code to create dummy parquet files) ...
#     print("Running alignment directly (example usage - replace paths)")
#     alignment_two_paths(
#         'path/to/production_output.parquet',
#         'path/to/back_output.parquet',
#         'path/to/aligned_output.parquet'
#     )
