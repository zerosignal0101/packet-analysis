import pandas as pd
import datetime
import json
from scipy.stats import pearsonr
import numpy as np
import logging
import os  # Added for file existence checks
from typing import Dict, List, Any, Optional, Tuple  # Added for type hinting

# Logger
logger = logging.getLogger(__name__)


# 读取KPI映射的函数
def load_kpi_mapping(file_path: str) -> Dict[str, str]:
    """
    Loads KPI number to description mapping from a text file.

    Args:
        file_path: Path to the KPI mapping file.

    Returns:
        A dictionary mapping KPI numbers (str) to descriptions (str).

    Raises:
        FileNotFoundError: If the mapping file does not exist.
        IOError: If there's an error reading the file.
        ValueError: If a line in the file has an invalid format.
    """
    logger.info(f"Attempting to load KPI mapping from: {file_path}")
    if not os.path.exists(file_path):
        logger.error(f"KPI mapping file not found: {file_path}")
        raise FileNotFoundError(f"KPI mapping file not found: {file_path}")

    kpi_mapping = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    # Split only on the first colon
                    parts = line.split(":", 1)
                    if len(parts) != 2:
                        logger.warning(
                            f"Skipping invalid line {line_num} in {file_path}: Incorrect format (expected 'kpi_no: description'). Line content: '{line}'")
                        continue  # Skip lines without exactly one colon
                    kpi_no, description = map(str.strip, parts)
                    if not kpi_no:  # Check if kpi_no is empty after stripping
                        logger.warning(
                            f"Skipping invalid line {line_num} in {file_path}: Empty KPI number. Line content: '{line}'")
                        continue
                    kpi_mapping[kpi_no] = description
                except Exception as e:  # Catch potential errors during split/strip
                    logger.warning(f"Error processing line {line_num} in {file_path}: {e}. Line content: '{line}'")
                    # Decide whether to raise an error or just skip the line
                    # raise ValueError(f"Error processing line {line_num} in {file_path}: {e}") from e
    except IOError as e:
        logger.error(f"IOError reading KPI mapping file {file_path}: {e}")
        raise IOError(f"IOError reading KPI mapping file {file_path}: {e}") from e
    except Exception as e:
        logger.exception(f"An unexpected error occurred while loading KPI mapping from {file_path}")
        raise  # Re-raise unexpected exceptions

    logger.info(f"Successfully loaded {len(kpi_mapping)} KPI mappings from {file_path}.")
    return kpi_mapping


# 将DCTIME转换为可读的时间格式
def convert_dctime(dctime: Any) -> Optional[datetime.datetime]:
    """
    Converts a DCTIME (milliseconds since epoch) to a datetime object.

    Args:
        dctime: The timestamp in milliseconds since the epoch (can be int or str).

    Returns:
        A datetime object or None if conversion fails.
    """
    try:
        # Attempt to convert to float first to handle potential string inputs
        timestamp_ms = float(dctime)
        timestamp_s = timestamp_ms / 1000.0
        # Check for potential out-of-range timestamps for fromtimestamp
        if not (pd.Timestamp.min.timestamp() <= timestamp_s <= pd.Timestamp.max.timestamp()):
            logger.warning(f"DCTIME {dctime} results in an out-of-range timestamp: {timestamp_s}. Skipping conversion.")
            return None
        return datetime.datetime.fromtimestamp(timestamp_s)
    except (ValueError, TypeError, OverflowError) as e:
        logger.error(f"Failed to convert DCTIME '{dctime}' to datetime object: {e}")
        return None


# 提取数据的函数 将日志json格式化成需要的格式
def extract_data(json_data: Dict[str, Any], kpi_mapping: Dict[str, str]) -> List[Dict[str, Any]]:
    """
    Extracts and formats data from the input JSON based on monitor type.

    Args:
        json_data: The loaded JSON data.
        kpi_mapping: The KPI number to description mapping.

    Returns:
        A list of dictionaries, each representing a relevant data point.
        APM data is currently ignored.
    """
    extracted_data = []
    logger.info("Starting data extraction from JSON input.")
    processed_items_count = 0
    skipped_items_count = 0

    for monitor_type, machines in json_data.items():
        if monitor_type in ['server', 'databases']:
            logger.debug(f"Processing monitor_type: {monitor_type}")
            if not isinstance(machines, dict):
                logger.warning(f"Expected dictionary for '{monitor_type}', found {type(machines)}. Skipping.")
                continue
            for machine_type, ips in machines.items():
                if not isinstance(ips, dict):
                    logger.warning(
                        f"Expected dictionary for machine_type '{machine_type}' under '{monitor_type}', found {type(ips)}. Skipping.")
                    continue
                for ip_address, metrics in ips.items():
                    if not isinstance(metrics, dict):
                        logger.warning(
                            f"Expected dictionary for metrics at IP '{ip_address}' under '{machine_type}', found {type(metrics)}. Skipping.")
                        continue
                    for kpi_no, items in metrics.items():
                        if not isinstance(items, list):
                            logger.warning(
                                f"Expected list for items under KPI_NO '{kpi_no}' at IP '{ip_address}', found {type(items)}. Skipping.")
                            continue
                        for item in items:
                            if not isinstance(item, dict):
                                logger.warning(
                                    f"Expected dictionary for item under KPI_NO '{kpi_no}', found {type(item)}. Skipping item: {item}")
                                skipped_items_count += 1
                                continue

                            if 'DCTIME' in item and 'VALUE' in item:
                                dt_object = convert_dctime(item['DCTIME'])
                                if dt_object:
                                    kpi_name = kpi_mapping.get(kpi_no,
                                                               f'未知指标 ({kpi_no})')  # Include kpi_no if unknown
                                    # Attempt to convert VALUE to numeric here to catch errors early
                                    try:
                                        value_numeric = pd.to_numeric(item['VALUE'])
                                        extracted_data.append({
                                            'monitor_type': monitor_type,
                                            'machine_type': machine_type,  # Included for potential future use
                                            'ip_address': ip_address,
                                            'DCTIME': dt_object,  # Store as datetime object
                                            'VALUE': value_numeric,  # Store as numeric
                                            'kpi_no': kpi_no,
                                            'kpi_name': kpi_name
                                        })
                                        processed_items_count += 1
                                    except (ValueError, TypeError) as e:
                                        logger.warning(
                                            f"Could not convert VALUE '{item['VALUE']}' to numeric for KPI {kpi_no} at {ip_address}. Skipping item: {item}. Error: {e}")
                                        skipped_items_count += 1
                                else:
                                    # Error already logged in convert_dctime
                                    skipped_items_count += 1
                            else:
                                logger.warning(
                                    f"Missing 'DCTIME' or 'VALUE' in item under KPI {kpi_no} at {ip_address}. Skipping item: {item}")
                                skipped_items_count += 1
        elif monitor_type == 'apm':
            logger.info("Found 'apm' data, which is currently ignored for correlation analysis.")
            # If APM data needs processing later, add logic here.
            # For now, we explicitly do nothing with it.
            # extracted_data.append({
            #     'monitor_type': monitor_type,
            #     'original_data': machines # Original behavior, but likely not useful
            # })
        else:
            logger.warning(f"Unrecognized top-level monitor_type '{monitor_type}' found in JSON. Skipping.")

    logger.info(
        f"Finished data extraction. Processed {processed_items_count} valid items, skipped {skipped_items_count} items.")
    # The check for empty extracted_data happens in the main function now.
    return extracted_data


def safe_format(value: Optional[float]) -> str:
    """
    Formats a float to 6 decimal places, returning '0.000000' for NaN or None.
    Consider returning an empty string '' or None depending on downstream needs
    if '0.000000' might be misinterpreted as a real zero correlation.
    """
    if value is None or np.isnan(value):
        return "0.000000"
    return "{:.6f}".format(value)


# 计算相关系数的函数
def compute_correlation_for_group(
        kpi_group_data: List[Dict[str, Any]],
        request_data: pd.DataFrame,
        kpi_name: str,
        time_threshold_seconds: int = 10,
        ip_address: Optional[str] = None,
        monitor_type: Optional[str] = None
) -> Tuple[Optional[pd.DataFrame], Optional[float], Optional[str]]:
    """
    Computes correlation for a specific KPI group against request delays.

    Args:
        kpi_group_data: List of dicts for a single KPI group, sorted by time.
        request_data: DataFrame of request data with 'Sniff_time' and 'Time_since_request'.
        kpi_name: Name of the KPI being analyzed.
        time_threshold_seconds: Window size (in seconds) around each KPI point to find matching requests.
        ip_address: IP address associated with this KPI group (used for server filtering).
        monitor_type: Type of monitor ('server', 'databases').

    Returns:
        A tuple containing:
        - DataFrame: Aligned KPI values and mean delays for this group (or None if insufficient data).
        - float: Calculated Pearson correlation coefficient (or None).
        - str: The effective monitor type used for filtering ('server', 'databases', or 'database_server' if fallback occurred).
    """
    aligned_data = []
    time_delta = datetime.timedelta(seconds=time_threshold_seconds)
    effective_monitor_type = monitor_type  # Track potential change for server fallback

    logger.debug(
        f"Computing correlation for KPI: '{kpi_name}', Monitor: {monitor_type}, IP: {ip_address}, Threshold: {time_threshold_seconds}s")

    if 'Sniff_time' not in request_data.columns or 'Time_since_request' not in request_data.columns:
        logger.error("Request data DataFrame must contain 'Sniff_time' and 'Time_since_request' columns.")
        return None, None, effective_monitor_type
    if not pd.api.types.is_datetime64_any_dtype(request_data['Sniff_time']):
        logger.error("'Sniff_time' column in request data must be of datetime type.")
        # Or attempt conversion: request_data['Sniff_time'] = pd.to_datetime(request_data['Sniff_time'], errors='coerce')
        return None, None, effective_monitor_type

    for kpi_point in kpi_group_data:
        kpi_time = kpi_point['DCTIME']
        kpi_value = kpi_point['VALUE']
        start_time = kpi_time - time_delta
        end_time = kpi_time + time_delta

        # --- Filtering Logic ---
        ip_filter_applied = False
        if monitor_type == 'server' and ip_address:
            # Try filtering by destination IP first for server KPIs
            mask = (
                    (request_data['Sniff_time'] >= start_time) &
                    (request_data['Sniff_time'] <= end_time) &
                    (request_data['Ip_dst'] == ip_address)  # Assumes server IP corresponds to Destination IP
            )
            filtered_requests = request_data[mask]
            ip_filter_applied = True
            # --- Server Fallback Logic ---
            # If no requests found using destination IP, try without IP filter.
            # This assumes maybe the server's activity correlates with *any* traffic
            # in that window, possibly database traffic it initiated (where it's src_ip).
            # Renaming to 'database_server' indicates this fallback occurred.
            if filtered_requests.empty:
                # logger.debug(
                #     f"No requests found for server {ip_address} (as Dst IP) in window {start_time}-{end_time}. Trying without IP filter.")
                mask_no_ip = (
                        (request_data['Sniff_time'] >= start_time) &
                        (request_data['Sniff_time'] <= end_time)
                )
                filtered_requests = request_data[mask_no_ip]
                if not filtered_requests.empty:
                    effective_monitor_type = 'database_server'  # Mark that fallback was used
                    ip_filter_applied = False  # Indicate IP filter wasn't the effective one
                #else: logger.debug(f"Still no requests found for server {ip_address} even without IP filter.")

        else:
            # For databases or servers without specific IP logic
            mask = (
                    (request_data['Sniff_time'] >= start_time) &
                    (request_data['Sniff_time'] <= end_time)
            )
            filtered_requests = request_data[mask]
        # --- End Filtering Logic ---

        if not filtered_requests.empty:
            # Ensure 'Time_since_request' is numeric before calculating mean
            mean_delay = filtered_requests['Time_since_request'].mean()
            if not pd.isna(mean_delay):  # Check if mean is valid
                aligned_data.append({
                    'KPI_Value': kpi_value,
                    'Mean_Delay': mean_delay,
                    'KPI_Timestamp': kpi_time  # Keep timestamp for potential later analysis
                })
            # else: logger.warning(f"Mean delay calculation resulted in NaN for window {start_time}-{end_time}. Check 'Time_since_request' values.")
        # else: logger.debug(f"No requests found in window {start_time} - {end_time} for KPI '{kpi_name}' (IP filter applied: {ip_filter_applied})")

    if len(aligned_data) < 2:
        logger.warning(
            f"KPI '{kpi_name}' (Monitor: {effective_monitor_type}, IP: {ip_address}): Insufficient aligned data points ({len(aligned_data)}) for correlation calculation.")
        return None, None, effective_monitor_type

    # Create DataFrame from aligned data
    aligned_df = pd.DataFrame(aligned_data)
    kpi_values = aligned_df['KPI_Value']
    mean_delays = aligned_df['Mean_Delay']

    # Double-check for NaNs that might have slipped through (shouldn't happen with checks above)
    valid_indices = (~np.isnan(mean_delays)) & (~np.isnan(kpi_values))
    if valid_indices.sum() < 2:
        logger.warning(
            f"KPI '{kpi_name}' (Monitor: {effective_monitor_type}, IP: {ip_address}): Fewer than 2 valid non-NaN pairs after alignment ({valid_indices.sum()}). Cannot calculate correlation.")
        return None, None, effective_monitor_type

    mean_delays = mean_delays[valid_indices]
    kpi_values = kpi_values[valid_indices]

    # Calculate Pearson correlation
    correlation = None
    try:
        # Check for constant input which causes ValueError in pearsonr
        if len(np.unique(mean_delays)) < 2 or len(np.unique(kpi_values)) < 2:
            logger.warning(
                f"KPI '{kpi_name}' (Monitor: {effective_monitor_type}, IP: {ip_address}): Cannot calculate correlation because at least one variable (KPI values or mean delays) is constant.")
            correlation = np.nan  # Treat as NaN correlation
        else:
            correlation, p_value = pearsonr(mean_delays, kpi_values)
            logger.debug(
                f"KPI '{kpi_name}' (Monitor: {effective_monitor_type}, IP: {ip_address}): Correlation = {correlation:.4f}, p-value = {p_value:.4f} ({len(mean_delays)} points)")

    except ValueError as e:
        logger.error(
            f"Error calculating Pearson correlation for KPI '{kpi_name}' (Monitor: {effective_monitor_type}, IP: {ip_address}): {e}. This might happen with invalid input data.")
        correlation = np.nan  # Assign NaN on error

    # Prepare the DataFrame slice to be returned for later aggregation
    # Rename columns for clarity in the final combined CSV
    output_df_slice = pd.DataFrame({
        f'{kpi_name}_Value': kpi_values,
        f'{kpi_name}_Mean_Delay': mean_delays
    })
    output_df_slice.reset_index(drop=True, inplace=True)  # Ensure clean index for concatenation

    return output_df_slice, correlation, effective_monitor_type


# 主程序执行函数
def calc_correlation(
        json_file_path: str,
        request_data: pd.DataFrame,
        output_correlation_csv_path: str,
        output_kpi_delay_csv_path: str,
        kpi_mapping_file: str = 'src/packet_analysis/services/json_build/kpi_mapping.txt',
        time_threshold_seconds: int = 10
) -> pd.DataFrame:
    """
    Calculates correlations between KPIs from a JSON file and request delays from a DataFrame.

    Args:
        json_file_path: Path to the input JSON log file.
        request_data: DataFrame containing packet request/response data,
                      must include 'Sniff_time' (datetime) and 'Time_since_request' (numeric),
                      and 'Ip_dst' (string, used for server filtering).
        output_correlation_csv_path: Path to save the final correlation summary CSV.
        output_kpi_delay_csv_path: Path to save the aligned KPI values and mean delays CSV.
        kpi_mapping_file: Path to the KPI mapping file.
        time_threshold_seconds: Window size (seconds) for aligning KPI and request data.

    Returns:
        A pandas DataFrame containing the calculated correlations, sorted by absolute correlation value,
        or an empty DataFrame if no correlations could be calculated.
    """
    logger.info("Starting correlation calculation process.")
    all_correlation_results = []
    all_aligned_data_dfs = []  # Store individual DataFrames for KPIs/Delays

    # --- Input Validation and Loading ---
    try:
        kpi_mapping = load_kpi_mapping(kpi_mapping_file)
    except (FileNotFoundError, IOError, ValueError) as e:
        logger.error(f"Failed to load KPI mapping: {e}. Aborting calculation.")
        # Return empty DataFrame with expected columns
        return pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])

    if not os.path.exists(json_file_path):
        logger.error(f"Input JSON file not found: {json_file_path}. Aborting.")
        return pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])

    try:
        with open(json_file_path, 'r', encoding='utf-8') as f:
            json_data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Failed to decode JSON from {json_file_path}: {e}. Aborting.")
        return pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])
    except IOError as e:
        logger.error(f"IOError reading JSON file {json_file_path}: {e}. Aborting.")
        return pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])

    if not isinstance(request_data, pd.DataFrame) or request_data.empty:
        logger.error("Input request_data is not a valid or non-empty DataFrame. Aborting.")
        return pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])

    # Check required columns in request_data
    required_cols = ['Sniff_time', 'Time_since_request', 'Ip_dst']
    if not all(col in request_data.columns for col in required_cols):
        logger.error(f"Request data DataFrame is missing one or more required columns: {required_cols}. Aborting.")
        return pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])

    # --- Data Extraction and Preparation ---
    extracted_info = extract_data(json_data, kpi_mapping)
    if not extracted_info:
        logger.warning("No processable KPI data extracted from the JSON file. Cannot calculate correlations.")
        # # Still create empty output files for consistency
        # pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value']).to_csv(output_correlation_csv_path,
        #                                                                                index=False,
        #                                                                                encoding='utf-8-sig')
        # pd.DataFrame().to_csv(output_kpi_delay_csv_path, index=False, encoding='utf-8-sig')
        # logger.info(f"Empty correlation summary saved to {output_correlation_csv_path}")
        # logger.info(f"Empty KPI/delay data saved to {output_kpi_delay_csv_path}")
        return pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])

    extracted_df = pd.DataFrame(extracted_info)
    # Ensure DCTIME is datetime (should be from extract_data, but double check)
    extracted_df['DCTIME'] = pd.to_datetime(extracted_df['DCTIME'], errors='coerce')
    extracted_df.dropna(subset=['DCTIME'], inplace=True)  # Remove rows where time conversion failed

    if extracted_df.empty:
        logger.warning(
            "No valid KPI data points remaining after initial processing and time conversion. Cannot calculate correlations.")
        # Create empty output files
        pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value']).to_csv(output_correlation_csv_path,
                                                                                       index=False,
                                                                                       encoding='utf-8-sig')
        pd.DataFrame().to_csv(output_kpi_delay_csv_path, index=False, encoding='utf-8-sig')
        logger.info(f"Empty correlation summary saved to {output_correlation_csv_path}")
        logger.info(f"Empty KPI/delay data saved to {output_kpi_delay_csv_path}")
        return pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])

    # --- Correlation Calculation Loop ---
    logger.info(f"Processing {len(extracted_df['kpi_no'].unique())} unique KPIs across relevant monitor types...")
    # Group by monitor_type, kpi_no, and ip_address (essential for server distinction)
    try:
        grouped_kpi = extracted_df.groupby(['monitor_type', 'kpi_no', 'ip_address'],
                                           observed=True)  # Use observed=True for potential performance benefit
        group_count = len(grouped_kpi)
        logger.info(f"Created {group_count} groups for correlation analysis.")

        request_data = request_data.copy()

        # Pre-convert Time_since_request to numeric if it's not already
        request_data['Time_since_request'] = pd.to_numeric(request_data['Time_since_request'], errors='coerce')
        # Drop rows where conversion failed
        request_data.dropna(subset=['Time_since_request'], inplace=True)

        for i, ((monitor_type, kpi_no, host_ip), kpi_group) in enumerate(grouped_kpi):
            logger.debug(f"Processing group {i + 1}/{group_count}: Monitor={monitor_type}, KPI={kpi_no}, IP={host_ip}")
            kpi_name = kpi_mapping.get(kpi_no, f'未知指标 ({kpi_no})')
            # Sort group by time before passing to computation
            kpi_group = kpi_group.sort_values(by='DCTIME')

            # Convert group to list of dicts for compute function
            kpi_group_records = kpi_group.to_dict('records')

            # Call the computation function for this group
            aligned_df_slice, correlation_value, effective_monitor_type = compute_correlation_for_group(
                kpi_group_data=kpi_group_records,
                request_data=request_data,  # Pass a copy to avoid modification issues if any
                kpi_name=kpi_name,
                time_threshold_seconds=time_threshold_seconds,
                ip_address=host_ip,
                monitor_type=monitor_type
            )

            # Collect results if successful
            if correlation_value is not None and not np.isnan(correlation_value):
                all_correlation_results.append({
                    # Use effective_monitor_type which reflects server fallback if it happened
                    'monitor_type': effective_monitor_type,
                    'ip_address': host_ip,  # Add IP address to output for clarity
                    'kpi_name': kpi_name,
                    'correlation_value': correlation_value
                })
            if aligned_df_slice is not None and not aligned_df_slice.empty:
                # Add identifier columns to the aligned data slice before storing
                aligned_df_slice['monitor_type'] = effective_monitor_type
                aligned_df_slice['ip_address'] = host_ip
                all_aligned_data_dfs.append(aligned_df_slice)

    except KeyError as e:
        logger.error(
            f"KeyError during grouping or processing: {e}. Check if columns 'monitor_type', 'kpi_no', 'ip_address', 'DCTIME' exist in extracted data.")
        # Decide if to abort or continue; here we abort for safety
        return pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])
    except Exception as e:
        logger.exception(f"An unexpected error occurred during the correlation calculation loop: {e}")
        # Depending on severity, might choose to abort or just log and continue
        # Returning empty dataframe for now
        return pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])

    # --- Final Output Generation ---
    final_correlation_df = pd.DataFrame()  # Initialize empty DataFrame
    if all_correlation_results:
        correlation_df = pd.DataFrame(all_correlation_results)
        # Sort by absolute value of correlation (descending) to see strongest relationships first
        correlation_df['correlation_value_float'] = pd.to_numeric(correlation_df['correlation_value'], errors='coerce')
        correlation_df['abs_correlation'] = correlation_df['correlation_value_float'].abs()
        final_correlation_df = correlation_df.sort_values(by='abs_correlation', ascending=False).drop(
            columns=['correlation_value_float', 'abs_correlation'])

        try:
            final_correlation_df.to_csv(output_correlation_csv_path, index=False, encoding='utf-8-sig')
            logger.info(f"Correlation summary saved to CSV: {output_correlation_csv_path}")
        except IOError as e:
            logger.error(f"Failed to write correlation summary CSV to {output_correlation_csv_path}: {e}")
        except Exception as e:
            logger.exception(
                f"An unexpected error occurred while writing correlation summary CSV to {output_correlation_csv_path}")

    else:
        logger.warning(
            f"No valid correlations were calculated. The output file '{output_correlation_csv_path}' will contain only headers.")
        # Create empty file with headers
        try:
            pd.DataFrame(columns=['monitor_type', 'ip_address', 'kpi_name', 'correlation_value']).to_csv(
                output_correlation_csv_path, index=False, encoding='utf-8-sig')
        except IOError as e:
            logger.error(f"Failed to write empty correlation summary CSV to {output_correlation_csv_path}: {e}")

    # Combine and save all aligned KPI/Delay data (Efficiently done once)
    if all_aligned_data_dfs:
        # Concatenate horizontally, aligning by index (which should be 0..N for each slice)
        # This requires careful handling if lengths differ. Padding might be needed.
        # Let's try a simple concat which might result in many NaNs if lengths vary.
        # Consider aligning timestamps if a more precise combined view is needed.
        try:
            # Pad DataFrames to the same length before concatenating horizontally
            max_len = max(len(df) for df in all_aligned_data_dfs)
            padded_dfs = []
            for df in all_aligned_data_dfs:
                pad_len = max_len - len(df)
                if pad_len > 0:
                    # Create a DataFrame of NaNs for padding
                    nan_padding = pd.DataFrame(np.nan, index=np.arange(pad_len), columns=df.columns)
                    padded_df = pd.concat([df, nan_padding], ignore_index=True)
                    padded_dfs.append(padded_df)
                else:
                    padded_dfs.append(df)

            combined_kpi_delay_df = pd.concat(padded_dfs, axis=1)

            # Remove the redundant identifier columns added during collection
            combined_kpi_delay_df = combined_kpi_delay_df.loc[:,
                                    ~combined_kpi_delay_df.columns.duplicated(keep='first')]  # Keep first occurrence
            if 'monitor_type' in combined_kpi_delay_df.columns: combined_kpi_delay_df.drop(columns=['monitor_type'],
                                                                                           inplace=True,
                                                                                           errors='ignore')
            if 'ip_address' in combined_kpi_delay_df.columns: combined_kpi_delay_df.drop(columns=['ip_address'],
                                                                                         inplace=True, errors='ignore')

            combined_kpi_delay_df.to_csv(output_kpi_delay_csv_path, index=False, encoding='utf-8-sig')
            logger.info(f"Combined KPI/Delay data saved to CSV: {output_kpi_delay_csv_path}")
        except IOError as e:
            logger.error(f"Failed to write combined KPI/Delay CSV to {output_kpi_delay_csv_path}: {e}")
        except Exception as e:
            logger.exception(
                f"An unexpected error occurred while writing combined KPI/Delay CSV to {output_kpi_delay_csv_path}")
    else:
        logger.warning(
            f"No aligned KPI/Delay data was generated. The output file '{output_kpi_delay_csv_path}' will be empty.")
        # Create empty file
        try:
            pd.DataFrame().to_csv(output_kpi_delay_csv_path, index=False, encoding='utf-8-sig')
        except IOError as e:
            logger.error(f"Failed to write empty KPI/Delay CSV to {output_kpi_delay_csv_path}: {e}")

    logger.info("Correlation calculation process finished.")
    # Return the final correlation DataFrame (could be empty)
    return final_correlation_df
