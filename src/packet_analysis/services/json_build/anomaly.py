import os
import os.path
from typing import List, Dict, Any, Tuple, Optional
import logging
import pandas as pd

# Project imports (assuming logger_config is set up correctly)

# Logger
logger = logging.getLogger(__name__)

# --- Constants ---
DEFAULT_THRESHOLD_MULTIPLIER = 2.0
REQUEST_CATEGORIES = ['api_post', 'api_get', 'static_resource', 'dynamic_resource', 'other']


# --- Helper Functions ---

def classify_path(path: Optional[str]) -> str:
    """
    Classifies a request path into predefined categories.

    Args:
        path: The URL path string.

    Returns:
        The category name as a string.
    """
    if path is None:
        return 'other'  # Handle potential None paths

    path_lower = path.lower()
    if 'post' in path_lower or path == '/portal_todo_moa/api/getDataByUserId':
        return 'api_post'
    elif 'get' in path_lower:
        return 'api_get'
    elif '/static/' in path or path.endswith(('.css', '.js', '.png', '.jpg', '.gif', '.svg', '.woff', '.ttf', '.eot')):
        return 'static_resource'
    elif path.endswith(
            ('.php', '.asp', '.jsp', '.html')):  # .html might be static, but often implies dynamic generation
        return 'dynamic_resource'
    else:
        return 'other'


def create_url_delay_map(data_list: List[Dict[str, Any]]) -> Dict[str, float]:
    """
    Creates a mapping from URL to its average production delay.

    Args:
        data_list: A list of dictionaries, each containing at least 'url'
                   and 'production_delay_mean'.

    Returns:
        A dictionary mapping URL strings to float delay values. Returns empty
        dict if input is invalid or delay cannot be converted to float.
    """
    url_delay_map = {}
    if not isinstance(data_list, list):
        logger.error("Invalid data_list provided for URL delay map creation. Expected list.")
        return url_delay_map

    for item in data_list:
        if isinstance(item, dict) and "url" in item and "production_delay_mean" in item:
            try:
                # Ensure delay is treated as float, handle potential errors
                delay = float(item["production_delay_mean"])
                url_delay_map[item["url"]] = delay
            except (ValueError, TypeError) as e:
                logger.warning(
                    f"Could not convert production_delay_mean for URL '{item.get('url', 'N/A')}' to float: {e}. Skipping.")
        else:
            logger.warning(f"Invalid item format in data_list: {item}. Skipping.")

    return url_delay_map


# --- Core Logic Functions ---

def detect_anomalies(
        df: pd.DataFrame,
        category: str,
        csv_folder_output: str,
        identifier_suffix: str,
        url_delay_map: Dict[str, float],
        threshold_multiplier: float = DEFAULT_THRESHOLD_MULTIPLIER
) -> Tuple[pd.DataFrame, Optional[str]]:
    """
    Detects anomalies in request times based on reference delays.

    Args:
        df: DataFrame containing request data for a specific category.
        category: The name of the request category being processed.
        csv_folder_output: Path to the folder where anomaly CSVs will be saved.
        identifier_suffix: A string (e.g., numbers_env) to append to filenames.
        url_delay_map: A dictionary mapping URL paths to their reference delay times.
        threshold_multiplier: Factor to multiply reference delay by to set the anomaly threshold.

    Returns:
        A tuple containing:
            - The input DataFrame with an added 'anomaly' column (-1 for anomaly, 1 for normal).
            - The path to the saved anomaly CSV file, or None if no anomalies were found or
              no valid data remained after filtering.
    """
    if df.empty:
        logger.info(f"分类 {category}: DataFrame is empty, skipping anomaly detection.")
        return df, None

    # --- Data Preprocessing ---
    # Ensure Time_since_request is numeric and non-negative
    df['Time_since_request'] = pd.to_numeric(df['Time_since_request'], errors='coerce')
    df = df.dropna(subset=['Time_since_request'])
    df = df[df['Time_since_request'] >= 0].copy()  # Use .copy() to avoid SettingWithCopyWarning

    if df.empty:
        logger.info(f"分类 {category}: DataFrame empty after Time_since_request cleaning.")
        return df, None

    # --- Filter by Mapped URLs ---
    valid_paths = url_delay_map.keys()
    original_count = len(df)
    df = df[df['Path'].isin(valid_paths)].copy()  # Filter and copy
    filtered_count = len(df)
    logger.info(f"分类 {category}: Kept {filtered_count}/{original_count} rows with mapped URLs.")

    if df.empty:
        logger.warning(
            f"分类 {category}: No data remaining after filtering for mapped URLs in url_delay_map. Skipping anomaly detection.")
        return df, None

    # --- Anomaly Detection ---
    df['reference_delay'] = df['Path'].map(url_delay_map)

    # Initialize 'anomaly' column (1 = normal, -1 = anomaly)
    df['anomaly'] = 1

    # Identify anomalies: Time_since_request > threshold * reference_delay
    # Handle potential division by zero or near-zero reference delays if necessary (though filtering should help)
    anomaly_condition = df['Time_since_request'] > threshold_multiplier * df['reference_delay']
    df.loc[anomaly_condition, 'anomaly'] = -1

    # --- Save Anomalies ---
    anomaly_data = df.loc[df['anomaly'] == -1].copy()  # Use .loc for explicit indexing
    csv_save_path = None

    if not anomaly_data.empty:
        # Add the average reference delay for context in the output file
        anomaly_data['Average_Time_since_request'] = anomaly_data['reference_delay']

        # Construct filename and save
        filename = f'{category}_anomalies_{identifier_suffix}.csv'
        csv_save_path = os.path.join(csv_folder_output, filename)
        try:
            anomaly_data.to_csv(csv_save_path, index=False, encoding='utf-8')
            logger.info(f"分类 {category}: {len(anomaly_data)} 异常点数据已保存至: {csv_save_path}")
        except IOError as e:
            logger.error(f"Failed to save anomaly CSV for {category} to {csv_save_path}: {e}")
            csv_save_path = None  # Indicate failure
    else:
        logger.info(f"分类 {category}: 未检测到异常点.")

    return df, csv_save_path


# # --- Visualization Function ---
#
# def plot_anomalies(
#         df: pd.DataFrame,
#         title: str,
#         filename: str,
#         plot_folder_output: str
# ) -> Optional[str]:
#     """
#     Generates and saves a scatter plot highlighting anomalies.
#
#     Args:
#         df: DataFrame with 'Relative_time', 'Time_since_request', and 'anomaly' columns.
#         title: Title for the plot.
#         filename: Base filename for the saved plot (without extension).
#         plot_folder_output: Path to the folder where plots will be saved.
#
#     Returns:
#         The full path to the saved plot file, or None if plotting failed or df was empty.
#     """
#     if df.empty or 'anomaly' not in df.columns:
#         logger.warning(f"No data or 'anomaly' column found for plotting: {title}")
#         return None
#
#     if 'Relative_time' not in df.columns or 'Time_since_request' not in df.columns:
#         logger.error(f"Missing required columns ('Relative_time', 'Time_since_request') for plotting: {title}")
#         return None
#
#     plt.figure(figsize=(14, 7))
#     markers = {1: 'o', -1: 'x'}
#     colors = {1: 'blue', -1: 'red'}
#     labels = {1: 'Normal', -1: 'Anomaly'}
#
#     for anomaly_status, group in df.groupby('anomaly'):
#         if anomaly_status in markers:  # Check if status is expected (1 or -1)
#             plt.scatter(group['Relative_time'], group['Time_since_request'],
#                         c=colors[anomaly_status], marker=markers[anomaly_status],
#                         label=labels[anomaly_status], alpha=0.7)
#
#     # Add statistical lines if data exists
#     if not df['Time_since_request'].empty:
#         mean_value = df['Time_since_request'].mean()
#         median_value = df['Time_since_request'].median()
#         std_dev = df['Time_since_request'].std()
#
#         plt.axhline(y=mean_value, color='g', linestyle='-', label=f'Mean: {mean_value:.3f}')
#         plt.axhline(y=median_value, color='orange', linestyle='--', label=f'Median: {median_value:.3f}')
#         plt.axhline(y=mean_value + std_dev, color='purple', linestyle=':',
#                     label=f'Mean + 1 Std Dev: {mean_value + std_dev:.3f}')
#         plt.axhline(y=max(0, mean_value - std_dev), color='purple', linestyle=':',
#                     label=f'Mean - 1 Std Dev: {max(0, mean_value - std_dev):.3f}')  # Ensure lower bound is >= 0
#
#     plt.title(title)
#     plt.xlabel('Relative Time (s)')
#     plt.ylabel('Time Since Request (s)')
#     plt.legend(loc='upper right')
#     plt.xticks(rotation=45)
#     plt.grid(True, linestyle='--', alpha=0.6)
#     plt.tight_layout()
#
#     plot_save_path = os.path.join(plot_folder_output, f'{filename}_anomalies.png')
#     try:
#         plt.savefig(plot_save_path, dpi=300)
#         logger.info(f"Anomaly plot saved to: {plot_save_path}")
#         plt.close()  # Close the figure to free memory
#         return plot_save_path
#     except Exception as e:
#         logger.error(f"Failed to save plot {plot_save_path}: {e}")
#         plt.close()  # Ensure plot is closed even on error
#         return None


# --- Main Analysis Orchestrator ---

def analysis(
        parquet_input: str,
        folder_output: str,
        numbers: str,
        data_list: List[Dict[str, Any]],
        env: str,
        plot_results: bool = False,
        threshold_multiplier: float = DEFAULT_THRESHOLD_MULTIPLIER
) -> Tuple[List[Optional[str]], List[Optional[str]]]:
    """
    Performs the main analysis workflow: load, classify, detect anomalies, and optionally plot.

    Args:
        parquet_input: Path to the input CSV file containing request data.
        folder_output: Base directory for saving output files (CSV, plots).
        numbers: Identifier number (e.g., batch number) for filenames.
        data_list: List of dictionaries with URL reference delays.
        env: Environment identifier (e.g., 'prod', 'staging') for filenames.
        plot_results: If True, generate and save anomaly plots.
        threshold_multiplier: Factor to multiply reference delay by for anomaly detection.

    Returns:
        A tuple containing two lists:
            - List of paths to the generated CSV files (including classified data and anomaly files).
              Contains None for categories where no anomaly file was generated.
            - List of paths to the generated plot files (if plot_results=True).
              Contains None for categories where no plot was generated.
    """
    ret_csv_list: List[Optional[str]] = []
    ret_plot_list: List[Optional[str]] = []
    identifier_suffix = f"{numbers}_{env}"  # Combine identifiers

    # --- Create Output Directories ---
    csv_folder_output = os.path.join(folder_output, 'cluster_csv')
    plot_folder_output = os.path.join(folder_output, 'cluster_plots')
    os.makedirs(csv_folder_output, exist_ok=True)
    if plot_results:
        os.makedirs(plot_folder_output, exist_ok=True)

    # --- Load and Prepare Data ---
    try:
        data = pd.read_parquet(parquet_input)
        logger.info(f"Successfully loaded data from: {parquet_input}")
    except FileNotFoundError:
        logger.error(f"Input parquet file not found: {parquet_input}")
        return [], []
    except Exception as e:
        logger.error(f"Error reading parquet file {parquet_input}: {e}")
        return [], []

    required_columns = ['Path', 'Request_Method', 'Time_since_request', 'Sniff_time', 'No', 'Relative_time']
    if not all(col in data.columns for col in required_columns):
        logger.error(f"Input parquet missing required columns. Needed: {required_columns}, Found: {list(data.columns)}")
        return [], []

    # Basic cleaning
    data = data.dropna(subset=['Path', 'Time_since_request', 'Sniff_time'])
    if data.empty:
        logger.warning("Dataframe is empty after dropping initial NA values.")
        return [], []

    # --- Classify Requests ---
    data['request_type'] = data['Path'].apply(classify_path)

    # Save classified data
    classified_requests_csv_path = os.path.join(csv_folder_output, f'classified_requests_{identifier_suffix}.csv')
    try:
        data.to_csv(classified_requests_csv_path, index=False, encoding='utf-8')
        ret_csv_list.append(classified_requests_csv_path)
        logger.info(f"Classified requests saved to: {classified_requests_csv_path}")
    except IOError as e:
        logger.error(f"Failed to save classified requests CSV: {e}")
        ret_csv_list.append(None)  # Add placeholder even if save failed

    # --- Create URL Delay Map ---
    url_delay_map = create_url_delay_map(data_list)
    if not url_delay_map:
        logger.warning("URL delay map is empty. Anomaly detection will likely find no matches.")
        # Continue processing, detect_anomalies handles empty maps

    # --- Process Each Category ---
    for category in REQUEST_CATEGORIES:
        logger.info(f"--- Processing category: {category} ---")
        category_data = data[data['request_type'] == category].copy()  # Filter and copy

        # Detect anomalies
        processed_data, csv_anomaly_path = detect_anomalies(
            category_data,
            category,
            csv_folder_output,
            identifier_suffix,
            url_delay_map,
            threshold_multiplier
        )
        ret_csv_list.append(csv_anomaly_path)  # Will be None if no anomalies

        # # Plot results if enabled and data exists
        # plot_path = None
        # if plot_results and not processed_data.empty and 'anomaly' in processed_data.columns:
        #     plot_path = plot_anomalies(
        #         processed_data,
        #         f'{category.replace("_", " ").title()} Request Anomalies ({env})',
        #         f'{category}_{identifier_suffix}',
        #         plot_folder_output
        #     )
        # ret_plot_list.append(plot_path)  # Will be None if plotting disabled or failed

    logger.info("Analysis finished.")
    return ret_csv_list, ret_plot_list


# --- Anomaly Summary Function ---

def get_anomalies_summary(
        file_path: str,
        environment: str,
        host_ip: str
) -> List[Dict[str, Any]]:
    """
    Reads an anomaly CSV file and formats the anomalies into a list of dictionaries.

    Args:
        file_path: Path to the anomaly CSV file.
        environment: The environment identifier.
        host_ip: The host IP address.

    Returns:
        A list of dictionaries, each representing an anomaly record.
    """
    try:
        df = pd.read_csv(file_path, encoding='utf-8')
    except FileNotFoundError:
        logger.error(f"Anomaly file not found: {file_path}")
        return []
    except Exception as e:
        logger.error(f"Error reading anomaly file {file_path}: {e}")
        return []

    if df.empty:
        logger.info(f"Anomaly file is empty: {file_path}")
        return []

    # Ensure required columns exist (adjust based on actual columns in anomaly CSVs)
    required_summary_cols = ['Path', 'Request_Method', 'request_type', 'Time_since_request',
                             'Average_Time_since_request', 'Sniff_time', 'No']
    if not all(col in df.columns for col in required_summary_cols):
        logger.error(f"Anomaly file {file_path} missing required columns for summary. "
                     f"Needed: {required_summary_cols}, Found: {list(df.columns)}")
        return []

    details = []
    # Calculate path counts efficiently once
    path_counts = df['Path'].value_counts().to_dict()  # Convert to dict for faster lookup

    # Use list comprehension or apply for potentially better performance than iterrows,
    # but iterrows is clear for this transformation.
    for _, row in df.iterrows():
        df_row = {
            'request_url': row['Path'],
            'request_method': row['Request_Method'],
            'env': environment,
            'hostip': host_ip,
            'class_method': row['request_type'],
            'anomaly_delay': f"{row['Time_since_request']:.6f}",  # Format delay
            'count': path_counts.get(row['Path'], 0),  # Get count from pre-calculated dict
            'average_delay': f"{row['Average_Time_since_request']:.6f}",  # Format average delay
            'anomaly_time': row['Sniff_time'],
            'packet_position': f"Packet {row['No']}"  # Format packet number
        }
        details.append(df_row)

    return details


def process_anomalies(
        file_paths: List[Optional[str]],
        environment: str,
        host_ip: str
) -> List[Dict[str, Any]]:
    """
    Processes multiple anomaly CSV files and aggregates the details.

    Args:
        file_paths: A list of paths to anomaly CSV files (can include None values).
        environment: The environment identifier.
        host_ip: The host IP address.

    Returns:
        A list containing all anomaly details combined from the valid input files.
    """
    all_details: List[Dict[str, Any]] = []

    valid_paths = [fp for fp in file_paths if fp and isinstance(fp, str) and 'anomalies' in os.path.basename(fp)]
    # Filter out None, ensure it's a string, and check if 'anomalies' is in the filename

    if not valid_paths:
        logger.warning("No valid anomaly file paths provided to process_anomalies.")
        return []

    for file_path in valid_paths:
        logger.info(f"Processing anomaly summary for file: {file_path}")
        details = get_anomalies_summary(file_path, environment, host_ip)
        all_details.extend(details)  # Add results from this file to the main list

    logger.info(f"Aggregated {len(all_details)} anomaly records from {len(valid_paths)} files.")
    return all_details


# --- Main Execution Guard ---
if __name__ == '__main__':
    print('This script is intended to be imported as a module. Please run your main execution script.')
    # Example usage (for testing purposes):
    # Make sure you have a sample 'input.csv' and appropriate 'data_list'
    # DUMMY_DATA_LIST = [
    #     {"url": "/portal_todo_moa/api/getDataByUserId", "production_delay_mean": 0.5},
    #     {"url": "/static/css/main.css", "production_delay_mean": 0.05},
    #     {"url": "/api/v1/users/get", "production_delay_mean": 0.2},
    #     {"url": "/index.html", "production_delay_mean": 0.1},
    #     # Add more realistic mappings
    # ]
    # try:
    #     csv_files, plot_files = analysis(
    #         csv_input='path/to/your/input.csv', # Replace with actual path
    #         folder_output='output_analysis',
    #         numbers='001',
    #         data_list=DUMMY_DATA_LIST, # Replace with actual data
    #         env='dev',
    #         plot_results=True,
    #         threshold_multiplier=2.5
    #     )
    #     print("Generated CSVs:", csv_files)
    #     print("Generated Plots:", plot_files)

    #     if csv_files:
    #         summary = process_anomalies(
    #             file_paths=csv_files,
    #             environment='dev',
    #             host_ip='127.0.0.1'
    #         )
    #         print(f"\nAnomaly Summary ({len(summary)} items):")
    #         # Print first few summary items for inspection
    #         for item in summary[:5]:
    #             print(item)

    # except Exception as main_e:
    #      print(f"An error occurred during example execution: {main_e}")

