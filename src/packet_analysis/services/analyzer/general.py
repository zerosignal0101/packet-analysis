import os
from collections import defaultdict
from typing import Dict, Any, List, Tuple
import logging
import pandas as pd
import traceback  # Import traceback for detailed error logging

# Project imports
from src.packet_analysis.services.json_build.correlation import calc_correlation, safe_format
from src.packet_analysis.services.json_build.database import load_database_logs, match_database_logs
from src.packet_analysis.services.json_build.exception import load_exception_logs, match_exception_logs
from src.packet_analysis.services.json_build.random_forest import calc_forest_model
from src.packet_analysis.services.json_build.suggestions import (
    optimization_suggestions_correlation,
    optimization_suggestions_random_forest
)

# Logger
logger = logging.getLogger(__name__)


def general_data_analyzer(result_df: pd.DataFrame, options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Performs comprehensive analysis on processed packet data and system logs.

    This function orchestrates several analysis steps:
    1. Correlation Analysis: Calculates the correlation between system performance metrics
       (from logs) and network processing time (from packet data).
    2. Random Forest Analysis: Builds a random forest model to determine the importance
       of different system metrics in predicting network processing time.
    3. Database Log Analysis: Identifies potential database bottlenecks by analyzing slow
       database queries recorded in logs and correlating them with specific requests.
    4. Exception Log Analysis: Identifies application exceptions recorded in logs and
       correlates them with specific requests.

    Args:
        result_df: DataFrame containing processed packet data, including request/response
                   matching, timestamps, and processing times. Expected to have a 'Dataframe'
                   column containing dictionaries mapping request paths to details.
        options: A dictionary containing configuration options and paths:
            - "side": "producer" or "consumer" (or equivalent like "replay") indicating
                      the environment being analyzed.
            - "host_ip_list": A list of host IP addresses relevant to this analysis.
            - "collect_log": Path to the system/application log file for the "producer" side.
            - "replay_log": Path to the system/application log file for the "replay" side.
            - "pcap_info_idx": An identifier for the current pcap analysis session, used
                               for naming output files/directories.
            - "task_result_path": Base path where analysis results (like CSVs) should be stored.

    Returns:
        A dictionary containing the results of all analysis steps, structured for easy
        consumption (e.g., JSON serialization). Includes keys like:
        - "analysis_result_correlation"
        - "analysis_result_random_forest"
        - "bottleneck_analysis_database"
        - "bottleneck_analysis_exception"
    """
    logger.info(f"Starting general data analysis for side: {options.get('side', 'N/A')}")

    # --- Setup ---
    try:
        side = options["side"]
        host_ip_list = options["host_ip_list"]
        host_ip_str = ", ".join(host_ip_list) if isinstance(host_ip_list, list) else str(host_ip_list)
        # Determine environment names (English and Chinese for descriptions)
        env_en_name = "production" if side == "producer" else "replay"
        env_name = '生产' if side == 'producer' else '回放'
        # Get the correct log path based on the side
        log_key = 'collect_log' if side == 'producer' else 'replay_log'
        json_path = options[log_key]
        pcap_info_idx = options["pcap_info_idx"]
        task_result_path = options["task_result_path"]

        # Ensure task result path exists
        if not os.path.exists(task_result_path):
            os.makedirs(task_result_path, exist_ok=True)
            logger.info(f"Created task result directory: {task_result_path}")

        # Result dictionary initialization
        result = {}
        kpi_result_file_path = None  # Initialize path, will be set in correlation analysis

    except KeyError as e:
        logger.error(f"Missing required key in options: {e}", exc_info=True)
        return {
            "error": f"Configuration error: Missing option '{e}'",
            "analysis_result_correlation": {},
            "analysis_result_random_forest": {},
            "performance_bottleneck_analysis": {},
            "bottleneck_analysis_database": {},
            "bottleneck_analysis_exception": {}
        }
    except Exception as e:
        logger.error(f"Unexpected error during setup: {e}", exc_info=True)
        return {
            "error": f"Unexpected setup error: {e}",
            "analysis_result_correlation": {},
            "analysis_result_random_forest": {},
            "performance_bottleneck_analysis": {},
            "bottleneck_analysis_database": {},
            "bottleneck_analysis_exception": {}
        }

    logger.debug(
        f"Analysis parameters: side={side}, host_ips='{host_ip_str}', env='{env_en_name}', log_path='{json_path}', pcap_idx='{pcap_info_idx}', result_path='{task_result_path}'")

    # --- 1. Correlation Analysis ---
    logger.info(f"Starting Correlation Analysis for {env_name} environment.")
    # Initialize result structure with default/error message
    analysis_result_correlation = {
        "env": env_en_name,
        "hostip": host_ip_str,
        "description": f"{env_name}环境采集点的性能数据与服务器平均处理时延的相关系数",
        "conclusion": f"未能成功计算相关性。",  # Default conclusion
        "solution": "请检查日志文件与pcap文件的时间戳是否匹配或是否存在性能数据。",  # Default solution
        "correlation_data": [{
            "index_id": f"{env_name}环境性能日志文件与pcap包时间不匹配或数据不足，无法计算相关系数。",
            "value": 9999  # Sentinel value indicating an issue
        }]
    }
    correlation_result_df = pd.DataFrame()  # Initialize empty DataFrame

    try:
        # Define paths for correlation output files
        correlation_analysis_path = os.path.join(task_result_path, f"correlation_analysis_{pcap_info_idx}")
        if not os.path.exists(correlation_analysis_path):
            os.makedirs(correlation_analysis_path, exist_ok=True)  # Use makedirs for nested paths
            logger.info(f"Created correlation analysis directory: {correlation_analysis_path}")

        correlation_result_file_path = os.path.join(correlation_analysis_path, f'{env_en_name}_correlation.csv')
        kpi_result_file_path = os.path.join(correlation_analysis_path,
                                            f'{env_en_name}_kpi.csv')  # Path for aligned KPI data

        logger.info(
            f"Calculating correlations. Input log: {json_path}. Output CSV: {correlation_result_file_path}, KPI CSV: {kpi_result_file_path}")
        # Perform correlation calculation
        correlation_result_df = calc_correlation(json_path,
                                                 result_df,
                                                 correlation_result_file_path,
                                                 kpi_result_file_path)

        # Process the correlation results if successful and not empty
        if not correlation_result_df.empty and '相关系数' in correlation_result_df.columns and 'KPI名称' in correlation_result_df.columns:
            logger.info(f"Successfully calculated correlations. Processing {len(correlation_result_df)} results.")
            processed_data = []
            max_corr_kpi = None
            max_corr_value = -1  # Initialize with a value lower than any possible correlation

            for index, row in correlation_result_df.iterrows():
                # Check if correlation coefficient is valid
                if pd.notna(row['相关系数']):
                    kpi_name = row['KPI名称']
                    correlation_value = row['相关系数']
                    processed_data.append({
                        "index_id": kpi_name,
                        "value": correlation_value  # Keep as float
                    })
                    # Track the KPI with the highest absolute correlation
                    if abs(correlation_value) > abs(max_corr_value):
                        max_corr_value = correlation_value
                        max_corr_kpi = kpi_name

            # Update the result structure if valid data was found
            if processed_data:
                analysis_result_correlation['correlation_data'] = processed_data
                if max_corr_kpi:
                    analysis_result_correlation[
                        'conclusion'] = f"{env_name}环境中与平均处理时延相关性最强的指标是 {max_corr_kpi} (相关系数: {max_corr_value:.4f})"
                    analysis_result_correlation['solution'] = optimization_suggestions_correlation.get(max_corr_kpi,
                                                                                                       '该项指标暂无特定的优化建议。')
                else:
                    # This case should ideally not happen if processed_data is non-empty, but included for safety
                    analysis_result_correlation[
                        'conclusion'] = f"{env_name}环境计算得到相关系数，但无法确定最强相关指标。"
                    analysis_result_correlation['solution'] = "请检查计算结果。"
                logger.info(f"Correlation analysis processed. Strongest correlation KPI: {max_corr_kpi}")
            else:
                # Keep the default error message if no valid correlations were found
                logger.warning("Correlation analysis yielded no valid numeric correlation coefficients.")

        elif correlation_result_df.empty:
            logger.warning("Correlation analysis resulted in an empty DataFrame. Check input data and time alignment.")
        else:
            logger.warning(
                f"Columns '相关系数' or 'KPI名称' missing in correlation result DataFrame. Columns found: {correlation_result_df.columns.tolist()}")
            # Keep the default error message

    except FileNotFoundError as e:
        logger.error(f"Correlation analysis failed: Input log file not found at {json_path}. Error: {e}", exc_info=True)
        analysis_result_correlation['conclusion'] = "相关性分析失败：输入的日志文件未找到。"
        analysis_result_correlation['solution'] = f"请确认路径 '{json_path}' 是否正确以及文件是否存在。"
    except pd.errors.EmptyDataError as e:
        logger.error(f"Correlation analysis failed: Input log file or pcap data seems empty or invalid. Error: {e}",
                     exc_info=True)
        analysis_result_correlation['conclusion'] = "相关性分析失败：输入的日志文件或pcap数据为空或格式无效。"
        analysis_result_correlation['solution'] = "请检查输入文件的内容和格式。"
    except ValueError as e:
        logger.error(
            f"Correlation analysis failed: Likely due to time misalignment or insufficient overlapping data. Error: {e}",
            exc_info=True)
        analysis_result_correlation['conclusion'] = "相关性分析失败：日志与pcap数据时间戳无法对齐或重叠数据不足。"
        analysis_result_correlation['solution'] = "请检查日志和pcap文件的时间范围，确保有足够的重叠数据段。"
    except Exception as e:
        # Catch any other unexpected error during correlation analysis
        logger.error(f"Correlation analysis failed with an unexpected error: {e}", exc_info=True)
        # Keep the default error message in analysis_result_correlation
        analysis_result_correlation['conclusion'] = "相关性分析失败：发生未知错误。"
        analysis_result_correlation['solution'] = f"请检查日志输出获取详细错误信息。Error: {e}"
    finally:
        # Ensure the result dictionary always contains the correlation analysis part
        result["analysis_result_correlation"] = analysis_result_correlation

    # --- 2. Random Forest Analysis ---
    logger.info(f"Starting Random Forest Analysis for {env_name} environment.")
    # Initialize result structures with default/error messages
    analysis_result_random_forest = {
        "env": env_en_name,
        "hostip": host_ip_str,
        "description": f"{env_name}环境各性能指标对服务器平均处理时延的重要性分析",  # Updated description
        "conclusion": f"未能成功建立随机森林模型。",  # Default conclusion
        "solution": "请检查KPI数据文件是否存在或是否包含有效数据。",  # Default solution
        "importance_data": [{
            "index_id": f"{env_name}环境未能计算指标重要性（可能由于相关性分析失败或数据不足）。",
            "value": 9999  # Sentinel value
        }]
    }

    try:
        # Check if the required KPI input file exists (generated by correlation step)
        if kpi_result_file_path and os.path.exists(kpi_result_file_path) and os.path.getsize(kpi_result_file_path) > 0:
            logger.info(f"Calculating Random Forest model using KPI data: {kpi_result_file_path}")
            # Perform Random Forest model calculation
            mse_df, importance_df = calc_forest_model(kpi_result_file_path, correlation_analysis_path, env_en_name)
            logger.info(f"Random Forest model calculation completed for {env_name}.")

            # Process the importance results if successful and not empty
            if not importance_df.empty and 'Importance' in importance_df.columns and 'KPI' in importance_df.columns:
                logger.info(f"Processing Random Forest importance results. Found {len(importance_df)} features.")
                processed_importance = []
                top_importance_kpi = None
                top_importance_value = -1  # Initialize

                # Sort by importance descending to easily find the top one
                importance_df_sorted = importance_df.sort_values(by='Importance', ascending=False)

                for index, row in importance_df_sorted.iterrows():
                    # Check if importance value is valid
                    if pd.notna(row['Importance']):
                        kpi_name = row['KPI']
                        importance_value = row['Importance']
                        processed_importance.append({
                            "index_id": kpi_name,
                            "value": safe_format(importance_value)  # Format safely
                        })
                        # Track the top KPI (first one after sorting)
                        if top_importance_kpi is None:
                            top_importance_kpi = kpi_name
                            top_importance_value = importance_value

                # Update the result structure if valid importance data was found
                if processed_importance:
                    analysis_result_random_forest['importance_data'] = processed_importance
                    if top_importance_kpi:
                        # Update conclusion and solution based on the most important KPI
                        analysis_result_random_forest[
                            'conclusion'] = f"{env_name}环境中对平均处理时延影响最重要的指标是 {top_importance_kpi} (重要性: {safe_format(top_importance_value)})"
                        analysis_result_random_forest['solution'] = optimization_suggestions_random_forest.get(
                            top_importance_kpi, '该项指标暂无特定的优化建议。')
                        logger.info(f"Random Forest analysis processed. Most important KPI: {top_importance_kpi}")

                    else:
                        analysis_result_random_forest[
                            'conclusion'] = f"{env_name}环境计算得到指标重要性，但无法确定最重要指标。"
                        analysis_result_random_forest['solution'] = "请检查计算结果。"

                else:
                    # Keep the default error message if no valid importance values were found
                    logger.warning("Random Forest analysis yielded no valid numeric importance values.")

            elif importance_df.empty:
                logger.warning(
                    "Random Forest analysis resulted in an empty importance DataFrame. Check input KPI data.")
            else:
                logger.warning(
                    f"Columns 'Importance' or 'KPI' missing in importance result DataFrame. Columns found: {importance_df.columns.tolist()}")
                # Keep the default error message

        else:
            # Log warning if the prerequisite KPI file is missing or empty
            if not kpi_result_file_path:
                logger.warning(
                    "Skipping Random Forest Analysis because KPI file path was not generated (likely due to correlation analysis failure).")
            elif not os.path.exists(kpi_result_file_path):
                logger.warning(
                    f"Skipping Random Forest Analysis because KPI file does not exist: {kpi_result_file_path}")
            else:  # File exists but is empty
                logger.warning(f"Skipping Random Forest Analysis because KPI file is empty: {kpi_result_file_path}")
            # The default error messages initialized earlier will be used.

    except FileNotFoundError as e:
        logger.error(f"Random Forest analysis failed: Input KPI file not found. Error: {e}", exc_info=True)
        # Update only if the default hasn't already covered this
        if "未能成功建立" in analysis_result_random_forest['conclusion']:
            analysis_result_random_forest['conclusion'] = "随机森林分析失败：输入的KPI数据文件未找到。"
            analysis_result_random_forest[
                'solution'] = f"请确认文件 '{kpi_result_file_path}' 是否已由相关性分析成功生成。"
    except ValueError as e:
        logger.error(
            f"Random Forest analysis failed: Likely due to insufficient data or invalid values in KPI file. Error: {e}",
            exc_info=True)
        if "未能成功建立" in analysis_result_random_forest['conclusion']:
            analysis_result_random_forest['conclusion'] = "随机森林分析失败：KPI数据文件中的数据不足或包含无效值。"
            analysis_result_random_forest['solution'] = "请检查KPI数据文件的内容和格式。"
    except Exception as e:
        # Catch any other unexpected error during Random Forest analysis
        logger.error(f"Random Forest analysis failed with an unexpected error: {e}", exc_info=True)
        # Keep or update the default error message
        analysis_result_random_forest['conclusion'] = "随机森林分析失败：发生未知错误。"
        analysis_result_random_forest['solution'] = f"请检查日志输出获取详细错误信息。Error: {e}"
    finally:
        # Ensure the result dictionary always contains the RF analysis parts
        result["analysis_result_random_forest"] = analysis_result_random_forest

    # --- 3. Database Log Analysis ---
    logger.info(f"Starting Database Log Analysis for {env_name} environment.")
    # Extract request data from result_df (used for matching logs to requests)
    try:
        # Assuming 'Dataframe' column holds dictionaries mapping paths to details
        df_list_raw = result_df['Dataframe'].tolist()
        # Combine all dictionaries into one for easier lookup
        df_list = {}
        for item in df_list_raw:
            if isinstance(item, dict):
                df_list.update(item)
        logger.debug(f"Extracted {len(df_list)} request paths from result_df for log matching.")
    except KeyError:
        logger.error("'Dataframe' column not found in result_df. Cannot perform log matching.", exc_info=True)
        df_list = {}  # Set to empty dict to prevent downstream errors, analysis will be limited
    except Exception as e:
        logger.error(f"Error processing 'Dataframe' column from result_df: {e}", exc_info=True)
        df_list = {}

    # Initialize result structure with default/error message
    bottleneck_analysis_database = {
        "hostip": host_ip_str,
        "env": env_en_name,
        "class_name": f"{env_name}环境数据库日志分析",
        "details": [
            {
                "bottleneck_type": "分析失败或无数据",
                "cause": "未能加载或解析数据库日志，或无法关联到请求。",
                "count": 0,  # Default count
                "total_count": 0,  # Default total
                "ratio": 0,  # Default ratio
                "solution": "请检查数据库日志文件路径、格式以及与pcap数据的关联性，并查看程序日志。",
                "request_paths": []  # Default empty list
            }
        ]
    }
    # Define the threshold for slow database query execution time (in milliseconds)
    exec_time_threshold = 400  # Example threshold: 400ms
    logger.info(f"Database slow query threshold set to: {exec_time_threshold} ms")

    try:
        # Load database logs exceeding the threshold
        database_logs, database_logs_count = load_database_logs(json_path, exec_time_threshold)
        logger.info(f"Loaded {database_logs_count} total database log entries.")
        logger.info(f"Found {len(database_logs)} slow database queries (>{exec_time_threshold}ms).")

        analysis_database_logs: List[Dict[str, Any]] = []  # Type hint for clarity
        database_logs_ratio = 0.0

        if df_list and database_logs:
            # Match slow database logs with request data from result_df
            logger.info("Matching slow database logs to request paths...")
            analysis_database_logs = match_database_logs(
                database_logs,
                df_list  # Pass the combined dictionary
            )
            logger.info(
                f"Successfully matched {len(analysis_database_logs)} slow database queries to specific requests.")
        elif not df_list:
            logger.warning("Cannot match database logs as request path data ('df_list') is unavailable.")
        elif not database_logs:
            logger.info("No slow database queries found above the threshold.")

        # Calculate the ratio of matched slow queries to total log entries
        if database_logs_count > 0:
            database_logs_ratio = len(analysis_database_logs) / database_logs_count
        else:
            database_logs_ratio = 0.0  # Avoid division by zero

        # Determine bottleneck type and solution based on the ratio
        # Define a threshold for considering the ratio significant (e.g., 1%)
        significance_threshold = 0.01
        is_significant = database_logs_ratio > significance_threshold

        bottleneck_type = "数据库查询时间异常" if is_significant else "数据库查询无明显性能瓶颈"
        cause = f"部分请求关联到慢查询 (占比 {database_logs_ratio:.2%})" if is_significant else "未发现显著比例的慢查询或无法关联到请求"
        solution = f"建议排查关联请求 ({len(analysis_database_logs)}个) 的数据库查询性能，检查索引、SQL语句或数据库负载。" if is_significant else "数据库性能表现正常，或慢查询与捕获的请求关联性不强。"

        # Update the result structure
        bottleneck_analysis_database = {
            "hostip": host_ip_str,
            "env": env_en_name,
            "class_name": f"{env_name}环境数据库日志分析",
            "details": [
                {
                    "bottleneck_type": bottleneck_type,
                    "cause": cause,
                    "count": len(analysis_database_logs),  # Count of *matched* slow queries
                    "total_count": database_logs_count,  # Total DB log entries processed
                    "ratio": safe_format(database_logs_ratio),  # Ratio of *matched* slow queries to total
                    "solution": solution,
                    "request_paths": analysis_database_logs  # List of matched slow queries with context
                }
            ]
        }
        logger.info("Database log analysis completed.")

    except FileNotFoundError:
        logger.error(f"Database analysis failed: Input log file not found at {json_path}", exc_info=True)
        bottleneck_analysis_database['details'][0]['cause'] = f"输入的日志文件未找到: {json_path}"
        bottleneck_analysis_database['details'][0]['solution'] = "请确认日志文件路径是否正确。"
    except Exception as e:
        # Catch any other unexpected error during database analysis
        logger.error(f"Database analysis failed with an unexpected error: {e}", exc_info=True)
        # Use the default error message but add specific error details
        bottleneck_analysis_database['details'][0]['cause'] = f"分析过程中发生未知错误: {e}"
        bottleneck_analysis_database['details'][0]['solution'] = "请检查程序日志获取详细错误信息。"
        # Optionally add traceback:
        # bottleneck_analysis_database['details'][0]['error_details'] = traceback.format_exc()
    finally:
        # Ensure the result dictionary always contains the database analysis part
        result['bottleneck_analysis_database'] = bottleneck_analysis_database

    # --- 4. Exception Log Analysis ---
    logger.info(f"Starting Exception Log Analysis for {env_name} environment.")
    # Initialize result structure with default/error message
    bottleneck_analysis_exception = {
        "hostip": host_ip_str,
        "env": env_en_name,
        "class_name": f"{env_name}环境异常日志分析",
        "details": [
            {
                "bottleneck_type": "分析失败或无数据",
                "cause": "未能加载或解析异常日志，或无法关联到请求。",
                "total_count": 0,  # Default count
                "solution": "请检查异常日志文件路径、格式以及与pcap数据的关联性，并查看程序日志。",
                "request_paths": []  # Default empty list
            }
        ]
    }

    try:
        # Load exception logs
        exception_logs, exception_logs_count = load_exception_logs(json_path)
        logger.info(f"Loaded {exception_logs_count} total exception log entries.")
        logger.info(f"Found {len(exception_logs)} unique exception patterns.")  # load_exception_logs might aggregate

        analysis_exception_logs: List[Dict[str, Any]] = []  # Type hint

        if df_list and exception_logs:
            # Match exception logs with request data from result_df
            logger.info("Matching exception logs to request paths...")
            analysis_exception_logs = match_exception_logs(
                exception_logs,  # This might be aggregated exceptions
                df_list  # Pass the combined dictionary
            )
            logger.info(
                f"Successfully matched {len(analysis_exception_logs)} exception occurrences to specific requests.")
        elif not df_list:
            logger.warning("Cannot match exception logs as request path data ('df_list') is unavailable.")
        elif not exception_logs:
            logger.info("No exception logs found in the provided file.")

        # Determine bottleneck type and solution based on findings
        # Note: Unlike DB logs, we might not have a simple "slow" threshold. Presence of exceptions is usually the focus.
        # We report the total count found and the ones we could match.
        has_exceptions = exception_logs_count > 0
        has_matched_exceptions = len(analysis_exception_logs) > 0

        bottleneck_type = "发现程序异常" if has_exceptions else "未在日志中发现程序异常"
        cause = f"在 {exception_logs_count} 条日志中发现异常，其中 {len(analysis_exception_logs)} 条可关联到具体请求。" if has_matched_exceptions else f"在 {exception_logs_count} 条日志中发现异常，但未能关联到具体请求。" if has_exceptions else "未发现异常日志。"
        solution = f"建议排查关联请求 ({len(analysis_exception_logs)}个) 对应的程序模块功能，分析异常原因。" if has_matched_exceptions else "发现未关联的异常日志，建议检查日志模式或扩大pcap捕获时间范围以尝试关联。" if has_exceptions else "未发现异常，应用程序运行稳定。"

        # Update the result structure
        bottleneck_analysis_exception = {
            "hostip": host_ip_str,
            "env": env_en_name,
            "class_name": f"{env_name}环境异常日志分析",
            "details": [
                {
                    "bottleneck_type": bottleneck_type,
                    "cause": cause,
                    "total_count": exception_logs_count,  # Total exception entries found
                    # "matched_count": len(analysis_exception_logs), # Optionally add matched count explicitly
                    "solution": solution,
                    "request_paths": analysis_exception_logs  # List of matched exceptions with context
                }
            ]
        }
        logger.info("Exception log analysis completed.")

    except FileNotFoundError:
        logger.error(f"Exception analysis failed: Input log file not found at {json_path}", exc_info=True)
        bottleneck_analysis_exception['details'][0]['cause'] = f"输入的日志文件未找到: {json_path}"
        bottleneck_analysis_exception['details'][0]['solution'] = "请确认日志文件路径是否正确。"
    except Exception as e:
        # Catch any other unexpected error during exception analysis
        logger.error(f"Exception analysis failed with an unexpected error: {e}", exc_info=True)
        # Use the default error message but add specific error details
        bottleneck_analysis_exception['details'][0]['cause'] = f"分析过程中发生未知错误: {e}"
        bottleneck_analysis_exception['details'][0]['solution'] = "请检查程序日志获取详细错误信息。"
        # Optionally add traceback:
        # bottleneck_analysis_exception['details'][0]['error_details'] = traceback.format_exc()

    finally:
        # Ensure the result dictionary always contains the exception analysis part
        result['bottleneck_analysis_exception'] = bottleneck_analysis_exception

    # --- Result Return ---
    logger.info(f"General data analysis completed for side: {side}")
    return result
