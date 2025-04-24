import pandas as pd
import numpy as np  # Needed for NaN handling if not using pd.isna explicitly everywhere
from pathlib import Path  # For better path handling
from typing import Dict, Tuple, List, Any, Optional
import logging

logger = logging.getLogger(__name__)

# Project imports
from src.packet_analysis.services.json_build.suggestions import safe_format
from src.packet_analysis.services.json_build.correlation import load_kpi_mapping

# --- Configuration ---
DEFAULT_API_CONFIG_PATH = 'src/packet_analysis/services/json_build/api_config.txt'
STATS_COL = 'Time_since_request'
DECIMALS = 6


# --- Main Class ---

class DB:
    """
    Analyzes and compares performance metrics between production and replay environments
    using data loaded from Parquet files.
    """

    def __init__(self, parquet_production: str, parquet_back: str, api_config_path: str = DEFAULT_API_CONFIG_PATH):
        """
        Initializes the DB class.

        Args:
            parquet_production (str): Path to the production data Parquet file.
            parquet_back (str): Path to the replay (back) data Parquet file.
            api_config_path (str): Path to the API path description mapping file.
        """
        pd.options.display.float_format = f'{{:.{DECIMALS}f}}'.format  # Set pandas display format
        self.parquet_production = Path(parquet_production)
        self.parquet_back = Path(parquet_back)
        self.api_config_path = api_config_path

        try:
            logger.info(f"Loading production data from: {self.parquet_production}")
            self.df_product = pd.read_parquet(self.parquet_production)
            logger.info(f"Loading replay data from: {self.parquet_back}")
            self.df_back = pd.read_parquet(self.parquet_back)
            logger.info("Data loaded successfully.")
        except FileNotFoundError as e:
            logger.error(f"Error loading Parquet file: {e}")
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during data loading: {e}")
            raise  # Re-raise after logging

        self.request_info_dict = load_kpi_mapping(self.api_config_path)
        self._analysis_results: Optional[List[Dict[str, Any]]] = None
        self._path_delay_dict: Optional[Dict[str, Dict[str, float]]] = None
        self._contrast_delay_conclusion: Optional[str] = None

    def get_all_paths(self) -> List[str]:
        """Returns a list of unique 'Path' values from the production data."""
        if 'Path' not in self.df_product.columns:
            logger.error("Column 'Path' not found in production dataframe.")
            return []
        unique_values = self.df_product['Path'].unique()
        return list(unique_values)

    def _filter_data_for_url(self, url: str) -> Tuple[pd.DataFrame, pd.DataFrame, Optional[str]]:
        """Filters production and replay data for a specific URL."""
        df_prod_filtered = self.df_product[self.df_product['Path'] == url].copy()
        df_back_filtered = self.df_back[self.df_back['Path'] == url].copy()

        request_method = None
        if not df_prod_filtered.empty and 'Request_Method' in df_prod_filtered.columns:
            # Use mode(), handle potential multiple modes by taking the first
            modes = df_prod_filtered['Request_Method'].mode()
            if not modes.empty:
                request_method = modes[0]
        elif not df_back_filtered.empty and 'Request_Method' in df_back_filtered.columns:
            # Fallback to replay data if production is empty but has method
            modes = df_back_filtered['Request_Method'].mode()
            if not modes.empty:
                request_method = modes[0]

        return df_prod_filtered, df_back_filtered, request_method

    @staticmethod
    def _calculate_stats(df: pd.DataFrame, col: str) -> Dict[str, Optional[float]]:
        """Calculates count, mean, median, min, max for a DataFrame column."""
        stats = {'count': 0, 'mean': None, 'median': None, 'min': None, 'max': None}
        if df.empty or col not in df.columns or df[col].isnull().all():
            return stats  # Return defaults if df is empty, col missing, or all NaNs

        # Drop NaNs before calculating stats to avoid issues with some aggregations
        valid_data = df[col].dropna()
        if valid_data.empty:
            return stats  # Return defaults if only NaNs existed

        stats['count'] = len(df)  # Count all rows for this URL, even if Time_since_request is NaN
        agg_results = valid_data.agg(['mean', 'median', 'min', 'max'])
        stats.update(agg_results.to_dict())  # Update with calculated stats

        # Ensure numerical types (especially after potential NaNs)
        for key in ['mean', 'median', 'min', 'max']:
            if key in stats and not pd.isna(stats[key]):
                try:
                    stats[key] = float(stats[key])
                except (ValueError, TypeError):
                    logger.warning(f"Could not convert stat '{key}' ({stats[key]}) to float. Setting to None.")
                    stats[key] = None
        return stats

    def get_function_description(self, url: str, count_pro: int, count_replay: int) -> Dict[str, str]:
        """Generates a description string including function info and count comparison."""
        base_info = f"生产请求数量: {count_pro}, 回放请求数量: {count_replay}."
        description = f" 路径对应业务: {self.request_info_dict.get(url, 'N/A')}."  # Use .get for safety
        additional_info = ""

        if count_pro > 0 and count_replay > 0:
            try:
                # Avoid division by zero
                ratio = count_pro / count_replay if count_replay > 0 else float('inf')
                if ratio > 2:
                    additional_info = " WARNING: 回放请求数量显著低于生产环境。"
                elif count_replay / count_pro > 2:  # Check the other way too
                    additional_info = " WARNING: 生产请求数量显著低于回放。"
                else:
                    additional_info = " 两环境请求数量相当。"
            except ZeroDivisionError:
                additional_info = " Note: 由于回放中请求数为零，无法比较计数。"
        elif count_pro == 0 and count_replay > 0:
            additional_info = " Note: 仅发现回放环境请求。"
        elif count_pro > 0 and count_replay == 0:
            additional_info = " Note: 仅发现生产环境请求。"
        else:
            additional_info = " Note: 未在任一环境中找到针对此URL的请求。"

        return {"function_description": base_info + description + additional_info}

    def built_single_dict(self, url: str, df_prod: pd.DataFrame, df_back: pd.DataFrame,
                          request_method: Optional[str]) -> Dict[str, Any]:
        """Builds a dictionary with calculated statistics for a single URL."""
        prod_stats = self._calculate_stats(df_prod, STATS_COL)
        back_stats = self._calculate_stats(df_back, STATS_COL)

        prod_mean = prod_stats.get('mean')
        back_mean = back_stats.get('mean')

        # Calculate difference ratio safely
        difference_ratio = None
        if back_mean is not None and prod_mean is not None and prod_mean != 0:
            difference_ratio = back_mean / prod_mean
        elif back_mean is not None and (prod_mean is None or prod_mean == 0):
            difference_ratio = float('inf')  # Replay exists, production doesn't or is zero

        # Get description and counts
        description_info = self.get_function_description(url, int(prod_stats['count']),
                                                         int(back_stats['count']))  # Ensure counts are int

        single_dict = {
            'url': url,
            'request_method': request_method if request_method else None,
            'production_delay_mean': safe_format(prod_mean),
            'replay_delay_mean': safe_format(back_mean),
            'production_delay_median': safe_format(prod_stats.get('median')),
            'replay_delay_median': safe_format(back_stats.get('median')),
            'production_delay_min': safe_format(prod_stats.get('min')),
            'replay_delay_min': safe_format(back_stats.get('min')),
            'production_delay_max': safe_format(prod_stats.get('max')),
            'replay_delay_max': safe_format(back_stats.get('max')),
            'mean_difference_ratio': safe_format(difference_ratio),
            'request_count_production': int(prod_stats['count']),
            'request_count_replay': int(back_stats['count']),
        }
        single_dict.update(description_info)  # Add analysis notes

        return single_dict

    def get_difference_ratio_weighted(self, all_df_list: List[Dict[str, Any]]) -> str:
        """计算加权平均值并提供摘要对比"""
        total_prod_requests = 0
        total_replay_requests = 0
        total_weighted_production_delay = 0.0
        total_weighted_replay_delay = 0.0

        # 使用生产环境请求数作为权重
        total_weight = 0.0

        for df_dict in all_df_list:
            try:
                prod_mean = float(df_dict['production_delay_mean'])
                replay_mean = float(df_dict['replay_delay_mean'])
                prod_count = int(df_dict['request_count_production'])

                # 仅当两个均值都有效且生产环境计数>0时纳入加权计算
                if not pd.isna(prod_mean) and not pd.isna(replay_mean) and prod_count > 0:
                    weight = prod_count  # 以生产环境请求数为权重
                    total_weighted_production_delay += prod_mean * weight
                    total_weighted_replay_delay += replay_mean * weight
                    total_weight += weight

                total_prod_requests += prod_count
                total_replay_requests += int(df_dict['request_count_replay'])

            except (ValueError, TypeError, KeyError) as e:
                logger.warning(
                    f"跳过无效数据条目: {df_dict.get('url', 'N/A')}, 错误: {e}")
                continue

        if total_weight == 0:
            return "无法进行整体比较：未找到具有有效延迟的可比请求"

        overall_production_delay = total_weighted_production_delay / total_weight
        overall_replay_delay = total_weighted_replay_delay / total_weight

        # 总结结论
        faster_env = "生产环境" if overall_production_delay <= overall_replay_delay else "回放环境"
        slower_env = "回放环境" if faster_env == "生产环境" else "生产环境"

        conclusion = (
            f"整体加权比较（分析 {total_prod_requests:,} 个生产请求 / {total_replay_requests:,} 个回放请求）：\n"
            f"  - 加权平均生产延迟: {overall_production_delay:.{DECIMALS}f}秒\n"
            f"  - 加权平均回放延迟: {overall_replay_delay:.{DECIMALS}f}秒\n"
            f"  - 结论: {faster_env}的加权平均延迟低于{slower_env}"
        )
        return conclusion

    def analyze_all(self) -> None:
        """Performs the full analysis across all URLs."""
        if self._analysis_results is not None:
            logger.info("Analysis already performed. Skipping re-computation.")
            return

        all_results = []
        path_delay_dict = {}
        all_paths = self.get_all_paths()
        if not all_paths:
            logger.warning("No paths found to analyze in production data.")
            self._analysis_results = []
            self._path_delay_dict = {}
            self._contrast_delay_conclusion = "No data to analyze."
            return

        logger.info(f"Analyzing {len(all_paths)} unique paths...")
        for i, url in enumerate(all_paths):
            if (i + 1) % 50 == 0:  # Log progress
                logger.info(f"  Processed {i + 1}/{len(all_paths)} paths...")

            df_prod, df_back, req_method = self._filter_data_for_url(url)
            single_dict = self.built_single_dict(url, df_prod, df_back, req_method)
            all_results.append(single_dict)

            # Store raw means (handle potential string conversion issues if needed)
            try:
                prod_mean_val = float(single_dict['production_delay_mean']) if single_dict[
                                                                                   'production_delay_mean'] is not None else np.nan
                replay_mean_val = float(single_dict['replay_delay_mean']) if single_dict[
                                                                                 'replay_delay_mean'] is not None else np.nan
            except ValueError:
                prod_mean_val = np.nan
                replay_mean_val = np.nan

            path_delay_dict[url] = {
                "production_delay_mean": prod_mean_val,
                "replay_delay_mean": replay_mean_val,
            }

        logger.info("Analysis complete. Calculating overall summary...")
        self._analysis_results = all_results
        self._path_delay_dict = path_delay_dict
        self._contrast_delay_conclusion = self.get_difference_ratio_weighted(all_results)
        logger.info("Overall summary calculated.")

    def get_analysis_results(self) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, float]], str]:
        """
         Returns the analysis results. Performs analysis if not already done.

         Returns:
             Tuple containing:
               - List of dictionaries, one for each URL with detailed stats.
               - Dictionary mapping URL to its production and replay mean delays.
               - String containing the overall weighted comparison conclusion.
         """
        if self._analysis_results is None or self._path_delay_dict is None or self._contrast_delay_conclusion is None:
            logger.info("Analysis results not found, running analysis...")
            self.analyze_all()
        # Ensure None isn't returned if analysis failed to produce results
        return self._analysis_results or [], self._path_delay_dict or {}, self._contrast_delay_conclusion or "Analysis failed or produced no results."

    def add_mean_delay_to_dataframes(self) -> None:
        """Adds the calculated mean delay for each path back to the original DataFrames."""
        _, path_delay_dict, _ = self.get_analysis_results()  # Ensure analysis is done

        if not path_delay_dict:
            logger.warning("Path delay dictionary is empty. Cannot add mean delays.")
            return

        logger.info("Adding average delays back to original DataFrames...")

        # Create Series mappers from the path_delay_dict
        prod_mean_map = {url: data.get("production_delay_mean") for url, data in path_delay_dict.items()}
        replay_mean_map = {url: data.get("replay_delay_mean") for url, data in path_delay_dict.items()}

        # Map the means; use .get inside lambda for robustness if a path is missing in dict (shouldn't happen with current logic)
        self.df_product['average_delay'] = self.df_product['Path'].map(
            lambda p: prod_mean_map.get(p))  # Fill with NaN if path not found
        self.df_back['average_delay'] = self.df_back['Path'].map(
            lambda p: replay_mean_map.get(p))  # Fill with NaN if path not found
        logger.info("Average delays added.")

    def save_results(self, output_summary_parquet: str, output_plot_png: Optional[str] = None) -> None:
        """
        Saves the analysis summary to a Parquet file, optionally generates a plot,
        and overwrites the original input Parquet files with added average delay column.

        Args:
            output_summary_parquet (str): Path to save the summary results Parquet file.
            output_plot_png (str, optional): Path to save the difference ratio plot PNG file. If None, plot is not saved.
        """
        all_dicts, _, conclusion = self.get_analysis_results()  # Ensure analysis is done

        if not all_dicts:
            logger.warning("No analysis results to save.")
            return

        # 1. Save Summary DataFrame
        logger.info(f"Saving analysis summary to: {output_summary_parquet}")
        summary_df = pd.DataFrame(all_dicts)
        try:
            summary_df.to_parquet(output_summary_parquet, index=False)
            logger.info("Summary saved successfully.")
            print("\n" + "=" * 30 + " Overall Summary " + "=" * 30)
            print(conclusion)
            print("=" * 77 + "\n")
        except Exception as e:
            logger.error(f"Failed to save summary Parquet file: {e}")

        # 2. Add mean delay and Save Augmented Original DataFrames (Overwrite)
        try:
            self.add_mean_delay_to_dataframes()
            logger.info(f"Saving augmented production data back to: {self.parquet_production}")
            self.df_product.to_parquet(self.parquet_production, index=False)
            logger.info(f"Saving augmented replay data back to: {self.parquet_back}")
            self.df_back.to_parquet(self.parquet_back, index=False)
            logger.info("Augmented dataframes saved successfully (overwritten).")
        except Exception as e:
            logger.error(f"Failed to save augmented dataframes: {e}")

        # 3. Generate and Save Plot (Optional)
        if output_plot_png:
            logger.info(f"Generating and saving plot to: {output_plot_png}")
            try:
                self.plot_mean_difference_ratio(summary_df, output_plot_png)
                logger.info("Plot saved successfully.")
            except Exception as e:
                logger.error(f"Failed to generate or save plot: {e}")

    # def plot_mean_difference_ratio(self, summary_df: pd.DataFrame, file_name: str) -> None:
    #     """Generates and saves a bar plot of the mean difference ratios."""
    #     if summary_df.empty or 'mean_difference_ratio' not in summary_df.columns:
    #         logger.warning("Summary DataFrame is empty or missing 'mean_difference_ratio' column. Cannot generate plot.")
    #         return
    #
    #     # Convert ratio to numeric, coercing errors to NaN
    #     summary_df['ratio_float'] = pd.to_numeric(summary_df['mean_difference_ratio'], errors='coerce')
    #
    #     # Filter out NaN ratios and potentially infinite values if desired
    #     plot_df = summary_df.dropna(subset=['ratio_float'])
    #     plot_df = plot_df[np.isfinite(plot_df['ratio_float'])] # Remove Inf/-Inf if they exist
    #
    #     if plot_df.empty:
    #          logger.warning("No valid data points to plot after cleaning ratios.")
    #          return
    #
    #     plt.figure(figsize=(max(14, len(plot_df)*0.5), 8)) # Dynamic width based on number of bars
    #
    #     # Colors: Blue if ratio >= 1 (Replay slower or equal), Red if ratio < 1 (Replay faster)
    #     colors = ['blue' if ratio >= 1 else 'red' for ratio in plot_df['ratio_float']]
    #
    #     bars = plt.bar(plot_df['url'], plot_df['ratio_float'], color=colors)
    #
    #     plt.xlabel('URL Path', fontsize=10)
    #     plt.ylabel('Mean Difference Ratio (Replay Mean / Production Mean)', fontsize=10)
    #     plt.title('Mean Response Time Ratio (Replay vs Production) per URL', fontsize=12)
    #     plt.axhline(1, color='grey', linestyle='--', linewidth=0.8) # Line at ratio = 1 for reference
    #     plt.xticks(rotation=60, ha='right', fontsize=8) # Rotate more for potentially long URLs
    #     plt.yticks(fontsize=9)
    #     plt.grid(axis='y', linestyle=':', alpha=0.6)
    #     plt.tight_layout() # Adjust layout
    #
    #     # Add value labels on bars
    #     for bar in bars:
    #         height = bar.get_height()
    #         plt.text(bar.get_x() + bar.get_width() / 2.0, height, f'{height:.2f}',
    #                  ha='center', va='bottom', fontsize=7, rotation=0)
    #
    #     try:
    #         plt.savefig(file_name, dpi=150) # Increase DPI for better resolution
    #         # plt.show() # Uncomment if you want to display the plot interactively
    #         plt.close() # Close the figure to free memory
    #     except Exception as e:
    #         logger.error(f"Error saving plot '{file_name}': {e}")


# Example Usage:
if __name__ == '__main__':
    # Create dummy Parquet files for demonstration
    # In a real scenario, these files would already exist.
    data_prod = {
        'Path': ['/api/v1/users', '/api/v1/items', '/api/v1/users', '/api/v1/orders', '/api/v1/items', '/api/v1/users'],
        'Request_Method': ['GET', 'GET', 'GET', 'POST', 'GET', 'GET'],
        'Time_since_request': [0.12, 0.35, 0.15, 0.80, 0.40, 0.11]
    }
    data_back = {
        'Path': ['/api/v1/users', '/api/v1/items', '/api/v1/users', '/api/v1/items', '/api/v1/users',
                 '/api/v1/unknown'],
        'Request_Method': ['GET', 'GET', 'GET', 'GET', 'GET', 'GET'],
        'Time_since_request': [0.10, 0.50, 0.11, 0.45, 0.09, 1.2]  # Replay times
    }
    df_prod_dummy = pd.DataFrame(data_prod)
    df_back_dummy = pd.DataFrame(data_back)

    prod_parquet_path = 'production_data_demo.parquet'
    back_parquet_path = 'replay_data_demo.parquet'
    summary_output_path = 'analysis_summary_demo.parquet'
    plot_output_path = 'difference_ratio_plot_demo.png'
    api_config_demo_path = 'api_config_demo.txt'

    df_prod_dummy.to_parquet(prod_parquet_path)
    df_back_dummy.to_parquet(back_parquet_path)

    # Create a dummy API config file
    with open(api_config_demo_path, 'w', encoding='utf-8') as f:
        f.write("/api/v1/users: Get user list\n")
        f.write("/api/v1/items: Get item list\n")
        f.write("#/api/v1/orders: Create order (commented out)\n")
        f.write("/api/v1/orders: Submit a new order\n")  # Example with actual description

    logger.info("--- Starting Analysis ---")

    # Initialize the DB class with Parquet paths
    analyzer = DB(parquet_production=prod_parquet_path,
                  parquet_back=back_parquet_path,
                  api_config_path=api_config_demo_path)

    # Perform analysis and save results
    analyzer.save_results(output_summary_parquet=summary_output_path,
                          output_plot_png=plot_output_path)

    logger.info("--- Analysis Finished ---")

    # Verify output (optional)
    print(f"\nSummary saved to: {summary_output_path}")
    if Path(summary_output_path).exists():
        summary = pd.read_parquet(summary_output_path)
        print("Summary DataFrame Head:\n", summary.head())

    print(f"\nPlot saved to: {plot_output_path}")

    print(f"\nOriginal data files ({prod_parquet_path}, {back_parquet_path}) updated with 'average_delay' column.")
    if Path(prod_parquet_path).exists():
        updated_prod = pd.read_parquet(prod_parquet_path)
        print("Updated Production DataFrame Head:\n", updated_prod.head())

    # Clean up dummy files (optional)
    # Path(prod_parquet_path).unlink(missing_ok=True)
    # Path(back_parquet_path).unlink(missing_ok=True)
    # Path(summary_output_path).unlink(missing_ok=True)
    # Path(plot_output_path).unlink(missing_ok=True)
    # Path(api_config_demo_path).unlink(missing_ok=True)
