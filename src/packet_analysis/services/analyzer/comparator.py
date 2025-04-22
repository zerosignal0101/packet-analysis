import os
from typing import List, Dict, Any
import logging
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from pathlib import Path

# Project imports
from src.packet_analysis.config import Config
from src.packet_analysis.services.json_build.correlation import load_kpi_mapping
from src.packet_analysis.services.analyzer.data_align import alignment_two_paths

# Logger
logger = logging.getLogger(__name__)


def compare_producer_playback(
        producer_data: Dict[str, Any],
        playback_data: Dict[str, Any],
        options: Dict[str, Any]) -> Dict[str, Any]:
    """
    TODO: Implement comparison between producer and playback data
    - Align producer and playback data streams
    - Calculate synchronization metrics
    - Identify discrepancies between original and playback
    """
    # Debug
    if Config.DEBUG:
        logger.debug("Comparing producer and playback data")
        logger.debug(f"Producer data: {producer_data}")
        logger.debug(f"Playback data: {playback_data}")

    # Path 路径
    Path(options['task_result_path']).mkdir(parents=True, exist_ok=True)
    producer_parquet_file_path = producer_data['parquet_file_path']
    playback_parquet_file_path = playback_data['parquet_file_path']
    alignment_parquet_file_path = os.path.join(options['task_result_path'], f"alignment_{options['pcap_info_idx']}.parquet")
    # Align 对齐
    alignment_two_paths(producer_parquet_file_path, playback_parquet_file_path, alignment_parquet_file_path)


    contrast_delay_conclusion = None
    res = {
        "comparison_analysis": {},
        "anomaly_detection": {},
    }
    anomaly_dict = [{
        "request_url": "/portal_todo/api/getAllUserTodoData",
        "env": "production",
        "count": 9999,  # hyf 修改格式
        "hostip": ", ".join(options["producer_host_ip_list"]),
        "class_method": "api_get",
        "bottleneck_cause": "(当前该部分为展示样例)",
        "solution": "(当前该部分为展示样例)"
    }]
    res['anomaly_detection']['dict'] = anomaly_dict
    if Config.DEBUG:
        logger.debug(f"Anomaly_dict data: {anomaly_dict}")
    return []


class MergedFrame:
    def __init__(self, url, request_method, back_dataframe, production_dataframe):
        self.url = url
        self.request_method = request_method
        self.data_back = back_dataframe
        self.data_production = production_dataframe

    def get_production_delay_mean(self):
        return round(self.data_production['Time_since_request'].mean(), 6)

    def get_replay_delay_mean(self):
        return round(self.data_back['Time_since_request'].mean(), 6)

    def get_replay_delay_median(self):
        return round(self.data_back['Time_since_request'].median(), 6)

    def get_production_delay_median(self):
        return round(self.data_production['Time_since_request'].median(), 6)

    def get_production_delay_max(self):
        return round(self.data_production['Time_since_request'].max(), 6)

    def get_replay_delay_max(self):
        return round(self.data_back['Time_since_request'].max(), 6)

    def get_production_delay_min(self):
        return round(self.data_production['Time_since_request'].min(), 6)

    def get_replay_delay_min(self):
        return round(self.data_back['Time_since_request'].min(), 6)

    def get_request_count(self):
        return self.data_production.shape[0]

    def get_request_count_replay(self):
        return self.data_back.shape[0]

    def get_difference_ratio(self):
        return round(self.get_replay_delay_mean() / self.get_production_delay_mean(), 6)


class DB:
    def __init__(self, csv_production, csv_back):
        pd.options.display.float_format = '{:.6f}'.format  # 保证数值不使用科学计数法
        self.csv_production = csv_production  # 保存文件路径
        self.csv_back = csv_back
        self.df_product = pd.read_csv(csv_production, encoding='utf-8')
        self.df_back = pd.read_csv(csv_back, encoding='utf-8')
        self.request_info_dict = load_kpi_mapping('src/packet_analysis/services/json_build/api_config.txt')

    def get_all_path(self):
        unique_values = self.df_product['Path'].unique()
        unique_values_list = list(unique_values)
        return unique_values_list

    def built_df(self, url):
        df_product = self.df_product[self.df_product['Path'] == url]
        df_back = self.df_back[self.df_back['Path'] == url]

        # Extract the most frequent Request_Method for this URL
        if not df_product.empty:
            request_method = df_product['Request_Method'].mode()[0]
        else:
            request_method = None

        dataframe = MergedFrame(url, request_method, df_back, df_product)
        production_delay_mean = dataframe.get_production_delay_mean()

        replay_delay_mean = dataframe.get_replay_delay_mean()

        return dataframe, production_delay_mean, replay_delay_mean

    # def get_function_description(self, url, count_pro, count_replay):
    #     """
    #     查询路径的功能描述信息，返回对应的详细说明。
    #     """
    #     if url in self.request_info_dict:
    #         return {"function_description": self.request_info_dict[url]}
    #     else:
    #         return {"function_description": "未查询到功能介绍"}

    def get_function_description(self, url, count_pro, count_replay):
        """
        查询路径的功能描述信息，返回对应的详细说明。
        参数:
            url (str): 请求的 URL 路径。
            count_pro (int): 生产环境中该 URL 请求的数量。
            count_replay (int): 回放环境中该 URL 请求的数量。
        返回:
            dict: 包含功能描述和请求数量信息的字典。
        """
        # 基础信息
        base_info = f"生产环境请求了 {count_pro} 次，回放环境请求了 {count_replay} 次。"

        # 判断是否存在功能描述
        if url in self.request_info_dict:
            description = f"该请求的功能介绍：{self.request_info_dict[url]}"
        else:
            description = "未查询到功能介绍"
        # 判断是否需要增加额外提示
        additional_info = ""
        if count_pro > 0 and count_replay > 0 and count_pro / count_replay > 2:
            additional_info = " 该请求回放环境的数据量远远不够，请仔细检查相关信息。"
        elif count_pro > 0 and count_replay > 0 and count_pro / count_replay <= 2:
            additional_info = " 该请求生产环境和回放环境数据量基本正常"

        # 返回最终信息
        return {
            "function_description": base_info + description + additional_info
        }

    # def built_single_dict(self, df: df):
    #     df_dict = {}
    #     production_delay_mean = "{:.6f}".format(df.get_production_delay_mean())
    #     replay_delay_mean = "{:.6f}".format(df.get_replay_delay_mean())
    #     replay_delay_median = "{:.6f}".format(df.get_replay_delay_median())
    #     production_delay_median = "{:.6f}".format(df.get_production_delay_median())
    #     production_delay_max = "{:.6f}".format(df.get_production_delay_max())
    #     replay_delay_max = "{:.6f}".format(df.get_replay_delay_max())
    #     production_delay_min = "{:.6f}".format(df.get_production_delay_min())
    #     replay_delay_min = "{:.6f}".format(df.get_replay_delay_min())
    #     request_count = df.get_request_count()
    #     difference_ratio = "{:.6f}".format(df.get_difference_ratio())

    #     # Get additional information from the function description file
    #     description_info = self.get_function_description(df.url)

    #     df_dict['url'] = df.url
    #     df_dict['request_method'] = df.request_method
    #     df_dict['production_delay_mean'] = production_delay_mean
    #     df_dict['replay_delay_mean'] = replay_delay_mean
    #     df_dict['production_delay_median'] = production_delay_median
    #     df_dict['replay_delay_median'] = replay_delay_median
    #     df_dict['production_delay_min'] = production_delay_min
    #     df_dict['replay_delay_min'] = replay_delay_min
    #     df_dict['production_delay_max'] = production_delay_max
    #     df_dict['replay_delay_max'] = replay_delay_max
    #     df_dict['mean_difference_ratio'] = difference_ratio
    #     df_dict['request_count'] = request_count
    #     df_dict.update(description_info)

    #     return df_dict

    def built_single_dict(self, df: MergedFrame):
        def safe_format(value):
            # 如果值是 NaN 或 None，则返回 0 或其他默认值
            if pd.isna(value):
                return "0"  # 或者根据需求返回 None
            return "{:.6f}".format(value)

        df_dict = {}
        production_delay_mean = safe_format(df.get_production_delay_mean())
        replay_delay_mean = safe_format(df.get_replay_delay_mean())
        replay_delay_median = safe_format(df.get_replay_delay_median())
        production_delay_median = safe_format(df.get_production_delay_median())
        production_delay_max = safe_format(df.get_production_delay_max())
        replay_delay_max = safe_format(df.get_replay_delay_max())
        production_delay_min = safe_format(df.get_production_delay_min())
        replay_delay_min = safe_format(df.get_replay_delay_min())
        difference_ratio = safe_format(df.get_difference_ratio())

        request_count = df.get_request_count()
        request_count_replay = df.get_request_count_replay()

        # Get additional information from the function description file
        description_info = self.get_function_description(df.url, request_count, request_count_replay)

        df_dict['url'] = df.url
        df_dict['request_method'] = df.request_method
        df_dict['production_delay_mean'] = production_delay_mean
        df_dict['replay_delay_mean'] = replay_delay_mean
        df_dict['production_delay_median'] = production_delay_median
        df_dict['replay_delay_median'] = replay_delay_median
        df_dict['production_delay_min'] = production_delay_min
        df_dict['replay_delay_min'] = replay_delay_min
        df_dict['production_delay_max'] = production_delay_max
        df_dict['replay_delay_max'] = replay_delay_max
        df_dict['mean_difference_ratio'] = difference_ratio
        df_dict['request_count'] = request_count
        df_dict.update(description_info)

        return df_dict

    def get_difference_ratio_weighted(self, all_df_list):
        # 用来统计总请求数、回放时延较低的请求数和生产时延较低的请求数
        total_requests = 0
        replay_lower_count = 0
        production_lower_count = 0

        total_weighted_production_delay = 0
        total_weighted_replay_delay = 0

        # 用来加权计算
        weighted_replay = 0
        weighted_production = 0

        for df_dict in all_df_list:
            # 获取每个 URL 的信息
            difference_ratio = float(df_dict['mean_difference_ratio'])  # difference_ratio
            request_count = df_dict['request_count']  # 每种请求的数量
            production_delay_mean = float(df_dict["production_delay_mean"])
            replay_delay_mean = float(df_dict["replay_delay_mean"])

            total_requests += request_count  # 累加总请求数

            # 如果该url不存在回放请求，为保证加权平均时延的一致性，生产的也不计算了
            if replay_delay_mean != 0.0:
                total_weighted_production_delay += production_delay_mean * request_count
                total_weighted_replay_delay += replay_delay_mean * request_count
            else:
                total_weighted_production_delay += 0
                total_weighted_replay_delay += 0

            if difference_ratio >= 1:
                production_lower_count += request_count  # 生产时延较低
                weighted_production += request_count * difference_ratio  # 加权计算生产时延

            else:
                replay_lower_count += request_count  # 回放时延较低
                if difference_ratio != 0.0:
                    weighted_replay += request_count * (1 / difference_ratio)  # 加权计算回放时延
                else:
                    weighted_replay += 0

        # 计算整体加权
        weighted_average_production = weighted_production / total_requests
        weighted_average_replay = weighted_replay / total_requests

        overall_production_delay = total_weighted_production_delay / total_requests
        overall_replay_delay = total_weighted_replay_delay / total_requests

        # 得出结论
        if overall_replay_delay > overall_production_delay:
            contrast_delay_conclusion = f"生产环境整体时延较低,生产环境加权平均时延为{round(overall_production_delay, 6)}s,回放环境加权平均时延为{round(overall_replay_delay, 6)}s,生产环境时延低的权重为：{weighted_average_production}, 回放环境时延低的权重为：{weighted_average_replay},生产较快的请求数为{production_lower_count},回放较快的请求数为{replay_lower_count},总请求数为{total_requests}"
        else:
            contrast_delay_conclusion = f"回放环境整体时延较低,回放环境加权平均时延为{round(overall_replay_delay, 6)}s,生产环境加权平均时延为{round(overall_production_delay, 6)}s,回放环境时延低的权重为：{weighted_average_replay}, 生产环境时延低的权重为：{weighted_average_production},回放较快的请求数为{replay_lower_count},生产较快的请求数为{production_lower_count},总请求数为{total_requests}"

        return contrast_delay_conclusion

    def built_all_dict(self):
        all_df_list = []
        path_delay_dict = {}
        for url in self.get_all_path():
            df, production_delay_mean, replay_delay_mean = self.built_df(url)  # 先构建了一个df结构
            all_df_list.append(self.built_single_dict(df))
            path_delay_dict[url] = {
                "production_delay_mean": production_delay_mean,

                "replay_delay_mean": replay_delay_mean,

            }
        contrast_delay_conclusion = self.get_difference_ratio_weighted(all_df_list)
        return all_df_list, path_delay_dict, contrast_delay_conclusion

    def add_delay_to_df(self):
        _, path_delay_dict, _ = self.built_all_dict()

        # 遍历 path，给 self.df_product 和 self.df_back 添加平均值
        self.df_product['average_delay'] = self.df_product['Path'].map(
            lambda path: path_delay_dict.get(path, {}).get("production_delay_mean", None)
        )

        self.df_back['average_delay'] = self.df_back['Path'].map(
            lambda path: path_delay_dict.get(path, {}).get("replay_delay_mean", None)
        )

    def save_to_csv(self, file_name):
        self.add_delay_to_df()
        self.df_product.to_csv(self.csv_production, encoding='utf-8-sig', index=False)
        self.df_back.to_csv(self.csv_back, encoding='utf-8-sig', index=False)

        all_dicts, _, _ = self.built_all_dict()
        df_result = pd.DataFrame(all_dicts)
        df_result.to_csv(file_name, encoding='utf-8-sig', index=False)  # 使用'utf-8-sig'编码保证中文不乱码

    # def plot_mean_difference_ratio(self, file_name):
    #     all_dicts, _, _ = self.built_all_dict()
    #     df_result = pd.DataFrame(all_dicts)
    #
    #     # 将'mean_difference_ratio'转为浮点数
    #     df_result['mean_difference_ratio'] = df_result['mean_difference_ratio'].astype(float)
    #
    #     plt.figure(figsize=(14, 8))  # 调整图片尺寸
    #
    #     # 颜色：如果mean_difference_ratio小于1，则柱状图为红色，否则为蓝色
    #     colors = ['red' if ratio < 1 else 'blue' for ratio in df_result['mean_difference_ratio']]
    #
    #     bars = plt.bar(df_result['url'], df_result['mean_difference_ratio'], color=colors)
    #
    #     plt.xlabel('URL', fontsize=10)  # 调整x轴标签字体大小
    #     plt.ylabel('Mean Difference Ratio', fontsize=10)  # 调整y轴标签字体大小
    #     plt.title('Mean Difference Ratio for Each Request', fontsize=12)  # 调整标题字体大小
    #
    #     plt.xticks(rotation=45, ha='right', fontsize=8)  # 旋转x轴标签并调整字体大小
    #     plt.tight_layout()  # 自动调整布局防止重叠
    #
    #     # 在柱状图上方显示数值，调整字体大小
    #     for bar in bars:
    #         height = bar.get_height()
    #         plt.text(bar.get_x() + bar.get_width() / 2.0, height, f'{height:.2f}', ha='center', va='bottom', fontsize=8)
    #
    #     plt.savefig(file_name)
    #     # plt.show()