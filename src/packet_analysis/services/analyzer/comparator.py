import os
from collections import defaultdict
from typing import List, Dict, Any
import logging
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from pathlib import Path
from datetime import datetime

# Project imports
from src.packet_analysis.config import Config
from src.packet_analysis.services.analyzer.data_align import alignment_two_paths
from src.packet_analysis.services.json_build.alignment_analysis import analyze_status_code, analyze_empty_responses, \
    analyze_zero_window_issues
from src.packet_analysis.services.json_build.anomaly import analysis, process_anomalies
from src.packet_analysis.services.json_build.comparison import DB
from src.packet_analysis.services.json_build.suggestions import safe_format, get_bottleneck_analysis
from src.packet_analysis.utils.dict_checker import check_json_serializable

# Logger
logger = logging.getLogger(__name__)


def compare_producer_playback(
        producer_data: Dict[str, Any],
        playback_data: Dict[str, Any],
        options: Dict[str, Any]):
    """
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
    outputs_path = Path(options['task_result_path'])
    pcap_info_idx = options['pcap_info_idx']
    producer_parquet_file_path = producer_data['parquet_file_path']
    playback_parquet_file_path = playback_data['parquet_file_path']
    alignment_parquet_file_path = os.path.join(options['task_result_path'], f"alignment_{pcap_info_idx}.parquet")
    # IP str
    producer_host_ip_str: str = ", ".join(options['producer_host_ip_list'])
    playback_host_ip_str: str = ", ".join(options['playback_host_ip_list'])
    # Align 对齐
    alignment_df = alignment_two_paths(producer_parquet_file_path, playback_parquet_file_path,
                                       alignment_parquet_file_path)

    # Anomaly_dict
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
    try:
        # Process CSV files and get comparison analysis data to build JSON
        logger.info(f"json comparison started at {datetime.now()}")
        comparison_database = DB(producer_parquet_file_path, playback_parquet_file_path)
        data_list, path_delay_dict, contrast_delay_conclusion = comparison_database.get_analysis_results()
        # process data list merge request_count_replay and request_count_production
        new_data_list = []  # 创建一个新的列表来存储处理后的字典
        for item in data_list:
            if 'request_count_production' in item and 'request_count_replay' in item:
                # # 创建新的 'request_count' 键，其值为一个字典
                # request_count = {
                #     'production': item['request_count_production'],
                #     'replay': item['request_count_replay']
                # }
                # 创建新的 'request_count' 键，其值为一个 int 和
                request_count = item['request_count_production'] + item['request_count_replay']

                # 创建一个新的字典，复制原字典并添加新键
                new_item = item.copy()  # 使用 copy() 进行浅复制
                new_item['request_count'] = request_count  # 添加新的键

                # 删除原来的键
                if 'request_count_production' in new_item:
                    del new_item['request_count_production']
                if 'request_count_replay' in new_item:
                    del new_item['request_count_replay']

                new_data_list.append(new_item)  # 添加处理后的字典到新列表
            else:
                # 如果字典中不包含这些键，则直接添加原字典（可选，根据需求调整）
                new_data_list.append(item)

        data_list = new_data_list

        # Update response with the data_list for the current analysis
        data_legend = {
            "production": "生产环境",
            "replay": "回放环境",
            "mean_difference_ratio": "差异倍数"
        }
        # res['comparison_analysis']['data'] = data_list
        res['replay_task_id'] = options['replay_task_id']
        res['replay_id'] = options['replay_id']
        res['comparison_analysis']['title'] = "生产与回放环境处理时延对比分析"
        res['comparison_analysis']['x_axis_label'] = "请求路径"
        res['comparison_analysis']['y_axis_label'] = "时延（s）"
        res['comparison_analysis']['data'] = data_list
        res['comparison_analysis']['legend'] = data_legend

        # production cluster anomaly and replay cluster anomaly 在这一步，不同组数据发生报错 该步骤输出classifiy文件 分类后每一类的异常数据文件
        folder_output_pro = os.path.join(outputs_path, f"cluster_production_{pcap_info_idx}")
        pro_anomaly_csv_list, pro_plot_cluster_list = analysis(producer_parquet_file_path, folder_output_pro,
                                                               pcap_info_idx, data_list, env='pro')
        folder_output_replay = os.path.join(outputs_path, f"cluster_replay_{pcap_info_idx}")
        replay_anomaly_csv_list, replay_plot_cluster_list = analysis(playback_parquet_file_path, folder_output_replay,
                                                                     pcap_info_idx, data_list, env='replay')

        # Process anomaly CSV files to build JSON
        all_pro_anomaly_details = process_anomalies(pro_anomaly_csv_list, "production",
                                                    producer_host_ip_str)
        all_replay_anomaly_details = process_anomalies(replay_anomaly_csv_list, "replay",
                                                       playback_host_ip_str)
        combined_anomaly_details = all_pro_anomaly_details + all_replay_anomaly_details
        # res['anomaly_detection']['details'] = combined_anomaly_details  #既包含生产又包含回放的异常数据0225hyf
        res['anomaly_detection']['details'] = all_replay_anomaly_details  # 只包含回放的异常数据

        request_summary = defaultdict(lambda: {"count": 0, "env": "", "hostip": "", "class_method": ""})

        for entry in all_replay_anomaly_details:
            request_url = entry["request_url"]
            request_summary[request_url]["count"] = int(entry["count"])
            request_summary[request_url]["env"] = entry["env"]
            request_summary[request_url]["hostip"] = entry["hostip"]
            request_summary[request_url]["class_method"] = entry["class_method"]

        # 生成目标格式
        dict_output = [
            {
                "request_url": url,
                "env": details["env"],
                "count": details["count"],
                "hostip": details["hostip"],
                "class_method": details["class_method"],
                "bottleneck_cause": get_bottleneck_analysis(url)['cause'],
                "solution": get_bottleneck_analysis(url)['solution']
            }
            for url, details in request_summary.items()
        ]
        res['anomaly_detection']['dict'] = dict_output
    except Exception as e:
        logger.error(f"Exception while comparing producer and playback data: {e}", exc_info=True)

    # 相关性、随机森林结果和预留传递数据
    res['anomaly_detection']['correlation'] = [
        producer_data['general_analysis_result']['analysis_result_correlation'],
        playback_data['general_analysis_result']['analysis_result_correlation']
    ]
    res['anomaly_detection']['random_forest'] = [
        producer_data['general_analysis_result']['analysis_result_random_forest'],
        playback_data['general_analysis_result']['analysis_result_random_forest']
    ]
    res['performance_bottleneck_analysis'] = {
        "bottlenecks": [
            {
                "env": "瓶颈发生的环境replay",
                "hostip": playback_host_ip_str,
                "class_name": "该部分为扩展用的备用瓶颈结论接口，暂无输出",
                "cause": "扩展用的瓶颈原因",
                "criteria": "判断为该瓶颈的标准",
                "solution": "该瓶颈的解决方案"
            },
            {
                "env": "瓶颈发生的环境production",
                "hostip": producer_host_ip_str,
                "class_name": "扩展用的瓶颈结论接口，暂无输出",
                "cause": "瓶颈原因的备用接口，可扩展",
                "criteria": "判断为该瓶颈的标准，扩展备用",
                "solution": "该瓶颈的解决方案，扩展备用"
            }
        ]
    }

    # 分析瓶颈1 状态码
    try:
        bottleneck_analysis_response_code = (
            analyze_status_code(alignment_df, output_prefix=f'{outputs_path}/test_status_code_analysis_{pcap_info_idx}'))
        # 方式1 返回的是txt文本内容
        # bottleneck_analysis_response_code["env"] = "replay"    #此处应该是生产加上回放，两环境的
        # bottleneck_analysis_response_code["hostip"] = replay_ip
        # logger.info(f"bottleneck_analysis_response_code: {bottleneck_analysis_response_code}")
        # res['performance_bottleneck_analysis']['bottlenecks'].append(bottleneck_analysis_response_code)

        # 方式2 返回json格式的信息
        if bottleneck_analysis_response_code:
            bottleneck_analysis_response_code[0]["hostip"] = producer_host_ip_str
            bottleneck_analysis_response_code[1]["hostip"] = playback_host_ip_str
            res['performance_bottleneck_analysis']['response_code'] = bottleneck_analysis_response_code
        else:
            res['performance_bottleneck_analysis']['response_code'] = []
    except Exception as e:
        res['performance_bottleneck_analysis']['response_code'] = []
        logger.error(f"Exception while analysing response code of producer and playback data: {e}", exc_info=True)
    # 分析瓶颈2 响应包是否完整
    try:
        bottleneck_analysis_empty_response = (
            analyze_empty_responses(alignment_df, output_prefix=f'{outputs_path}/empty_responses_analysis_{pcap_info_idx}'))

        # 方式1 返回的是txt文本内容
        # bottleneck_analysis_empty_response["env"] = "replay"    #此处应该是生产加上回放，两环境的
        # bottleneck_analysis_empty_response["hostip"] = replay_ip
        # logger.info(f"bottleneck_analysis_empty_response: {bottleneck_analysis_empty_response}")
        # res['performance_bottleneck_analysis']['bottlenecks'].append(bottleneck_analysis_empty_response)

        # 方式2 返回json格式的信息
        if bottleneck_analysis_empty_response:
            bottleneck_analysis_empty_response[0]["hostip"] = producer_host_ip_str
            bottleneck_analysis_empty_response[1]["hostip"] = playback_host_ip_str
            bottleneck_analysis_empty_response[0]["env"] = "production"
            bottleneck_analysis_empty_response[1]["env"] = "replay"
            res['performance_bottleneck_analysis']['empty_response'] = bottleneck_analysis_empty_response
        else:
            res['performance_bottleneck_analysis']['empty_response'] = []
    except Exception as e:
        res['performance_bottleneck_analysis']['empty_response'] = []
        logger.error(f"Exception while analysing empty response of producer and playback data: {e}", exc_info=True)
    # logger.warning("222222222222")
    # logger.warning(bottleneck_analysis_empty_response)

    # 分析瓶颈3 传输窗口瓶颈检测
    try:
        bottleneck_analysis_zero_window = (
            analyze_zero_window_issues(alignment_df, output_prefix=f'{outputs_path}/zero_window_analysis_{pcap_info_idx}'))
        # 方式1 返回的是txt文本内容
        # bottleneck_analysis_zero_window["env"] = "replay"    #此处应该是生产加上回放，两环境的
        # bottleneck_analysis_zero_window["hostip"] = replay_ip
        # logger.info(f"bottleneck_analysis_zero_window: {bottleneck_analysis_zero_window}")
        # res['performance_bottleneck_analysis']['bottlenecks'].append(bottleneck_analysis_zero_window)
        if bottleneck_analysis_zero_window:
            # 方式2 返回json格式的信息
            bottleneck_analysis_zero_window[0]["hostip"] = producer_host_ip_str
            bottleneck_analysis_zero_window[1]["hostip"] = playback_host_ip_str
            bottleneck_analysis_zero_window[0]["env"] = "production"
            bottleneck_analysis_zero_window[1]["env"] = "replay"
            res['performance_bottleneck_analysis']['transmission_window'] = bottleneck_analysis_zero_window
        else:
            res['performance_bottleneck_analysis']['transmission_window'] = []
    except Exception as e:
        res['performance_bottleneck_analysis']['transmission_window'] = []
        logger.error(f"Exception while analysing transmission window of producer and playback data: {e}", exc_info=True)

    # 分析瓶颈4 数据库查询瓶颈检测
    # 方式2 返回json格式的信息
    try:
        res['performance_bottleneck_analysis']['database'] = [
            producer_data['general_analysis_result']['bottleneck_analysis_database'],
            playback_data['general_analysis_result']['bottleneck_analysis_database']
        ]

        # 分析瓶颈5 Exception 分析
        res['performance_bottleneck_analysis']['exception'] = [
            producer_data['general_analysis_result']['bottleneck_analysis_exception'],
            playback_data['general_analysis_result']['bottleneck_analysis_exception']
        ]
    except Exception as e:
        res['performance_bottleneck_analysis']['database'] = []
        res['performance_bottleneck_analysis']['exception'] = []
        logger.error(f"Exception while copy database/exception result: {e}", exc_info=True)

    logger.info("Cluster_analysis finished.")
    # logger.debug(f"ID: {pcap_info_idx}, Res: {res}")

    # # Dict check
    # check_json_serializable(res)

    result_options = {
        **options,
        'contrast_delay_conclusion': contrast_delay_conclusion,
        'producer_parquet_file_path': producer_parquet_file_path,
        'playback_parquet_file_path': playback_parquet_file_path,
        'alignment_parquet_file_path': alignment_parquet_file_path,
        'res': res
    }

    return result_options
