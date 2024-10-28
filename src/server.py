import json
import uuid
import os

from flask import Flask, request, jsonify
from pydantic import BaseModel, ValidationError
from typing import List
import requests
from celery import Celery, group, chain, chord
from multiprocessing import Process

from src.packet_analysis.json_build.json_host_database_correlation import calc_correlation
# Import the new function
from src.packet_analysis.preprocess import extract_to_csv, alignment_two_paths
from src.packet_analysis.utils import postapi

from src.packet_analysis.json_build.comparison_analysis import *
from src.packet_analysis.analysis import cluster
from src.packet_analysis.json_build import anomaly_detection
from src.packet_analysis.utils.logger_config import logger
from datetime import datetime

app = Flask(__name__)
# 使用新格式的配置名称
app.config.update(
    include=['src.server'],
    result_backend='redis://redis:6379/0',  # 'redis://redis:6379/0'
    broker_url='redis://redis:6379/0'  # 'redis://redis:6379/0'
)

celery = Celery(app.name, broker=app.config['broker_url'])
celery.conf.update(app.config)


class CollectPcap(BaseModel):
    collect_path: str
    ip: str
    port: int


class ReplayPcap(BaseModel):
    replay_path: str
    ip: str
    port: int
    replay_speed: str
    replay_multiplier: str


class PcapInfo(BaseModel):
    collect_pcap: List[CollectPcap]
    collect_log: str
    replay_pcap: ReplayPcap
    replay_log: str
    replay_task_id: int
    replay_id: str


class PcapInfoList(BaseModel):
    pcap_info: List[PcapInfo]


@celery.task(name='server.extract_data')
def extract_data(pcap_file_path, extracted_csv_file_path, anomalies_csv_file_path):
    logger.info(f"pcap_file_path {pcap_file_path}")
    extract_to_csv.preprocess_data([pcap_file_path], extracted_csv_file_path)


@celery.task(name='server.align_data')
def align_data(results, production_csv_file_path, replay_csv_file_path, alignment_csv_file_path):
    alignment_two_paths.alignment_two_paths(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path)


@celery.task(name='server.cluster_analysis_data')
def cluster_analysis_data(results, index, replay_task_id, replay_id, production_ip, replay_ip, replay_csv_file_path,
                          production_csv_file_path, task_id, production_json_path, replay_json_path):
    # res variable
    res = {
        "comparison_analysis": {},
        "anomaly_detection": {},
    }

    # Process CSV files and get comparison analysis data to build JSON
    # Request_Info_File_Path = f"packet_analysis/json_build/path_function.csv"
    logger.info(f"json started at {datetime.now()}")
    DataBase = DB(csv_back=replay_csv_file_path, csv_production=production_csv_file_path)
    # 添加返回值
    data_list = DataBase.built_all_dict()

    outputs_path = f'./results/{task_id}'

    # # 保存两环境对比数据csv、对比图到本地
    # comparison_csv_path = os.path.join(outputs_path, f"comparison_analysis_data_{index}.csv")
    # DataBase.save_to_csv(comparison_csv_path)
    # comparison_png_path = os.path.join(outputs_path, f"comparison_analysis_data_{index}.png")
    # DataBase.plot_mean_difference_ratio(comparison_png_path)

    # Update response with the data_list for the current analysis
    data_legend = {
        "production": "生产环境",
        "replay": "回放环境",
        "mean_difference_ratio": "差异倍数"
    }
    res['comparison_analysis']['data'] = data_list
    res['replay_task_id'] = replay_task_id
    res['replay_id'] = replay_id
    res['comparison_analysis']['title'] = "生产与回放环境处理时延对比分析"
    res['comparison_analysis']['x_axis_label'] = "请求路径"
    res['comparison_analysis']['y_axis_label'] = "时延（s）"
    res['comparison_analysis']['data'] = data_list
    res['comparison_analysis']['legend'] = data_legend

    # production cluster anomaly and replay cluster anomaly
    folder_output_pro = os.path.join(outputs_path, f"cluster_production_{index}")
    pro_anomaly_csv_list, pro_plot_cluster_list = cluster.analysis(production_csv_file_path, folder_output_pro)
    folder_output_replay = os.path.join(outputs_path, f"cluster_replay_{index}")
    replay_anomaly_csv_list, replay_plot_cluster_list = cluster.analysis(replay_csv_file_path, folder_output_replay)

    # Process anomaly CSV files to build JSON
    all_pro_anomaly_details = anomaly_detection.process_anomalies(pro_anomaly_csv_list, "production",
                                                                  production_ip)
    all_replay_anomaly_details = anomaly_detection.process_anomalies(replay_anomaly_csv_list, "replay",
                                                                     replay_ip)
    combined_anomaly_details = all_pro_anomaly_details + all_replay_anomaly_details
    res['anomaly_detection']['details'] = combined_anomaly_details

    # 先预设的'anomaly_detection'中的dict部分
    data_dict = [
        {
            "request_url": "/portal_todo/api/getAllUserTodoData",
            "env": "production",
            "hostip": production_ip,
            "class_method": "api_get",
            "bottleneck_cause": "数据库查询慢",
            "solution": "优化数据库查询，增加索引"
        }
    ]
    res['anomaly_detection']['dict'] = data_dict

    production_correlation_path = os.path.join(outputs_path, 'production_correlation.csv')
    production_correlation_df = calc_correlation(production_json_path, production_csv_file_path, production_correlation_path)

    replay_correlation_path = os.path.join(outputs_path, 'replay_correlation.csv')
    replay_correlation_df = calc_correlation(replay_json_path, replay_csv_file_path, replay_correlation_path)

    # 先预设的'anomaly_detection'中的correlation部分
    data_correlation = [
        {
            "env": "production",
            "hostip": "production_ip",
            "class_method": "api_get",
            "correlation_data": []
        },
        {
            "env": "replay",
            "hostip": "replay_ip",
            "class_method": "get_post",
            "correlation_data": []
        }
    ]
    # 将 corr_df 中的 KPI名称 和 相关系数 对应到 index_id 和 value
    for index, row in production_correlation_df.iterrows():
        if pd.notna(row['相关系数']):  # 只处理非 NaN 的相关系数
            correlation_data = {
                "index_id": row['KPI名称'],
                "value": row['相关系数']
            }
            # 将数据添加到 production 和 replay 的 correlation_data 中
            data_correlation[0]['correlation_data'].append(correlation_data)
    # 将 corr_df 中的 KPI名称 和 相关系数 对应到 index_id 和 value
    for index, row in replay_correlation_df.iterrows():
        if pd.notna(row['相关系数']):  # 只处理非 NaN 的相关系数
            correlation_data = {
                "index_id": row['KPI名称'],
                "value": row['相关系数']
            }
            # 将数据添加到 production 和 replay 的 correlation_data 中
            data_correlation[1]['correlation_data'].append(correlation_data)
    res['anomaly_detection']['correlation'] = data_correlation

    # 先预设的'anomaly_detection'中的correlation部分
    data_performance_bottleneck_analysis = {
        "bottlenecks": [
            {
                "env": "replay",
                "hostip": replay_ip,
                "class_name": "database",
                "cause": "数据库查询慢",
                "criteria": "请求时延超过300ms，查询次数过多",
                "solution": "优化数据库查询，增加索引"
            },
            {
                "env": "production",
                "hostip": production_ip,
                "class_name": "network",
                "cause": "网络带宽不足",
                "criteria": "数据传输时延大，带宽利用率高",
                "solution": "增加网络带宽或优化传输协议"
            }
        ]
    }
    res['performance_bottleneck_analysis'] = data_performance_bottleneck_analysis

    return index, res


@celery.task(name='server.final_task')
def final_task(results, data, task_id, ip_address):
    pcap_info_list = PcapInfoList.parse_obj(data)
    # Initialize the global response with predefined values
    response = {
        "task_id": task_id,
        "individual_analysis_info": [
            {
                "replay_task_id": info.replay_task_id,
                "replay_id": info.replay_id,
                "comparison_analysis": {
                    "title": "生产与回放环境处理时延对比分析",
                    "x_axis_label": "请求路径",
                    "y_axis_label": "时延（s）",
                    "legend": {
                        "production": "生产环境",
                        "replay": "回放环境",
                        "mean_difference_ratio": "差异倍数"
                    },
                    "data": [

                    ]
                },
                "anomaly_detection": {
                    "details": [

                    ],
                    "dict": [
                        {
                            "request_url": "/api/v1/data",
                            "env": "production",
                            "hostip": info.collect_pcap[0].ip,
                            "class_method": "api_get",
                            "bottleneck_cause": "数据库查询慢",
                            "solution": "优化数据库查询，增加索引"
                        }
                    ],
                    "correlation": [
                        {
                            "env": "production",
                            "hostip": info.collect_pcap[0].ip,
                            "class_method": "api_get",
                            "correlation_data": [
                                {
                                    "index_id": "非root用户进程数",
                                    "value": 0.6
                                },
                                {
                                    "index_id": "活动进程数",
                                    "value": 0.7
                                }
                            ]
                        },
                        {
                            "env": "replay",
                            "hostip": info.replay_pcap.ip,
                            "class_method": "get_post",
                            "correlation_data": [
                                {
                                    "index_id": "会话数",
                                    "value": 0.6
                                },
                                {
                                    "index_id": "当前数据库的连接数",
                                    "value": 0.7
                                }
                            ]
                        }
                    ]
                },
                "performance_bottleneck_analysis": {
                    "bottlenecks": [
                        {
                            "env": "replay",
                            "hostip": info.replay_pcap.ip,
                            "class_name": "database",
                            "cause": "数据库查询慢",
                            "criteria": "请求时延超过300ms，查询次数过多",
                            "solution": "优化数据库查询，增加索引"
                        },
                        {
                            "env": "production",
                            "hostip": info.collect_pcap[0].ip,
                            "class_name": "network",
                            "cause": "网络带宽不足",
                            "criteria": "数据传输时延大，带宽利用率高",
                            "solution": "增加网络带宽或优化传输协议"
                        }
                    ]
                }
            }
            for info in pcap_info_list.pcap_info
        ],
        "overall_analysis_info": {
            "summary": {
                "performance_trends": "整体性能趋势，例如重放环境与生产相比通常表现出更高还是更低的延迟。",
                "common_bottlenecks": "识别在多次分析中观察到的任何反复出现的瓶颈（例如网络问题、数据库减速）例如：网络带宽限制和数据库查询性能是多个任务中经常出现的瓶颈。优化这些方面可显著提高性能。",
                "anomalies": "突出显示在多个单独分析中出现的任何显著异常，并注意它们是孤立的还是更广泛趋势的一部分。讨论这些异常的可能系统性原因。例如：文件上传过程中最常出现异常，表明服务器端处理或网络稳定性存在潜在问题",
                "recommendations": "根据单独的发现提供综合建议，例如应优先考虑优化工作的领域。例如：建议优先考虑数据库索引和查询优化，并探索升级网络基础设施。"
            },
            "overview": [
                {
                    "replay_task_id": info.replay_task_id,
                    "replay_id": info.replay_id,
                    "text": "回放存在显著性能差异" if info.replay_task_id % 2 == 0 else "回放正常"
                    # TODO: Add logic to determine if replay is normal or not
                }
                for info in pcap_info_list.pcap_info
            ]
        }
    }

    logger.info(f"Results: {results}")

    for result in results:
        if result is not None:
            index, res = result
            response['individual_analysis_info'][index] = res

    # Post the response to the callback URL
    callback_url = os.getenv("CALLBACK_URL", f'http://{ip_address}:18088/api/replay-core/aglAnalysisResult')
    postapi.post_url(json.dumps(response), callback_url)


def run_tasks_in_parallel(data, task_id, ip_address):
    # Create results directory if not exists
    logger.info(f"11111Current working directory: {os.getcwd()}")

    if not os.path.exists('results'):
        os.makedirs('results')

    if not os.path.exists(f'results/{task_id}'):
        logger.info(f"Mkdir: results/{task_id}")
        os.makedirs(f'results/{task_id}')

    pcap_info_list = PcapInfoList.parse_obj(data)

    # high_cost_tasks
    task_groups = []

    outputs_path = f'results/{task_id}'

    # Process each pcap info
    for index, pcap_info in enumerate(pcap_info_list.pcap_info):
        logger.info(f"Processing pcap info {index}")
        # Extract production and replay data
        production_csv_file_path = os.path.join(outputs_path, f"extracted_production_data_{index}.csv")
        production_anomalies_csv_file_path = os.path.join(outputs_path, "production_tcp_anomalies.csv")
        replay_csv_file_path = os.path.join(outputs_path, f"extracted_replay_data_{index}.csv")
        replay_anomalies_csv_file_path = os.path.join(outputs_path, "replay_tcp_anomalies.csv")

        # Align production and replay data
        alignment_csv_file_path = os.path.join(outputs_path, f"aligned_data_{index}.csv")

        # Parallelize the tasks 调用任务 extract_data 的异步签名 (s)，提取生产环境中的 pcap 数据
        # 使用 os.path.join 拼接 collect.collect_path，生成每个收集到的 pcap 文件的完整路径。
        logger.info(f"222222Current working directory: {os.getcwd()}")

        task_group = group(group(
            extract_data.s([os.path.join(collect.collect_path) for collect in pcap_info.collect_pcap],
                           production_csv_file_path, production_anomalies_csv_file_path),
            extract_data.s([os.path.join(pcap_info.replay_pcap.replay_path)],
                           replay_csv_file_path, replay_anomalies_csv_file_path))
            | align_data.s(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path)
            | cluster_analysis_data.s(index, pcap_info.replay_task_id, pcap_info.replay_id,
                                      pcap_info.collect_pcap[0].ip,pcap_info.replay_pcap.ip,
                                      replay_csv_file_path, production_csv_file_path, task_id, pcap_info.collect_log, pcap_info.replay_log))
        task_groups.append(task_group)

    # 使用chord确保所有任务子项完成后执行最终任务
    final_chord = chord(task_groups)(final_task.s(data, task_id, ip_address))


@app.route('/api/algorithm/analyze', methods=['POST'])
def process():
    try:
        data = request.json  # 假设请求体是JSON格式
        ip_address = request.remote_addr

        # 生成唯一的 task_id
        task_id = str(uuid.uuid4())

        # 异步执行任务
        run_tasks_in_parallel(data, task_id, ip_address)

        return jsonify({"message": "Request received", "task_id": task_id, "status": "queued"}), 202
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=7956)
