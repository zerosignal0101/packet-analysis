import json
import os
import threading
from flask import Flask, request, jsonify
from pydantic import BaseModel, ValidationError
from typing import List

# Import the new function
from packet_analysis.preprocess import extract_to_csv, alignment
from packet_analysis.preprocess import extract_to_csv_split
from packet_analysis.utils import postapi

from packet_analysis.json_build.comparison_analysis import *
from packet_analysis.analysis import cluster
from packet_analysis.json_build import anomaly_detection

app = Flask(__name__)


class CollectPcap(BaseModel):
    collect_path: str
    ip: str
    prot: int


class ReplayPcap(BaseModel):
    replay_path: str
    ip: str
    prot: int
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


def process_pcap_files(index, pcap_info,production_csv_file_path,replay_csv_file_path):
    # 创建线程，用于并行处理 production 和 replay 的 pcap 文件

    # 线程任务函数
    def process_production():
        extract_to_csv_split.preprocess_data(
            [os.path.join(collect.collect_path) for collect in pcap_info.collect_pcap],
            production_csv_file_path)

    def process_replay():
        extract_to_csv_split.preprocess_data(
            [os.path.join(pcap_info.replay_pcap.replay_path)], replay_csv_file_path)

    # 创建两个线程
    production_thread = threading.Thread(target=process_production)
    replay_thread = threading.Thread(target=process_replay)
    # 启动线程
    production_thread.start()
    replay_thread.start()
    # 等待两个线程都完成
    production_thread.join()
    replay_thread.join()

    # 当两个线程都完成后，执行对齐操作
    alignment_csv_file_path = f"../results/aligned_data_{index}_{pcap_info.replay_id}.csv"
    alignment.alignment_path_query(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path)

def process_request(pcap_info_list: PcapInfoList):
    # Create results directory if not exists
    if not os.path.exists('../results'):
        os.makedirs('../results')

    # Initialize the global response with predefined values
    response = {
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
                            "class_method": "get_api",
                            "bottleneck_cause": "数据库查询慢",
                            "solution": "优化数据库查询，增加索引"
                        }
                    ],
                    "correlation": [
                        {
                            "env": "production",
                            "hostip": info.collect_pcap[0].ip,
                            "class_method": "get_api",
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

    # Process each pcap info
    for index, pcap_info in enumerate(pcap_info_list.pcap_info):
        # Extract production and replay data
        production_csv_file_path = f"../results/extracted_production_data_{index}_{pcap_info.replay_id}.csv"
        replay_csv_file_path = f"../results/extracted_replay_data_{index}_{pcap_info.replay_id}.csv"
        process_pcap_files(index, pcap_info,production_csv_file_path,replay_csv_file_path)


        # Process CSV files and get comparison analysis data to build JSON
        # Request_Info_File_Path = f"packet_analysis/json_build/path_function.csv"
        DataBase = DB(csv_back=replay_csv_file_path, csv_production=production_csv_file_path)
        data_list = DataBase.built_all_dict()
        # Update response with the data_list for the current analysis
        response['individual_analysis_info'][index]['comparison_analysis']['data'] = data_list
        response['individual_analysis_info'][index]['replay_task_id'] = pcap_info.replay_task_id
        response['individual_analysis_info'][index]['replay_id'] = pcap_info.replay_id

        # production cluster anomaly and replay cluster anomaly
        # folder_output_pro = f"../results/cluster_production_{index}_{pcap_info.replay_id}"
        # pro_anomaly_csv_list, pro_plot_cluster_list = cluster.analysis(production_csv_file_path, folder_output_pro)
        # folder_output_replay = f"../results/cluster_replay_{index}_{pcap_info.replay_id}"
        # replay_anomaly_csv_list, replay_plot_cluster_list = cluster.analysis(replay_csv_file_path, folder_output_replay)

        # Process anomaly CSV files to build JSON
        # all_pro_anomaly_details = anomaly_detection.process_anomalies(pro_anomaly_csv_list, "production",
        #                                                               pcap_info.collect_pcap[0].ip)
        # all_replay_anomaly_details = anomaly_detection.process_anomalies(replay_anomaly_csv_list, "replay",
        #                                                                  pcap_info.replay_pcap.ip)
        # combined_anomaly_details = all_pro_anomaly_details + all_replay_anomaly_details
        # response['individual_analysis_info'][index]['anomaly_detection']['details'] = combined_anomaly_details

    # Post the response to the callback URL
    # callback_url = os.getenv("CALLBACK_URL", 'http://10.180.124.116:18088/api/replay-core/aglAnalysisResult')
    # postapi.post_url(json.dumps(response), callback_url)

    return response


import logging

logging.basicConfig(level=logging.INFO)


@app.route('/api/algorithm/analyze', methods=['POST'])
def process():
    try:
        data = request.json
        logging.info("2222 This is a debug message")
        pcap_info_list = PcapInfoList.parse_obj(data)
        result = process_request(pcap_info_list)
        return jsonify(result)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=7956)
