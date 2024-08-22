import asyncio
import json
import os

from flask import Flask, request, jsonify
from pydantic import BaseModel, ValidationError
from typing import List
import requests
import time

# Import the new function
from packet_analysis.preprocess import extract_to_csv
from packet_analysis.preprocess import alignment
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


def process_request(pcap_info_list: PcapInfoList):
    # Create results directory if not exists
    if not os.path.exists('results'):
        os.makedirs('results')

    # Initialize the global response with predefined values
    response = {
        "individual_analysis_info": [
            {
                "replay_task_id": "111",
                "replay_id": "1",
                "comparison_analysis": {
                    "title": "生产与回放环境处理时延对比分析",
                    "x_axis_label": "请求路径",
                    "y_axis_label": "时延（ms）",
                    "legend": {
                        "production": "生产环境",
                        "replay": "回放环境",
                        "difference_ratio": "差异倍数"
                    },
                    "data": []
                },
                "anomaly_detection": {
                    "details": [],
                    "dict": [
                        {
                            "request_url": "/api/v1/data",
                            "env": "prod",
                            "class_method": "get_api",
                            "bottleneck_cause": "数据库查询慢",
                            "solution": "优化数据库查询，增加索引"
                        }
                    ]
                },
                "performance_bottleneck_analysis": {
                    "bottlenecks": [
                        {
                            "class_name": "database",
                            "cause": "数据库查询慢",
                            "criteria": "请求时延超过300ms，查询次数过多",
                            "solution": "优化数据库查询，增加索引"
                        },
                        {
                            "class_name": "network",
                            "cause": "网络带宽不足",
                            "criteria": "数据传输时延大，带宽利用率高",
                            "solution": "增加网络带宽或优化传输协议"
                        }
                    ]
                }
            },
            {
                "replay_task_id": "2222",
                "replay_id": "2",
                "comparison_analysis": {
                    "title": "生产与回放环境处理时延对比分析",
                    "x_axis_label": "请求路径",
                    "y_axis_label": "时延（ms）",
                    "legend": {
                        "production": "生产环境",
                        "replay": "回放环境",
                        "difference_ratio": "差异倍数"
                    },
                    "data": [
                        {
                            "url": "/api/v1/data",
                            "request_method": "get",
                            "production_delay_mean": 200,
                            "replay_delay_mean": 150,
                            "production_delay_median": 190,
                            "replay_delay_median": 140,
                            "production_delay_min": 100,
                            "replay_delay_min": 80,
                            "production_delay_max": 300,
                            "replay_delay_max": 220,
                            "mean_difference_ratio": 1.33,
                            "request_count": 1000,
                            "function_description": "数据查询接口"
                        },
                        {
                            "url": "/api/v1/upload",
                            "request_method": "get",
                            "production_delay_mean": 500,
                            "replay_delay_mean": 600,
                            "production_delay_median": 480,
                            "replay_delay_median": 580,
                            "production_delay_min": 400,
                            "replay_delay_min": 450,
                            "production_delay_max": 700,
                            "replay_delay_max": 800,
                            "mean_difference_ratio": 0.83,
                            "request_count": 800,
                            "function_description": "文件上传接口"
                        }
                    ]
                },
                "anomaly_detection": {
                    "details": [
                        {
                            "request_url": "/api/v1/data",
                            "request_method": "get",
                            "env": "prod",
                            "class_method": "get_api",
                            "anomaly_delay": 400,
                            "average_delay": 200,
                            "anomaly_time": "2024-07-23 10:00",
                            "packet_position": "Packet 102"
                        }
                    ],
                    "dict": [
                        {
                            "request_url": "/api/v1/data",
                            "env": "prod",
                            "class_method": "get_api",
                            "bottleneck_cause": "数据库查询慢",
                            "solution": "优化数据库查询，增加索引"
                        }
                    ]
                },
                "performance_bottleneck_analysis": {
                    "bottlenecks": [
                        {
                            "class_name": "database",
                            "cause": "数据库查询慢",
                            "criteria": "请求时延超过300ms，查询次数过多",
                            "solution": "优化数据库查询，增加索引"
                        },
                        {
                            "class_name": "network",
                            "cause": "网络带宽不足",
                            "criteria": "数据传输时延大，带宽利用率高",
                            "solution": "增加网络带宽或优化传输协议"
                        }
                    ]
                }
            }
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
                    "replay_task_id": 1111,
                    "replay_id": "1",
                    "text": "回放存在显著性能差异"
                },
                {
                    "replay_task_id": 1111,
                    "replay_id": "1",
                    "text": "回放正常"
                }
            ]
        }
    }

    # Process each pcap info
    for index, pcap_info in enumerate(pcap_info_list.pcap_info):

        # Extract production and replay data
        production_csv_file_path = f"results/extracted_production_data_{index}.csv"
        # extract_to_csv.preprocess_data(
        #     [os.path.join("raw_data", collect.collect_path) for collect in pcap_info.collect_pcap],
        #     production_csv_file_path)

        replay_csv_file_path = f"results/extracted_replay_data_{index}.csv"
        # extract_to_csv.preprocess_data(
        #     [os.path.join("raw_data", pcap_info.replay_pcap.replay_path)], replay_csv_file_path)

        # Align production and replay data
        alignment_csv_file_path = f"results/aligned_data_{index}.csv"
        # alignment.alignment_path_query(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path)

        # Process CSV files and get comparison analysis data to build JSON
        DataBase = DB(csv_back=replay_csv_file_path, csv_production=production_csv_file_path)
        data_list = DataBase.built_all_dict()
        # Update response with the data_list for the current analysis
        response['individual_analysis_info'][index]['comparison_analysis']['data'] = data_list

        #production cluster anomaly and replay cluster anomaly
        folder_output_pro = f"results/cluster_pro_{index}"
        pro_anomaly_csv_list, pro_plot_cluster_list = cluster.analysis(production_csv_file_path, folder_output_pro)
        folder_output_replay = f"results/cluster_replay_{index}"
        replay_anomaly_csv_list, replay_plot_cluster_list = cluster.analysis(replay_csv_file_path, folder_output_replay)

        # Process anomaly CSV files to build JSON
        all_pro_anomaly_details = anomaly_detection.process_anomalies(pro_anomaly_csv_list, "production")
        all_replay_anomaly_details = anomaly_detection.process_anomalies(replay_anomaly_csv_list, "replay")
        combined_anomaly_details = all_pro_anomaly_details + all_replay_anomaly_details
        response['individual_analysis_info'][index]['anomaly_detection']['details'] = combined_anomaly_details



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
