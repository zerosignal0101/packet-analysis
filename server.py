import asyncio
import json
import os

from flask import Flask, request, jsonify
from pydantic import BaseModel, ValidationError
from typing import List
import requests
import time

from packet_analysis.preprocess import extract_to_csv
from packet_analysis.preprocess import alignment
from packet_analysis.utils import postapi

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

    if not os.path.exists('results'):
        os.makedirs('results')

    proc_list = []

    # 提取所有的 collect_path
    for index, pcap_info in enumerate(pcap_info_list.pcap_info):
        collect_paths = []
        for collect_pcap in pcap_info.collect_pcap:
            collect_paths.append(os.path.join("raw_data", collect_pcap.collect_path))
        print(collect_paths)

        # 预处理数据
        # 生成 production_csv_file_path
        production_csv_file_path = f"results/extracted_production_data_{index}.csv"
        # 调用 preprocess_data 函数处理生产环境的数据
        extract_to_csv.preprocess_data(collect_paths, production_csv_file_path)

        # 生成 replay_csv_file_path
        replay_csv_file_path = f"results/extracted_replay_data_{index}.csv"
        # 预处理数据

        # 调用 preprocess_data 函数处理回放环境的数据
        extract_to_csv.preprocess_data(
            [os.path.join("raw_data", pcap_info.replay_pcap.replay_path)], replay_csv_file_path)

        # 调用 align_data 函数对生产环境和回放环境的数据进行对齐
        alignment_csv_file_path = f"results/aligned_data_{index}.csv"
        alignment.alignment_path_query(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path)


    # Generate the response JSON
    response = {
        "individual_analysis_info": [
            {
                "replay_task_id": info.replay_task_id,
                "replay_id": info.replay_id,
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
                            "production_delay_mean": 200,
                            "replay_delay_mean": 150,
                            "production_delay_median": 190,
                            "replay_delay_median": 140,
                            "production_delay_min": 100,
                            "replay_delay_min": 80,
                            "production_delay_max": 300,
                            "replay_delay_max": 220,
                            "difference_ratio": 1.33,
                            "request_count": 1000,
                            "function_description": "数据查询接口"
                        },
                        {
                            "url": "/api/v1/upload",
                            "production_delay_mean": 500,
                            "replay_delay_mean": 600,
                            "production_delay_median": 480,
                            "replay_delay_median": 580,
                            "production_delay_min": 400,
                            "replay_delay_min": 450,
                            "production_delay_max": 700,
                            "replay_delay_max": 800,
                            "difference_ratio": 0.83,
                            "request_count": 800,
                            "function_description": "文件上传接口"
                        }
                    ]
                },
                "anomaly_detection": {
                    "GET": {
                        "total_anomalies": 10,
                        "details": [
                            {
                                "request_url": "/api/v1/data",
                                "anomaly_delay": 400,
                                "average_delay": 200,
                                "anomaly_time": "2024-07-23 10:00",
                                "packet_position": "Packet 102",
                                "bottleneck_cause": "数据库查询慢",
                                "solution": "优化数据库查询，增加索引"
                            }
                        ]
                    },
                    "POST": {
                        "total_anomalies": 5,
                        "details": [
                            {
                                "request_url": "/api/v1/submit",
                                "anomaly_delay": 700,
                                "average_delay": 300,
                                "anomaly_time": "2024-07-23 11:00",
                                "packet_position": "Packet 204",
                                "bottleneck_cause": "网络带宽不足",
                                "solution": "增加网络带宽或优化传输协议"
                            }
                        ]
                    },
                    "static_resources": {
                        "total_anomalies": 3,
                        "details": [
                            {
                                "request_url": "/static/js/app.js",
                                "anomaly_delay": 500,
                                "average_delay": 100,
                                "anomaly_time": "2024-07-23 12:00",
                                "packet_position": "Packet 305",
                                "bottleneck_cause": "文件服务器响应慢",
                                "solution": "优化文件服务器配置"
                            }
                        ]
                    },
                    "others": {
                        "total_anomalies": 2,
                        "details": [
                            {
                                "request_url": "/api/v1/other",
                                "anomaly_delay": 800,
                                "average_delay": 200,
                                "anomaly_time": "2024-07-23 13:00",
                                "packet_position": "Packet 406",
                                "bottleneck_cause": "未知原因",
                                "solution": "进一步分析数据包"
                            }
                        ]
                    }
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
                }
                for info in pcap_info_list.pcap_info
            ]
        }
    }

    callback_url = os.getenv("CALLBACK_URL", 'http://10.180.124.116:18088/api/replay-core/aglAnalysisResult')
    postapi.post_url(json.dumps(response), callback_url)

    return response


@app.route('/api/algorithm/analyze', methods=['POST'])
def process():
    try:
        data = request.json
        pcap_info_list = PcapInfoList.parse_obj(data)
        result = process_request(pcap_info_list)
        return jsonify(result)
    except ValidationError as e:
        return jsonify({"error": str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True, port=7956)
