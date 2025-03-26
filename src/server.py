import csv
import json
import uuid
import os
import time

from flask import Flask, request, jsonify
from pydantic import BaseModel, ValidationError
from typing import List
import requests
from celery import Celery, group, chain, chord
import redis
from contextlib import contextmanager
import glob
import subprocess
import traceback
import pandas as pd
from datetime import datetime
from collections import defaultdict

# Project imports
from src.packet_analysis.json_build.json_host_database_correlation import calc_correlation
from src.packet_analysis.json_build.random_forest_model import calc_forest_model
from src.packet_analysis.preprocess import extract_to_csv, alignment
from src.packet_analysis.utils import postapi
from src.packet_analysis.json_build.comparison_analysis import *
from src.packet_analysis.analysis import cluster
from src.packet_analysis.json_build import anomaly_detection
from src.packet_analysis.utils.logger_config import logger
from src.packet_analysis.json_build import alignment_analysis, db_analysis, exception_analysis


app = Flask(__name__)

redis_url = "redis://redis:6379/0"
celery = Celery(app.name, broker=redis_url, backend=redis_url)

# 配置 Celery 日志
celery.log.already_setup = True

# Initialize a Redis client for locking and state management
redis_client = redis.StrictRedis(host='redis', port=6379, db=0)


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


@celery.task(name='mark_task_complete')
def mark_task_complete(results, name):
    redis_client.set(f"{name}_completed", b'1')  # Use string '1' instead of True


def set_task_status(task_id, index, status, step, message):
    # 将状态信息存储为一个字典
    status_info = {
        "status": status,
        "step": step,
        "message": message,
        "timestamp": datetime.now().isoformat()  # 添加时间戳
    }
    # 将状态信息追加到列表中
    redis_client.rpush(f"task_status_history:{task_id}:{index}", json.dumps(status_info))

@celery.task(name='server.extract_data_coordinator')
def extract_data_coordinator(pcap_file_path, csv_file_path, anomalies_csv_file_path, task_id, pcap_index):
    try:
        # 更新任务状态为 "正在处理"
        # redis_client.hset(f"task_status:{task_id}:{pcap_index}", "status", "正在处理")
        # redis_client.hset(f"task_status:{task_id}:{pcap_index}", "step", "extract_data_coordinator")
        # redis_client.hset(f"task_status:{task_id}:{pcap_index}", "message", f"模块{pcap_index}正在进行第一步，对 pcap 文件信息提取处理，共5步")
        set_task_status(task_id, pcap_index, "正在处理", "extract_data_coordinator", f"模块{pcap_index}正在进行第1步：对 pcap 文件信息提取处理，共5步")


        # 原有的处理逻辑
        logger.info(f"pcap_file_path {pcap_file_path}")

        split_files_list = []
        output_dir = f'results/{task_id}/split_pcap'  # 分割后的文件存储目录

        if not os.path.exists(output_dir):
            # os.mkdir(output_dir)  
            os.makedirs(output_dir, exist_ok=True)  # hyf

        # check if the [0] is type of list
        if isinstance(pcap_file_path[0], list):
            pcap_file_path = pcap_file_path[0]

        # 如果csv文件已存在，则删除
        if os.path.exists(csv_file_path):
            os.remove(csv_file_path)

        for file_path in pcap_file_path:

            base_filename = os.path.basename(file_path)  # Extract the base filename from the file path
            split_prefix = os.path.join(output_dir, base_filename)  # Prefix includes the target directory

            # Run the editcap command to split the pcap file and save the splits in the specified directory
            command = f"editcap -c 100000 {file_path} {split_prefix}"
            logger.info(command)
            subprocess.run(command, shell=True)

            # Use glob to find the split files matching the pattern in the output directory
            base_filename_without_extension = os.path.splitext(base_filename)[0]  # 去掉扩展名
            split_file_pattern = os.path.join(output_dir, f"{base_filename_without_extension}_*.pcap")
            cur_split_files = glob.glob(split_file_pattern)

            # Add the found split files to the dictionary
            for pcap_file_path in cur_split_files:
                split_files_list.append(pcap_file_path)

        # 定义 CSV 文件头
        csv_headers = [
            'Sniff_time', 'Relative_time', 'Scheme', 'Netloc', 'Path', 'Query',
            'Time_since_request', 'Processing_delay', 'Transmission_delay',
            'Ip_src', 'Ip_dst', 'Src_Port', 'Dst_Port', 'Is_zero_window', 'Is_tcp_reset',
            'Request_Method', 'Request_Packet_Length', 'Response_Packet_Length',
            'Response_Total_Length', 'Response_code'
        ]

        # 打开 CSV 文件并写入数据
        with open(csv_file_path, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_headers)

            # 写入文件头
            writer.writeheader()

        for pcap_file_path in split_files_list:
            extract_data_executor.apply_async((pcap_file_path, csv_file_path, csv_headers),
                                              link=mark_task_complete.s(pcap_file_path))

        for pcap_file_path in split_files_list:
            while True:
                if redis_client.get(f"{pcap_file_path}_completed") == b'1':
                    redis_client.delete(f"{pcap_file_path}_completed")
                    break
                time.sleep(1)

        df = pd.read_csv(csv_file_path)

        # 按照 'Sniff_time' 列排序
        df['Sniff_time'] = pd.to_datetime(df['Sniff_time'])
        df.sort_values(by='Sniff_time', inplace=True)

        # 添加 'No' 列，从 1 开始的序号
        df.insert(0, 'No', range(1, len(df) + 1))

        # 获取第一个Sniff_time的时间戳
        first_sniff_time = df['Sniff_time'].iloc[0]

        # 计算每个Sniff_time相对于第一个Sniff_time的相对时间（以秒为单位）
        df['Relative_time'] = (df['Sniff_time'] - first_sniff_time).dt.total_seconds()

        df.to_csv(csv_file_path)

        set_task_status(task_id, pcap_index, "完成", "extract_data_coordinator", f"模块{pcap_index}第1步：对 pcap 文件信息提取处理已完成，共5步")
        return

        # 更新任务状态为 "完成"
        # redis_client.hset(f"task_status:{task_id}:{pcap_index}", "status", "正在处理")
        # redis_client.hset(f"task_status:{task_id}:{pcap_index}", "message", f"模块{pcap_index}第一步pcap 文件信息提取正在进行，共5步")

    except Exception as e:
        # 更新任务状态为 "失败"
        set_task_status(task_id, pcap_index, "失败", "extract_data_coordinator", f"模块{pcap_index}第一步pcap 文件信息提取时出错，共5步，错误如下: {str(e)}")
        # redis_client.hset(f"task_status:{task_id}:{pcap_index}", "status", "失败")
        # redis_client.hset(f"task_status:{task_id}:{pcap_index}", "message", f"模块{pcap_index}第一步pcap 文件信息提取时出错，共5步，错误如下: {str(e)}")
        # logger.error(f"对 pcap 文件信息提取时出错: {str(e)}")
        raise


@contextmanager
def redis_lock(lock_name, timeout=10):
    lock = redis_client.lock(lock_name, timeout=timeout)
    acquired = lock.acquire(blocking=True)
    try:
        yield acquired
    finally:
        if acquired:
            lock.release()


@celery.task(name='server.extract_data_executor')
def extract_data_executor(pcap_file_path, csv_file_path, csv_headers):
    logger.info(f"One pcap_file_path {pcap_file_path}")
    results = extract_to_csv.preprocess_data([pcap_file_path])
    os.remove(pcap_file_path)
    logger.info(f"Write to CSV: {csv_file_path}")
    with redis_lock('csv_lock', 20):
        with open(csv_file_path, 'a', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=csv_headers)
            # 写入数据行

            for res in results:
                # 将 sniff_time 转换为字符串格式
                sniff_time_str = res['sniff_time'].strftime('%Y-%m-%d %H:%M:%S.%f')

                # 构建写入 CSV 的数据行
                row = {
                    'Sniff_time': sniff_time_str,
                    'Relative_time': '',
                    'Scheme': res['request_scheme'],
                    'Netloc': res['request_netloc'],
                    'Path': res['request_path'],
                    'Query': res['request_query'],
                    'Time_since_request': round(res['time_since_request'].total_seconds(), 6),
                    'Processing_delay': round(res['processing_delay'].total_seconds(), 6)
                    if res['processing_delay'] is not None else '',
                    'Transmission_delay': round(res['transmission_delay'].total_seconds(), 6)
                    if res['transmission_delay'] is not None else '',
                    'Ip_src': res['ip_src'],
                    'Ip_dst': res['ip_dst'],
                    'Src_Port': res['src_port'],
                    'Dst_Port': res['dst_port'],
                    'Is_zero_window': res['is_zero_window'],
                    'Is_tcp_reset': res['is_tcp_reset'],
                    'Request_Method': res['request_http_method'],
                    'Request_Packet_Length': res['request_packet_length'],
                    'Response_Packet_Length': res['response_packet_length'],
                    'Response_Total_Length': res['response_total_length'],
                    'Response_code': res['response_code']
                }

                # 写入数据行
                writer.writerow(row)
    return


@celery.task(name='server.align_data')
def align_data(results, production_csv_file_path, replay_csv_file_path, alignment_csv_file_path, task_id, pcap_index):
    try:
        # 更新任务状态为 "正在处理"
        # redis_client.hset(f"task_status:{task_id}", "status", "正在处理")
        # redis_client.hset(f"task_status:{task_id}", "step", "align_data")
        # redis_client.hset(f"task_status:{task_id}", "message", "正在进行第二步：生产、回放数据对齐，共5步")

        set_task_status(task_id, pcap_index, "正在处理", "align_data", f"模块{pcap_index}正在进行第2步：生产、回放数据对齐，共5步")
        alignment.alignment_two_paths(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path)

        # 更新任务状态为 "完成"
        # redis_client.hset(f"task_status:{task_id}", "status", "完成")
        # redis_client.hset(f"task_status:{task_id}", "message", "第二步生成、回放数据对齐完成，共5步")
        set_task_status(task_id, pcap_index, "完成", "align_data", f"模块{pcap_index}第二步生成、回放数据对齐完成，共5步")

    except Exception as e:
        # 更新任务状态为 "失败"
        # redis_client.hset(f"task_status:{task_id}", "status", "失败")
        # redis_client.hset(f"task_status:{task_id}", "message", f"第二步生成、回放数据对齐时出错，共5步，报错如下: {str(e)}")
        # redis_client.hset(f"task_status:{task_id}", "error", str(e))
        set_task_status(task_id, pcap_index, "失败", "align_data", f"模块{pcap_index}第二步生成、回放数据对齐时出错，共5步，报错如下: {str(e)}")
        logger.error(f"数据对齐时出错: {str(e)}")
        raise


def safe_format(value):
    # 如果值是 NaN 或 None，则返回 0 或其他默认值
    if pd.isna(value):
        return None  # 或者根据需求返回 None
    return "{:.6f}".format(value)

def get_bottleneck_analysis(url):
    """根据URL特征返回字符串格式的分析"""
    # 增强版规则库
    analysis_rules = [
        {
            'keywords': ['account', 'act'],
            'cause': "高频账户操作导致数据库锁竞争",
            'solution': "优化账户表索引（添加复合索引）；引入Redis缓存账户状态信息；批量处理账户操作"  # 改为字符串
        },
        {
            'keywords': ['cust', 'customer'],
            'cause': "客户信息关联查询复杂度过高",
            'solution': "物化视图预计算关联数据；引入Elasticsearch优化查询；业务拆分降低事务粒度"
        },
        {
            'keywords': ['insert', 'create'],
            'cause': "逐条写入导致IO压力过大",
            'solution': "批量操作合并数据库事务；采用异步队列缓冲写入；调整存储引擎配置"
        },
        {
            'keywords': ['file', 'upload'],
            'cause': "大文件传输引发网络瓶颈",
            'solution': "实现分块上传/断点续传；使用OSS对象存储分流；启用Brotli压缩传输"
        }
    ]

    # 带优先级的匹配逻辑
    for rule in analysis_rules:
        if any(kw in url.lower() for kw in rule['keywords']):
            return rule

    # 默认返回（也保持字符串格式）
    return {
        'cause': "业务逻辑处理耗时过长",
        'solution': "使用性能剖析工具定位热点；优化算法时间复杂度；考虑JIT编译优化"
    }

@celery.task(name='server.cluster_analysis_data')
def cluster_analysis_data(results, pcap_index, replay_task_id, replay_id, production_ip, replay_ip,
                          replay_csv_file_path,
                          production_csv_file_path, task_id, production_json_path, replay_json_path,
                          alignment_csv_file_path):

    contrast_delay_conclusion = None
    res = {
        "comparison_analysis": {},
        "anomaly_detection": {},
    }
    anomaly_dict = [{
        "request_url": "/portal_todo/api/getAllUserTodoData",
        "env": "production",
        "count": 9999,  # hyf 修改格式
        "hostip": production_ip,
        "class_method": "api_get",
        "bottleneck_cause": "(当前该部分为展示样例)",
        "solution": "(当前该部分为展示样例)"
    }]
    res['anomaly_detection']['dict'] = anomaly_dict

    try:
        # 更新任务状态为 "正在处理"
        # redis_client.hset(f"task_status:{task_id}", "status", "正在处理")
        # redis_client.hset(f"task_status:{task_id}", "step", "cluster_analysis_data")
        # redis_client.hset(f"task_status:{task_id}", "message", "正在进行第三步，聚类分析，共5步")
        set_task_status(task_id, pcap_index, "正在处理", "cluster_analysis_data", f"模块{pcap_index}正在进行第三步，聚类分析，共5步")

        # res variable  我感觉这个res应该放在try except 外面
        # res = {
        #     "comparison_analysis": {},
        #     "anomaly_detection": {},
        # }

        # Process CSV files and get comparison analysis data to build JSON
        # Request_Info_File_Path = f"packet_analysis/json_build/path_function.csv"
        logger.info(f"json started at {datetime.now()}")
        DataBase = DB(csv_back=replay_csv_file_path, csv_production=production_csv_file_path)
        # 添加返回值
        data_list, path_delay_dict, contrast_delay_conclusion = DataBase.built_all_dict()

        outputs_path = f'./results/{task_id}'

        # # 保存两环境对比数据csv、对比图到本地
        comparison_csv_path = os.path.join(outputs_path, f"comparison_analysis_data_{pcap_index}.csv")
        DataBase.save_to_csv(comparison_csv_path)
        comparison_png_path = os.path.join(outputs_path, f"comparison_analysis_data_{pcap_index}.png")
        DataBase.plot_mean_difference_ratio(comparison_png_path)

        # Update response with the data_list for the current analysis
        data_legend = {
            "production": "生产环境",
            "replay": "回放环境",
            "mean_difference_ratio": "差异倍数"
        }
        # res['comparison_analysis']['data'] = data_list
        res['replay_task_id'] = replay_task_id
        res['replay_id'] = replay_id
        res['comparison_analysis']['title'] = "生产与回放环境处理时延对比分析"
        res['comparison_analysis']['x_axis_label'] = "请求路径"
        res['comparison_analysis']['y_axis_label'] = "时延（s）"
        res['comparison_analysis']['data'] = data_list
        res['comparison_analysis']['legend'] = data_legend

        # production cluster anomaly and replay cluster anomaly 在这一步，不同组数据发生报错 该步骤输出classifiy文件 分类后每一类的异常数据文件
        folder_output_pro = os.path.join(outputs_path, f"cluster_production_{pcap_index}")
        pro_anomaly_csv_list, pro_plot_cluster_list = cluster.analysis(production_csv_file_path, folder_output_pro,pcap_index,data_list,env='pro')
        folder_output_replay = os.path.join(outputs_path, f"cluster_replay_{pcap_index}")
        replay_anomaly_csv_list, replay_plot_cluster_list = cluster.analysis(replay_csv_file_path, folder_output_replay,pcap_index,data_list,env='replay')

        # Process anomaly CSV files to build JSON
        all_pro_anomaly_details = anomaly_detection.process_anomalies(pro_anomaly_csv_list, "production",
                                                                      production_ip)
        all_replay_anomaly_details = anomaly_detection.process_anomalies(replay_anomaly_csv_list, "replay",
                                                                         replay_ip)
        combined_anomaly_details = all_pro_anomaly_details + all_replay_anomaly_details
        # res['anomaly_detection']['details'] = combined_anomaly_details  #既包含生产又包含回放的异常数据0225hyf
        res['anomaly_detection']['details'] = all_replay_anomaly_details  #只包含回放的异常数据

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
        res['anomaly_detection']['dict']=dict_output



        # redis_client.hset(f"task_status:{task_id}", "status", "完成")
        # redis_client.hset(f"task_status:{task_id}", "message", "第三步聚类分析完成，共5步")
        set_task_status(task_id, pcap_index, "完成", "cluster_analysis_data", f"模块{pcap_index}第三步聚类分析完成，共5步")

    except Exception as e:
        # 更新任务状态为 "失败"
        # redis_client.hset(f"task_status:{task_id}", "status", "失败")
        # redis_client.hset(f"task_status:{task_id}", "message", f"第三步聚类分析时出错，共5步，报错如下： {str(e)}")
        set_task_status(task_id, pcap_index, "失败", "cluster_analysis_data", f"模块{pcap_index}第三步聚类分析时出错，共5步，报错如下： {str(e)}")
        logger.error(f"聚类分析时出错: {str(e)}")
        raise

    # 先预设的'anomaly_detection'中的correlation, bottleneck部分
    data_correlation = [
        {
            "env": "production",
            "hostip": production_ip,
            # "class_method": "api_get",  #hyf删掉这个字段，没用到
            "description": "生产环境采集点的性能数据与服务器平均处理时延的相关系数",  # 新增 关于介绍谁和谁的相关系数的描述字段
            "conclusion": "生产环境中与平均处理时延相关性最强的指标是xxx",  # 新增 通过计算相关系数，给出分析结论
            "solution": "优化建议是xxx",  # 新增给出优化建议的字段
            "correlation_data": [{
                "index_id": "生产环境采集的性能数据json文件与pcap包时间不匹配，无法计算相关系数",
                "value": 9999
            }
            ]
        },
        {
            "env": "replay",
            "hostip": replay_ip,
            # "class_method": "api_post",  #hyf删掉这个字段，没用到
            "description": "回放环境采集点的性能数据与服务器平均处理时延的相关系数",  # 新增 关于介绍谁和谁的相关系数的描述字段
            "conclusion": "回放环境中与平均处理时延相关性最强的指标是xxx",  # 新增 通过计算相关系数，给出分析结论
            "solution": "优化建议是xxx",  # 新增给出优化建议的字段
            "correlation_data": [{
                "index_id": "回放环境采集的性能数据json文件与pcap包时间不匹配，无法计算相关系数",
                "value": 9999
            }
            ]
        }
    ]

    data_random_forest = [
        {
            "env": "production",
            "hostip": production_ip,
            # "class_method": "api_get",  #hyf删掉这个字段，没用到
            "description": "生产环境采集点的性能数据与服务器平均处理时延的相关系数",  # 新增 关于介绍谁和谁的相关系数的描述字段
            "conclusion": "生产环境中与平均处理时延相关性最强的指标是xxx",  # 新增 通过计算相关系数，给出分析结论
            "solution": "优化建议是xxx",  # 新增给出优化建议的字段
            "importance_data": [{
                "index_id": "生产环境采集的性能数据json文件与pcap包时间不匹配，无法计算相关系数",
                "value": 9999
            }
            ]
        },
        {
            "env": "replay",
            "hostip": replay_ip,
            # "class_method": "api_post",  #hyf删掉这个字段，没用到
            "description": "回放环境采集点的性能数据与服务器平均处理时延的相关系数",  # 新增 关于介绍谁和谁的相关系数的描述字段
            "conclusion": "回放环境中与平均处理时延相关性最强的指标是xxx",  # 新增 通过计算相关系数，给出分析结论
            "solution": "优化建议是xxx",  # 新增给出优化建议的字段
            "importance_data": [{
                "index_id": "回放环境采集的性能数据json文件与pcap包时间不匹配，无法计算相关系数",
                "value": 9999
            }
            ]
        }
    ]

    data_performance_bottleneck_analysis = {
        "bottlenecks": [
            {
                "env": "replay",
                "hostip": replay_ip,
                "class_name": "error warning",
                "cause": "回放环境随机森林模型建立失败，为确保顺利返回，当前为预设值，具体原因请排查",
                "criteria": "可能是回放环境采集时间不足，日志文件和数据包文件时间不匹配",
                "solution": "具体原因可以结合输出日志分析"
            },
            {
                "env": "production",
                "hostip": production_ip,
                "class_name": "error warning",
                "cause": "生产环境随机森林模型建立失败，为确保顺利返回，当前为预设值，具体原因请排查",
                "criteria": "可能是生产环境采集时间不足，日志文件和数据包文件时间不匹配",
                "solution": "具体原因可以结合输出日志分析"
            }
        ]
    }
    optimization_suggestions_correlation = {
        "非root用户进程数": "1. 使用`ulimit`命令限制用户的最大进程数。2. 检查是否有异常进程（如僵尸进程），使用`ps aux`和`kill`命令清理。3. 优化应用程序，减少不必要的进程创建。",
        "活动进程数": "1. 检查是否有不必要的后台进程，使用`ps aux`和`kill`命令终止。2. 优化应用程序逻辑，减少并发进程数。3. 使用进程池（如Python的`multiprocessing.Pool`）限制并发进程数。",
        "当前运行队列等待运行的进程数": "1. 增加CPU资源（如升级CPU或增加CPU核心数）。2. 优化任务调度，使用优先级调度（如`nice`命令）确保关键任务优先执行。3. 减少不必要的任务并发，避免任务堆积。",
        "处在非中断睡眠状态的进程数": "1. 检查是否有进程因I/O操作阻塞，优化I/O性能（如使用SSD、增加磁盘带宽）。2. 优化数据库查询，减少锁等待时间。3. 检查是否有死锁或资源竞争问题，使用工具（如`strace`）分析进程状态。",
        "CPU利用率": "1. 优化代码逻辑，减少CPU密集型操作（如循环嵌套、复杂计算）。2. 使用多线程或多进程分担CPU负载。3. 升级CPU或增加CPU核心数。",
        "内存利用率": "1. 优化应用程序，减少内存泄漏（如使用内存分析工具`Valgrind`）。2. 增加物理内存或使用交换区（Swap）。3. 减少不必要的缓存，释放未使用的内存。",
        "1分钟平均负载": "1. 检查是否有高负载进程，使用`top`或`htop`命令定位并优化。2. 增加服务器资源（如CPU、内存）。3. 优化任务调度，避免短时间内大量任务并发。",
        "CPU平均等待IO率": "1. 优化磁盘I/O性能（如使用SSD、增加磁盘带宽）。2. 减少不必要的I/O操作（如批量读写数据）。3. 使用缓存（如Redis）减少对磁盘的依赖。",
        "中央处理器平均系统调用率": "1. 优化应用程序，减少频繁的系统调用（如合并小文件读写操作）。2. 使用更高效的系统调用（如`sendfile`替代`read/write`）。3. 检查是否有异常的系统调用（如频繁的文件打开/关闭），使用`strace`工具分析。",
        "交换区利用率": "1. 增加物理内存，减少对交换区的依赖。2. 优化应用程序，减少内存使用（如释放未使用的内存）。3. 调整交换区配置（如`swappiness`参数），减少交换区使用频率。",
        "等待连接数": "1. 优化服务器配置（如增加`backlog`参数）。2. 增加服务器资源（如CPU、内存）以处理更多连接。3. 使用负载均衡（如Nginx）分散连接压力。",
        "关闭连接数": "1. 检查是否有连接泄漏，使用工具（如`netstat`）分析连接状态。2. 优化应用程序，及时关闭不再使用的连接。3. 调整连接超时时间（如`keepalive_timeout`）。",
        "文件系统总利用率": "1. 清理不必要的文件（如日志文件、临时文件）。2. 增加磁盘容量或使用分布式文件系统（如HDFS）。3. 优化文件存储（如压缩文件、使用更高效的文件系统）。"
    }
    optimization_suggestions_random_forest = {
        "非root用户进程数": "1. 使用`ulimit`命令限制用户的最大进程数。2. 检查是否有异常进程（如僵尸进程），使用`ps aux`和`kill`命令清理。3. 优化应用程序，减少不必要的进程创建。4. 使用容器化技术（如Docker）限制每个容器的进程数。",
        "活动进程数": "1. 检查是否有不必要的后台进程，使用`ps aux`和`kill`命令终止。2. 优化应用程序逻辑，减少并发进程数。3. 使用进程池（如Python的`multiprocessing.Pool`）限制并发进程数。4. 使用任务队列（如Celery）管理异步任务。",
        "当前运行队列等待运行的进程数": "1. 增加CPU资源（如升级CPU或增加CPU核心数）。2. 优化任务调度，使用优先级调度（如`nice`命令）确保关键任务优先执行。3. 减少不必要的任务并发，避免任务堆积。4. 使用分布式任务调度系统（如Kubernetes）分散任务负载。",
        "处在非中断睡眠状态的进程数": "1. 检查是否有进程因I/O操作阻塞，优化I/O性能（如使用SSD、增加磁盘带宽）。2. 优化数据库查询，减少锁等待时间。3. 检查是否有死锁或资源竞争问题，使用工具（如`strace`）分析进程状态。4. 使用异步I/O（如AIO）减少阻塞。",
        "CPU利用率": "1. 优化代码逻辑，减少CPU密集型操作（如循环嵌套、复杂计算）。2. 使用多线程或多进程分担CPU负载。3. 升级CPU或增加CPU核心数。4. 使用JIT编译器（如PyPy）优化代码执行效率。",
        "内存利用率": "1. 优化应用程序，减少内存泄漏（如使用内存分析工具`Valgrind`）。2. 增加物理内存或使用交换区（Swap）。3. 减少不必要的缓存，释放未使用的内存。4. 使用内存池技术（如jemalloc）优化内存分配。",
        "1分钟平均负载": "1. 检查是否有高负载进程，使用`top`或`htop`命令定位并优化。2. 增加服务器资源（如CPU、内存）。3. 优化任务调度，避免短时间内大量任务并发。4. 使用自动扩展机制（如AWS Auto Scaling）动态调整资源。",
        "CPU平均等待IO率": "1. 优化磁盘I/O性能（如使用SSD、增加磁盘带宽）。2. 减少不必要的I/O操作（如批量读写数据）。3. 使用缓存（如Redis）减少对磁盘的依赖。4. 使用异步I/O模型（如Node.js）提高I/O效率。",
        "中央处理器平均系统调用率": "1. 优化应用程序，减少频繁的系统调用（如合并小文件读写操作）。2. 使用更高效的系统调用（如`sendfile`替代`read/write`）。3. 检查是否有异常的系统调用（如频繁的文件打开/关闭），使用`strace`工具分析。4. 使用用户态网络栈（如DPDK）减少内核态系统调用。",
        "交换区利用率": "1. 增加物理内存，减少对交换区的依赖。2. 优化应用程序，减少内存使用（如释放未使用的内存）。3. 调整交换区配置（如`swappiness`参数），减少交换区使用频率。4. 使用内存压缩技术（如Zswap）减少交换区压力。",
        "等待连接数": "1. 优化服务器配置（如增加`backlog`参数）。2. 增加服务器资源（如CPU、内存）以处理更多连接。3. 使用负载均衡（如Nginx）分散连接压力。4. 使用连接池技术（如HikariCP）管理数据库连接。",
        "关闭连接数": "1. 检查是否有连接泄漏，使用工具（如`netstat`）分析连接状态。2. 优化应用程序，及时关闭不再使用的连接。3. 调整连接超时时间（如`keepalive_timeout`）。4. 使用长连接复用技术（如HTTP/2）减少连接开销。",
        "文件系统总利用率": "1. 清理不必要的文件（如日志文件、临时文件）。2. 增加磁盘容量或使用分布式文件系统（如HDFS）。3. 优化文件存储（如压缩文件、使用更高效的文件系统）。4. 使用对象存储（如S3）替代本地文件系统。"
    }
    try:
        # 更新任务状态为 "正在处理"
        # redis_client.hset(f"task_status:{task_id}", "status", "正在处理")
        # redis_client.hset(f"task_status:{task_id}", "step", "cluster_analysis_data")
        # redis_client.hset(f"task_status:{task_id}", "message", "开始进行第四步：相关系数和随机森林模型分析，共5步")
        set_task_status(task_id, pcap_index, "正在处理", "cluster_analysis_data", f"模块{pcap_index}进行第四步：相关系数和随机森林模型分析，共5步")

        correlation_analysis_path = os.path.join(outputs_path, f'correlation_analysis_csv_{pcap_index}')
        if not os.path.exists(correlation_analysis_path):
            os.mkdir(correlation_analysis_path)
        production_correlation_path = os.path.join(correlation_analysis_path, f'production_correlation.csv')
        production_kpi_csv_path = os.path.join(correlation_analysis_path, f'production_kpi.csv')
        production_correlation_df = calc_correlation(production_json_path, production_csv_file_path,
                                                     production_correlation_path, production_kpi_csv_path)
        logger.info("生产环境相关系数计算完毕")

        replay_correlation_path = os.path.join(correlation_analysis_path, f'replay_correlation.csv')
        replay_kpi_csv_path = os.path.join(correlation_analysis_path, f'replay_kpi.csv')
        replay_correlation_df = calc_correlation(replay_json_path, replay_csv_file_path,
                                                 replay_correlation_path, replay_kpi_csv_path)
        logger.info("回放环境相关系数计算完毕")

        # 将 corr_df 中的 KPI名称 和 相关系数 对应到 index_id 和 value
        if not production_correlation_df.empty:
            if '相关系数' in production_correlation_df.columns and 'KPI名称' in production_correlation_df.columns:
                for index, row in production_correlation_df.iterrows():
                    if pd.notna(row['相关系数']):  # 只处理非 NaN 的相关系数
                        correlation_data = {
                            "index_id": row['KPI名称'],
                            "value": row['相关系数']
                        }
                        # 检查是否需要清除默认值
                        if len(data_correlation[0]['correlation_data']) == 1 and \
                                data_correlation[0]['correlation_data'][0]['value'] == 9999:
                            # 如果列表中只有默认值，清空它
                            data_correlation[0]['correlation_data'].clear()
                            data_correlation[0]['conclusion'] = f"生产环境中与平均处理时延相关性最强的指标是{row['KPI名称']}"
                            data_correlation[0]['solution']=optimization_suggestions_correlation.get(row['KPI名称'],'该项指标暂无更好的优化建议')

                        # 将数据添加到 production 和 replay 的 correlation_data 中
                        data_correlation[0]['correlation_data'].append(correlation_data)
            else:
                print("列 '相关系数' 或 'KPI名称' 不存在于 生产 DataFrame 中")
        # 将 corr_df 中的 KPI名称 和 相关系数 对应到 index_id 和 value
        if not replay_correlation_df.empty:
            if '相关系数' in replay_correlation_df.columns and 'KPI名称' in replay_correlation_df.columns:
                for index, row in replay_correlation_df.iterrows():
                    if pd.notna(row['相关系数']):  # 只处理非 NaN 的相关系数
                        correlation_data = {
                            "index_id": row['KPI名称'],
                            "value": row['相关系数']
                        }

                        # 检查是否需要清除默认值
                        if len(data_correlation[1]['correlation_data']) == 1 and \
                                data_correlation[1]['correlation_data'][0]['value'] == 9999:
                            # 如果列表中只有默认值，清空它
                            data_correlation[1]['correlation_data'].clear()
                            data_correlation[1]['conclusion'] = f"回放环境中与平均处理时延相关性最强的指标是{row['KPI名称']}"
                            data_correlation[1]['solution'] = optimization_suggestions_correlation.get(row['KPI名称'],'该项指标暂无更好的优化建议')

                        # 将数据添加到 production 和 replay 的 correlation_data 中
                        data_correlation[1]['correlation_data'].append(correlation_data)
            else:
                print("列 '相关系数' 或 'KPI名称' 不存在于 回放 DataFrame 中")

        # 随机森林计算
        try:
            production_mse_df, production_importance_df = calc_forest_model(production_kpi_csv_path,
                                                                            correlation_analysis_path, 'production')
            logger.info(f"生产计算随机森林模型ok")
        except Exception as e:
            logger.info(f"生产环境计算随机森林模型时报错，报错如下：{e}")
            production_mse_df = None
            production_importance_df = pd.DataFrame()

        try:
            replay_mse_df, replay_importance_df = calc_forest_model(replay_kpi_csv_path,
                                                                    correlation_analysis_path, 'replay')
            logger.info(f"回放计算随机森林模型ok")
        except Exception as e:
            logger.info(f"回放计算随机森林模型时报错，报错如下：{e}")
            replay_mse_df = None
            replay_importance_df = pd.DataFrame()

        if not production_importance_df.empty:
            if 'Importance' in production_importance_df.columns and 'KPI' in production_importance_df.columns:
                for index, row in production_importance_df.iterrows():
                    if pd.notna(row['Importance']):  # 只处理非 NaN 的相关系数
                        importance_data = {
                            "index_id": row['KPI'],
                            "value": safe_format(row['Importance'])
                        }
                        # 检查是否需要清除默认值
                        if len(data_random_forest[0]['importance_data']) == 1 and \
                                data_random_forest[0]['importance_data'][0]['value'] == 9999:
                            # 如果列表中只有默认值，清空它
                            data_random_forest[0]['importance_data'].clear()
                            data_random_forest[0]['conclusion'] = f"生产环境中重要性排序最强的指标是{row['KPI']}"
                            data_random_forest[0]['solution'] = optimization_suggestions_random_forest.get(row['KPI'],'该项指标暂无更好的优化建议')

                        # 将数据添加到 production 和 replay 的 correlation_data 中
                        data_random_forest[0]['importance_data'].append(importance_data)
            else:
                print("列 'Importance' 或 'KPI' 不存在于 生产 DataFrame 中")
        # 将 corr_df 中的 KPI名称 和 相关系数 对应到 index_id 和 value
        if not replay_importance_df.empty:
            if 'Importance' in replay_importance_df.columns and 'KPI' in replay_importance_df.columns:
                for index, row in replay_importance_df.iterrows():
                    if pd.notna(row['Importance']):  # 只处理非 NaN 的相关系数
                        importance_data = {
                            "index_id": row['KPI'],
                            "value": safe_format(row['Importance'])
                        }
                        # 检查是否需要清除默认值
                        if len(data_random_forest[1]['importance_data']) == 1 and \
                                data_random_forest[1]['importance_data'][0]['value'] == 9999:
                            # 如果列表中只有默认值，清空它
                            data_random_forest[1]['importance_data'].clear()
                            data_random_forest[1]['conclusion'] = f"回放环境中重要性排序最强的指标是{row['KPI']}"
                            data_random_forest[1]['solution'] = optimization_suggestions_random_forest.get(row['KPI'],'该项指标暂无更好的优化建议')

                        # 将数据添加到 production 和 replay 的 correlation_data 中
                        data_random_forest[1]['importance_data'].append(importance_data)
            else:
                print("列 'Importance' 或 'KPI' 不存在于 生产 DataFrame 中")

        # 更新任务状态为 "完成"
        # redis_client.hset(f"task_status:{task_id}", "status", "完成")
        # redis_client.hset(f"task_status:{task_id}", "message", "第四步：相关系数和随机森林模型分析完成，共5步")
        set_task_status(task_id, pcap_index, "完成", "cluster_analysis_data", f"模块{pcap_index}第四步：相关系数和随机森林模型分析完成，共5步")

        # 检查 replay_importance_df 是否为空
        # if not replay_importance_df.empty:
        #     # 如果不为空，构建 cause 和 criteria 字符串
        #     replay_cause = ", ".join([row['KPI'] for index, row in replay_importance_df.iterrows()])
        #     replay_criteria = ", ".join([str(row['Importance']) for index, row in replay_importance_df.iterrows()])
        #     # 提取最重要的两个 KPI
        #     kpi_index_0 = replay_importance_df.iloc[0]['KPI'] if replay_importance_df.shape[0] > 0 else ''
        #     kpi_index_1 = replay_importance_df.iloc[1]['KPI'] if replay_importance_df.shape[0] > 1 else ''
        #     replay_solution = f"{kpi_index_0}和{kpi_index_1}指标对服务器处理时延影响力较大，建议排查该方面的原因进行优化。" if kpi_index_0 and kpi_index_1 else "回放环境采集的性能数据json文件指标数目太少,不能建立随机森林模型"
        # else:
        #     replay_cause = "回放环境采集的性能数据json文件与pcap包时间段不匹配"
        #     replay_criteria = "无法建立随机森林模型，计算重要性"
        #     replay_solution = "请检测输入的回放log文件与回放pcap包是否一致"

        # if not production_importance_df.empty:
        #     # 如果不为空，构建 cause 和 criteria 字符串
        #     production_cause = ", ".join([row['KPI'] for index, row in production_importance_df.iterrows()])
        #     production_criteria = ", ".join([str(row['Importance']) for index, row in production_importance_df.iterrows()])
        #     # 提取最重要的两个 KPI
        #     kpi_index_0 = production_importance_df.iloc[0]['KPI'] if production_importance_df.shape[0] > 0 else ''
        #     kpi_index_1 = production_importance_df.iloc[1]['KPI'] if production_importance_df.shape[0] > 1 else ''
        #     production_solution = f"{kpi_index_0}和{kpi_index_1}指标对服务器处理时延影响力较大，建议排查该方面的原因进行优化。" if kpi_index_0 and kpi_index_1 else "生产环境采集的性能数据json文件指标数目太少,不能建立随机森林模型"
        # else:
        #     production_cause = "生产环境采集的性能数据json文件与pcap包时间段不匹配"
        #     production_criteria = "无法建立随机森林模型，计算重要性"
        #     production_solution = "请检测输入的生产log文件与生产pcap包是否一致"
        # txt old代码
        data_performance_bottleneck_analysis = {
            "bottlenecks": [
                {
                    "env": "瓶颈发生的环境replay",
                    "hostip": replay_ip,
                    "class_name": "该部分为扩展用的备用瓶颈结论接口，暂无输出",
                    "cause": "扩展用的瓶颈原因",
                    "criteria": "判断为该瓶颈的标准",
                    "solution": "该瓶颈的解决方案"
                },
                {
                    "env": "瓶颈发生的环境production",
                    "hostip": production_ip,
                    "class_name": "扩展用的瓶颈结论接口，暂无输出",
                    "cause": "瓶颈原因的备用接口，可扩展",
                    "criteria": "判断为该瓶颈的标准，扩展备用",
                    "solution": "该瓶颈的解决方案，扩展备用"
                }
            ]
        }
    except Exception as e:
        # 更新任务状态为 "失败"
        # redis_client.hset(f"task_status:{task_id}", "status", "失败")
        # redis_client.hset(f"task_status:{task_id}", "message", f"第四步：相关系数和随机森林模型分析时出错，共5步，报错如下: {str(e)}")
        set_task_status(task_id, pcap_index, "失败", "cluster_analysis_data", f"模块{pcap_index}第四步：相关系数和随机森林模型分析时出错，共5步，报错如下: {str(e)}")

        # print(f"发生 KeyError: {e}")
        logger.info(f"发生 错误: {e}")
        pass
    res['anomaly_detection']['correlation'] = data_correlation
    res['anomaly_detection']['random_forest'] = data_random_forest
    res['performance_bottleneck_analysis'] = data_performance_bottleneck_analysis  # txt old

    # 分析瓶颈1 状态码
    bottleneck_analysis_response_code = alignment_analysis.analyze_status_code(alignment_csv_file_path,
                                                                               output_prefix=f'{outputs_path}/test_status_code_analysis_{pcap_index}')
    # 方式1 返回的是txt文本内容
    # bottleneck_analysis_response_code["env"] = "replay"    #此处应该是生产加上回放，两环境的
    # bottleneck_analysis_response_code["hostip"] = replay_ip
    # logger.info(f"bottleneck_analysis_response_code: {bottleneck_analysis_response_code}")
    # res['performance_bottleneck_analysis']['bottlenecks'].append(bottleneck_analysis_response_code)

    # 方式2 返回json格式的信息
    bottleneck_analysis_response_code[0]["hostip"] = production_ip
    bottleneck_analysis_response_code[1]["hostip"] = replay_ip
    res['performance_bottleneck_analysis']['response_code'] = bottleneck_analysis_response_code

    # 分析瓶颈2 响应包是否完整
    bottleneck_analysis_empty_response = alignment_analysis.analyze_empty_responses(alignment_csv_file_path,
                                                                                    output_prefix=f'{outputs_path}/empty_responses_analysis_{pcap_index}')

    # 方式1 返回的是txt文本内容
    # bottleneck_analysis_empty_response["env"] = "replay"    #此处应该是生产加上回放，两环境的
    # bottleneck_analysis_empty_response["hostip"] = replay_ip
    # logger.info(f"bottleneck_analysis_empty_response: {bottleneck_analysis_empty_response}")
    # res['performance_bottleneck_analysis']['bottlenecks'].append(bottleneck_analysis_empty_response)

    # 方式2 返回json格式的信息
    bottleneck_analysis_empty_response[0]["hostip"] = production_ip
    bottleneck_analysis_empty_response[1]["hostip"] = replay_ip
    bottleneck_analysis_empty_response[0]["env"] = "production"
    bottleneck_analysis_empty_response[1]["env"] = "replay"
    res['performance_bottleneck_analysis']['empty_response'] = bottleneck_analysis_empty_response
    # print("222222222222")
    # print(bottleneck_analysis_empty_response)

    # 分析瓶颈3 传输窗口瓶颈检测
    bottleneck_analysis_zero_window = alignment_analysis.analyze_zero_window_issues(alignment_csv_file_path,
                                                                                    output_prefix=f'{outputs_path}/zero_window_analysis_{pcap_index}')
    # 方式1 返回的是txt文本内容
    # bottleneck_analysis_zero_window["env"] = "replay"    #此处应该是生产加上回放，两环境的
    # bottleneck_analysis_zero_window["hostip"] = replay_ip
    # logger.info(f"bottleneck_analysis_zero_window: {bottleneck_analysis_zero_window}")
    # res['performance_bottleneck_analysis']['bottlenecks'].append(bottleneck_analysis_zero_window)

    # 方式2 返回json格式的信息
    bottleneck_analysis_zero_window[0]["hostip"] = production_ip
    bottleneck_analysis_zero_window[1]["hostip"] = replay_ip
    bottleneck_analysis_zero_window[0]["env"] = "production"
    bottleneck_analysis_zero_window[1]["env"] = "replay"
    res['performance_bottleneck_analysis']['transmission_window'] = bottleneck_analysis_zero_window

    # 分析瓶颈4 数据库查询瓶颈检测
    df_list_production = db_analysis.load_csv_logs(production_csv_file_path)
    df_list_replay = db_analysis.load_csv_logs(replay_csv_file_path)
    # 设置执行时间阈值（单位：毫秒）
    exec_time_threshold = 400
    production_database_logs, production_database_logs_count \
        = db_analysis.load_database_logs(production_json_path, exec_time_threshold)
    production_bottleneck_analysis_database = db_analysis.match_logs(
        production_database_logs,
        df_list_production
    )
    logger.info(f"Production database logs count: {production_database_logs_count}")
    replay_database_logs, replay_database_logs_count \
        = db_analysis.load_database_logs(replay_json_path, exec_time_threshold)
    replay_bottleneck_analysis_database = db_analysis.match_logs(
        replay_database_logs,
        df_list_replay
    )
    logger.info(f"Replay database logs count: {replay_database_logs_count}")

    production_database_logs_ratio = (len(production_bottleneck_analysis_database) / production_database_logs_count) if production_database_logs_count else 0
    replay_database_logs_ratio = (len(replay_bottleneck_analysis_database) / replay_database_logs_count) if replay_database_logs_count else 0

    bottleneck_analysis_database = [
        {
            "hostip": production_ip,
            "env": "production",
            "class_name": "生产环境数据库日志分析",
            "details": [
                {
                    "bottleneck_type": "数据库查询时间异常" if production_database_logs_ratio > 0.01 else "数据库部分无明显异常",
                    "cause": "异常请求影响" if production_database_logs_ratio > 0.01 else "-",
                    "count": len(production_bottleneck_analysis_database),
                    "total_count": production_database_logs_count,
                    "ratio": production_database_logs_ratio,
                    "solution": "排查对应请求的数据库查询性能" if production_database_logs_ratio > 0.01 else "-",
                    "request_paths": production_bottleneck_analysis_database
                }
            ]
        },
        {
            "hostip": replay_ip,
            "env": "replay",
            "class_name": "回放环境数据库日志分析",
            "details": [
                {
                    "bottleneck_type": "数据库查询时间异常" if replay_database_logs_ratio > 0.01 else "数据库部分无明显异常",
                    "cause": "异常请求影响" if replay_database_logs_ratio > 0.01 else "-",
                    "count": len(replay_bottleneck_analysis_database),
                    "total_count": replay_database_logs_count,
                    "ratio": replay_database_logs_ratio,
                    "solution": "排查对应请求的数据库查询性能" if replay_database_logs_ratio > 0.01 else "-",
                    "request_paths": replay_bottleneck_analysis_database
                }
            ]
        }
    ]
    # 方式2 返回json格式的信息
    res['performance_bottleneck_analysis']['database'] = bottleneck_analysis_database

    # Exception 分析
    production_exception_logs, production_exception_logs_count \
        = exception_analysis.load_exception_logs(production_json_path)
    production_bottleneck_analysis_exception = exception_analysis.match_logs(
        production_exception_logs,
        df_list_production
    )
    logger.info(f"Production exception logs count: {production_exception_logs_count}")
    replay_exception_logs, replay_exception_logs_count \
        = exception_analysis.load_exception_logs(replay_json_path)
    replay_bottleneck_analysis_exception = exception_analysis.match_logs(
        replay_exception_logs,
        df_list_replay
    )
    logger.info(f"Replay exception logs count: {replay_exception_logs_count}")

    bottleneck_exception_database = [
        {
            "hostip": production_ip,
            "env": "production",
            "class_name": "生产环境异常日志分析",
            "details": [
                {
                    "bottleneck_type": "数据库或模块报错",
                    "cause": "异常请求影响",
                    "total_count": production_exception_logs_count,
                    "solution": "排查对应程序模块功能",
                    "request_paths": production_bottleneck_analysis_exception
                }
            ]
        },
        {
            "hostip": replay_ip,
            "env": "replay",
            "class_name": "回放环境异常日志分析",
            "details": [
                {
                    "bottleneck_type": "数据库或模块报错",
                    "cause": "异常请求影响",
                    "total_count": replay_exception_logs_count,
                    "solution": "排查对应程序模块功能",
                    "request_paths": replay_bottleneck_analysis_exception
                }
            ]
        }
    ]
    # 方式2 返回json格式的信息
    res['performance_bottleneck_analysis']['exception'] = bottleneck_exception_database

    # anomaly_dict = [{
    #     "request_url": "/portal_todo/api/getAllUserTodoData",
    #     "env": "production",
    #     "count": 9999,  # hyf 修改格式
    #     "hostip": production_ip,
    #     "class_method": "api_get",
    #     "bottleneck_cause": "(当前该部分为展示样例)",
    #     "solution": "(当前该部分为展示样例)"
    # }]
    # res['anomaly_detection']['dict'] = anomaly_dict

    logger.info("Cluster_analysis finished.")

    return pcap_index, res, contrast_delay_conclusion


def save_response_to_file(response, file_path="response.json"):
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(response, file, ensure_ascii=False, indent=4)
        print(f"Response successfully saved to {file_path}")
    except Exception as e:
        print(f"Failed to save response: {e}")

def generate_overview_conclusion(task_id, index):
    """
    生成结论信息。
    
    参数:
        task_id (str): 任务 ID。
        index (int): 模块索引。
    
    返回:
        str: 生成的结论信息。
    """
    # 读取生产环境和回放环境的 CSV 文件
    production_csv_path = f'results/{task_id}/extracted_production_data_{index}.csv'
    replay_csv_path = f'results/{task_id}/extracted_replay_data_{index}.csv'
    aligned_csv_path = f'results/{task_id}/aligned_data_{index}.csv'

    try:
        # 获取生产环境和回放环境的请求数量
        production_df = pd.read_csv(production_csv_path)
        replay_df = pd.read_csv(replay_csv_path)
        production_count = len(production_df)
        replay_count = len(replay_df)

        # 生成请求数量结论
        count_conclusion = f"生产环境有 {production_count} 个请求，回放环境有 {replay_count} 个请求。"
        if max(production_count, replay_count) / min(production_count, replay_count) >= 1.2:
            count_conclusion += " 生产环境和回放环境请求数量上存在显著差异，请检查回放时间是否足够"
        else:
            count_conclusion += " 生产环境和回放环境数量上差异不大。"

        # 获取对齐结果
        aligned_df = pd.read_csv(aligned_csv_path)
        success_count = len(aligned_df[aligned_df['state'].isin(['fail1 no best match but has match', 'success'])])
        # fail_count = len(aligned_df[aligned_df['state'] == 'fail2 no match'])
        fail_count = len(aligned_df[aligned_df['state'] == 'failed'])
        total_count = success_count + fail_count
        success_ratio = success_count / total_count if total_count > 0 else 0

        # 生成对齐结论
        alignment_conclusion = f"生产环境和回放环境对齐了 {success_count} 个，失败了 {fail_count} 个，对齐成功的比例是 {success_ratio:.2%}。"
        if success_ratio >= 0.9:
            alignment_conclusion += " 生产环境和回放环境相同请求数据匹配，基本对齐。"
        else:
            alignment_conclusion += " 生产环境和回放环境相同请求数据匹配度不高，建议重新查看该模块的回放数据。"

        # 返回完整结论
        return count_conclusion + " " + alignment_conclusion

    except Exception as e:
        return f"生成结论时出错: {str(e)}"

@celery.task(name='server.final_task')
def final_task(results, data, task_id, ip_address):
    try:
        # 更新任务状态为 "正在处理"
        # redis_client.hset(f"task_status:{task_id}", "status", "正在处理")
        # redis_client.hset(f"task_status:{task_id}", "step", "final_task")
        # redis_client.hset(f"task_status:{task_id}", "message", "正在进行第五步：开始生成最终报告，共5步")
        set_task_status(task_id, 200, "正在处理", "final_task", f"正在进行第五步：开始生成最终报告，共5步")

        pcap_info_list = PcapInfoList.parse_obj(data)
        # Initialize the global response with predefined values
        response = {
            "task_id": task_id,
            "individual_analysis_info": [
                {}
                for info in pcap_info_list.pcap_info
            ],
            "overall_analysis_info": {
                "summary": {
                    "performance_trends": "整体性能趋势，重放环境与生产相比通常表现出更高还是更低的延迟。",
                    "common_bottlenecks": "识别在多次分析中观察到的任何反复出现的瓶颈（例如网络问题、数据库减速）例如：网络带宽限制和数据库查询性能是多个任务中经常出现的瓶颈。优化这些方面可显著提高性能。",
                    "anomalies": "突出显示在多个单独分析中出现的任何显著异常，并注意它们是孤立的还是更广泛趋势的一部分。讨论这些异常的可能系统性原因。例如：文件上传过程中最常出现异常，表明服务器端处理或网络稳定性存在潜在问题",
                    "recommendations": "根据单独的发现提供综合建议，例如应优先考虑优化工作的领域。例如：建议优先考虑数据库索引和查询优化，并探索升级网络基础设施。"
                },
                "overview": [
                    {
                        "replay_task_id": info.replay_task_id,
                        "replay_id": info.replay_id,
                        # "text": "回放存在显著性能差异" if info.replay_task_id % 2 == 0 else "回放正常"
                        "text": generate_overview_conclusion(task_id, index)
                        # TODO: Add logic to determine if replay is normal or not
                    }
                    for index, info in enumerate(pcap_info_list.pcap_info)
                ]
            }
        }

        # 控制台输出内容
        # logger.info(f"Results: {results}")

        production_faster_count = 0
        replay_faster_count = 0
        production_faster_modules = []
        replay_faster_modules = []
        for result in results:
            if result is not None:
                index, res, contrast_delay_conclusion = result
                response['individual_analysis_info'][index] = res
                response['overall_analysis_info']['overview'][index]['text'] += contrast_delay_conclusion #这里是额外的内容

                # 统计时延情况
                if "生产环境整体时延较低" in contrast_delay_conclusion:
                    production_faster_count += 1
                    production_faster_modules.append(index)
                elif "回放环境整体时延较低" in contrast_delay_conclusion:
                    replay_faster_count += 1
                    replay_faster_modules.append(index)
        # 生成总结性结论
        total_modules = len(results)
        trends_conclusion = f"此次任务共有{total_modules}个模块，"
        if production_faster_modules:
            trends_conclusion += f"其中模块{', '.join(map(str, production_faster_modules))}生产环境平均时延较低，"
        if replay_faster_modules:
            trends_conclusion += f"模块{', '.join(map(str, replay_faster_modules))}回放环境平均时延较低，"
        if production_faster_count > replay_faster_count:
            trends_conclusion += "整体性能对比上，生产环境快的模块较多，回放环境还需优化。"
        elif production_faster_count < replay_faster_count:
            trends_conclusion += "整体性能对比上，回放环境快的模块较多。"
        else:
            trends_conclusion += "整体性能对比上，生产和回放环境时延相当。"
        response['overall_analysis_info']['summary']['performance_trends'] = trends_conclusion


        save_response_to_file(response, f'./results/{task_id}/response.json')

        # Post the response to the callback URL
        callback_url = os.getenv("CALLBACK_URL", f'http://{ip_address}:18088/api/replay-core/aglAnalysisResult')
        postapi.post_url(json.dumps(response), callback_url)

        # 更新任务状态为 "完成"
        # redis_client.hset(f"task_status:{task_id}", "status", "完成")
        # redis_client.hset(f"task_status:{task_id}", "message", "第五步：最终报告生成完成，共5步")
        set_task_status(task_id, 200, "完成", "final_task", f"第五步：最终报告生成完成，共5步")

    except Exception as e:
        # 更新任务状态为 "失败"
        # redis_client.hset(f"task_status:{task_id}", "status", "失败")
        # redis_client.hset(f"task_status:{task_id}", "message", f"第五步：生成最终报告时出错，共5步，报错如下: {str(e)}")
        set_task_status(task_id, 200, "失败", "final_task", f"第五步：生成最终报告时出错，共5步，报错如下: {str(e)}")
        logger.error(f"生成最终报告时出错: {str(e)}")
        raise


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
            extract_data_coordinator.s([os.path.join(collect.collect_path) for collect in pcap_info.collect_pcap],
                                       production_csv_file_path, production_anomalies_csv_file_path, task_id, index),
            extract_data_coordinator.s([os.path.join(pcap_info.replay_pcap.replay_path)],
                                       replay_csv_file_path, replay_anomalies_csv_file_path, task_id, index))
                           | align_data.s(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path,
                                          task_id, index)
                           | cluster_analysis_data.s(index, pcap_info.replay_task_id, pcap_info.replay_id,
                                                     pcap_info.collect_pcap[0].ip, pcap_info.replay_pcap.ip,
                                                     replay_csv_file_path, production_csv_file_path, task_id,
                                                     pcap_info.collect_log, pcap_info.replay_log,
                                                     alignment_csv_file_path))
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


@app.route('/api/algorithm/status/<task_id>/<int:index>', methods=['GET'])
def get_task_status(task_id, index):
    base_response = {  # 基础响应结构
        "task_id": task_id,
        "module_index": index,
        "status_history": []
    }

    try:
        status_history = redis_client.lrange(f"task_status_history:{task_id}:{index}", 0, -1)

        if not status_history:
            # 构造标准化的错误状态条目
            error_status = {
                "message": f"任务 {task_id} 的模块 {index} 不存在",
                "status": "模块ID错误，模块ID从0开始，len(模块)-1结束，模块ID为200时为该任务所有模块最终状态查询",
                "step": "状态查询",
                "timestamp": datetime.now().isoformat()
            }
            base_response["status_history"].append(error_status)
            return jsonify(base_response), 404

        # 正常数据处理
        decoded_history = [json.loads(item.decode('utf-8')) for item in status_history]
        base_response["status_history"] = decoded_history
        return jsonify(base_response), 200

    except Exception as e:
        # 异常状态条目构建
        error_status = {
            "message": f"系统错误: {str(e)}",
            "status": "异常",
            "step": "状态查询",
            "timestamp": datetime.datetime.now().isoformat()
        }
        base_response["status_history"].append(error_status)
        return jsonify(base_response), 500


# @app.route('/api/algorithm/status/<task_id>/<int:index>', methods=['GET'])
# def get_task_status(task_id, index):
#     try:
#         # 从 Redis 中获取指定模块的状态历史
#         status_history = redis_client.lrange(f"task_status_history:{task_id}:{index}", 0, -1)
#         if not status_history:
#             return jsonify({"error": f"任务 {task_id} 的模块 {index} 不存在"}), 404

#         # 将字节字符串解码为普通字符串，并解析 JSON
#         decoded_history = [json.loads(item.decode('utf-8')) for item in status_history]

#         # 返回任务状态历史信息
#         return jsonify({
#             "task_id": task_id,
#             "module_index": index,
#             "status_history": decoded_history
#         }), 200
#     except Exception as e:
#         # 如果发生异常，返回错误信息
#         return jsonify({"error": f"查询任务状态时出错: {str(e)}"}), 500

# def get_task_status(task_id,index):
#     try:
#         # 从 Redis 中获取指定模块的任务状态
#         status = redis_client.hgetall(f"task_status:{task_id}:{index}")
#         if not status:
#             return jsonify({"error": f"任务id为{task_id}的模块{index}不存在"}), 404

#         # 将字节字符串解码为普通字符串
#         decoded_status = {key.decode('utf-8'): value.decode('utf-8') for key, value in status.items()}

#         # 返回任务状态信息
#         return jsonify({
#             "task_id": task_id,
#             "status": decoded_status.get("status", "未知状态"),
#             "step": decoded_status.get("step", "未知步骤"),
#             "message": decoded_status.get("message", "无额外信息"),
#             "error": decoded_status.get("error", "无错误信息")
#         }), 200
#     except Exception as e:
#         # 如果发生异常，返回错误信息
#         return jsonify({"error": f"查询任务状态时出错: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=7956)
