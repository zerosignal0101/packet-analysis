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
from multiprocessing import Process
import subprocess
import traceback

from src.packet_analysis.json_build.json_host_database_correlation import calc_correlation
from src.packet_analysis.json_build.random_forest_model import calc_forest_model
# Import the new function
from src.packet_analysis.preprocess import extract_to_csv, alignment
from src.packet_analysis.utils import postapi

from src.packet_analysis.json_build.comparison_analysis import *
from src.packet_analysis.analysis import cluster
from src.packet_analysis.json_build import anomaly_detection
from src.packet_analysis.utils.logger_config import logger
from datetime import datetime
from src.packet_analysis.json_build import alignment_analysis, db_analysis

app = Flask(__name__)
# 使用新格式的配置名称
app.config.update(
    include=['src.server'],
    result_backend='redis://redis:6379/0',  # 'redis://redis:6379/0'
    broker_url='redis://redis:6379/0',  # 'redis://redis:6379/0'
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='Asia/Shanghai',
    enable_utc=True,
)

celery = Celery(app.name, broker=app.config['broker_url'])
celery.conf.update(app.config)

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


@celery.task(name='server.extract_data_coordinator')
def extract_data_coordinator(pcap_file_path, csv_file_path, anomalies_csv_file_path, task_id):
    try:
        # 更新任务状态为 "正在处理"
        redis_client.hset(f"task_status:{task_id}", "status", "正在处理")
        redis_client.hset(f"task_status:{task_id}", "step", "extract_data_coordinator")
        redis_client.hset(f"task_status:{task_id}", "message", "正在对 pcap 文件信息提取处理")

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
        # return

        # 更新任务状态为 "完成"
        redis_client.hset(f"task_status:{task_id}", "status", "完成")
        redis_client.hset(f"task_status:{task_id}", "message", "pcap 文件信息提取处理完成")

    except Exception as e:
        # 更新任务状态为 "失败"
        redis_client.hset(f"task_status:{task_id}", "status", "失败")
        redis_client.hset(f"task_status:{task_id}", "message", f" pcap 文件信息提取时出错: {str(e)}")
        logger.error(f"对 pcap 文件信息提取时出错: {str(e)}")
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
def align_data(results, production_csv_file_path, replay_csv_file_path, alignment_csv_file_path, task_id):
    try:
        # 更新任务状态为 "正在处理"
        redis_client.hset(f"task_status:{task_id}", "status", "正在处理")
        redis_client.hset(f"task_status:{task_id}", "step", "align_data")
        redis_client.hset(f"task_status:{task_id}", "message", "正在进行生成、回放数据对齐")
        alignment.alignment_two_paths(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path)

        # 更新任务状态为 "完成"
        redis_client.hset(f"task_status:{task_id}", "status", "完成")
        redis_client.hset(f"task_status:{task_id}", "message", "生成、回放数据对齐完成")

    except Exception as e:
        # 更新任务状态为 "失败"
        redis_client.hset(f"task_status:{task_id}", "status", "失败")
        redis_client.hset(f"task_status:{task_id}", "message", f"生成、回放数据对齐时出错: {str(e)}")
        redis_client.hset(f"task_status:{task_id}", "error", str(e))
        logger.error(f"数据对齐时出错: {str(e)}")
        raise


def safe_format(value):
    # 如果值是 NaN 或 None，则返回 0 或其他默认值
    if pd.isna(value):
        return "999999.999999"  # 或者根据需求返回 None
    return "{:.6f}".format(value)


@celery.task(name='server.cluster_analysis_data')
def cluster_analysis_data(results, pcap_index, replay_task_id, replay_id, production_ip, replay_ip,
                          replay_csv_file_path,
                          production_csv_file_path, task_id, production_json_path, replay_json_path,
                          alignment_csv_file_path):
    try:
        # 更新任务状态为 "正在处理"
        redis_client.hset(f"task_status:{task_id}", "status", "正在处理")
        redis_client.hset(f"task_status:{task_id}", "step", "cluster_analysis_data")
        redis_client.hset(f"task_status:{task_id}", "message", "开始进行聚类分析")

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
        data_list, path_delay_dict = DataBase.built_all_dict()

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

        # production cluster anomaly and replay cluster anomaly
        folder_output_pro = os.path.join(outputs_path, f"cluster_production_{pcap_index}")
        pro_anomaly_csv_list, pro_plot_cluster_list = cluster.analysis(production_csv_file_path, folder_output_pro)
        folder_output_replay = os.path.join(outputs_path, f"cluster_replay_{pcap_index}")
        replay_anomaly_csv_list, replay_plot_cluster_list = cluster.analysis(replay_csv_file_path, folder_output_replay)

        # Process anomaly CSV files to build JSON
        all_pro_anomaly_details = anomaly_detection.process_anomalies(pro_anomaly_csv_list, "production",
                                                                      production_ip)
        all_replay_anomaly_details = anomaly_detection.process_anomalies(replay_anomaly_csv_list, "replay",
                                                                         replay_ip)
        combined_anomaly_details = all_pro_anomaly_details + all_replay_anomaly_details
        res['anomaly_detection']['details'] = combined_anomaly_details

        redis_client.hset(f"task_status:{task_id}", "status", "完成")
        redis_client.hset(f"task_status:{task_id}", "message", "聚类分析完成")

    except Exception as e:
        # 更新任务状态为 "失败"
        redis_client.hset(f"task_status:{task_id}", "status", "失败")
        redis_client.hset(f"task_status:{task_id}", "message", f"聚类分析时出错: {str(e)}")
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
                "criteria": "可能是日志文件和数据包文件时间不匹配",
                "solution": "具体原因可以结合输出日志分析"
            },
            {
                "env": "production",
                "hostip": production_ip,
                "class_name": "error warning",
                "cause": "生产环境随机森林模型建立失败，为确保顺利返回，当前为预设值，具体原因请排查",
                "criteria": "可能是日志文件和数据包文件时间不匹配",
                "solution": "具体原因可以结合输出日志分析"
            }
        ]
    }
    try:
        # 更新任务状态为 "正在处理"
        redis_client.hset(f"task_status:{task_id}", "status", "正在处理")
        redis_client.hset(f"task_status:{task_id}", "step", "cluster_analysis_data")
        redis_client.hset(f"task_status:{task_id}", "message", "开始进行相关系数和随机森林模型分析")

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
                            data_correlation[0][
                                'conclusion'] = f"生产环境中与平均处理时延相关性最强的指标是{row['KPI名称']}"
                            # data_correlation[0]['solution']=f"生产环境中与平均处理时延相关性最强的指标是{row['KPI名称']}"

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
                            data_correlation[1][
                                'conclusion'] = f"回放环境中与平均处理时延相关性最强的指标是{row['KPI名称']}"

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

                        # 将数据添加到 production 和 replay 的 correlation_data 中
                        data_random_forest[1]['importance_data'].append(importance_data)
            else:
                print("列 'Importance' 或 'KPI' 不存在于 生产 DataFrame 中")

        # 更新任务状态为 "完成"
        redis_client.hset(f"task_status:{task_id}", "status", "完成")
        redis_client.hset(f"task_status:{task_id}", "message", "相关系数和随机森林模型分析完成")

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
                    "env": "replay",
                    "hostip": replay_ip,
                    "class_name": "随机森林模型对回放环境KPI性能数据做重要性排序(从大到小)",
                    "cause": "replay_cause",
                    "criteria": "replay_criteria",
                    "solution": "replay_solution"
                },
                {
                    "env": "production",
                    "hostip": production_ip,
                    "class_name": "随机森林模型对生产环境KPI性能数据做重要性排序(从大到小)",
                    "cause": "production_cause",
                    "criteria": "production_criteria",
                    "solution": "production_solution"
                }
            ]
        }
    except Exception as e:
        # 更新任务状态为 "失败"
        redis_client.hset(f"task_status:{task_id}", "status", "失败")
        redis_client.hset(f"task_status:{task_id}", "message", f"相关系数和随机森林模型分析时出错: {str(e)}")

        # print(f"发生 KeyError: {e}")
        logger.info(f"发生 错误: {e}")
        pass
    res['anomaly_detection']['correlation'] = data_correlation
    res['anomaly_detection']['random_forest'] = data_random_forest
    res['performance_bottleneck_analysis'] = data_performance_bottleneck_analysis  # txt old

    # 分析瓶颈1 状态码
    bottleneck_analysis_response_code = alignment_analysis.analyze_status_code(alignment_csv_file_path,
                                                                               output_prefix=f'{outputs_path}/test_status_code_analysis')
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
                                                                                    output_prefix=f'{outputs_path}/empty_responses_analysis')

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
                                                                                    output_prefix=f'{outputs_path}/zero_window_analysis')
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
    # 设置执行时间阈值（单位：毫秒）
    exec_time_threshold = 400
    production_database_logs, production_database_logs_count \
        = db_analysis.load_database_logs(production_json_path, exec_time_threshold)
    production_bottleneck_analysis_database = db_analysis.match_logs(
        production_database_logs,
        db_analysis.load_csv_logs(production_csv_file_path)
    )
    replay_database_logs, replay_database_logs_count \
        = db_analysis.load_database_logs(replay_json_path, exec_time_threshold)
    replay_bottleneck_analysis_database = db_analysis.match_logs(
        replay_database_logs,
        db_analysis.load_csv_logs(replay_csv_file_path)
    )
    bottleneck_analysis_database = [
        {
            "hostip": production_ip,
            "env": "production",
            "class_name": "生产环境数据库日志分析",
            "details": [
                {
                    "bottleneck_type": "数据库查询时间异常",
                    "cause": "异常请求影响",
                    "count": len(production_bottleneck_analysis_database),
                    "total_count": production_database_logs_count,
                    "ratio": len(production_bottleneck_analysis_database) / production_database_logs_count,
                    "solution": "排查对应请求的数据库查询性能",
                    "request_paths": production_bottleneck_analysis_database
                }
            ]
        },
        {
            "hostip": replay_ip,
            "env": "replay",
            "class_name": "生产环境数据库日志分析",
            "details": [
                {
                    "bottleneck_type": "数据库查询时间异常",
                    "cause": "异常请求影响",
                    "count": len(replay_bottleneck_analysis_database),
                    "total_count": replay_database_logs_count,
                    "ratio": len(replay_bottleneck_analysis_database) / replay_database_logs_count,
                    "solution": "排查对应请求的数据库查询性能",
                    "request_paths": replay_bottleneck_analysis_database
                }
            ]
        }
    ]
    # 方式2 返回json格式的信息
    res['performance_bottleneck_analysis']['database'] = bottleneck_analysis_database

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

    return pcap_index, res


def save_response_to_file(response, file_path="response.json"):
    try:
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump(response, file, ensure_ascii=False, indent=4)
        print(f"Response successfully saved to {file_path}")
    except Exception as e:
        print(f"Failed to save response: {e}")


@celery.task(name='server.final_task')
def final_task(results, data, task_id, ip_address):
    try:
        # 更新任务状态为 "正在处理"
        redis_client.hset(f"task_status:{task_id}", "status", "正在处理")
        redis_client.hset(f"task_status:{task_id}", "step", "final_task")
        redis_client.hset(f"task_status:{task_id}", "message", "开始生成最终报告")

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

        # 控制台输出内容
        # logger.info(f"Results: {results}")

        for result in results:
            if result is not None:
                index, res = result
                response['individual_analysis_info'][index] = res

        save_response_to_file(response, f'./results/{task_id}/response.json')

        # Post the response to the callback URL
        callback_url = os.getenv("CALLBACK_URL", f'http://{ip_address}:18088/api/replay-core/aglAnalysisResult')
        postapi.post_url(json.dumps(response), callback_url)

        # 更新任务状态为 "完成"
        redis_client.hset(f"task_status:{task_id}", "status", "完成")
        redis_client.hset(f"task_status:{task_id}", "message", "最终报告生成完成")

    except Exception as e:
        # 更新任务状态为 "失败"
        redis_client.hset(f"task_status:{task_id}", "status", "失败")
        redis_client.hset(f"task_status:{task_id}", "message", f"生成最终报告时出错: {str(e)}")
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
                                       production_csv_file_path, production_anomalies_csv_file_path, task_id),
            extract_data_coordinator.s([os.path.join(pcap_info.replay_pcap.replay_path)],
                                       replay_csv_file_path, replay_anomalies_csv_file_path, task_id))
                           | align_data.s(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path,
                                          task_id)
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


@app.route('/api/algorithm/status/<task_id>', methods=['GET'])
def get_task_status(task_id):
    try:
        # 从 Redis 中获取任务状态
        status = redis_client.hgetall(f"task_status:{task_id}")
        if not status:
            return jsonify({"error": "任务不存在"}), 404

        # 将字节字符串解码为普通字符串
        decoded_status = {key.decode('utf-8'): value.decode('utf-8') for key, value in status.items()}

        # 返回任务状态信息
        return jsonify({
            "task_id": task_id,
            "status": decoded_status.get("status", "未知状态"),
            "step": decoded_status.get("step", "未知步骤"),
            "message": decoded_status.get("message", "无额外信息"),
            "error": decoded_status.get("error", "无错误信息")
        }), 200
    except Exception as e:
        # 如果发生异常，返回错误信息
        return jsonify({"error": f"查询任务状态时出错: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True, port=7956)
