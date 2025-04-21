import json
import csv
from datetime import datetime
from datetime import timedelta
import logging

import pandas as pd

# Project imports
from src.packet_analysis.utils.path import classify_path

# Logger
logger = logging.getLogger(__name__)


def load_exception_logs(json_file):
    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    exception_logs_ori = []

    # 检查是否存在 "apm" 键
    if "apm" in data:
        apm_data = data["apm"]

        # 检查是否存在 "EXCEPTION_INFO" 键
        if "EXCEPTION_INFO" in apm_data:
            for type_name, logs in apm_data["EXCEPTION_INFO"].items():
                if logs is not None:
                    exception_logs_ori.extend(logs)
                else:
                    logger.warning(f"Exception logs of \"{type_name}\" is Null")
        else:
            logger.warning("Key \"EXCEPTION_INFO\" not found in apm data")
    else:
        logger.warning("Key \"apm\" not found in data")

    total_count = len(exception_logs_ori)

    # # debug
    # for log in exception_logs_ori:
    #     print(f"Log: {log['startTime']}")

    return exception_logs_ori, total_count


def _load_csv_logs(csv_file):
    logs = []
    with open(csv_file, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            logs.append(row)
    return logs


def match_exception_logs(exception_logs, csv_logs: pd.DataFrame):
    matched_results = []

    for db_log in exception_logs:
        db_time = datetime.strptime(db_log["startTime"], "%Y-%m-%dT%H:%M:%S.%fZ")
        db_exec_time = db_log["execTime"] / 1000  # 将毫秒转换为秒

        # 定义时间范围：数据库请求之前的 0-3 秒
        time_start = db_time - timedelta(seconds=10)
        time_end = db_time

        # 初始化最接近的 URL 请求
        closest_log = None
        min_time_diff = float("inf")

        # 在时间范围内寻找 URL 请求
        for index, csv_log in csv_logs.iterrows():
            csv_time = csv_log["Sniff_time"]
            time_since_request = csv_log["Time_since_request"].total_seconds()

            # 检查是否在时间范围内，并且 Time_since_request 大于数据库执行时间
            if time_end - timedelta(
                    seconds=time_since_request) <= csv_time <= time_end and time_since_request > db_exec_time:
                # 计算时间差
                time_diff = abs((db_time - csv_time).total_seconds())

                # 如果时间差更小，则更新最接近的日志
                if time_diff < min_time_diff:
                    min_time_diff = time_diff
                    closest_log = csv_log

        # 如果找到匹配的日志，则关联结果
        if closest_log:
            matched_results.append({
                "exception_start_time": db_log["startTime"],
                "exception_type": db_log["exceptionType"],
                "component_type": db_log["componentType"],
                "agent_id": db_log["agentId"],
                "simple_class": db_log["simpleClass"],
                "exception_content": db_log["exceptionContent"],
                "exec_time": db_log["execTime"],
                "url_path": closest_log["Path"],
                "url_sniff_time": closest_log["Sniff_time"],
                "time_since_request": closest_log["Time_since_request"],
                "response_code": closest_log["Response_code"],
                "request_method": closest_log["Request_Method"],
                "class_method": classify_path(closest_log["Path"])
            })
        else:
            matched_results.append({
                "exception_start_time": db_log["startTime"],
                "exception_type": db_log["exceptionType"],
                "component_type": db_log["componentType"],
                "agent_id": db_log["agentId"],
                "simple_class": db_log["simpleClass"],
                "exception_content": db_log["exceptionContent"],
                "exec_time": db_log["execTime"],
                "url_path": '',
                "url_sniff_time": '',
                "time_since_request": '',
                "response_code": '',
                "request_method": '',
                "class_method": ''
            })

    return matched_results
