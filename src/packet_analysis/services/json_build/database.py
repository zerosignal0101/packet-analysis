import json
import csv
from datetime import datetime
from datetime import timedelta
import logging

# Project imports
from src.packet_analysis.utils.path import classify_path

# Logger
logger = logging.getLogger(__name__)


# 1. 加载数据库日志并筛选处理时间长的日志
def load_database_logs(json_file, exec_time_threshold):
    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    database_logs_ori = []

    # 检查是否存在 "apm" 键
    if "apm" in data:
        apm_data = data["apm"]

        # 检查是否存在 "DATABASE_INFO" 键
        if "DATABASE_INFO" in apm_data:
            for database_name, logs in apm_data["DATABASE_INFO"].items():
                if logs is not None:
                    database_logs_ori.extend(logs)
                else:
                    logger.warning(f"Database logs of \"{database_name}\" is Null")
        else:
            logger.warning("Key \"DATABASE_INFO\" not found in apm data")
    else:
        logger.warning("Key \"apm\" not found in data")

    try:
        # 总数量
        total_count = len(database_logs_ori)

        # 筛选出执行时间超过阈值的日志
        long_running_logs = [
            entry for entry in database_logs_ori
            if entry["execTime"] > exec_time_threshold
        ]
    except AttributeError as e:
        total_count = 0
        long_running_logs = []

    # # 打印调试信息
    # logger.info(f"Loaded {len(long_running_logs)} long-running logs.")
    # for log in long_running_logs:
    #     logger.info(log)

    return long_running_logs, total_count


# 2. 时间匹配
def match_database_logs(database_logs, csv_logs):
    matched_results = []

    for db_log in database_logs:
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
            time_since_request = csv_log["Time_since_request"]

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
                "db_start_time": db_log["startTime"],
                "sql_content": db_log["sqlContent"],
                "exec_time": db_log["execTime"],
                "url_path": closest_log["Path"],
                "url_sniff_time": closest_log["Sniff_time"],
                "time_since_request": closest_log["Time_since_request"],
                "ratio": db_log["execTime"] / 1000 / float(closest_log["Time_since_request"]),
                "response_code": closest_log["Response_code"],
                "request_method": closest_log["Request_Method"],
                "class_method": classify_path(closest_log["Path"])
            })

    return matched_results
