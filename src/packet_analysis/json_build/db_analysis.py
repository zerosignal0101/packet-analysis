import json
import csv
from datetime import datetime
from datetime import timedelta


# 1. 加载数据库日志并筛选处理时间长的日志
def load_database_logs(json_file, exec_time_threshold):
    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    # 筛选出执行时间超过阈值的日志
    long_running_logs = [
        entry for entry in data["apm"]["DATABASE_INFO"]["CSchinatower-smc-inner-service"]
        if entry["execTime"] > exec_time_threshold
    ]
    return long_running_logs


# 2. 加载 CSV 文件
def load_csv_logs(csv_file):
    logs = []
    with open(csv_file, "r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        for row in reader:
            logs.append(row)
    return logs


# 3. 时间匹配
def match_logs(database_logs, csv_logs):
    matched_results = []

    for db_log in database_logs:
        db_time = datetime.strptime(db_log["startTime"], "%Y-%m-%dT%H:%M:%S.%fZ") + timedelta(hours=8)
        db_exec_time = db_log["execTime"] / 1000  # 将毫秒转换为秒

        # 定义时间范围：数据库请求之前的 0-3 秒
        time_start = db_time - timedelta(seconds=10)
        time_end = db_time

        # 初始化最接近的 URL 请求
        closest_log = None
        min_time_diff = float("inf")

        # 在时间范围内寻找 URL 请求
        for csv_log in csv_logs:
            csv_time = datetime.strptime(csv_log["Sniff_time"], "%Y-%m-%d %H:%M:%S.%f")
            time_since_request = float(csv_log["Time_since_request"])

            # 检查是否在时间范围内，并且 Time_since_request 大于数据库执行时间
            if time_end - timedelta(seconds=time_since_request) <= csv_time <= time_end and time_since_request > db_exec_time:
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
                "response_code": closest_log["Response_code"],
                "request_method": closest_log["Request_Method"],
                "request_packet_length": closest_log["Request_Packet_Length"],
                "response_packet_length": closest_log["Response_Packet_Length"],
                "time_diff": min_time_diff  # 添加时间差信息
            })

    return matched_results