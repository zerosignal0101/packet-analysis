import json
import csv
from datetime import datetime
from datetime import timedelta

from src.packet_analysis.utils.logger_config import logger
from src.packet_analysis.analysis.cluster import classify_path


# 1. 加载数据库日志并筛选处理时间长的日志
def load_database_logs(json_file, exec_time_threshold):
    with open(json_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    # 获取所有数据库的日志
    database_logs_ori = []
    for database_name, logs in data["apm"]["DATABASE_INFO"].items():
        database_logs_ori.extend(logs)

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
        db_time = datetime.strptime(db_log["startTime"], "%Y-%m-%dT%H:%M:%S.%fZ")
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


# 4. 主函数
def main():
    # 文件路径
    json_file = "../../../raw_data/raw_data_1883351909503537154/collect_20250123_205906_1882216342594195457_242.json"
    csv_file = "/home/zsig/Documents/gits/packet-analysis/results/ae1b1bc1-d784-4007-aba3-d0a0331a264b/extracted_production_data_3.csv"

    # 设置执行时间阈值（单位：毫秒）
    exec_time_threshold = 200

    # 加载日志
    database_logs, total_count = load_database_logs(json_file, exec_time_threshold)
    csv_logs = load_csv_logs(csv_file)

    # Test
    print("时延较大的数据库处理项目数：", len(database_logs))

    # 匹配日志
    matched_results = match_logs(database_logs, csv_logs)

    # 输出结果
    print("===== 匹配结果 =====")
    for result in matched_results:
        print(f"数据库请求开始时间: {result['db_start_time']}")
        print(f"数据库执行时间: {result['exec_time']} 毫秒")
        print(f"SQL 查询内容: {result['sql_content']}")
        print(f"URL 请求路径: {result['url_path']}")
        print(f"URL 请求时间: {result['url_sniff_time']}")
        print(f"Time since request: {result['time_since_request']} 秒")
        print(f"Ratio: {result['ratio']}")
        print(f"响应状态码: {result['response_code']}")
        print(f"请求方法: {result['request_method']}")
        print(f"请求类别：{result['class_method']}")
        print("-----------------------------")


if __name__ == "__main__":
    main()
