import pandas as pd
import datetime
import json
from scipy.stats import pearsonr
import numpy as np
from src.packet_analysis.utils.logger_config import logger


# 将DCTIME转换为可读的时间格式
def convert_dctime(dctime):
    timestamp_s = dctime / 1000.0
    readable_time = datetime.datetime.fromtimestamp(timestamp_s)
    return readable_time.strftime('%Y-%m-%d %H:%M:%S')


# KPI_NO 与 采集指标名称的映射关系
kpi_mapping = {
    "20200413185029": "非root用户进程数",
    "20200413185030": "活动进程数",
    "20200413185032": "当前运行队列等待运行的进程数",
    "20200413185033": "处在非中断睡眠状态的进程数",
    "20200413185034": "CPU利用率",
    "20200413185035": "内存利用率",
    "20200413185042": "1分钟平均负载",
    "20200413185044": "CPU平均等待I0率",
    "20200413185046": "中央处理器平均系统调用率",
    "20200413185059": "交换区利用率",
    "20200413185063": "等待连接数",
    "20200413185065": "关闭连接数",
    "20200413185079": "文件系统总利用率",
    "20200415181115": "当前连接数",
    "20211118174008": "当前活动会话数",
    "20200508191078": "当前会话数",
    "20210208170202": "活动会话数",
    "202303150917015": "活动线程数",
    "202303150917017": "全部会话数",
    "202303150917018": "活动会话数",
    "1710403746551": "当前数据库的连接数",
    "20240702090703": "活动会话数(铁塔)",
    "20240702090704": "会话数（铁塔）",
    "20240702090709": "阻塞会话数",
    # 更多KPI_NO映射关系可以根据需要补充
}


# 提取数据的函数
def extract_data(json_data):
    extracted_data = []

    # 遍历监控类型 (如 server, databases, apm)
    for monitor_type, machines in json_data.items():
        if monitor_type in ['server', 'databases']:
            # 遍历主机或数据库类型 (如 MOD_UNIX_LINUX, mysql)
            for machine_type, ips in machines.items():
                # 确保 ips 是一个字典
                if not isinstance(ips, dict):
                    print(f"Warning: {machine_type} 的值不是字典类型, 跳过处理")
                    continue

                # 遍历IP地址 (如 192.168.49.134)
                for ip_address, metrics in ips.items():
                    # 确保 metrics 是一个字典
                    if not isinstance(metrics, dict):
                        print(f"Warning: IP地址 {ip_address} 的 metrics 不是字典, 跳过处理")
                        continue

                    # 遍历每种KPI_NO的指标信息列表
                    for kpi_no, items in metrics.items():
                        # 确保 items 是一个列表
                        if not isinstance(items, list):
                            print(f"Warning: KPI_NO {kpi_no} 的 items 不是列表, 跳过处理")
                            continue

                        for item in items:
                            # 检查 'DCTIME' 和 'VALUE' 是否存在
                            if 'DCTIME' in item and 'VALUE' in item:
                                try:
                                    readable_time = convert_dctime(int(item['DCTIME']))
                                    kpi_name = kpi_mapping.get(kpi_no, '未知指标')  # 获取对应的指标名称
                                    extracted_data.append({
                                        '监控类型': monitor_type,
                                        '主机或数据库类型': machine_type,
                                        'IP地址': ip_address,
                                        'DCTIME': readable_time,
                                        'VALUE': item['VALUE'],
                                        'KPI_NO': kpi_no,
                                        '指标名称': kpi_name  # 添加指标名称
                                    })
                                except ValueError as e:
                                    print(f"Error: DCTIME 转换失败 for item: {item}, 错误信息: {e}")
                            else:
                                print(f"Warning: 缺少 'DCTIME' 或 'VALUE' in item: {item}, 跳过此条记录")

        elif monitor_type == 'apm':
            # 对于 apm 监控类型，直接将原始数据添加到输出中
            extracted_data.append({
                '监控类型': monitor_type,
                '原始数据': machines  # 将 apm 的数据原样保存
            })

    return extracted_data

# 计算相关系数的函数
# Modified compute_correlation function with adjustable time threshold
def compute_correlation(kpi_data, request_data, kpi_name, time_threshold=15, ip_address=None, monitor_type=None):
    print(3333333333)
    mean_delays = []
    kpi_values = []

    # Loop through each KPI data point
    for interval in kpi_data:
        start_time = interval['DCTIME'] - datetime.timedelta(seconds=time_threshold)
        end_time = interval['DCTIME'] + datetime.timedelta(seconds=time_threshold)
        print(f"时间范围: {start_time} - {end_time}")

        # Filter request data based on time range and IP address (for server type)
        if monitor_type == 'server' and ip_address:
            filtered_requests = request_data[
                (request_data['Sniff_time'] >= start_time) &
                (request_data['Sniff_time'] <= end_time) &
                (request_data['Ip_src'] == ip_address)
                ]
        else:
            filtered_requests = request_data[
                (request_data['Sniff_time'] >= start_time) &
                (request_data['Sniff_time'] <= end_time)
                ]

        print(f"这段时间内有 {len(filtered_requests)}个数据包")

        if not filtered_requests.empty:
            mean_delay = filtered_requests['Time_since_request'].mean()
            mean_delays.append(mean_delay)
            kpi_values.append(interval['VALUE'])
        else:
            print("No requests found in this time window.")

    # Convert to numeric and filter valid data
    kpi_values = pd.to_numeric(kpi_values, errors='coerce')
    valid_indices = (~np.isnan(mean_delays)) & (~np.isnan(kpi_values))
    mean_delays = np.array(mean_delays)[valid_indices]
    kpi_values = np.array(kpi_values)[valid_indices]

    # Calculate Pearson correlation
    if len(mean_delays) > 1 and len(kpi_values) > 1:
        print(mean_delays)
        print(kpi_values)
        correlation, _ = pearsonr(mean_delays, kpi_values)
        print(f"{kpi_name} Pearson correlation: {correlation}")
        return {
            '监控类型': monitor_type,
            'KPI名称': kpi_name,
            '相关系数': correlation
        }
    else:
        print("Insufficient data for correlation calculation.")
        return None


# 读取 JSON 文件并提取数据
with open('../../../raw_data/生产采集collect_20240829_08301130.json', 'r', encoding='utf-8') as f:
    json_data = json.load(f)

extracted_info = extract_data(json_data)
extracted_df = pd.DataFrame(extracted_info)
extracted_df.to_csv('../../../results/test1.csv', index=False, encoding='utf-8-sig')


# 读取应用请求信息的CSV文件
request_data = pd.read_csv('../../../results/extracted_replay_data_3h.csv', encoding='utf-8')

# 将时间戳转换为时间格式
request_data['Sniff_time'] = pd.to_datetime(request_data['Sniff_time'])

# 初始化结果列表
all_correlations = []


# Updated grouping logic with different handling for 'server' and 'databases'
for (monitor_type, kpi_no, host_ip), kpi_group in extracted_df.groupby(['监控类型', 'KPI_NO', 'IP地址']):
    correlations = None
    kpi_name = kpi_mapping.get(kpi_no, '未知指标')
    kpi_group['DCTIME'] = pd.to_datetime(kpi_group['DCTIME'])
    kpi_group = kpi_group.sort_values(by='DCTIME')

    if monitor_type == 'databases':
        # Standard correlation calculation for databases 数据库的性能数据，两个生产节点一起算
        correlations = compute_correlation(kpi_group.to_dict('records'), request_data, kpi_name,monitor_type=monitor_type)
    # elif monitor_type == 'server':
    #     # Pass IP address and monitor_type to compute_correlation for server 主机的性能数据，两个生产节点分开算
    #     correlations = compute_correlation(kpi_group.to_dict('records'), request_data, kpi_name, ip_address=host_ip,
    #                                        monitor_type=monitor_type)
    # correlations = compute_correlation(kpi_group.to_dict('records'), request_data, kpi_name)
    # 将 kpi_group 数据框转换为字典 列表 格式，每一行数据变为一个字典，字典的键是列名，值是对应的单元格内容。'records' 表示每一行是一个独立的字典。
    if correlations:
        all_correlations.append(correlations)


# 将结果转换为 DataFrame 并按相关系数排序
print(3333,all_correlations)
correlation_df = pd.DataFrame(all_correlations)
correlation_df = correlation_df.sort_values(by='相关系数', ascending=False)

# 输出最高相关性的指标信息
print(22222,correlation_df.head())

# 保存相关系数结果到 CSV
correlation_df.to_csv('../../../results/kpi_request_correlations.csv', index=False, encoding='utf-8-sig')
print("结果已经保存到csv文件")
