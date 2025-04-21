import pandas as pd
import datetime
import json
from scipy.stats import pearsonr
import numpy as np
import logging

# Logger
logger = logging.getLogger(__name__)


# 读取KPI映射的函数
def load_kpi_mapping(file_path):
    kpi_mapping = {}
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            # 跳过空行和注释行
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 按照冒号分割行内容，并去除多余空格
            kpi_no, description = map(str.strip, line.split(":", 1))
            kpi_mapping[kpi_no] = description
    return kpi_mapping


# 将DCTIME转换为可读的时间格式
def convert_dctime(dctime):
    timestamp_s = dctime / 1000.0
    readable_time = datetime.datetime.fromtimestamp(timestamp_s)
    return readable_time.strftime('%Y-%m-%d %H:%M:%S')


# 提取数据的函数 将日志json格式化成需要的格式
def extract_data(json_data, kpi_mapping):
    extracted_data = []
    logger.info("Extracting data from json file")
    for monitor_type, machines in json_data.items():
        if monitor_type in ['server', 'databases']:
            for machine_type, ips in machines.items():
                if not isinstance(ips, dict):
                    logger.warning(f"Warning: {machine_type} 的值不是字典类型, 跳过处理")
                    continue
                for ip_address, metrics in ips.items():
                    if not isinstance(metrics, dict):
                        logger.warning(f"Warning: IP地址 {ip_address} 的 metrics 不是字典, 跳过处理")
                        continue
                    for kpi_no, items in metrics.items():
                        if not isinstance(items, list):
                            logger.warning(f"Warning: KPI_NO {kpi_no} 的 items 不是列表, 跳过处理")
                            continue
                        for item in items:
                            if 'DCTIME' in item and 'VALUE' in item:
                                try:
                                    readable_time = convert_dctime(int(item['DCTIME']))
                                    kpi_name = kpi_mapping.get(kpi_no, '未知指标')
                                    extracted_data.append({
                                        'monitor_type': monitor_type,
                                        'machine_type': machine_type,
                                        'ip_address': ip_address,
                                        'DCTIME': readable_time,
                                        'VALUE': item['VALUE'],
                                        'kpi_no': kpi_no,
                                        'kpi_name': kpi_name
                                    })
                                except ValueError as e:
                                    logger.error(f"DCTIME 转换失败 for item: {item}, 错误信息: {e}")
                            else:
                                logger.warning(f"缺少 'DCTIME' 或 'VALUE' in item: {item}, 跳过此条记录")
        elif monitor_type == 'apm':
            extracted_data.append({
                'monitor_type': monitor_type,
                'original_data': machines
            })
    return extracted_data
    # 上述代码用于提取信息，就算输入的回放数据为空，extracted_data里面至少也会有一个apm的字典


def safe_format(value):
    # 如果值是 NaN 或 None，则返回 0 或其他默认值
    if pd.isna(value):
        return "0.000000"  # 或者根据需求返回 None
    return "{:.6f}".format(value)


# 计算相关系数的函数
def compute_correlation(kpi_data, request_data, kpi_name, output_kpi_csv_path, time_threshold=10, ip_address=None,
                        monitor_type=None):
    mean_delays = []
    kpi_values = []

    for interval in kpi_data:
        start_time = interval['DCTIME'] - datetime.timedelta(seconds=time_threshold)
        end_time = interval['DCTIME'] + datetime.timedelta(seconds=time_threshold)
        # # Debug
        # logger.info(f"时间范围: {start_time} - {end_time}")
        if monitor_type == 'server' and ip_address:
            filtered_requests = request_data[
                (request_data['Sniff_time'] >= start_time) &
                (request_data['Sniff_time'] <= end_time) &
                (request_data['Ip_dst'] == ip_address)  # hyf 此处用的的目的IP dstIP 对应服务器
                ]
            if filtered_requests.empty:
                filtered_requests = request_data[
                    (request_data['Sniff_time'] >= start_time) &
                    (request_data['Sniff_time'] <= end_time)
                    ]
                if not filtered_requests.empty:
                    monitor_type = 'database_server'

        else:
            filtered_requests = request_data[
                (request_data['Sniff_time'] >= start_time) &
                (request_data['Sniff_time'] <= end_time)
                ]
        # # Debug
        # logger.info(f"这段时间内有 {len(filtered_requests)}个数据包")

        if not filtered_requests.empty:
            mean_delay = filtered_requests['Time_since_request'].mean()
            mean_delays.append(mean_delay)
            kpi_values.append(interval['VALUE'])
        else:
            # # Debug
            # logger.info("No requests found in this time window.")
            pass

    kpi_values = pd.to_numeric(kpi_values, errors='coerce')
    valid_indices = (~np.isnan(mean_delays)) & (~np.isnan(kpi_values))
    mean_delays = np.array(mean_delays)[valid_indices]
    kpi_values = np.array(kpi_values)[valid_indices]

    if len(mean_delays) > 1 and len(kpi_values) > 1:
        # # Debug
        # logger.info(f'{mean_delays}')
        # logger.info(f'{kpi_values}')

        # 创建要写入的数据列，KPI列名和时延列名
        columns = {kpi_name: kpi_values, f'平均时延_{kpi_name}': mean_delays}
        df_to_write = pd.DataFrame(columns)

        # 追加写入 CSV 文件，列不断增加
        try:
            existing_df = pd.read_csv(output_kpi_csv_path, encoding='utf-8-sig')
            combined_df = pd.concat([existing_df, df_to_write], axis=1)
        except FileNotFoundError:
            # 如果文件不存在，直接写入
            combined_df = df_to_write

        # 将更新后的DataFrame写回CSV
        combined_df.to_csv(output_kpi_csv_path, mode='w', index=False, encoding='utf-8-sig')

        correlation, _ = pearsonr(mean_delays, kpi_values)

        return {
            'monitor_type': monitor_type,
            'kpi_name': kpi_name,
            'correlation_value': safe_format(correlation)
            # 'correlation_value': "{:.6f}".format(correlation)  #hyf
        }
    else:
        logger.warning(f"{kpi_name} 数据不足以进行相关性计算")
        return None


# 主程序执行函数
def calc_correlation(json_file_path: str, request_data: pd.DataFrame, output_csv_path: str, output_kpi_csv_path: str,
                     kpi_mapping_file='src/packet_analysis/services/json_build/kpi_mapping.txt', time_threshold=10):
    kpi_mapping = load_kpi_mapping(kpi_mapping_file)
    # logger.debug(f'{kpi_mapping}')

    with open(json_file_path, 'r', encoding='utf-8') as f:
        json_data = json.load(f)
    extracted_info = extract_data(json_data, kpi_mapping)  # 返回的格式是一个字典列表
    # 判断提取出来的信息是否空白
    if not extracted_info:
        logger.debug("Extracted data is empty. Cannot calculate correlation.")
        return pd.DataFrame()
    # logger.debug("1111111111此处输出json提取处理后的日志信息1111111111")
    # logger.debug(extracted_info)

    extracted_df = pd.DataFrame(extracted_info)

    all_correlations = []
    try:
        for (monitor_type, kpi_no, host_ip), kpi_group in extracted_df.groupby(['monitor_type', 'kpi_no', 'ip_address']):
            kpi_name = kpi_mapping.get(kpi_no, '未知指标')
            kpi_group['DCTIME'] = pd.to_datetime(kpi_group['DCTIME'])
            kpi_group = kpi_group.sort_values(by='DCTIME')

            # if monitor_type == 'databases':
            #     # Standard correlation calculation for databases 数据库的性能数据，两个生产节点一起算
            #     correlations = compute_correlation(kpi_group.to_dict('records'), request_data, kpi_name,monitor_type=monitor_type)
            # elif monitor_type == 'server':
            #     # Pass IP address and monitor_type to compute_correlation for server 主机的性能数据，两个生产节点分开算
            #     correlations = compute_correlation(kpi_group.to_dict('records'), request_data, kpi_name, ip_address=host_ip,
            #                                        monitor_type=monitor_type)
            correlations = compute_correlation(kpi_group.to_dict('records'), request_data, kpi_name,
                                               output_kpi_csv_path,
                                               time_threshold, ip_address=host_ip, monitor_type=monitor_type)
            # 将 kpi_group 数据框转换为字典 列表 格式，每一行数据变为一个字典，字典的键是列名，值是对应的单元格内容。'records' 表示每一行是一个独立的字典。
            if correlations:
                all_correlations.append(correlations)
    except Exception as e:
        logger.error(f'计算相关系数分组时候发生错误：{e}')
        raise e

    if all_correlations:  # 检查是否有有效的相关性数据
        correlation_df = pd.DataFrame(all_correlations).sort_values(by='correlation_value', ascending=False)
        correlation_df.to_csv(output_csv_path, index=False, encoding='utf-8-sig')
        logger.info(f"结果已保存到CSV文件 {output_csv_path}")
    else:
        logger.warning(f"没有计算出有效的相关性数据，输出文件 {output_csv_path} 将为空")
        # 创建一个空的 DataFrame，并添加相关列，写入文件
        empty_df = pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])
        empty_df.to_csv(output_csv_path, index=False, encoding='utf-8-sig')

    return correlation_df if 'correlation_df' in locals() else pd.DataFrame(columns=['monitor_type', 'kpi_name', 'correlation_value'])
