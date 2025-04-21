import os.path
import pandas as pd
import heapq
from datetime import datetime
from collections import defaultdict
import logging

# Project imports
from src.packet_analysis.utils.path import classify_path

# Logging
logger = logging.getLogger(__name__)


def parse_time(sniff_time):
    """
    尝试解析时间字符串，支持两种格式:
    - "%Y-%m-%d %H:%M:%S"
    - "%M:%S.%f"
    """
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%M:%S.%f"):
        try:
            return datetime.strptime(sniff_time, fmt)
        except ValueError:
            continue
    raise ValueError(f"时间格式不匹配: {sniff_time}")


def alignment_two_paths(csv_production_output, csv_back_output, alignment_csv_file_path):
    # 计时
    start = datetime.now()
    logger.info("开始对齐")

    # Debug
    logger.debug(f"csv_production_output: {csv_production_output}")
    logger.debug(f"csv_back_output: {csv_back_output}")
    logger.debug(f"alignment_csv_file_path: {alignment_csv_file_path}")

    # Step 1: 读取数据
    production_df = pd.read_csv(csv_production_output)
    back_df = pd.read_csv(csv_back_output)

    # Step 2: 将回放数据加载到最小堆中
    # 堆中存储 (Sniff_time, index, row) 三元组
    back_heap = []
    for production_index, row in back_df.iterrows():
        sniff_time = parse_time(row['Sniff_time'])
        heapq.heappush(back_heap, (sniff_time, production_index, row.to_dict()))

    # Step 3: 初始化对齐数据结构
    aligned_data = {
        'No': [],
        'Path': [],
        'Query': [],
        'Src_Port': [],
        'Request_Method': [],
        # 生产环境
        'Production_Sniff_time': [],
        'Production_Relative_time': [],
        'Production_Time_since_request': [],
        'Production_Processing_delay': [],
        'Production_Transmission_delay': [],
        'Production_Request_Packet_Length': [],
        'Production_Response_Packet_Length': [],
        'Production_Response_Total_Length': [],
        'Production_Is_zero_window': [],
        'Production_Is_tcp_reset': [],
        'Production_Response_Code': [],
        'Production_Src_Ip': [],
        'Production_Dst_Ip': [],
        # 回放环境
        'Back_Sniff_time': [],
        'Back_Relative_time': [],
        'Back_Time_since_request': [],
        'Back_Processing_delay': [],
        'Back_Transmission_delay': [],
        'Back_Request_Packet_Length': [],
        'Back_Response_Packet_Length': [],
        'Back_Response_Total_Length': [],
        'Back_Is_zero_window': [],
        'Back_Is_tcp_reset': [],
        'Back_Response_Code': [],
        'Back_Src_Ip': [],
        'Back_Dst_Ip': [],
        'Request_type': [],
        'Time_since_request_ratio': [],
        'Index_diff': [],
        'state': []
    }

    # Step 4: 对齐数据
    # 遍历生产环境数据
    for production_index, production_row in production_df.iterrows():
        # Debug
        if production_index % 1000 == 0:
            logger.info(f"Processing index: {production_index}")

        # 获取时间，路径，查询参数用于对齐
        production_sniff_time = parse_time(production_row['Sniff_time'])
        production_path = production_row['Path'] if not pd.isna(production_row['Path']) else ''
        production_query = production_row['Query'] if not pd.isna(production_row['Query']) else ''

        # 从堆中查找匹配的回放数据
        matched = False
        temp_heap = []  # 临时存储未匹配的回放数据
        while back_heap:
            back_sniff_time, back_index, back_row = heapq.heappop(back_heap)
            back_path = back_row['Path'] if not pd.isna(back_row['Path']) else ''
            back_query = back_row['Query'] if not pd.isna(back_row['Query']) else ''

            # 检查 index 差值是否超过阈值
            if production_index - back_index > 1000:
                continue

            # 判断是否为同一路径
            if production_path == back_path and production_query == back_query:
                # 记录成功匹配
                aligned_data['No'].append(production_row['No'])
                aligned_data['Path'].append(production_path)
                aligned_data['Query'].append(production_query)
                aligned_data['Src_Port'].append(production_row['Src_Port'])
                aligned_data['Request_Method'].append(production_row['Request_Method'])
                # 生产环境
                aligned_data['Production_Sniff_time'].append(production_sniff_time)
                aligned_data['Production_Relative_time'].append(production_row['Relative_time'])
                aligned_data['Production_Time_since_request'].append(production_row['Time_since_request'])
                aligned_data['Production_Processing_delay'].append(production_row['Processing_delay'])
                aligned_data['Production_Transmission_delay'].append(production_row['Transmission_delay'])
                aligned_data['Production_Request_Packet_Length'].append(production_row['Request_Packet_Length'])
                aligned_data['Production_Response_Packet_Length'].append(production_row['Response_Packet_Length'])
                aligned_data['Production_Response_Total_Length'].append(production_row['Response_Total_Length'])
                aligned_data['Production_Is_zero_window'].append(production_row['Is_zero_window'])
                aligned_data['Production_Is_tcp_reset'].append(production_row['Is_tcp_reset'])
                aligned_data['Production_Response_Code'].append(production_row['Response_code'])
                aligned_data['Production_Src_Ip'].append(production_row['Ip_src'])
                aligned_data['Production_Dst_Ip'].append(production_row['Ip_dst'])
                # 回放环境
                aligned_data['Back_Sniff_time'].append(back_sniff_time)
                aligned_data['Back_Relative_time'].append(back_row['Relative_time'])
                aligned_data['Back_Time_since_request'].append(back_row['Time_since_request'])
                aligned_data['Back_Processing_delay'].append(back_row['Processing_delay'])
                aligned_data['Back_Transmission_delay'].append(back_row['Transmission_delay'])
                aligned_data['Back_Request_Packet_Length'].append(back_row['Request_Packet_Length'])
                aligned_data['Back_Response_Packet_Length'].append(back_row['Response_Packet_Length'])
                aligned_data['Back_Response_Total_Length'].append(back_row['Response_Total_Length'])
                aligned_data['Back_Is_zero_window'].append(back_row['Is_zero_window'])
                aligned_data['Back_Is_tcp_reset'].append(back_row['Is_tcp_reset'])
                aligned_data['Back_Response_Code'].append(back_row['Response_code'])
                aligned_data['Back_Src_Ip'].append(back_row['Ip_src'])
                aligned_data['Back_Dst_Ip'].append(back_row['Ip_dst'])
                # 请求类型
                aligned_data['Request_type'].append(classify_path(production_path))
                # 生产、回放 Time_since_request 时间差比率
                production_time_since_request = production_row['Time_since_request']
                back_time_since_request = back_row['Time_since_request']
                if production_time_since_request != 0 and back_time_since_request != 0:
                    time_since_request_ratio = back_time_since_request / production_time_since_request
                elif production_time_since_request == 0:
                    time_since_request_ratio = 'Infinity'
                elif back_time_since_request == 0:
                    time_since_request_ratio = 0
                else:
                    time_since_request_ratio = 'NaN'
                aligned_data['Time_since_request_ratio'].append(time_since_request_ratio)
                # 状态
                aligned_data['state'].append('success')
                # 记录 index 差值
                aligned_data['Index_diff'].append(production_index - back_index)
                matched = True
                break
            else:
                # 未匹配的回放数据暂存到临时堆
                heapq.heappush(temp_heap, (back_sniff_time, back_index, back_row))
                if len(temp_heap) > 1000:
                    break

        # 将未匹配的回放数据重新放回堆中
        while temp_heap:
            heapq.heappush(back_heap, heapq.heappop(temp_heap))

        # 如果没有找到匹配的回放数据，记录失败
        if not matched:
            aligned_data['No'].append(production_row['No'])
            aligned_data['Path'].append(production_path)
            aligned_data['Query'].append(production_query)
            aligned_data['Src_Port'].append(production_row['Src_Port'])
            aligned_data['Request_Method'].append(production_row['Request_Method'])
            # 生产环境
            aligned_data['Production_Sniff_time'].append(production_sniff_time)
            aligned_data['Production_Relative_time'].append(production_row['Relative_time'])
            aligned_data['Production_Time_since_request'].append(production_row['Time_since_request'])
            aligned_data['Production_Processing_delay'].append(production_row['Processing_delay'])
            aligned_data['Production_Transmission_delay'].append(production_row['Transmission_delay'])
            aligned_data['Production_Request_Packet_Length'].append(production_row['Request_Packet_Length'])
            aligned_data['Production_Response_Packet_Length'].append(production_row['Response_Packet_Length'])
            aligned_data['Production_Response_Total_Length'].append(production_row['Response_Total_Length'])
            aligned_data['Production_Is_zero_window'].append(production_row['Is_zero_window'])
            aligned_data['Production_Is_tcp_reset'].append(production_row['Is_tcp_reset'])
            aligned_data['Production_Response_Code'].append(production_row['Response_code'])
            aligned_data['Production_Src_Ip'].append(production_row['Ip_src'])
            aligned_data['Production_Dst_Ip'].append(production_row['Ip_dst'])
            # 回放环境
            aligned_data['Back_Sniff_time'].append('')
            aligned_data['Back_Relative_time'].append('')
            aligned_data['Back_Time_since_request'].append('')
            aligned_data['Back_Processing_delay'].append('')
            aligned_data['Back_Transmission_delay'].append('')
            aligned_data['Back_Request_Packet_Length'].append('')
            aligned_data['Back_Response_Packet_Length'].append('')
            aligned_data['Back_Response_Total_Length'].append('')
            aligned_data['Back_Is_zero_window'].append('')
            aligned_data['Back_Is_tcp_reset'].append('')
            aligned_data['Back_Response_Code'].append('')
            aligned_data['Back_Src_Ip'].append('')
            aligned_data['Back_Dst_Ip'].append('')
            # 请求类型
            aligned_data['Request_type'].append(classify_path(production_path))
            # 生产、回放 Time_since_request 时间差比率
            aligned_data['Time_since_request_ratio'].append('')
            # 状态
            aligned_data['state'].append('failed')
            # 记录 index 差值
            aligned_data['Index_diff'].append('')

    # Debug 输出对齐数据的 state 状况计数
    state_counter = defaultdict(int)
    for state in aligned_data['state']:
        state_counter[state] += 1
    logger.info("对齐数据的 state 状况计数: ")
    for state, count in state_counter.items():
        logger.info(f"{state}: {count}")

    # Step 5: 保存对齐数据
    aligned_df = pd.DataFrame(aligned_data)
    aligned_df.to_csv(alignment_csv_file_path, index=False)
    logger.info(f"对齐 {os.path.basename(csv_production_output)}, {os.path.basename(csv_back_output)} 数据完成")
    logger.info(f"对齐数据保存至: {alignment_csv_file_path}")

    # 计时
    end = datetime.now()
    logger.info(f"对齐模块总耗时: {end - start}")


# Main
if __name__ == '__main__':
    print('Do not run this script directly. Please run run.py instead.')