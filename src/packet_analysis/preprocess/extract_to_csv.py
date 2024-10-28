from collections import defaultdict
import asyncio
import csv
import pyshark
from urllib.parse import urlparse, urlunparse
import time
import heapq
from datetime import datetime
from src.packet_analysis.utils.logger_config import logger


# 检查最高层协议是否合适
def check_highest_layer_suitable(layer):
    return ((layer == 'DATA-TEXT-LINES')
            or (layer == 'JSON')
            or (layer == 'PNG')
            or (layer == 'URLENCODED-FORM')
            or (layer == 'MEDIA')
            or (layer == 'IMAGE-JFIF'))


# 预处理函数
def preprocess_data(file_paths, csv_file_path):
    # log the input file paths
    logger.info(f"Input file paths: {file_paths}")

    # check if the [0] is type of list
    if isinstance(file_paths[0], list):
        file_paths = file_paths[0]

    # 创建新的事件循环
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # 储存时间戳、Url、业务处理时间、响应时延等信息的列表
    results = []

    for cur_pcap in file_paths:
        # 使用pyshark打开pcap文件
        capture = pyshark.FileCapture(cur_pcap, display_filter='tcp')

        # 用于存储TCP流及其包的字典
        tcp_streams = defaultdict(list)

        for packet in capture:
            if 'TCP' in packet:
                tcp_stream_key = packet.tcp.stream
                # 将数据包添加到对应TCP流的列表中，Sniff_time转换为%Y-%m-%d %H:%M:%S.%f字符串
                has_http = True if 'HTTP' in packet else False
                data = {
                    'sniff_time': packet.sniff_time,
                    'ip_src': packet.ip.src if hasattr(packet, 'ip') else None,
                    'ip_dst': packet.ip.dst if hasattr(packet, 'ip') else None,
                    'src_port': packet.tcp.srcport,  # 添加源端口号
                    'dst_port': packet.tcp.dstport,  # 添加目的端口号
                    'flags': packet.tcp.flags,
                    'stream': packet.tcp.stream,
                    'packet_length': int(packet.length),
                    'content_length': (int(packet.http.content_length) if
                                       hasattr(packet.http, 'content_length') else None) if has_http else None,
                    'chunk_size': (int(packet.http.chunk_size)
                                   if (hasattr(packet.http, 'transfer_encoding') and
                                       hasattr(packet.http, 'chunk_size') and
                                       packet.http.transfer_encoding == 'chunked') else None) if has_http else None,
                    'has_http': has_http,
                    'request_http_method': (packet.http.request_method if
                                            hasattr(packet.http, 'request_method') else None) if has_http else None,
                    'request_full_uri': (packet.http.request_full_uri if hasattr(packet.http,
                                                                                 'request_full_uri') else None) if has_http else None,
                    'response_code': (packet.http.response_code if hasattr(packet.http,
                                                                           'response_code') else None) if has_http else None
                }
                tcp_streams[tcp_stream_key].append(data)

        for stream_id, packets in tcp_streams.items():
            logger.info(f"TCP Stream ID: {stream_id}")
            # 准备开始分析的Flag标识
            start_processing = False
            get_first_ack = False

            # 用于存储开始处理的时间
            start_time = None

            # 记录请求的时间戳
            request_time = None

            # 用于存储结束处理的时间
            end_time = None

            # 成功获取的标识符
            success_flag = False

            # 用于存储结果
            request_method = None
            request_full_uri = None
            request_packet_length = None
            processing_delay = None

            for packet in packets:
                # 检查是否为HTTP数据包
                if packet['has_http'] is True:
                    # 检查是否存在response_code字段，以判断是否为响应包
                    if packet['response_code'] is None:
                        request_time = packet['sniff_time']
                        # 输出HTTP数据包的路径
                        if packet['request_full_uri'] is not None:
                            # logger.info(packet['request_full_uri'])
                            request_full_uri = packet['request_full_uri']
                        else:
                            logger.warning("No request_full_uri field")
                        # 储存HTTP请求方式
                        request_method = packet['request_http_method']
                        request_packet_length = packet['packet_length']
                        start_processing = True
                        get_first_ack = False
                        start_time = None
                        success_flag = False
                    else:
                        start_processing = False
                        get_first_ack = False
                        start_time = None
                        if success_flag:
                            # 如果有，记录URL
                            if packet['request_full_uri'] is not None:
                                request_full_uri = packet['request_full_uri']
                            # 如果有，记录 Time since request 时间
                            if request_time is not None:
                                time_since_request = packet['sniff_time'] - request_time
                            else:
                                time_since_request = None
                                request_time = None
                            success_flag = False
                            # 添加到结果列表
                            transmission_delay = None
                            if processing_delay is not None and time_since_request is not None:
                                transmission_delay = time_since_request - processing_delay
                            # 提取 File Data 长度  条件3
                            if packet['content_length'] is not None:
                                response_total_length = packet['content_length']
                            elif packet['chunk_size'] is not None:
                                response_total_length = packet['chunk_size']
                            else:
                                response_total_length = packet['packet_length']
                            # 使用urlparse分解URI
                            parsed_uri = urlparse(request_full_uri)
                            # 数据输出
                            res_data = {
                                'sniff_time': packet['sniff_time'],
                                'ip_src': packet['ip_src'],
                                'ip_dst': packet['ip_dst'],
                                'src_port': packet['src_port'],  # 添加源端口号
                                'dst_port': packet['dst_port'],  # 添加目的端口号
                                'request_http_method': request_method,
                                'request_scheme': parsed_uri.scheme,
                                'request_netloc': parsed_uri.netloc,
                                'request_path': parsed_uri.path,
                                'request_query': parsed_uri.query,
                                'request_packet_length': request_packet_length,
                                'response_packet_length': packet['packet_length'],
                                'response_total_length': response_total_length,
                                'response_code': packet['response_code'],
                                'processing_delay': processing_delay,
                                'transmission_delay': transmission_delay,
                                'time_since_request': time_since_request
                            }
                            results.append(res_data)
                            # 清空中间变量
                            request_method = None
                            request_full_uri = None
                            request_packet_length = None
                            processing_delay = None

                # 检查标识位，如果为True则开始处理
                if start_processing:
                    # 输出TCP数据包的标识符
                    logger.info(packet['flags'])
                    # 输出TCP数据包的时间戳
                    logger.info(packet['sniff_time'])
                    # 检查标识符是否仅有ACK标志
                    if not get_first_ack:
                        if int(packet['flags'], 16) == int('0x0010', 16):
                            # logger.info('Processing started, get the first ACK packet')
                            # 记录开始处理时间
                            start_time = packet['sniff_time']
                            # 设置标识位
                            get_first_ack = True
                    # 检查是否为PSH-ACK标志
                    elif int(packet['flags'], 16) == int('0x0018', 16):
                        # logger.info('Processing ended, get the last PSH-ACK packet')
                        # 记录结束处理时间
                        end_time = packet['sniff_time']
                        # 计算处理时间
                        if start_time is not None:
                            processing_delay = end_time - start_time
                            logger.info(f"Start time: {start_time}")
                            logger.info(f"End time: {end_time}")
                            logger.info(f"Processing time: {processing_delay}")
                            success_flag = True
                        else:
                            processing_delay = None
                            start_time = None
                        # 重置标识位
                        start_processing = False
                        get_first_ack = False

            # 输出TCP流的包数量
            logger.info(f"Stream {stream_id} ended, Number of packets: {len(packets)}")
            logger.info("-" * 50)

    # 按 sniff_time 排序
    results.sort(key=lambda x: x['sniff_time'])
    logger.info('CSV Sorted.')

    # 添加序号
    for i, res in enumerate(results, start=1):
        res['No'] = i

    # 定义 CSV 文件头
    csv_headers = [
        'No', 'Sniff_time', 'Relative_time', 'Scheme', 'Netloc', 'Path', 'Query',
        'Time_since_request', 'Processing_delay', 'Transmission_delay',
        'Ip_src', 'Ip_dst', 'Src_Port', 'Dst_Port',
        'Request_Method', 'Request_Packet_Length', 'Response_Packet_Length',
        'Response_Total_Length', 'Response_code'
    ]

    # # Test Results
    # logger.info(f'{results}')

    # 打开 CSV 文件并写入数据
    with open(csv_file_path, 'w', newline='') as csvfile:
        logger.info('CSV Opened.')
        writer = csv.DictWriter(csvfile, fieldnames=csv_headers)

        # 写入文件头
        writer.writeheader()

        # 写入数据行
        count_index = 0
        for res in results:
            # 将 sniff_time 转换为字符串格式
            sniff_time_str = res['sniff_time'].strftime('%Y-%m-%d %H:%M:%S.%f')

            # 计算 Relative_time（假设第一个 sniff_time 为基准时间）
            if res['No'] == 1:
                base_time = res['sniff_time']
            relative_time = (res['sniff_time'] - base_time).total_seconds()

            # 构建写入 CSV 的数据行
            row = {
                'No': res['No'],
                'Sniff_time': sniff_time_str,
                'Relative_time': relative_time,
                'Scheme': res['request_scheme'],
                'Netloc': res['request_netloc'],
                'Path': res['request_path'],
                'Query': res['request_query'],
                'Time_since_request': res['time_since_request'].total_seconds(),
                'Processing_delay': res['processing_delay'].total_seconds(),
                'Transmission_delay': res['transmission_delay'].total_seconds(),
                'Ip_src': res['ip_src'],
                'Ip_dst': res['ip_dst'],
                'Src_Port': res['src_port'],
                'Dst_Port': res['dst_port'],
                'Request_Method': res['request_http_method'],
                'Request_Packet_Length': res['request_packet_length'],
                'Response_Packet_Length': res['response_packet_length'],
                'Response_Total_Length': res['response_total_length'],
                'Response_code': res['response_code']
            }

            logger.info(f'Writing - {count_index}')
            count_index = count_index + 1

            # 写入数据行
            writer.writerow(row)

    logger.info(f"数据已成功写入 {csv_file_path} 文件")


if __name__ == "__main__":
    print('Do not run this script directly. Please run run.py instead.')
