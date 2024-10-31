from collections import defaultdict
import asyncio
import csv
import sys
import pyshark
import pandas as pd
from urllib.parse import urlparse, urlunparse
import time
import heapq
from datetime import datetime, timedelta
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
def preprocess_data(file_paths):
    # log the input file paths
    logger.info(f"Input file paths: {file_paths}")

    # check if the [0] is type of list
    if isinstance(file_paths[0], list):
        file_paths = file_paths[0]

    # 储存时间戳、Url、业务处理时间、响应时延等信息的列表
    results = []

    for cur_pcap in file_paths:
        # 使用pyshark打开pcap文件
        capture = pyshark.FileCapture(cur_pcap, display_filter='tcp', keep_packets=False)

        # 用于存储TCP流及其包
        data_list = []

        for packet in capture:
            if 'TCP' in packet:
                tcp_stream_key = packet.tcp.stream
                # 将数据包添加到对应TCP流的列表中，Sniff_time转换为%Y-%m-%d %H:%M:%S.%f字符串
                has_http = True if 'HTTP' in packet else False
                data = (
                    packet.sniff_time,
                    packet.ip.src if hasattr(packet, 'ip') else None,
                    packet.ip.dst if hasattr(packet, 'ip') else None,
                    packet.tcp.srcport if hasattr(packet, 'tcp') else None,
                    packet.tcp.dstport if hasattr(packet, 'tcp') else None,
                    packet.tcp.flags if hasattr(packet, 'tcp') else None,
                    packet.tcp.stream if hasattr(packet, 'tcp') else None,
                    (packet.length),
                    ((packet.http.content_length) if hasattr(packet.http,
                                                             'content_length') else None) if has_http else None,
                    ((packet.http.chunk_size) if (hasattr(packet.http, 'transfer_encoding') and
                                                  hasattr(packet.http, 'chunk_size') and
                                                  packet.http.transfer_encoding == 'chunked') else None) if has_http else None,
                    has_http,
                    (packet.http.request_method if hasattr(packet.http,
                                                           'request_method') else None) if has_http else None,
                    (packet.http.request_full_uri if hasattr(packet.http,
                                                             'request_full_uri') else None) if has_http else None,
                    (packet.http.response_code if hasattr(packet.http, 'response_code') else None) if has_http else None
                )
                # print(sys.getsizeof(data))
                data_list.append(data)
                # print(sys.getsizeof(data_list))

        # 创建 DataFrame 并添加表头
        columns = [
            'sniff_time', 'ip_src', 'ip_dst', 'src_port', 'dst_port',
            'flags', 'stream', 'packet_length', 'content_length',
            'chunk_size', 'has_http', 'request_http_method',
            'request_full_uri', 'response_code'
        ]

        # 创建DataFrame
        df = pd.DataFrame(data_list, columns=columns)
        del data_list
        df['stream'] = pd.to_numeric(df['stream'], errors='coerce')

        # 按 'stream' 列排序
        df_sorted = df.sort_values(by=['stream', 'sniff_time'], na_position='last')

        # # test output
        # df_sorted.to_csv('results/df_sorted.csv')

        logger.info(f"Pcap read ended, start preprocessing")
        # 准备开始分析的Flag标识
        start_processing = False
        get_first_ack = False

        # 用于存储开始处理的时间
        start_time = None

        # 记录请求的时间戳
        request_time = None

        # 成功获取的标识符
        success_flag = False

        # 用于存储结果
        request_method = None
        request_full_uri = None
        request_packet_length = None
        processing_delay = None
        time_since_request = None
        transmission_delay = None

        # Stream 标识
        cur_stream_id = None

        for index, packet in df_sorted.iterrows():
            # 检查Stream标识
            if packet['stream'] != cur_stream_id:
                # 准备开始分析的Flag标识
                start_processing = False
                get_first_ack = False

                # 用于存储开始处理的时间
                start_time = None

                # 记录请求的时间戳
                request_time = None

                # 成功获取的标识符
                success_flag = False

                # 用于存储结果
                request_method = None
                request_full_uri = None
                request_packet_length = None
                processing_delay = None
                time_since_request = None
                transmission_delay = None

                cur_stream_id = packet['stream']
            # 检查是否为HTTP数据包
            if packet['has_http'] is True:
                # 检查是否存在response_code字段，以判断是否为响应包
                if packet['response_code'] is None:
                    # # test log
                    # logger.info("A response packet found. --S")
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
                else:
                    # logger.info("A request packet found. ++Q")
                    # 如果有，记录URL
                    if packet['request_full_uri'] is not None:
                        request_full_uri = packet['request_full_uri']
                    # 如果有，记录 Time since request 时间
                    if request_time is not None and request_method is not None:
                        time_since_request = packet['sniff_time'] - request_time
                        # 计算传输时延
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
                            'ip_src': packet['ip_dst'],  # 以请求为基准
                            'ip_dst': packet['ip_src'],  # 以请求为基准
                            'src_port': packet['dst_port'],  # 添加源端口号，以请求为基准
                            'dst_port': packet['src_port'],  # 添加目的端口号，以请求为基准
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
                        # # test print
                        # sniff_time = packet['sniff_time']
                        # logger.info(f'Sniff time: {sniff_time}')
                        # logger.info(f"Time Since Request: {time_since_request}")
                        # logger.info(f'Transmission delay: {transmission_delay}')
                        # logger.info(f'Processing delay {processing_delay}')
                        results.append(res_data)
                    # 清空中间变量
                    start_processing = False
                    get_first_ack = False
                    start_time = None
                    request_method = None
                    request_full_uri = None
                    request_time = None
                    request_packet_length = None
                    processing_delay = None
                    transmission_delay = None
                    time_since_request = None

            # 检查标识位，如果为True则开始处理
            if start_processing:
                # 输出TCP数据包的标识符
                # logger.info(packet['flags'])
                # 输出TCP数据包的时间戳
                # logger.info(packet['sniff_time'])
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
                        success_flag = True
                    else:
                        processing_delay = None
                        start_time = None
                    # 重置标识位
                    start_processing = False
                    get_first_ack = False

        # 输出TCP流的包数量
        logger.info(f"Pcap ended, Number of packets: {len(df_sorted)}")
        logger.info("-" * 50)

    # 按 sniff_time 排序
    results.sort(key=lambda x: x['sniff_time'])
    logger.info('CSV Sorted.')

    return results


if __name__ == "__main__":
    print('Do not run this script directly. Please run run.py instead.')
