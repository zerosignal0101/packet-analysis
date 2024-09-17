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


# 处理数据包，提取HTTP请求和响应信息
def process_packet(pkt, index, first_packet_time, request_response_pairs, unmatched_requests, match_num):
    if check_highest_layer_suitable(pkt.highest_layer) or hasattr(pkt, 'http'):
        # 显示当前处理进度
        logger.info(f"HTTP: {index}")
        sniff_time = pkt.sniff_time
        if first_packet_time is None:
            first_packet_time = sniff_time
        relative_time = (sniff_time - first_packet_time).total_seconds()

        if hasattr(pkt.http, 'request_method'):
            try:
                url = pkt.http.request_full_uri
                seq_num = int(pkt.tcp.seq)
                next_seq_num = seq_num + int(pkt.tcp.len)
                key = (pkt.ip.src, pkt.ip.dst, pkt.tcp.srcport, pkt.tcp.dstport, url, next_seq_num)
                keys_no_ack = (pkt.ip.src, pkt.ip.dst, pkt.tcp.srcport, pkt.tcp.dstport, url)
                keys_no_url = (pkt.ip.src, pkt.ip.dst, pkt.tcp.srcport, pkt.tcp.dstport, next_seq_num)
                request_response_pairs[key] = {
                    'request_sniff_time': sniff_time,
                    'request_relative_time': relative_time,
                    'request_index': index,
                    'ip_src': pkt.ip.src,
                    'ip_dst': pkt.ip.dst,
                    'src_port': pkt.tcp.srcport,  # 添加源端口号
                    'dst_port': pkt.tcp.dstport,  # 添加目的端口号
                    'url': url,
                    'request_method': pkt.http.request_method,  # 存储请求类型
                    'request_packet_length': int(pkt.length),
                    'matched': False,
                    'keys_no_ack': keys_no_ack,  # 存储备用的无ACK键
                    'keys_no_url': keys_no_url  # 存储备用的无URL键
                }
            except AttributeError:  # 有时候会出现解析错误
                logger.info("error")
        elif hasattr(pkt.http, 'response_code'):
            try:
                # 处理HTTP响应
                url = pkt.http.response_for_uri if hasattr(pkt.http, 'response_for_uri') else None
                ack_num = int(pkt.tcp.ack)
                potential_keys = [
                    (pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport, pkt.tcp.srcport, url, ack_num),
                    (pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport, pkt.tcp.srcport, url, ack_num - 1)
                ]
            except AttributeError:  # 有时候会出现解析错误
                logger.info("Attr error")
                return first_packet_time, match_num

            matched_key = None

            # 首先尝试使用URL和ACK匹配
            if url is not None:
                for key in potential_keys:
                    if key in request_response_pairs and not request_response_pairs[key]['matched']:
                        matched_key = key
                        break

            # 如果URL和ACK匹配失败，尝试不使用ACK匹配
            if matched_key is None:
                potential_keys_no_ack = (pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport, pkt.tcp.srcport, url)
                for request_key, request_value in request_response_pairs.items():
                    if request_value['keys_no_ack'] == potential_keys_no_ack and not request_value['matched']:
                        matched_key = request_key
                        break

            # 如果URL和ACK匹配失败，尝试不使用URL匹配
            if matched_key is None:
                potential_keys_no_url = [
                    (pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport, pkt.tcp.srcport, ack_num),
                    (pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport, pkt.tcp.srcport, ack_num - 1)
                ]
                for key_no_url in potential_keys_no_url:
                    for request_key, request_value in request_response_pairs.items():
                        if request_value['keys_no_url'] == key_no_url and not request_value['matched']:
                            matched_key = request_key
                            break
                    if matched_key:
                        break

            if matched_key:
                # 处理过程中显示配对成功数
                match_num += 1
                logger.info(f"{index} is matched {match_num} in all")

                # 提取 File Data 长度  条件3
                response_total_length = 0
                if hasattr(pkt.http, 'content_length'):
                    response_total_length = int(pkt.http.content_length)
                elif hasattr(pkt.http, 'transfer_encoding') and pkt.http.transfer_encoding == 'chunked':
                    response_total_length = 0
                    try:
                        response_total_length = pkt.http.chunk_size
                    except:
                        logger.info("error")
                else:
                    response_total_length = int(pkt.length)

                request_response_pairs[matched_key].update({
                    'response_time': sniff_time,
                    'response_index': index,
                    'response_packet_length': int(pkt.length),
                    'response_total_length': response_total_length,  # 存储总的响应长度
                    'matched': True
                })
                logger.info(f"66666 {response_total_length} {pkt.length}")

    return first_packet_time, match_num


# 提取并写入配对信息
def extract_packet_info(csv_file_path, request_response_pairs, unmatched_requests):
    with open(csv_file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(
            ['No', 'Request_Index', 'Response_Index', 'Sniff_time', 'Relative_time', 'Scheme', 'Netloc', 'Path',
             'Query', 'Time_since_request', 'Ip_src', 'Ip_dst', 'Src_Port', 'Dst_Port', 'Request_Method',
             'Request_Packet_Length', 'Response_Packet_Length', 'Response_Total_Length', 'Match_Status'])

        index = 0
        for key, pair in sorted(request_response_pairs.items(), key=lambda item: item[1]['request_sniff_time']):
            index += 1
            sniff_time = pair['request_sniff_time'].strftime("%Y-%m-%d %H:%M:%S.%f")  # 修改时间格式
            relative_time = pair['request_relative_time']

            url = pair['url']
            parsed_url = urlparse(url) if url else urlparse('')
            query = urlunparse(('', '', '', parsed_url.params, parsed_url.query, ''))

            if pair['matched']:
                response_time = pair['response_time']
                time_since_request = (response_time - pair['request_sniff_time']).total_seconds()
                time_since_request = "{:.6f}".format(time_since_request)  # 保留六位小数

                writer.writerow(
                    [index, pair['request_index'], pair['response_index'], sniff_time, relative_time, parsed_url.scheme,
                     parsed_url.netloc, parsed_url.path, query, time_since_request, pair['ip_src'], pair['ip_dst'],
                     pair['src_port'], pair['dst_port'], pair['request_method'], pair['request_packet_length'],
                     pair['response_packet_length'], pair['response_total_length'], 'matched'])
            else:
                writer.writerow(
                    [index, pair['request_index'], None, sniff_time, relative_time, parsed_url.scheme,
                     parsed_url.netloc, parsed_url.path, query, None, pair['ip_src'], pair['ip_dst'],
                     pair['src_port'], pair['dst_port'], pair['request_method'], pair['request_packet_length'],
                     None, None, 'unmatched'])
                unmatched_requests.append(pair)
            logger.info("----写入66666666666----第 /15000次-------")


class PacketWrapper:
    def __init__(self, timestamp, packet, gen):
        self.timestamp = timestamp
        self.packet = packet
        self.gen = gen

    def __lt__(self, other):
        return self.timestamp < other.timestamp


# 预处理函数
def preprocess_data(file_paths, csv_file_path):
    # log the input file paths
    logger.info(f"Input file paths: {file_paths}")

    # check if the [0] is type of list
    if isinstance(file_paths[0], list):
        file_paths = file_paths[0]

    request_response_pairs = {}
    unmatched_requests = []
    first_packet_time = None
    match_num = 0

    # 创建新的事件循环
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    if len(file_paths) == 1:
        # cap = pyshark.FileCapture(file_paths[0], keep_packets=False)
        cap = pyshark.FileCapture(file_paths[0], keep_packets=False, tshark_path="F:\\softwares_f\\Wireshark\\tshark.exe")
        index = 0
        for pkt in cap:
            index += 1
            first_packet_time, match_num = process_packet(pkt, index, first_packet_time, request_response_pairs, unmatched_requests, match_num)

        # 提取并写入配对信息
        extract_packet_info(csv_file_path, request_response_pairs, unmatched_requests)

    elif len(file_paths) > 1:
        # packet_generators = [
        #     pyshark.FileCapture(file_path, keep_packets=False) for
        #     file_path in file_paths]
        packet_generators = [
            pyshark.FileCapture(file_path, keep_packets=False, tshark_path="F:\\softwares_f\\Wireshark\\tshark.exe") for
            file_path in file_paths]
        current_packets = []

        # Initialize the heap with the first packet from each file
        for gen in packet_generators:
            gen_iter = iter(gen)
            try:
                first_packet = next(gen_iter)
                heapq.heappush(current_packets, PacketWrapper(first_packet.sniff_time, first_packet, gen_iter))
            except StopIteration:
                continue

        index = 0
        while current_packets:
            # Get the packet with the smallest timestamp0
            packet_wrapper = heapq.heappop(current_packets)
            packet = packet_wrapper.packet
            gen = packet_wrapper.gen
            index += 1
            first_packet_time, match_num = process_packet(packet, index, first_packet_time, request_response_pairs,
                                                          unmatched_requests, match_num)

            gen_iter = iter(gen)

            # Push the next packet from the same generator into the heap
            try:
                next_packet = next(gen_iter)
                heapq.heappush(current_packets, PacketWrapper(next_packet.sniff_time, next_packet, gen))
            except StopIteration:
                continue

        # 提取并写入配对信息
        extract_packet_info(csv_file_path, request_response_pairs, unmatched_requests)


if __name__ == "__main__":
    print('Do not run this script directly. Please run run.py instead.')
