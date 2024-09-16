import asyncio
import csv
import pyshark
from urllib.parse import urlparse, urlunparse
import time
import heapq
from datetime import datetime
import os
import subprocess
import pandas as pd
import glob
from collections import OrderedDict
from itertools import islice


# 检查最高层协议是否合适
def check_highest_layer_suitable(layer):
    return ((layer == 'DATA-TEXT-LINES')
            or (layer == 'JSON')
            or (layer == 'PNG')
            or (layer == 'URLENCODED-FORM')
            or (layer == 'MEDIA')
            or (layer == 'IMAGE-JFIF'))

# 检测TCP状态问题
def check_tcp_anomalies(pkt):
    anomalies = []
    # 这里是'0' 不是0
    if hasattr(pkt.tcp, 'window_size_value') and pkt.tcp.window_size_value == '0':
        anomalies.append('TCP ZeroWindow')
    # 检查 TCP Window Full

    if hasattr(pkt.tcp, 'flags'):
        # pkt.tcp.flags 是一个16进制的字符串, 转换为整数进行位运算
        tcp_flags = int(pkt.tcp.flags, 16)
        # 检查 RST 位 (第3位)
        is_rst_set = tcp_flags & 0x04
        if is_rst_set:
            print("RST flag is set in the TCP packet")
            anomalies.append('TCP Reset')
    return anomalies


# 处理数据包，提取HTTP请求和响应信息
def process_packet(pkt, index, first_packet_time, request_response_pairs, unmatched_requests, match_num,tcp_anomalies):
    if check_highest_layer_suitable(pkt.highest_layer) or hasattr(pkt, 'http'):
        # 显示当前处理进度
        print("HTTP: ", index)
        sniff_time = pkt.sniff_time
        if first_packet_time is None:
            first_packet_time = sniff_time
        relative_time = (sniff_time - first_packet_time).total_seconds()

        if hasattr(pkt.http, 'request_method'): # 处理HTTP请求
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
                    'keys_no_url': keys_no_url,  # 存储备用的无URL键

                    'tcp_anomalies': None,  # 预设为None
                    'tcp_anomaly_sniff_time': None,  # 预设为None
                    'tcp_anomaly_index': None  # 预设为None
                }
            except AttributeError:  # 有时候会出现解析错误
                print("error")
        elif hasattr(pkt.http, 'response_code'):
            try:
                # 处理HTTP响应
                # 提取响应包状态码
                response_code = pkt.http.response_code
                url = pkt.http.response_for_uri if hasattr(pkt.http, 'response_for_uri') else None
                ack_num = int(pkt.tcp.ack)
                potential_keys = [
                    (pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport, pkt.tcp.srcport, url, ack_num),
                    (pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport, pkt.tcp.srcport, url, ack_num - 1)
                ]
            except AttributeError:  # 有时候会出现解析错误
                print("Attr error")
                return first_packet_time, match_num

            matched_key = None

            # 首先尝试使用URL和ACK匹配
            if url is not None:
                for key in potential_keys:
                    if key in reversed(request_response_pairs) and not request_response_pairs[key]['matched']:
                        matched_key = key
                        break

            # 如果URL和ACK匹配失败，尝试不使用ACK匹配
            if matched_key is None:
                potential_keys_no_ack = (pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport, pkt.tcp.srcport, url)
                for request_key, request_value in islice(reversed(request_response_pairs.items()), 20):
                    # 倒着遍历字典，并且只遍历20个
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
                    # 倒着遍历字典，并且只遍历20个
                    for request_key, request_value in islice(reversed(request_response_pairs.items()), 20):
                        if request_value['keys_no_url'] == key_no_url and not request_value['matched']:
                            matched_key = request_key
                            break
                    if matched_key:
                        break

            if matched_key:
                # 处理过程中显示配对成功数
                match_num += 1
                print(index, "is matched ", match_num, "in all")

                # 提取 File Data 长度  条件3
                response_total_length = 0
                if hasattr(pkt.http, 'content_length'):
                    response_total_length = int(pkt.http.content_length)
                elif hasattr(pkt.http, 'transfer_encoding') and pkt.http.transfer_encoding == 'chunked':
                    response_total_length = 0
                    try:
                        response_total_length = pkt.http.chunk_size
                    except:
                        print("error")
                else:
                    response_total_length = int(pkt.length)

                request_response_pairs[matched_key].update({
                    'response_time': sniff_time,
                    'response_index': index,
                    'response_packet_length': int(pkt.length),
                    'response_total_length': response_total_length,  # 存储总的响应长度
                    'response_code': response_code,  # 存储响应状态码
                    'matched': True
                })
                print(66666, response_total_length, int(pkt.length))

    # if hasattr(pkt, 'tcp'):
    #     print("TCP: ", index)
    #     anomalies = check_tcp_anomalies(pkt)
    #     if anomalies:  # 如果检测到TCP异常
    #         print(f"Detected TCP Anomalies in packet {index}: {anomalies}")
    #         print(666666666666)
    #         matched_key_for_tcp = None
    #         for request_key, request_value in islice(reversed(request_response_pairs.items()), 20):  # 只遍历最近的20个请求
    #             if ((pkt.ip.src == request_value['ip_src'] and pkt.ip.dst == request_value['ip_dst'] and
    #                  pkt.tcp.srcport == request_value['src_port'] and pkt.tcp.dstport == request_value['dst_port'])
    #                     or (pkt.ip.src == request_value['ip_dst'] and pkt.ip.dst == request_value['ip_src'] and
    #                         pkt.tcp.srcport == request_value['dst_port'] and pkt.tcp.dstport == request_value[
    #                             'src_port'])):
    #                 matched_key_for_tcp = request_key
    #                 break
    #
    #         if matched_key_for_tcp:
    #             request_response_pairs[matched_key_for_tcp].update({
    #                 'tcp_anomalies': anomalies,
    #                 'tcp_anomaly_sniff_time': pkt.sniff_time,
    #                 'tcp_anomaly_index': index
    #             })
    #         else:
    #             for anomaly in anomalies:
    #                 tcp_anomalies.append({
    #                     'anomaly_type': anomaly,
    #                     'ip_src': pkt.ip.src,
    #                     'ip_dst': pkt.ip.dst,
    #                     'src_port': pkt.tcp.srcport,
    #                     'dst_port': pkt.tcp.dstport,
    #                     'anomaly_sniff_time': pkt.sniff_time,
    #                     'anomaly_index': index
    #                 })
    #                 print("tcp_anomalies:",tcp_anomalies)

    return first_packet_time, match_num


# 提取并写入配对信息


def extract_packet_info(csv_file_path, request_response_pairs, write_header=True, final_chunk=False):
    # 打开文件并以追加模式写入数据
    with open(csv_file_path, 'a', newline='') as file:
        writer = csv.writer(file)

        # 只在首次写入时写入列名
        if write_header:
            writer.writerow(
                ['No', 'Request_Index', 'Response_Index', 'Sniff_time', 'Relative_time', 'Scheme', 'Netloc', 'Path',
                 'Query', 'Time_since_request', 'Ip_src', 'Ip_dst', 'Src_Port', 'Dst_Port', 'Request_Method',
                 'Request_Packet_Length', 'Response_Packet_Length', 'Response_Total_Length', 'Match_Status',
                 'Response_code', 'Tcp_anomalies', 'Tcp_anomaly_sniff_time', 'Tcp_anomaly_index'])

        index = 0
        keys_to_remove = []  # 用于记录需要移除的成功配对的键
        for key, pair in sorted(request_response_pairs.items(), key=lambda item: item[1]['request_sniff_time']):
            if final_chunk or pair['matched']:  # 最后一段文件或成功配对的请求
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
                         pair['response_packet_length'], pair['response_total_length'], 'matched', pair['response_code']
                            , pair['tcp_anomalies'], pair['tcp_anomaly_sniff_time'], pair['tcp_anomaly_index']])

                    keys_to_remove.append(key)  # 记录需要移除的键
                elif final_chunk:  # 如果是最后一段文件，需要写入所有数据
                    writer.writerow(
                        [index, pair['request_index'], None, sniff_time, relative_time, parsed_url.scheme,
                         parsed_url.netloc, parsed_url.path, query, None, pair['ip_src'], pair['ip_dst'],
                         pair['src_port'], pair['dst_port'], pair['request_method'], pair['request_packet_length'],
                         None, None, 'unmatched', None, pair['tcp_anomalies'], pair['tcp_anomaly_sniff_time'],
                         pair['tcp_anomaly_index']])

        # 移除成功配对的数据
        for key in keys_to_remove:
            del request_response_pairs[key]
        print("清理已配对matched后，request_response_pairs剩余的未配对字典：",request_response_pairs.keys())
    return request_response_pairs


class PacketWrapper:
    def __init__(self, timestamp, packet, gen):
        self.timestamp = timestamp
        self.packet = packet
        self.gen = gen

    def __lt__(self, other):
        return self.timestamp < other.timestamp


def sort_csv_by_sniff_time(csv_file_path):
    # 使用 pandas 读取 CSV 文件
    df = pd.read_csv(csv_file_path)
    # 将 Sniff_time 列转换为 datetime 对象
    df['Sniff_time'] = pd.to_datetime(df['Sniff_time'], format="%Y-%m-%d %H:%M:%S.%f")
    # 按 Sniff_time 列排序
    df.sort_values(by='Sniff_time', inplace=True)
    # 排序完成后，重新将 Sniff_time 列格式化为字符串
    df['Sniff_time'] = df['Sniff_time'].dt.strftime("%Y-%m-%d %H:%M:%S.%f")

    # 将排序后的数据写回 CSV 文件
    df.to_csv(csv_file_path, index=False)

def save_tcp_anomalies_to_file(tcp_anomalies, filename='../results/tcp_anomalies.csv'):
    fieldnames = ['anomaly_type', 'ip_src', 'ip_dst', 'src_port', 'dst_port', 'anomaly_sniff_time', 'anomaly_index']
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(tcp_anomalies)

# 预处理函数
def preprocess_data(file_paths, csv_file_path):

    split_files_dict = {}
    output_dir = "../raw_data/"

    header_written = False  # 控制变量，跟踪列名是否已写入

    # 创建新的事件循环
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Step 1: 使用 editcap 分割 pcap 文件

    for file_path in file_paths:
        split_files = []
        base_filename = os.path.basename(file_path)  # Extract the base filename from the file path
        split_prefix = os.path.join(output_dir, base_filename)  # Prefix includes the target directory

        # Run the editcap command to split the pcap file and save the splits in the specified directory
        command = f"editcap -c 200000 {file_path} {split_prefix}"
        subprocess.run(command, shell=True)

        # Use glob to find the split files matching the pattern in the output directory
        base_filename_without_extension = os.path.splitext(base_filename)[0]  # 去掉扩展名
        split_file_pattern = os.path.join(output_dir, f"{base_filename_without_extension}_*.pcap")
        split_files = glob.glob(split_file_pattern)

        # Add the found split files to the dictionary
        split_files_dict[file_path] = split_files

        # 将分割后的文件添加到 split_files 列表中
        # split_index = 0
        # while True:
        #     split_file = f"{split_prefix}_*.pcap"
        #     if os.path.exists(split_file):  #先看000.pcap是否存在 再看001.pcap是否存在......
        #         split_files.append(split_file)
        #         split_index += 1
        #     else:
        #         break
        # # 直接将 split_files 列表赋值给 split_files_dict[file_path]
        # split_files_dict[file_path] = split_files

    print("split_files_dict",split_files_dict)

    for file_path, split_files in split_files_dict.items():
        # Step 2: 分批处理每个path 分割后的多个文件
        # 我认为应该在这里添加局部变量
        print(222222222222222)
        request_response_pairs = {}
        unmatched_requests = []
        first_packet_time = None
        match_num = 0
        index = 0  #尤其是index 为了保证同一个path下 分段间的index有联系，而不是每一次都是从0开始
        tcp_anomalies = []
        for i, split_file in enumerate(split_files):   #按顺序做处理 enumerate枚举+输出标号
            cap = pyshark.FileCapture(split_file, keep_packets=False)  #在自己的主机要加上路径：tshark_path="F:\\softwares_f\\Wireshark\\tshark.exe"
            # 分批处理每个分割文件中的包
            for pkt in cap:
                index += 1
                first_packet_time, match_num = process_packet(pkt, index, first_packet_time, request_response_pairs,
                                                              unmatched_requests, match_num,tcp_anomalies)
            # 提取并写入配对信息
            # 如果是最后一个分段文件，执行特殊处理
            if i == len(split_files) - 1:  #写入后，把request_response_pairs中配对成功的键去除，没配对的继续使用，不应该会造成开头的一个包缺少配对啊
                request_response_pairs = extract_packet_info(csv_file_path, request_response_pairs, write_header=not header_written, final_chunk=True)
            else:
                request_response_pairs = extract_packet_info(csv_file_path, request_response_pairs, write_header=not header_written, final_chunk=False)
            print("第",i+1,"段包已写入，共",len(split_files),"段")

            # 确保在第一次写入列名后，将 header_written 设置为 True
            if not header_written:
                header_written = True

            # 清理资源
            cap.close()
            os.remove(split_file)  # 删除分割后的文件，节省磁盘空间
        save_tcp_anomalies_to_file(tcp_anomalies)  #写入异常文件的位置
    sort_csv_by_sniff_time(csv_file_path)
    print("数据处理完成，已生成CSV文件，已排序。")


    # 提取并写入配对信息
    # extract_packet_info(csv_file_path, request_response_pairs, unmatched_requests)


if __name__ == "__main__":
    print('Do not run this script directly. Please run run.py instead.')
