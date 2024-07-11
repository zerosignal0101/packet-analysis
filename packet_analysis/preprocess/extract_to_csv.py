import csv
import pyshark
from urllib.parse import urlparse, urlunparse
import time

# 全局变量
first_packet_time = None
request_response_pairs = {}
unmatched_requests = []
batch_size = 10000  # 每处理10000个数据包清理一次内存
match_num = 0
now = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


# 检查最高层协议是否合适
def check_highest_layer_suitable(layer):
    return ((layer == 'DATA-TEXT-LINES')
            or (layer == 'JSON')
            or (layer == 'PNG')
            or (layer == 'URLENCODED-FORM')
            or (layer == 'MEDIA')
            or (layer == 'IMAGE-JFIF')
            )


# 处理数据包，提取HTTP请求和响应信息
def process_packet(pkt, index):
    global first_packet_time
    global match_num

    if check_highest_layer_suitable(pkt.highest_layer) or hasattr(pkt, 'http'):
        # 显示当前处理进度
        print("HTTP: ", index)
        sniff_time = pkt.sniff_time
        if first_packet_time is None:
            first_packet_time = sniff_time
        relative_time = (sniff_time - first_packet_time).total_seconds()

        if hasattr(pkt.http, 'request_method'):
            # 处理HTTP请求
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
                'url': url,
                'request_method': pkt.http.request_method,  # 存储请求类型
                'request_packet_length': int(pkt.length),
                'matched': False,
                'keys_no_ack': keys_no_ack,  # 存储备用的无ACK键
                'keys_no_url': keys_no_url  # 存储备用的无URL键
            }
        elif hasattr(pkt.http, 'response_code'):
            # 处理HTTP响应
            url = pkt.http.response_for_uri if hasattr(pkt.http, 'response_for_uri') else None
            ack_num = int(pkt.tcp.ack)
            potential_keys = [
                (pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport, pkt.tcp.srcport, url, ack_num),
                (pkt.ip.dst, pkt.ip.src, pkt.tcp.dstport, pkt.tcp.srcport, url, ack_num - 1)
            ]

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
                print(index, "is matched ", match_num, "in all")

                # 提取 File Data 长度
                if hasattr(pkt.http, 'content_length'):
                    response_total_length = int(pkt.http.content_length)
                elif hasattr(pkt.http, 'chunk_size'):
                    response_total_length = int(pkt.http.chunk_size)
                else:
                    response_total_length = int(pkt.length)

                request_response_pairs[matched_key].update({
                    'response_time': sniff_time,
                    'response_index': index,
                    'response_packet_length': int(pkt.length),
                    'response_total_length': response_total_length,  # 存储总的响应长度
                    'matched': True
                })
                print(66666, response_total_length, int(pkt.length))


# 提取并写入配对信息
def extract_packet_info(csv_file_path):
    with open(csv_file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(
            ['No', 'Request_Index', 'Response_Index', 'Sniff_time', 'Relative_time', 'Scheme', 'Netloc', 'Path',
             'Query', 'Time_since_request', 'Ip_src', 'Ip_dst', 'Request_Method', 'Request_Packet_Length',
             'Response_Packet_Length', 'Response_Total_Length', 'Match_Status'])

        index = 0
        for key, pair in sorted(request_response_pairs.items(), key=lambda item: item[1]['request_sniff_time']):
            index += 1
            sniff_time = pair['request_sniff_time']
            relative_time = pair['request_relative_time']

            url = pair['url']
            parsed_url = urlparse(url) if url else urlparse('')
            query = urlunparse(('', '', '', parsed_url.params, parsed_url.query, ''))

            if pair['matched']:
                response_time = pair['response_time']
                time_since_request = (response_time - sniff_time).total_seconds()
                writer.writerow(
                    [index, pair['request_index'], pair['response_index'], sniff_time, relative_time, parsed_url.scheme,
                     parsed_url.netloc, parsed_url.path, query, time_since_request, pair['ip_src'], pair['ip_dst'],
                     pair['request_method'], pair['request_packet_length'], pair['response_packet_length'],
                     pair['response_total_length'], 'matched'])
                print("----------------------------- Success !")
                print(f"Num: {index}, Request Index: {pair['request_index']}, Response Index: {pair['response_index']}")
            else:
                writer.writerow(
                    [index, pair['request_index'], None, sniff_time, relative_time, parsed_url.scheme,
                     parsed_url.netloc, parsed_url.path, query, None, pair['ip_src'], pair['ip_dst'],
                     pair['request_method'], pair['request_packet_length'], None, None, 'unmatched'])
                unmatched_requests.append(pair)
                print("----------------------------- Unmatched Request !")
                print(f"Num: {index}, Request Index: {pair['request_index']}")


# 预处理函数
def preprocess_data(pcap_file_path, csv_file_path):
    global first_packet_time, request_response_pairs, unmatched_requests, match_num

    index = 0
    processed_packets = 0

    while True:
        cap = pyshark.FileCapture(pcap_file_path, keep_packets=False,
                                  tshark_path="F:\softwares_f\Wireshark\\tshark.exe",
                                  display_filter=f"frame.number > {index}")

        batch_processed = False
        for pkt in cap:
            index += 1
            process_packet(pkt, index)
            processed_packets += 1

            if processed_packets >= batch_size:
                cap.close()
                processed_packets = 0
                batch_processed = True
                break

        if not batch_processed:
            cap.close()
            break

    # 提取配对成功后的指标并写入CSV
    extract_packet_info(csv_file_path)


# Main
if __name__ == '__main__':
    print('Do not run this script directly. Please run run.py instead.')
