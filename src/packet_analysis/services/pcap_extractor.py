import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
import pyshark  # Make sure pyshark is installed
from pyshark.tshark.tshark import TSharkNotFoundException
import os
import logging
import datetime
from typing import Union, Dict, Any, Optional  # For type hinting
from pathlib import Path
from urllib.parse import urlparse
from contextlib import closing  # To ensure pyshark capture is closed
from redis.exceptions import LockError

# Assuming extract_to_csv and redis_utils are importable (though extract_to_csv might not be needed anymore)
# import extract_to_csv # No longer needed for this combined function
from src.packet_analysis.utils.cache import get_redis_client, get_file_hash, redis_lock, Config, CacheStatus

logger = logging.getLogger(__name__)

# --- Keep PARQUET_COLUMNS definition ---
PARQUET_COLUMNS = [
    'Sniff_time', 'Relative_time', 'Scheme', 'Netloc', 'Path', 'Query',
    'Time_since_request', 'Processing_delay', 'Transmission_delay',
    'Ip_src', 'Ip_dst', 'Src_Port', 'Dst_Port', 'Is_zero_window',
    'Is_tcp_reset', 'Request_Method', 'Request_Packet_Length',
    'Response_Packet_Length', 'Response_Total_Length', 'Response_code'
]


# --- Combined Processing Function ---

def process_pcap_to_parquet(pcap_file_path: Union[str, Path]) -> Optional[str]:
    """
    Reads a PCAP file using pyshark, analyzes TCP streams for HTTP metrics,
    saves results directly to Parquet, and utilizes Redis cache.

    Args:
        pcap_file_path: Path to the input PCAP file.

    Returns:
        Cache key of the chunk pcap file, or None if processing failed or no relevant data found.
    """
    pcap_file_path = str(pcap_file_path)  # Ensure it's a string path
    redis_client = get_redis_client()

    # --- Caching Logic (similar to before) ---
    if not redis_client or not redis_client._initialized:
        logger.error("Redis client is not available. Cannot proceed with caching.")
        return None

    try:
        file_hash = get_file_hash(pcap_file_path)
    except (FileNotFoundError, IOError) as e:
        logger.error(f"Cannot process PCAP {pcap_file_path}: {e}")
        return None

    cache_key = f"chunk_pcap_parquet:{file_hash}"
    lock_key = f"lock:pcap_process:{file_hash}"

    # Check Cache
    parquet_file_path_cache = redis_client.get_cache(cache_key)
    if parquet_file_path_cache:
        if os.path.exists(parquet_file_path_cache):
            logger.info(f"Cache hit for PCAP hash {file_hash}. Using existing Parquet: {parquet_file_path_cache}")
            return cache_key
        else:
            logger.warning(
                f"Cache hit for PCAP hash {file_hash}, but Parquet file {parquet_file_path_cache} not found. Re-processing.")
            try:
                # Attempt to delete the stale cache entry
                redis_client.delete_cache(cache_key)
            except Exception as redis_err:
                logger.error(f"Failed to delete stale cache key {cache_key}: {redis_err}")
            parquet_file_path_cache = None  # Treat as cache miss

    # Cache Miss or Invalid Cache Entry
    logger.info(f"Cache miss or invalid for PCAP hash {file_hash}. Processing: {pcap_file_path}")

    try:
        # Acquire lock
        with redis_lock(lock_key):
            # Double-check cache inside lock
            parquet_file_path_cache = redis_client.get_cache(cache_key)
            if parquet_file_path_cache and os.path.exists(parquet_file_path_cache):
                logger.info(
                    f"Cache populated while waiting for lock for hash {file_hash}. Using: {parquet_file_path_cache}")
                return cache_key

            # --- Processing Core Logic (Inside Lock) ---
            logger.info(f"Acquired lock '{lock_key}'. Processing PCAP stream: {pcap_file_path}")
            parquet_file_path = _process_pcap_stream_to_parquet(pcap_file_path, cache_key, file_hash)

            if parquet_file_path:
                # Cache the path
                abs_parquet_path = os.path.abspath(parquet_file_path)
                if redis_client.set_cache(cache_key, abs_parquet_path):
                    logger.info(f"Cached Parquet path '{abs_parquet_path}' for hash {file_hash} with key {cache_key}")
                else:
                    logger.warning(f"Failed to cache Parquet path for hash {file_hash}")
                # Note: _process_pcap_stream_to_parquet now handles PCAP cleanup on success
                return cache_key
            else:
                logger.error(f"Processing failed or no data found for {pcap_file_path}, Parquet file not generated.")
                return cache_key

    except LockError as e:
        logger.error(
            f"Failed to acquire lock for processing {pcap_file_path} (hash {file_hash}): {e}. Another process might be working on it.")
        return None  # Indicate failure or inability to process now
    except TSharkNotFoundException:
        logger.error(f"TShark not found. Please ensure TShark is installed and in the system PATH.")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during processing or caching for {pcap_file_path}: {e}",
                     exc_info=True)
        return None


def _process_pcap_stream_to_parquet(pcap_file_path: str, cache_key: Optional[str], file_hash: Optional[str]) -> \
        Optional[str]:
    """
    Internal function: Reads pcap stream, analyzes, generates final metrics, and saves to Parquet.
    Handles PCAP cleanup on success.
    """
    final_results = []  # Store the final calculated dictionaries for the DataFrame

    logger.info(f"Starting pyshark processing for: {pcap_file_path}")

    try:
        # 使用pyshark打开pcap文件
        capture = pyshark.FileCapture(pcap_file_path, display_filter='tcp', keep_packets=False)

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
                    packet.tcp.srcport,
                    packet.tcp.dstport,
                    packet.tcp.flags,
                    packet.tcp.stream,
                    packet.tcp.window_size_value if hasattr(packet.tcp, 'window_size_value') else None,
                    packet.length,
                    (packet.http.content_length if hasattr(packet.http,
                                                           'content_length') else None) if has_http else None,
                    (packet.http.chunk_size if (hasattr(packet.http, 'transfer_encoding') and
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
            'flags', 'stream', 'window_size_value', 'packet_length', 'content_length',
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

        # Zero window
        is_zero_window = False

        # TCP RST 标识
        is_tcp_reset = False

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

                # 记录零窗口的标识符
                is_zero_window = False

                # 用于存储结果
                request_method = None
                request_full_uri = None
                request_packet_length = None
                processing_delay = None
                time_since_request = None
                transmission_delay = None

                cur_stream_id = packet['stream']

                # TCP RST 标识
                is_tcp_reset = False
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
                        # logger.warning("No request_full_uri field")
                        pass
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
                        time_since_request = time_since_request.total_seconds()
                        # 计算传输时延
                        if processing_delay is not None and time_since_request is not None:
                            transmission_delay = time_since_request - processing_delay
                            # Already float
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
                            'Sniff_time': request_time,
                            'Relative_time': None,
                            'Scheme': parsed_uri.scheme,
                            'Netloc': parsed_uri.netloc,
                            'Path': parsed_uri.path,
                            'Query': parsed_uri.query,
                            'Time_since_request': time_since_request,
                            'Processing_delay': processing_delay,
                            'Transmission_delay': transmission_delay,
                            'Ip_src': packet['ip_dst'],  # 以请求为基准
                            'Ip_dst': packet['ip_src'],  # 以请求为基准
                            'Src_Port': packet['dst_port'],  # 添加源端口号，以请求为基准
                            'Dst_Port': packet['src_port'],  # 添加目的端口号，以请求为基准
                            'Is_zero_window': is_zero_window,
                            'Is_tcp_reset': is_tcp_reset,
                            'Request_Method': request_method,
                            'Request_Packet_Length': request_packet_length,
                            'Response_Packet_Length': packet['packet_length'],
                            'Response_Total_Length': response_total_length,
                            'Response_code': packet['response_code'],
                        }
                        # # test print
                        # sniff_time = packet['sniff_time']
                        # logger.info(f'Sniff time: {sniff_time}')
                        # logger.info(f"Time Since Request: {time_since_request}")
                        # logger.info(f'Transmission delay: {transmission_delay}')
                        # logger.info(f'Processing delay {processing_delay}')
                        if is_tcp_reset:
                            logger.warning('TCP reset detected.')
                        final_results.append(res_data)
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
                    is_zero_window = False
                    is_tcp_reset = False

            if packet['window_size_value'] == '0':
                is_zero_window = True

            # pkt.tcp.flags 是一个16进制的字符串, 转换为整数进行位运算
            tcp_flags = int(packet['flags'], 16)
            # 检查 RST 位 (第3位)
            if tcp_flags & 0x04:
                is_tcp_reset = True
                # logger.info("RST flag is set in the TCP packet")

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
                        processing_delay = processing_delay.total_seconds()
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

        # # 按 sniff_time 排序
        # results.sort(key=lambda x: x['sniff_time'])
        logger.info(f'Dataframe Sorted in extract_info_from_pcap for {pcap_file_path}.')

    except TSharkNotFoundException as e:
        logger.error(f"TShark not found during processing: {e}")
        raise  # Re-raise to be caught by the outer function
    except Exception as e:
        logger.error(f"Error during pyshark iteration or stream analysis for {pcap_file_path}: {e}", exc_info=True)
        return None  # Indicate failure

    # --- Post-Processing: Create DataFrame and Save ---
    if not final_results:
        logger.warning(
            f"No completed HTTP request/response pairs found in {pcap_file_path}. No Parquet file generated.")
        return None

    try:
        logger.info(f"Creating DataFrame from {len(final_results)} results.")
        df = pd.DataFrame(final_results)

        # Ensure columns and order, fill missing with None/NaN
        df = df.reindex(columns=PARQUET_COLUMNS)

        # Convert data types
        logger.info("Converting DataFrame column types...")
        df['Sniff_time'] = pd.to_datetime(df['Sniff_time'])
        # Convert float seconds back to Timedelta if needed by consumers, but Parquet handles float better. Storing seconds is usually fine.
        # df['Time_since_request'] = pd.to_timedelta(df['Time_since_request'], unit='s')
        # df['Processing_delay'] = pd.to_timedelta(df['Processing_delay'], unit='s')
        # df['Transmission_delay'] = pd.to_timedelta(df['Transmission_delay'], unit='s')

        # Use nullable integers and boolean types
        numeric_cols = ['Src_Port', 'Dst_Port', 'Request_Packet_Length',
                        'Response_Packet_Length', 'Response_Total_Length', 'Response_code']
        for col in numeric_cols:
            # Coerce errors to handle potential non-numeric values if preprocessing wasn't perfect
            df[col] = pd.to_numeric(df[col], errors='coerce').astype('Int64')

        boolean_cols = ['Is_zero_window', 'Is_tcp_reset']
        for col in boolean_cols:
            df[col] = df[col].astype('boolean')  # Nullable boolean type

        # String types (already strings or None, but explicit conversion is safe)
        string_cols = ['Scheme', 'Netloc', 'Path', 'Query', 'Request_Method', 'Ip_src', 'Ip_dst']
        for col in string_cols:
            df[col] = df[col].astype('string')  # Pandas nullable string type

        # Define Parquet file path
        parquet_filename_base = file_hash if file_hash else os.path.splitext(os.path.basename(pcap_file_path))[0]
        parquet_file_path = os.path.join(Config.PARQUET_STORAGE_DIR, f"{parquet_filename_base}.parquet")

        logger.info(f"Writing DataFrame to Parquet file: {parquet_file_path}...")
        os.makedirs(os.path.dirname(parquet_file_path), exist_ok=True)
        table = pa.Table.from_pandas(df, preserve_index=False)
        pq.write_table(table, parquet_file_path, compression='snappy')

        logger.info(f"Successfully wrote {len(df)} rows to Parquet: {parquet_file_path}")

        return parquet_file_path

    except Exception as df_parquet_err:
        logger.error(f"Error creating DataFrame or writing Parquet for {pcap_file_path}: {df_parquet_err}",
                     exc_info=True)
        # Don't clean up pcap here, let the caller handle cleanup on failure if needed
        return None


# --- Example Usage (Similar to before, using the new combined function) ---
if __name__ == "__main__":
    import rootutils

    # 查找项目根目录
    path = rootutils.find_root(search_from=__file__, indicator=".project-root")

    # 定义 Parquet 文件夹和文件路径
    Config.PARQUET_STORAGE_DIR = os.path.join(path, "results/parquet_data")

    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # If you have tshark and a sample pcap (e.g., sample.pcap):
    dummy_pcap_path = os.path.join(
        path, "raw_data/small_data_producer.pcap")

    logger.info(f"Processing PCAP file with combined function: {dummy_pcap_path}")

    # Ensure the storage directory exists if running standalone
    os.makedirs(Config.PARQUET_STORAGE_DIR, exist_ok=True)

    parquet_output_path = process_pcap_to_parquet(dummy_pcap_path)

    if parquet_output_path:
        logger.info(f"Processing successful. Parquet file generated at: {parquet_output_path}")
        try:
            df_read = pd.read_parquet(parquet_output_path)
            logger.info(
                f"Read back Parquet. Shape: {df_read.shape}\n Dtypes:\n{df_read.dtypes}\n Head:\n{df_read.head()}")
        except Exception as e:
            logger.error(f"Failed to read or cleanup Parquet file {parquet_output_path}: {e}")
    else:
        # This is expected for an empty dummy pcap
        logger.info("Processing failed or no data found (as expected for empty/dummy pcap).")

    # Test caching (recreate the file with same content)
    logger.info("\n--- Running again to test cache ---")
    parquet_output_path_cached = process_pcap_to_parquet(dummy_pcap_path)
    if parquet_output_path_cached:
        logger.info(f"Second run successful (cache hit expected). Parquet file: {parquet_output_path_cached}")
        # If the first run produced a file (unlikely with empty pcap), this path should match
        # assert parquet_output_path == parquet_output_path_cached
        # Clean up again if needed
        if os.path.exists(parquet_output_path_cached): os.remove(parquet_output_path_cached)

    else:
        logger.info(
            "Second run: Processing failed or no data found (cache hit expected if first run produced output, otherwise normal fail/no-data).")
