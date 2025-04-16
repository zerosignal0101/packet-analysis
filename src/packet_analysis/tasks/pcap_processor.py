import os
import hashlib

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.services.pcap_splitter import split_pcap_file
from src.packet_analysis.services.pcap_extractor import extract_info_from_pcap
from src.packet_analysis.utils.cache import check_cache, get_cache, set_cache


@celery_app.task
def split_pcap(pcap_files, max_size, use_cache=True):
    """将单个或多个 PCAP 文件分割成小块"""
    if isinstance(pcap_files, str):
        pcap_files = [pcap_files]

    result = {}
    for pcap_file in pcap_files:
        if not os.path.exists(pcap_file):
            continue

        file_hash = get_file_hash(pcap_file)

        if use_cache:
            cache_key = f"pcap_info:{file_hash}"
            # 尝试从缓存获取
            check_result = check_cache(cache_key)
            if check_result:
                result[file_hash] = None
                continue

        chunk_files = split_pcap_file(pcap_file, max_size)
        result[file_hash] = chunk_files

    return result


@celery_app.task
def extract_pcap_info(pcap_dicts: dict, pair_id, side, use_cache=True):
    """从 PCAP 文件中提取信息，并使用缓存避免重复提取"""
    extracted_data = []

    for file_hash, chunk_files in pcap_dicts:
        if use_cache and (chunk_files is None):
            cache_key = f"pcap_info:{file_hash}"
            extracted_data.append(get_cache(cache_key))
        else:
            for chunk_file in chunk_files:
                # 缓存未命中，执行提取
                chunk_info = extract_info_from_pcap(chunk_file)
                extracted_data.append(chunk_info)

            # 将结果存入缓存
            if use_cache:
                cache_key = f"pcap_info:{file_hash}"
                set_cache(cache_key, extracted_data, expire=86400)  # 24小时过期

    # 合并所有块的结果
    merged_info = {
        "pair_id": pair_id,
        "side": side,
        "packets_count": sum(r.get("packets_count", 0) for r in extracted_data),
        "extracted_data": [item for result in extracted_data for item in result.get("extracted_data", [])]
    }

    return merged_info


def get_file_hash(file_path):
    """计算文件内容的 MD5 哈希值作为缓存键"""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()