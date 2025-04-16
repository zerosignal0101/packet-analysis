import os
import hashlib

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.services.pcap_splitter import split_pcap_file
from src.packet_analysis.services.pcap_extractor import extract_info_from_pcap
from src.packet_analysis.utils.cache import get_cache, set_cache


@celery_app.task
def split_pcap(pcap_files, max_size):
    """将单个或多个 PCAP 文件分割成小块

    Args:
        pcap_files: 单个 PCAP 文件路径或路径列表
        max_size: 每个分割文件包含的最大包数量

    Returns:
        dict: 键为输入文件名，值为对应的分割文件列表
    """
    if isinstance(pcap_files, str):
        pcap_files = [pcap_files]

    result = {}
    for pcap_file in pcap_files:
        if not os.path.exists(pcap_file):
            continue

        chunk_files = split_pcap_file(pcap_file, max_size)
        result[pcap_file] = chunk_files

    return result


@celery_app.task
def extract_pcap_info(chunk_files, pair_id, side, use_cache=True):
    """从 PCAP 文件中提取信息，并使用缓存避免重复提取"""
    results = []

    for chunk_file in chunk_files:
        # 生成缓存键（基于文件内容的哈希）
        if use_cache:
            file_hash = get_file_hash(chunk_file)
            cache_key = f"pcap_info:{file_hash}"

            # 尝试从缓存获取
            cached_result = get_cache(cache_key)
            if cached_result:
                results.append(cached_result)
                continue

        # 缓存未命中，执行提取
        chunk_info = extract_info_from_pcap(chunk_file)
        results.append(chunk_info)

        # 将结果存入缓存
        if use_cache:
            set_cache(cache_key, chunk_info, expire=86400)  # 24小时过期

    # 合并所有块的结果
    merged_info = {
        "pair_id": pair_id,
        "side": side,
        "packets_count": sum(r.get("packets_count", 0) for r in results),
        "extracted_data": [item for result in results for item in result.get("extracted_data", [])]
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