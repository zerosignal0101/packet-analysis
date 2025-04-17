import os
from celery import group, chain, chord

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.services.pcap_splitter import split_pcap_file
# from src.packet_analysis.services.pcap_extractor import extract_info_from_pcap
from src.packet_analysis.utils.cache import RedisClient, with_file_lock, get_file_hash

cache_redis = RedisClient()


@celery_app.task
@with_file_lock(lambda pcap_files: [get_file_hash(f) for f in pcap_files if os.path.exists(f)])
def extract_pcap_info(pcap_file, pair_id, side, use_cache=True):
    # 若使用缓存，检查缓存是否存在
    if use_cache:
        file_hash = get_file_hash(pcap_file)
        cache_key = f"pcap_info:{file_hash}"
        if cache_redis.exists(cache_key):
            return cache_redis.get_cache(cache_key)

    # 没有缓存情况下，进行分割和多任务提取
    pcap_chunks = split_pcap_file(pcap_file, 100000)

    # 多任务组
    task_group = []
    for chunk in pcap_chunks:
        task_group.append(extract_pcap_info_executor.s(chunk))

    results = group(task_group).apply_async().get()

    return results


@celery_app.task
def extract_pcap_info_executor(pcap_file: str):
    # TODO: Fix extract_pcap_info_executor
    return f"{pcap_file} executor\n"
    pass
