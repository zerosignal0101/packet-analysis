import os
from celery import group, chain, chord
import redis
import logging
from celery.canvas import Signature
from collections import defaultdict
import time
from datetime import datetime, timedelta
import rootutils
from pathlib import Path

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.tasks.pcap_processor import extract_pcap_info_with_chord, try_remove_chunk
from src.packet_analysis.tasks.analyzer import analyze_producer, analyze_playback, compare_results_chord_callback
from src.packet_analysis.tasks.result_handler import merge_results, send_callback
from src.packet_analysis.config import Config
from src.packet_analysis.utils.cache import get_redis_client, CacheStatus

project_root = rootutils.find_root(search_from=__file__, indicator=".project-root")

# Logging
logger = logging.getLogger(__name__)


@celery_app.task
def process_analysis_request(task_id, pcap_info_list, remote_addr, options):
    logger.info(f'Task {task_id} started')
    """协调整个分析流程的主任务"""
    # Call back url
    default_callback_url = f'http://{remote_addr}:18088/api/replay-core/aglAnalysisResult'
    callback_url = Config.CALLBACK_URL if Config.CALLBACK_URL is not None else default_callback_url
    logger.info(f'Callback URL: {callback_url}')

    # # 创建任务状态跟踪
    # redis_client.hset(f"task:{task_id}", "status", "processing")
    # redis_client.hset(f"task:{task_id}", "total_pairs", str(len(pcap_info_list)))
    # redis_client.hset(f"task:{task_id}", "completed_pairs", "0")

    # 创建任务结果储存文件夹
    task_result_path = Path(project_root, 'results', f'{task_id}')
    # task_result_path.mkdir(parents=True, exist_ok=True)

    pair_tasks = []
    info_options_list = []
    for pcap_info_idx, pcap_info in enumerate(pcap_info_list):
        pair_id = f"{task_id}_{pcap_info_idx}"
        # # Debug
        # if Config.DEBUG:
        #     logger.debug(f"{pair_id}: {pcap_info}")
        #     logger.debug(f"Collect pcap: {pcap_info['collect_pcap']}")
        #     logger.debug(f"Replay pcap: {pcap_info['replay_pcap']}")
        #     logger.debug(f"DEBUG pcap info END")
        # 创建新字典合并原有options和新字段
        pair_options = {
            **options,
            'pcap_info_idx': pcap_info_idx,
            'task_result_path': str(task_result_path),
            'collect_log': pcap_info['collect_log'],
            'replay_log': pcap_info['replay_log'],
            'replay_task_id': pcap_info['replay_task_id']
        }
        pair_task, current_info_options = process_pair_with_chord(
            pair_id=pair_id,
            producer_pcap=pcap_info['collect_pcap'],
            playback_pcap=[pcap_info['replay_pcap']],
            options=pair_options
        )
        if not isinstance(pair_task, Signature):
            logger.debug(f"pair_task failure: {pair_task}")
            send_callback.delay(
                callback_url=callback_url,
                # Pass the final result structure expected by the callback
                result={
                    "task_id": task_id,
                    "status": "Failed to generate workflow",  # Overall status for the callback receiver
                    **pair_task  # Unpack results and summary from merge_results
                }
            )
            logger.info(f"Failure: {pair_task}")
            # 清理 info_options 对应的 pcap 分片和缓存键值
            info_options = merge_info_options(*info_options_list)
            clear_invalid_info_options.delay(info_options=info_options)
            return {"task_id": task_id, "status": "Failed to generate workflow", "ok": False}
        info_options_list.append(current_info_options)
        pair_tasks.append(pair_task)

    # 使用 chord 等待所有对分析完成后合并结果
    callback = chain(merge_results.s(task_id=task_id), send_callback.s(callback_url=callback_url))
    chord(group(pair_tasks), callback).apply_async()

    return {"task_id": task_id, "status": "initiated", "ok": True}


def process_pair_with_chord(pair_id, producer_pcap, playback_pcap, options):
    """处理单对生产/回放分析 (使用 Chord)"""
    # 生产环境提取与分析 Chord
    producer_chord, producer_info_options = create_analysis_chord("producer", pair_id, producer_pcap, options)
    # 生产环境分包处理出错，终止任务链生成，返回错误信息
    if not isinstance(producer_chord, Signature):
        logger.debug(f"Type of producer_chord is {type(producer_chord)}")
        logger.debug(f"Producer chord failure: {producer_chord}")
        return producer_chord, producer_info_options
    # 回放环境提取与分析 Chord
    playback_chord, playback_info_options = create_analysis_chord("playback", pair_id, playback_pcap, options)
    # Info options 列表
    info_options_list = [producer_info_options, playback_info_options]
    # 回放环境分包处理出错，终止任务链生成，返回错误信息
    if not isinstance(playback_chord, Signature):
        logger.debug(f"Type of playback_chord is {type(playback_chord)}")
        logger.debug(f"Playback chord failure: {playback_chord}")
        return playback_chord, merge_info_options(*info_options_list)
    # Chord 的 header 是并行执行的任务组
    header = group(producer_chord, playback_chord)
    # Chord 的 body 是回调任务的签名，它会自动接收 header 中所有任务的结果列表
    compare_options = {
        **options,
        'producer_host_ip_list': producer_info_options['host_ip_list'],
        'playback_host_ip_list': playback_info_options['host_ip_list'],
    }
    callback_task = compare_results_chord_callback.s(pair_id=pair_id, options=compare_options)
    # 创建 Chord 签名
    process_pair_chord = chord(header, callback_task)
    # Debug
    if Config.DEBUG:
        logger.debug(f"Type of process_pair_chord: {type(process_pair_chord)}")

    return process_pair_chord, merge_info_options(*info_options_list)


def create_analysis_chord(side, pair_id, pcap_list, options):
    """创建单侧分析任务链"""
    # 定义任务链: 分割 -> 提取信息 -> 分析
    task_signatures = []
    pcap_chunks = []
    cache_key_list = []
    host_ip_list = []
    for entry in pcap_list:
        if Config.DEBUG:
            logger.debug(f"[Entry in pcap_list]: {entry}")
        ip_address = entry["ip"]
        host_ip_list.append(ip_address)
        port_number = entry["port"]
        file_path = entry["collect_path" if side == "producer" else "replay_path"]
        # Options
        extraction_options = {
            **options,
            'side': side,
            'ip': ip_address,
            'port': port_number,
        }
        # 如果在 playback 环境，额外添加 replay_speed replay_multiplier
        if side == "playback":
            extraction_options.update({
                'replay_speed': entry["replay_speed"],
                'replay_multiplier': entry["replay_multiplier"]
            })
        # Pcap 提取任务组设定
        extract_pcap_info_signature, current_info_options = extract_pcap_info_with_chord(
            pcap_file=file_path,
            pair_id=pair_id,
            side=side,
            options=extraction_options,
        )
        # 若遍历到有问题的数据，返回报错信息到上一级任务链生成函数 process_pair_with_chord
        if not isinstance(extract_pcap_info_signature, Signature):
            # 由于不再执行工作流，返回需要清理的对象到上级函数
            info_options = {
                'pcap_chunks': pcap_chunks,
                'cache_keys': cache_key_list
            }
            return extract_pcap_info_signature, info_options
        # 分片 pcap 列表获取
        pcap_chunks += current_info_options['pcap_chunks']
        # 缓存键值获取
        cache_key = current_info_options.get('cache_key')
        if cache_key is not None:
            cache_key_list.append(cache_key)
        task_signatures.append(extract_pcap_info_signature)

    # 创建提取任务的 group 签名
    extraction_group_signature = group(task_signatures)
    # Options
    analyzer_options = {
        **options,
        'side': side,
        'host_ip_list': host_ip_list,
    }
    # 创建分析任务的签名
    analysis_signature = (
        analyze_producer.s(options=analyzer_options) if side == "producer" else
        analyze_playback.s(options=analyzer_options)
    )
    task_chord = chord(extraction_group_signature, analysis_signature)

    # Info options
    info_options = {
        'side': side,
        'host_ip_list': host_ip_list,
        'pcap_chunks': pcap_chunks,
        'cache_keys': cache_key_list
    }

    return task_chord, info_options


@celery_app.task
def cleanup_expired_cache():
    """
    清理过期的缓存项（由 Celery Beat 定期调度）。
    此实现依赖 Parquet 文件的最后修改时间来判断过期。
    注意：文件修改时间可能不完全等于缓存创建时间。
    更健壮的方法是在创建缓存时将时间戳存储在 Redis 中。
    """
    logger.info("Starting expired cache cleanup task...")
    redis_client = get_redis_client()
    # --- Caching Logic (similar to before) ---
    if not redis_client or not redis_client._initialized:
        logger.error("Redis client is not available. Cannot proceed with caching.")
        return None
    now = time.time()
    expiration_threshold = now - timedelta(days=Config.CACHE_TTL_DAYS).total_seconds()
    expiration_dt_str = datetime.fromtimestamp(expiration_threshold).strftime('%Y-%m-%d %H:%M:%S')
    logger.info(f"Cleaning up cache entries older than {Config.CACHE_TTL_DAYS} days (modified before {expiration_dt_str}).")
    keys_to_delete_redis = []
    files_deleted_count = 0
    keys_deleted_count = 0
    errors_count = 0
    try:
        # 使用 scan_iter 避免阻塞 Redis
        # 匹配 pcap_info:<hash> 格式的键
        for pcap_info_key in redis_client.redis.scan_iter(match="pcap_info:*"):
            try:
                file_path = redis_client.redis.get(pcap_info_key)
                if not file_path:
                    logger.warning(f"Key '{pcap_info_key}' exists but has no value. Adding to delete list.")
                    keys_to_delete_redis.append(pcap_info_key)
                    continue
                logger.debug(f"Checking key '{pcap_info_key}', file path: '{file_path}'")
                if not os.path.exists(file_path):
                    logger.warning(f"File '{file_path}' for key '{pcap_info_key}' does not exist. Scheduling Redis keys for deletion.")
                    keys_to_delete_redis.append(pcap_info_key)
                    status_key = pcap_info_key.replace("pcap_info:", "status:pcap_info:", 1)
                    if status_key != pcap_info_key:
                        keys_to_delete_redis.append(status_key)
                    continue
                # 获取文件最后修改时间
                file_mtime = os.path.getmtime(file_path)
                if file_mtime < expiration_threshold:
                    logger.info(f"Expired: Key '{pcap_info_key}', File '{file_path}' (mtime: {datetime.fromtimestamp(file_mtime).strftime('%Y-%m-%d %H:%M:%S')}). Deleting.")
                    # 1. 删除文件
                    try:
                        os.remove(file_path)
                        logger.info(f"Successfully deleted file: {file_path}")
                        files_deleted_count += 1
                        # 2. 文件删除成功后，准备删除 Redis 键
                        keys_to_delete_redis.append(pcap_info_key)
                    except FileNotFoundError:
                        logger.warning(f"File '{file_path}' was already gone before deletion attempt. Scheduling Redis keys for deletion.")
                        # 文件已不在，仍然清理 Redis 键
                        keys_to_delete_redis.append(pcap_info_key)
                    except OSError as e:
                        logger.error(f"Error deleting file '{file_path}': {e}. Skipping Redis key deletion for this entry.")
                        errors_count += 1
                else:
                    logger.debug(f"Not expired: Key '{pcap_info_key}', File '{file_path}' (mtime: {datetime.fromtimestamp(file_mtime).strftime('%Y-%m-%d %H:%M:%S')})")
            except Exception as e:
                logger.error(f"Error processing key '{pcap_info_key}': {e}")
                errors_count += 1
        # 批量删除 Redis 键
        if keys_to_delete_redis:
            # 去重，以防 status key 和 pcap_info key 因为某种原因重复添加
            unique_keys_to_delete = list(set(keys_to_delete_redis))
            logger.info(f"Attempting to delete {len(unique_keys_to_delete)} Redis keys: {unique_keys_to_delete}")
            try:
                deleted_count = 0
                for cache_key in unique_keys_to_delete:
                    redis_client.delete_cache(cache_key)
                    redis_client.delete_cache_status(cache_key)
                    deleted_count += 1
                keys_deleted_count = deleted_count
                logger.info(f"Successfully deleted {deleted_count} Redis keys.")
            except redis.RedisError as e:
                logger.error(f"Error deleting Redis keys: {e}")
                errors_count += len(unique_keys_to_delete) # 算作错误，因为未成功删除
    except redis.RedisError as e:
        logger.error(f"Redis connection error during scan: {e}")
        errors_count += 1
    except Exception as e:
        logger.error(f"An unexpected error occurred during cleanup: {e}")
        errors_count += 1
    logger.info(f"Cache cleanup task finished. Files deleted: {files_deleted_count}. Redis keys deleted: {keys_deleted_count}. Errors encountered: {errors_count}.")


@celery_app.task
def clear_invalid_info_options(info_options):
    # 获取 "pcap_chunks" 列表，移除未处理的 chunk
    pcap_chunks = info_options.get("pcap_chunks", [])
    for chunk in pcap_chunks:
        try_remove_chunk(chunk)
    # 获取 "cache_keys" 列表，根据 cache_key 情况移除或保留缓存记录
    cache_keys = info_options.get("cache_keys", [])
    redis_client = get_redis_client()
    if not redis_client or not redis_client._initialized:
        logger.warning(f"Redis not available for caching in clear_invalid_info_options.")
    for cache_key in cache_keys:
        if redis_client.check_status_exist(cache_key):
            cache_status = redis_client.get_cache_status(cache_key)
            if cache_status == CacheStatus.CACHE_PENDING:
                redis_client.set_cache_status(cache_key, CacheStatus.CACHE_MISSING)
            elif cache_status == CacheStatus.CACHE_READY:
                logger.info("Cache already ready. No need to clear this cache.")
            else:
                logger.info("Cache missing. Pass this cache.")


def merge_info_options(*info_options_list):
    merged = defaultdict(list)
    for info_options in info_options_list:
        for key in ["pcap_chunks", "cache_keys"]:
            if key in info_options:
                merged[key].extend(info_options[key])
        # 处理其他键（非列表合并）
        for key in info_options:
            if key not in ["pcap_chunks", "cache_keys"]:
                merged[key] = info_options[key]
    return dict(merged)
