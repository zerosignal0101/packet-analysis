from celery import group, chain, chord
import redis
import logging
from celery.canvas import Signature
from collections import defaultdict

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.tasks.pcap_processor import extract_pcap_info_with_chord, try_remove_chunk
from src.packet_analysis.tasks.analyzer import analyze_producer, analyze_playback, compare_results_chord_callback
from src.packet_analysis.tasks.result_handler import merge_results, send_callback
from src.packet_analysis.config import Config
from src.packet_analysis.utils.cache import get_redis_client, CacheStatus

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
    callback_task = compare_results_chord_callback.s(pair_id=pair_id, options=options)
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
    for entry in pcap_list:
        if Config.DEBUG:
            logger.debug(f"[Entry in pcap_list]: {entry}")
        ip_address = entry["ip"]
        port_number = entry["port"]
        file_path = entry["collect_path" if side == "producer" else "replay_path"]
        # Options
        extraction_options = {
            **options,
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
    # 创建分析任务的签名
    analysis_signature = (
        analyze_producer.s(options=options) if side == "producer" else
        analyze_playback.s(options=options)
    )
    task_chord = chord(extraction_group_signature, analysis_signature)

    # Info options
    info_options = {
        'pcap_chunks': pcap_chunks,
        'cache_keys': cache_key_list
    }

    return task_chord, info_options


@celery_app.task
def cleanup_expired_cache():
    """清理过期的缓存项（由 Celery Beat 定期调度）"""
    # 此处实现清理过期缓存的逻辑
    pass

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
                logger.error("Cache duplicated. Severe error message.")
                pass
            else:
                logger.error("Cache workflow already exist. Severe error message.")


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
