from celery import group, chain, chord
import redis
import logging

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.tasks.pcap_processor import extract_pcap_info_with_chord
from src.packet_analysis.tasks.analyzer import analyze_producer, analyze_playback, compare_results_chord_callback
from src.packet_analysis.tasks.result_handler import merge_results, send_callback
from src.packet_analysis.config import Config

logger = logging.getLogger(__name__)

# Redis 连接
redis_client = redis.Redis.from_url(Config.CELERY_RESULT_BACKEND)


@celery_app.task
def process_analysis_request(task_id, pcap_info_list, remote_addr, options):
    logger.info(f'Task {task_id} started')
    """协调整个分析流程的主任务"""
    # Call back url
    default_callback_url = f'http://{remote_addr}:18088/api/replay-core/aglAnalysisResult'
    callback_url = Config.CALLBACK_URL if Config.CALLBACK_URL is not None else default_callback_url
    logger.info(f'Callback URL: {callback_url}')

    # 创建任务状态跟踪
    redis_client.hset(f"task:{task_id}", "status", "processing")
    redis_client.hset(f"task:{task_id}", "total_pairs", str(len(pcap_info_list)))
    redis_client.hset(f"task:{task_id}", "completed_pairs", "0")

    pair_tasks = []
    for pcap_info_idx, pcap_info in enumerate(pcap_info_list):
        pair_id = f"{task_id}_{pcap_info_idx}"
        # Debug
        if Config.DEBUG:
            logger.debug(f"{pair_id}: {pcap_info}")
            logger.debug(f"Collect pcap: {pcap_info['collect_pcap']}")
            logger.debug(f"Replay pcap: {pcap_info['replay_pcap']}")
            logger.debug(f"DEBUG pcap info END")
        # 创建新字典合并原有options和新字段
        pair_options = {
            **options,
            'collect_log': pcap_info['collect_log'],
            'replay_log': pcap_info['replay_log'],
            'replay_task_id': pcap_info['replay_task_id']
        }
        pair_task = process_pair_with_chord(
            pair_id=pair_id,
            producer_pcap=pcap_info['collect_pcap'],
            playback_pcap=[pcap_info['replay_pcap']],
            options=pair_options
        )
        # if isinstance(pair_task, dict):
        #     logger.debug(f"pair_task failure: {pair_task}")
        #     send_callback.delay(
        #         callback_url=callback_url,
        #         # Pass the final result structure expected by the callback
        #         result={
        #             "task_id": task_id,
        #             "status": "Failed to generate workflow",  # Overall status for the callback receiver
        #             **pair_task  # Unpack results and summary from merge_results
        #         }
        #     )
        #     logger.info(f"Failure: {pair_task}")
        #     return {"task_id": task_id, "status": "Failed to generate workflow", "ok": False}
        pair_tasks.append(pair_task)

    # 使用 chord 等待所有对分析完成后合并结果
    callback = chain(merge_results.s(task_id=task_id), send_callback.s(callback_url=callback_url))
    chord(group(pair_tasks), callback).apply_async()

    return {"task_id": task_id, "status": "initiated", "ok": True}


def process_pair_with_chord(pair_id, producer_pcap, playback_pcap, options):
    """处理单对生产/回放分析 (使用 Chord)"""
    producer_chain = create_analysis_chord("producer", pair_id, producer_pcap, options)
    playback_chain = create_analysis_chord("playback", pair_id, playback_pcap, options)
    # # 检查数据是否为报错数据
    # if isinstance(producer_chain, dict):
    #     logger.debug(f"Type of producer_chain is {type(producer_chain)}")
    #     logger.debug(f"producer chain failure: {producer_chain}")
    #     return producer_chain
    # if isinstance(playback_chain, dict):
    #     logger.debug(f"Type of playback chain is {type(playback_chain)}")
    #     logger.debug(f"playback chain failure: {playback_chain}")
    #     return playback_chain
    # Chord 的 header 是并行执行的任务组 (这里是两个 chain)
    header = group(producer_chain, playback_chain)
    # Chord 的 body 是回调任务的签名，它会自动接收 header 中所有任务的结果列表
    # 注意：compare_results_chord_callback 需要能处理结果列表
    callback_task = compare_results_chord_callback.s(pair_id=pair_id, options=options)
    # 创建并执行 Chord
    # Chord 执行后，process_pair_with_chord 任务会立即完成，不阻塞 worker
    process_pair_chord = chord(header, callback_task)
    if Config.DEBUG:
        logger.debug(f"Type of process_pair_chord: {type(process_pair_chord)}")
    return process_pair_chord


def create_analysis_chord(side, pair_id, pcap_list, options):
    """创建单侧分析任务链"""
    # 定义任务链: 分割 -> 提取信息 -> 分析
    task_signatures = []
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
        extract_pcap_info_signature = extract_pcap_info_with_chord(
            pcap_file=file_path,
            pair_id=pair_id,
            side=side,
            options=extraction_options,
            use_cache=False
        )
        # # 若遍历到有问题的数据，返回报错信息到上一级任务链生成函数 process_pair_with_chord
        # if isinstance(extract_pcap_info_signature, dict):
        #     return extract_pcap_info_signature
        task_signatures.append(extract_pcap_info_signature)

    # 创建提取任务的 group 签名
    extraction_group_signature = group(task_signatures)
    # 创建分析任务的签名
    analysis_signature = (
        analyze_producer.s(options=options) if side == "producer" else
        analyze_playback.s(options=options)
    )
    task_chord = chord(extraction_group_signature, analysis_signature)

    return task_chord


@celery_app.task
def cleanup_expired_cache():
    """清理过期的缓存项（由 Celery Beat 定期调度）"""
    # 此处实现清理过期缓存的逻辑
    pass
