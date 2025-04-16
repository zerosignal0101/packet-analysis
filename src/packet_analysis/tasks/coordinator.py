from celery import group, chain, chord
import redis
import json

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.tasks.pcap_processor import extract_pcap_info
from src.packet_analysis.tasks.analyzer import analyze_producer, analyze_playback, compare_results
from src.packet_analysis.tasks.result_handler import merge_results, send_callback
from src.packet_analysis.config import Config

# Redis 连接
redis_client = redis.Redis.from_url(Config.CELERY_RESULT_BACKEND)


@celery_app.task
def process_analysis_request(task_id, pcap_files, pairs, callback_url, options):
    """协调整个分析流程的主任务"""
    # 创建任务状态跟踪
    redis_client.hset(f"task:{task_id}", "status", "processing")
    redis_client.hset(f"task:{task_id}", "total_pairs", str(len(pairs)))
    redis_client.hset(f"task:{task_id}", "completed_pairs", "0")

    # 针对每一对创建子任务
    pair_tasks = []
    for pair_idx, pair in enumerate(pairs):
        pair_id = f"{task_id}_{pair_idx}"
        pair_task = process_pair.s(
            pair_id=pair_id,
            producer_pcap=pcap_files[pair['producer_idx']],
            playback_pcap=pcap_files[pair['playback_idx']],
            options=options
        )
        pair_tasks.append(pair_task)

    # 使用 chord 等待所有对分析完成后合并结果
    callback = merge_and_send_results.s(task_id=task_id, callback_url=callback_url)
    chord(group(pair_tasks), callback).apply_async()

    return {"task_id": task_id, "status": "initiated"}


@celery_app.task
def process_pair(pair_id, producer_pcap, playback_pcap, options):
    """处理单对生产/回放分析"""
    # 并行处理生产和回放的 PCAP
    producer_chain = create_analysis_chain("producer", pair_id, producer_pcap, options)
    playback_chain = create_analysis_chain("playback", pair_id, playback_pcap, options)

    # 等待两边都完成后执行对比分析
    producer_result, playback_result = group([producer_chain, playback_chain]).apply_async().get()

    # 执行对比分析
    comparison_result = compare_results.delay(
        pair_id=pair_id,
        producer_result=producer_result,
        playback_result=playback_result,
        options=options
    ).get()

    return {
        "pair_id": pair_id,
        "producer_result": producer_result,
        "playback_result": playback_result,
        "comparison_result": comparison_result
    }


def create_analysis_chain(side, pair_id, pcap_files, options):
    """创建单侧分析任务链"""
    # 定义任务链: 分割 -> 提取信息 -> 分析
    task_group = []
    for pcap_file in pcap_files:
        task_group.append(extract_pcap_info.s(
            pcap_file=pcap_file,
            pair_id=pair_id,
            side=side,
            options=options
        ))

    # 分析提取的信息
    task_chain = chain(
        group(task_group),
        analyze_producer.s(options=options) if side == "producer" else
        analyze_playback.s(options=options)
    )

    return task_chain


@celery_app.task
def merge_and_send_results(pair_results, task_id, callback_url):
    """合并所有分析结果并发送回调"""
    # 合并结果
    merged_result = merge_results.delay(
        task_id=task_id,
        pair_results=pair_results
    ).get()

    # 更新任务状态
    redis_client.hset(f"task:{task_id}", "status", "completed")

    # 发送回调
    send_callback.delay(
        callback_url=callback_url,
        result=merged_result
    )

    return {"task_id": task_id, "status": "completed"}


@celery_app.task
def cleanup_expired_cache():
    """清理过期的缓存项（由 Celery Beat 定期调度）"""
    # 此处实现清理过期缓存的逻辑
    pass
