from typing import List, Dict, Any

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.services.analyzer.producer import analyze_producer_data
from src.packet_analysis.services.analyzer.playback import analyze_playback_data
from src.packet_analysis.services.analyzer.comparator import compare_producer_playback


@celery_app.task
def analyze_producer(results: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
    """分析生产端提取的数据"""
    res = analyze_producer_data(
        results,
        options
    )

    return {
        "side": options["side"],
        "parquet_file_path": res["parquet_file_path"],
        "general_analysis_result": res["general_analysis_result"],
    }


@celery_app.task
def analyze_playback(results: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
    """分析回放端提取的数据"""
    res = analyze_playback_data(
        results,
        options
    )

    result = {
        "side": "playback",
        "parquet_file_path": res["parquet_file_path"],
        "general_analysis_result": res["general_analysis_result"],
    }

    return result


@celery_app.task
def compare_results_chord_callback(results, pair_id, options):
    """比较生产和回放的分析结果"""
    producer_result = results[0]
    playback_result = results[1]
    comparison = compare_producer_playback(
        producer_data=producer_result,
        playback_data=playback_result,
        options=options
    )

    result = {
        "pair_id": pair_id,
        "comparison": comparison
    }

    return result
