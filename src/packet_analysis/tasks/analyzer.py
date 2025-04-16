from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.services.analyzer.producer import analyze_producer_data
from src.packet_analysis.services.analyzer.playback import analyze_playback_data
from src.packet_analysis.services.analyzer.comparator import compare_producer_playback


@celery_app.task
def analyze_producer(extracted_info, options):
    """分析生产端提取的数据"""
    pair_id = extracted_info["pair_id"]
    analysis_result = analyze_producer_data(extracted_info["extracted_data"], options)

    result = {
        "pair_id": pair_id,
        "side": "producer",
        "analysis": analysis_result
    }

    return result


@celery_app.task
def analyze_playback(extracted_info, options):
    """分析回放端提取的数据"""
    pair_id = extracted_info["pair_id"]
    analysis_result = analyze_playback_data(extracted_info["extracted_data"], options)

    result = {
        "pair_id": pair_id,
        "side": "playback",
        "analysis": analysis_result
    }

    return result


@celery_app.task
def compare_results(pair_id, producer_result, playback_result, options):
    """比较生产和回放的分析结果"""
    comparison = compare_producer_playback(
        producer_data=producer_result["analysis"],
        playback_data=playback_result["analysis"],
        options=options
    )

    result = {
        "pair_id": pair_id,
        "comparison": comparison
    }

    return result