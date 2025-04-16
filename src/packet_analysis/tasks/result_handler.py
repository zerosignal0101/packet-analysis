from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.services.result_manager import merge_analysis_results
from src.packet_analysis.utils.callback import send_callback_request
import json


@celery_app.task
def merge_results(task_id, pair_results):
    """合并所有分析对的结果"""
    # 调用合并服务
    merged_data = merge_analysis_results(pair_results)

    final_result = {
        "task_id": task_id,
        "status": "success",
        "results": merged_data,
        "summary": {
            "total_pairs": len(pair_results),
            "timestamp": int(time.time())
        }
    }

    return final_result


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def send_callback(self, callback_url, result):
    """向请求方发送回调通知"""
    try:
        # 发送回调请求
        response = send_callback_request(callback_url, result)

        if response.status_code not in (200, 201, 202):
            raise Exception(f"Callback failed with status code: {response.status_code}")

        return {
            "status": "callback_sent",
            "response_code": response.status_code
        }

    except Exception as exc:
        # 失败后重试
        raise self.retry(exc=exc)