import json
import time
import logging

# Project imports
from src.packet_analysis.celery_app.celery import celery_app
from src.packet_analysis.services.result_manager import merge_analysis_results
from src.packet_analysis.utils.callback import send_callback_request

# Logger
logger = logging.getLogger(__name__)


@celery_app.task
def merge_results(pair_results, options):
    """合并所有分析对的结果"""
    # 调用合并服务
    merged_data = merge_analysis_results(pair_results, options)

    task_id = options.get('task_id')

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
def send_callback(self, result, callback_url):
    """
    Sends the final result back to the requesting service via callback URL.
    Retries on failure.
    """
    logger.info(
        f"[send_callback] Task ID (from result): {result.get('task_id', 'N/A')}: Attempting callback to {callback_url}")
    try:
        # Make the actual HTTP request
        response = send_callback_request(callback_url, result)  # Pass the full result dictionary
        if response.status_code not in (200, 201, 202):
            # Log specific error before raising for retry
            error_msg = f"Callback failed for task {result.get('task_id', 'N/A')} to {callback_url}. Status code: {response.status_code}"
            logger.error(error_msg)
            # Raise an exception to trigger Celery's retry mechanism
            raise Exception(error_msg)
        logger.info(
            f"[send_callback] Task ID {result.get('task_id', 'N/A')}: Callback successful (Status: {response.status_code}).")
        # Optional: Update Redis status to 'callback_sent' or 'finished' here if needed,
        # but be aware this task might run on a different worker without direct redis_client access
        # unless configured globally or passed explicitly.
        return {
            "task_id": result.get('task_id'),
            "status": "callback_sent",
            "response_code": response.status_code
        }
    except Exception as exc:
        logger.error(
            f"[send_callback] Task ID {result.get('task_id', 'N/A')}: Callback attempt {self.request.retries + 1} failed: {exc}. Retrying...")
        # Celery's retry mechanism
        raise self.retry(exc=exc)
