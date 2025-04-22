import json
import os
from pathlib import Path
from flask import Blueprint, request, jsonify
from src.packet_analysis.tasks.coordinator import process_analysis_request
from src.packet_analysis.model.pcap_models import AnalysisRequest
import uuid
import rootutils
import logging

api_bp = Blueprint('api', __name__)

project_root = rootutils.find_root(search_from=__file__, indicator=".project-root")

# Logger
logger = logging.getLogger(__name__)


@api_bp.route('/analyze', methods=['POST'])
def submit_analysis():
    """接收分析请求并创建Celery任务"""
    try:
        # Validate request data using Pydantic model
        try:
            request_data = AnalysisRequest(**request.json)
        except Exception as e:
            return jsonify({'error': f'Invalid request data: {str(e)}'}), 400

        # Create unique task ID
        task_id = str(uuid.uuid4())

        # Convert Pydantic model to dict for Celery
        data_dict = request_data.model_dump()
        task_result_path = Path(project_root, 'results', f'{task_id}')
        try:
            response_json_path = os.path.join(task_result_path, 'request.json')
            task_result_path.mkdir(parents=True, exist_ok=True)
            with open(response_json_path, "w", encoding="utf-8") as file:
                json.dump(data_dict, file, ensure_ascii=False, indent=4)
            logger.info(f"Request successfully saved to {response_json_path}")
        except Exception as e:
            logger.warning(f"Failed to save request: {e}")

        # Options
        keys = ['replay_id', 'replay_speed', 'replay_multiplier']
        options = {key: data_dict[key] for key in keys}
        options.update({
            'task_id': task_id,
            'task_result_path': str(task_result_path),
        })

        # Start async processing task
        process_analysis_request.delay(
            task_id=task_id,
            pcap_info_list=data_dict['pcap_info'],
            remote_addr=request.remote_addr,
            options=options
        )

        return jsonify({
            'task_id': task_id,
            'status': 'queued',
            'message': 'Request received'
        }), 202

    except Exception as e:
        return jsonify({'error': str(e)}), 500
