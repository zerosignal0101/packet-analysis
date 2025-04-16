from flask import Blueprint, request, jsonify
from src.packet_analysis.tasks.coordinator import process_analysis_request
from src.packet_analysis.model.pcap_models import AnalysisRequest
import uuid

api_bp = Blueprint('api', __name__)


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
        data_dict = request_data.dict()

        # Start async processing task
        process_analysis_request.delay(
            task_id=task_id,
            pcap_info=data_dict['pcap_info'],
            collect_log=data_dict['collect_log'],
            replay_log=data_dict['replay_log'],
            replay_id=data_dict['replay_id'],
            replay_speed=data_dict['replay_speed'],
            replay_multiplier=data_dict['replay_multiplier']
        )

        return jsonify({
            'task_id': task_id,
            'status': 'queued',
            'message': 'Request received'
        }), 202

    except Exception as e:
        return jsonify({'error': str(e)}), 500
