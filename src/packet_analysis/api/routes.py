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

        # Options
        keys = ['replay_id', 'replay_speed', 'replay_multiplier']
        options = {key: data_dict[key] for key in keys}

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
