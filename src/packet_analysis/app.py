# app.py

from flask import Flask

# Project imports
from src.packet_analysis.celery_app import celery_app
from src.packet_analysis.api.routes import api_bp
from src.packet_analysis.config import Config


def create_app():
    """应用工厂函数"""
    app = Flask(__name__)

    # 从 Config 类加载配置
    app.config.update(
        SECRET_KEY=Config.SECRET_KEY,
        DEBUG=Config.DEBUG,
        CELERY_BROKER_URL=Config.CELERY_BROKER_URL,
        CELERY_RESULT_BACKEND=Config.CELERY_RESULT_BACKEND
    )

    # 注册蓝图
    app.register_blueprint(api_bp, url_prefix='/api')

    return app, celery_app
