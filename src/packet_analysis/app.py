# app.py

from flask import Flask

# Project imports
from src.packet_analysis.api.routes import api_bp
from src.packet_analysis.config import Config
from src.packet_analysis.utils.logger_config import flask_logger


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

    # 替换Flask的核心日志记录器
    app.logger.handlers = flask_logger.handlers
    app.logger.setLevel(flask_logger.level)
    app.logger.propagate = flask_logger.propagate

    # 注册蓝图
    app.register_blueprint(api_bp, url_prefix='/api')

    return app
