# app.py

from flask import Flask

# Project imports
from src.packet_analysis.api.routes import api_bp
from src.packet_analysis.config import Config
from src.packet_analysis.utils.logger_config import setup_flask_logging


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

    # --- Setup Logging ---
    # Configure logging *after* config is loaded but *before* blueprints/routes
    # that might log during setup.
    # Only configure logging if not in testing mode or if specifically desired
    if not app.testing:
        setup_flask_logging(app)
    # --- End Setup Logging ---

    # 注册蓝图
    app.register_blueprint(api_bp, url_prefix='/api/algorithm')

    # Example log message after setup
    app.logger.debug("create_app function finished.")

    return app
