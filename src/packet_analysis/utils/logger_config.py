import logging
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import rootutils

# 查找项目根目录
path = rootutils.find_root(search_from=__file__, indicator=".project-root")

# 定义日志文件夹和文件路径
LOG_FOLDER = os.path.join(path, "results/logs")
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

# 为Celery和Flask分别定义日志文件路径
CELERY_LOG_FILE = os.path.join(LOG_FOLDER, "celery.log")
FLASK_LOG_FILE = os.path.join(LOG_FOLDER, "flask.log")

# 定义日志格式
FILE_LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s - %(name)s - [%(filename)s:%(lineno)d]"
CONSOLE_LOG_FORMAT = "[%(asctime)s: %(levelname)s/%(processName)s] %(message)s"


def setup_logger(name, log_file, level=logging.DEBUG):
    """创建并配置一个日志记录器"""
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # 确保不重复添加处理器
    if logger.handlers:
        return logger

    # 创建文件处理器（按时间轮转）
    file_handler = TimedRotatingFileHandler(
        log_file,
        when="midnight",
        interval=1,
        backupCount=7,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_formatter = logging.Formatter(FILE_LOG_FORMAT)
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)

    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter(CONSOLE_LOG_FORMAT)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    return logger


# 为Celery和Flask分别创建日志记录器
celery_logger = setup_logger('celery', CELERY_LOG_FILE)
flask_logger = setup_logger('flask', FLASK_LOG_FILE)

# 测试日志
if __name__ == "__main__":
    # 测试Celery日志
    celery_logger.debug("This is a Celery debug message.")
    celery_logger.info("This is a Celery info message.")
    celery_logger.warning("This is a Celery warning message.")

    # 测试Flask日志
    flask_logger.debug("This is a Flask debug message.")
    flask_logger.info("This is a Flask info message.")
    flask_logger.error("This is a Flask error message.")
