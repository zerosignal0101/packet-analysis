import logging
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# 定义日志文件夹和文件路径
LOG_FOLDER = "/app/logs"
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)
LOG_FILE_CELERY = os.path.join(LOG_FOLDER, "celery.log")

# 定义日志格式
FILE_LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s - %(name)s - [%(filename)s:%(lineno)d]"
CONSOLE_LOG_FORMAT = "[%(asctime)s: %(levelname)s/%(processName)s] %(message)s"

# 获取 Celery 的根日志记录器
celery_logger = logging.getLogger('celery')
celery_logger.setLevel(logging.DEBUG)  # 设置日志级别

# 创建按时间轮转的文件处理器（可选）
timed_file_handler = TimedRotatingFileHandler(
    LOG_FILE_CELERY,
    when="midnight",  # 每天轮转一次
    interval=1,
    backupCount=7,  # 保留 7 天的日志
    encoding="utf-8",
)
timed_file_handler.setLevel(logging.DEBUG)
file_formatter = logging.Formatter(FILE_LOG_FORMAT)
timed_file_handler.setFormatter(file_formatter)
celery_logger.addHandler(timed_file_handler)

# 创建控制台处理器（可选）
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # 控制台日志级别
console_formatter = logging.Formatter(CONSOLE_LOG_FORMAT)
console_handler.setFormatter(console_formatter)
celery_logger.addHandler(console_handler)

# 获取日志记录器
logger = celery_logger

# 测试日志
if __name__ == "__main__":
    logger.debug("This is a debug message.")
    logger.info("This is an info message.")
    logger.warning("This is a warning message.")
    logger.error("This is an error message.")
    logger.critical("This is a critical message.")
