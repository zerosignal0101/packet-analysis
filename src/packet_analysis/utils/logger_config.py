import logging
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler

# 日志文件夹路径
LOG_FOLDER = "results/logs"
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

# 日志文件名
LOG_FILE = os.path.join(LOG_FOLDER, "run.log")

# 日志格式（文件日志用）
FILE_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s - [%(filename)s:%(lineno)d]"

# 日志格式（控制台日志用，更简洁）
CONSOLE_LOG_FORMAT = "%(levelname)s: %(message)s"


# 配置日志
def setup_logger():
    # 创建根日志记录器
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)  # 设置日志级别

    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)  # 控制台日志级别
    console_formatter = logging.Formatter(CONSOLE_LOG_FORMAT)
    console_handler.setFormatter(console_formatter)

    # 创建文件处理器（按文件大小轮转）
    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=10 * 1024 * 1024,  # 最大文件大小（10MB）
        backupCount=5,  # 保留的备份文件数量
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)  # 文件日志级别
    file_formatter = logging.Formatter(FILE_LOG_FORMAT)
    file_handler.setFormatter(file_formatter)

    # 创建按时间轮转的文件处理器（可选）
    timed_file_handler = TimedRotatingFileHandler(
        LOG_FILE,
        when="midnight",  # 每天轮转一次
        interval=1,
        backupCount=7,  # 保留 7 天的日志
        encoding="utf-8",
    )
    timed_file_handler.setLevel(logging.DEBUG)
    timed_file_handler.setFormatter(file_formatter)

    # 将处理器添加到日志记录器
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    # logger.addHandler(timed_file_handler)


# 初始化日志配置
setup_logger()

# 获取日志记录器
logger = logging.getLogger(__name__)

# 测试日志
if __name__ == "__main__":
    logger.debug("This is a debug message.")
    logger.info("This is an info message.")
    logger.warning("This is a warning message.")
    logger.error("This is an error message.")
    logger.critical("This is a critical message.")
