import logging
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import rootutils

# Project imports
from src.packet_analysis.config import Config


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
FILE_LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s - %(name)s - [%(filename)s:%(lineno)d/%(processName)s]"
CONSOLE_LOG_FORMAT = "[%(asctime)s: %(levelname)s/%(processName)s] %(message)s"

# 日志记录等级
LOG_LEVEL = 'DEBUG' if Config.DEBUG else Config.LOG_LEVEL

# --- Define Logging Configuration Dictionary ---
CELERY_LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,  # Important: Keep Celery's default loggers
    'formatters': {
        'default': {
            'format': '[%(asctime)s: %(levelname)s/%(processName)s] %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'task': {
            'format': '[%(asctime)s: %(levelname)s/%(processName)s][%(task_name)s(%(task_id)s)] %(message)s',
            'datefmt': '%Y-%m-%d %H:%M:%S',
        },
        'console_formatter': {
            'format': CONSOLE_LOG_FORMAT,
            'datefmt': '%Y-%m-%d %H:%M:%S',
        }
    },
    'handlers': {
        'celery_file': {
            'level': LOG_LEVEL,  # Log level for this handler
            'class': 'logging.handlers.RotatingFileHandler',  # Use rotating file handler
            'filename': CELERY_LOG_FILE,
            'maxBytes': 1024 * 1024 * 100,  # 100 MB log file size
            'backupCount': 5,  # Keep 5 backup logs
            'formatter': 'default',  # Use 'default' formatter for general logs
            'encoding': 'utf-8',
        },
        'celery_task_file': {  # You could use the same handler as above if format is the same
            # Or define a separate one if needed (e.g., different file/format)
            'level': LOG_LEVEL,
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': CELERY_LOG_FILE,  # Log tasks to the SAME file
            'maxBytes': 1024 * 1024 * 100,
            'backupCount': 5,
            'formatter': 'task',  # Use specific 'task' formatter for task logs
            'encoding': 'utf-8',
        },
        'console': {  # Optional: Keep logging to console as well
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'console_formatter',
        },
    },
    'loggers': {
        'celery': {  # Logger for base Celery messages
            'handlers': ['celery_file', 'console'],  # Send to file and console
            'level': LOG_LEVEL,
            'propagate': False,  # Do not pass messages up to the root logger
        },
        'celery.task': {  # Logger for task-related messages
            'handlers': ['celery_task_file', 'console'],  # Use the task handler/formatter
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'celery.beat': {  # Logger for Celery Beat
            'handlers': ['celery_file', 'console'],  # Use the default file handler
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'celery.worker': {  # Logger for Worker specific messages
            'handlers': ['celery_file', 'console'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        # You might want to configure the root logger or your app's loggers too
        'root': {
            'handlers': ['celery_file', 'console'],
            'level': LOG_LEVEL,
        },
        '__main__': {  # Logger for the main module running tasks
            'handlers': ['celery_file', 'console'],
            'level': LOG_LEVEL,
            'propagate': False,
        }
    },
}


def setup_flask_logging(app):
    """Configures logging for the Flask app (File and Console)."""
    log_level = logging.DEBUG if app.config.get('DEBUG') else logging.INFO
    # --- File Handler Setup ---
    file_handler = RotatingFileHandler(
        FLASK_LOG_FILE,
        maxBytes=1024 * 1024 * 5,  # 5 MB
        backupCount=5,
        encoding='utf-8'
    )
    file_handler.setLevel(log_level)  # File logs at the configured level
    file_formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    )
    file_handler.setFormatter(file_formatter)
    # --- Console Handler Setup ---
    console_handler = logging.StreamHandler()  # Writes to stderr by default
    # Set console level - maybe INFO even if DEBUG is on for file? Adjust as needed.
    # For simplicity, let's use the same log_level for now.
    console_handler.setLevel(log_level)
    # Use a simpler format for the console
    console_formatter = logging.Formatter(CONSOLE_LOG_FORMAT)
    console_handler.setFormatter(console_formatter)
    # Add handlers if they aren't already present
    # Check specifically for our file handler
    if not any(isinstance(h, logging.FileHandler) and getattr(h, 'baseFilename', None) == FLASK_LOG_FILE for h in
               app.logger.handlers):
        app.logger.addHandler(file_handler)
        app.logger.info(f"Added FileHandler logging to {FLASK_LOG_FILE}")
    # --- Configure Werkzeug Logger (for request logs) ---
    werkzeug_logger = logging.getLogger('werkzeug')
    # werkzeug_logger.setLevel(log_level)  # Set level for Werkzeug
    # Add file handler to Werkzeug logger (checking for duplicates)
    if not any(isinstance(h, logging.FileHandler) and getattr(h, 'baseFilename', None) == FLASK_LOG_FILE for h in
               werkzeug_logger.handlers):
        werkzeug_logger.addHandler(file_handler)
        werkzeug_logger.addHandler(console_handler)
    app.logger.info('Flask application logging configured.')
    # This message will now go to both file and console (if levels permit)
