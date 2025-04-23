import logging
import os
from logging.handlers import RotatingFileHandler, \
    TimedRotatingFileHandler  # Keep both imports for reference, but only use TimedRotatingFileHandler now
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

# --- Define Logging Configuration Dictionary (Modified for Time Rotation) ---
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
            'level': LOG_LEVEL,
            # --- MODIFIED HERE ---
            'class': 'logging.handlers.TimedRotatingFileHandler',  # Use time-based rotation
            'filename': CELERY_LOG_FILE,
            'when': 'midnight',  # Rotate daily at midnight
            'interval': 1,  # Check once per day (when='midnight')
            'backupCount': 7,  # Keep 7 backup logs (e.g., one week)
            # 'maxBytes': 1024 * 1024 * 100, # Removed maxBytes
            # --- END MODIFICATION ---
            'formatter': 'default',
            'encoding': 'utf-8',
        },
        'celery_task_file': {
            'level': LOG_LEVEL,
            # --- MODIFIED HERE ---
            'class': 'logging.handlers.TimedRotatingFileHandler',  # Use time-based rotation
            'filename': CELERY_LOG_FILE,  # Log tasks to the SAME file
            'when': 'midnight',  # Rotate daily at midnight (Consistent with celery_file)
            'interval': 1,  # Check once per day
            'backupCount': 7,  # Keep 7 backup logs (Consistent with celery_file)
            # 'maxBytes': 1024 * 1024 * 100, # Removed maxBytes
            # --- END MODIFICATION ---
            'formatter': 'task',  # Use specific 'task' formatter for task logs
            'encoding': 'utf-8',
        },
        'console': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'console_formatter',
        },
    },
    'loggers': {
        'celery': {
            'handlers': ['celery_file', 'console'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'celery.task': {
            'handlers': ['celery_task_file', 'console'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'celery.beat': {
            'handlers': ['celery_file', 'console'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'celery.worker': {
            'handlers': ['celery_file', 'console'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'root': {
            'handlers': ['celery_file', 'console'],
            'level': LOG_LEVEL,
        },
        '__main__': {
            'handlers': ['celery_file', 'console'],
            'level': LOG_LEVEL,
            'propagate': False,
        }
    },
}


def setup_flask_logging(app):
    """Configures logging for the Flask app (File and Console) with Time Rotation."""
    log_level = logging.DEBUG if app.config.get('DEBUG') else logging.INFO

    # --- File Handler Setup (Modified for Time Rotation) ---
    # --- MODIFIED HERE ---
    file_handler = TimedRotatingFileHandler(
        FLASK_LOG_FILE,
        when='midnight',  # Rotate daily at midnight
        interval=1,  # Check once per day
        backupCount=7,  # Keep 7 backup logs (e.g., one week)
        # maxBytes=1024 * 1024 * 5, # Removed maxBytes
        encoding='utf-8'
    )
    # --- END MODIFICATION ---

    file_handler.setLevel(log_level)
    file_formatter = logging.Formatter(FILE_LOG_FORMAT)
    file_handler.setFormatter(file_formatter)

    # --- Console Handler Setup ---
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_formatter = logging.Formatter(CONSOLE_LOG_FORMAT)
    console_handler.setFormatter(console_formatter)

    # Add handlers if they aren't already present
    # Check specifically for our file handler by filename
    if not any(isinstance(h, logging.FileHandler) and getattr(h, 'baseFilename', None) == FLASK_LOG_FILE for h in
               app.logger.handlers):
        app.logger.addHandler(file_handler)
        app.logger.info(f"Added TimedRotatingFileHandler logging to {FLASK_LOG_FILE}")

    # Add console handler if not present
    if not any(isinstance(h, logging.StreamHandler) for h in app.logger.handlers):
        app.logger.addHandler(console_handler)  # Also add console handler to app logger

    # --- Configure Werkzeug Logger (for request logs) ---
    werkzeug_logger = logging.getLogger('werkzeug')
    # Check and add handlers to Werkzeug logger
    if not any(isinstance(h, logging.FileHandler) and getattr(h, 'baseFilename', None) == FLASK_LOG_FILE for h in
               werkzeug_logger.handlers):
        werkzeug_logger.addHandler(file_handler)
    # Add console handler to Werkzeug if needed (ensures requests go to console too)
    if not any(isinstance(h, logging.StreamHandler) for h in werkzeug_logger.handlers):
        werkzeug_logger.addHandler(console_handler)

    # Set the level for the app logger itself AFTER adding handlers
    app.logger.setLevel(log_level)
    # Optionally set Werkzeug level (often INFO is sufficient)
    werkzeug_logger.setLevel(logging.INFO)  # Or use log_level if you want DEBUG requests logged

    app.logger.info('Flask application logging configured with Time Rotation.')
