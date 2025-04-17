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
FILE_LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s - %(name)s - [%(filename)s:%(lineno)d/%(processName)s]"
CONSOLE_LOG_FORMAT = "[%(asctime)s: %(levelname)s/%(processName)s] %(message)s"

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
    },
    'handlers': {
        'celery_file': {
            'level': 'INFO',  # Log level for this handler
            'class': 'logging.handlers.RotatingFileHandler',  # Use rotating file handler
            'filename': CELERY_LOG_FILE,
            'maxBytes': 1024 * 1024 * 100,  # 100 MB log file size
            'backupCount': 5,  # Keep 5 backup logs
            'formatter': 'default',  # Use 'default' formatter for general logs
            'encoding': 'utf-8',
        },
        'celery_task_file': {  # You could use the same handler as above if format is the same
            # Or define a separate one if needed (e.g., different file/format)
            'level': 'INFO',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': CELERY_LOG_FILE,  # Log tasks to the SAME file
            'maxBytes': 1024 * 1024 * 100,
            'backupCount': 5,
            'formatter': 'task',  # Use specific 'task' formatter for task logs
            'encoding': 'utf-8',
        },
        'console': {  # Optional: Keep logging to console as well
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'default',
        },
    },
    'loggers': {
        'celery': {  # Logger for base Celery messages
            'handlers': ['celery_file', 'console'],  # Send to file and console
            'level': 'INFO',
            'propagate': False,  # Do not pass messages up to the root logger
        },
        'celery.task': {  # Logger for task-related messages
            'handlers': ['celery_task_file', 'console'],  # Use the task handler/formatter
            'level': 'INFO',
            'propagate': False,
        },
        'celery.beat': {  # Logger for Celery Beat
            'handlers': ['celery_file', 'console'],  # Use the default file handler
            'level': 'INFO',
            'propagate': False,
        },
        'celery.worker': {  # Logger for Worker specific messages
            'handlers': ['celery_file', 'console'],
            'level': 'INFO',
            'propagate': False,
        },
        # You might want to configure the root logger or your app's loggers too
        'root': {
            'handlers': ['celery_file', 'console'],
            'level': 'WARNING',
        },
        '__main__': {  # Logger for the main module running tasks
            'handlers': ['celery_file', 'console'],
            'level': 'INFO',
            'propagate': False,
        }
    },
}


def setup_flask_logging(app):
    """Configures logging for the Flask app."""
    # Remove default handlers if they exist, to avoid duplicate logs if running non-debug
    # Be cautious if other parts of your setup rely on the default handler.
    # for handler in app.logger.handlers[:]:
    #    app.logger.removeHandler(handler)
    # Determine log level from Flask config or default to INFO
    log_level = logging.DEBUG if app.config.get('DEBUG') else logging.INFO
    app.logger.setLevel(log_level)
    # Create file handler
    # Use RotatingFileHandler for production environments to prevent huge log files
    # maxBytes=1024*1024*5 means rotate after 5MB
    # backupCount=5 means keep the last 5 rotated files
    file_handler = RotatingFileHandler(
        FLASK_LOG_FILE,
        maxBytes=1024 * 1024 * 5,  # 5 MB
        backupCount=5,
        encoding='utf-8'  # Explicitly set encoding
    )
    # Alternatively, for a simple, non-rotating file:
    # file_handler = logging.FileHandler(FLASK_LOG_FILE, encoding='utf-8')
    # Set the level for the handler
    file_handler.setLevel(log_level)
    # Create formatter and set it for the handler
    formatter = logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s '
        '[in %(pathname)s:%(lineno)d]'
    )
    file_handler.setFormatter(formatter)
    # Add the handler to the app's logger
    if not app.logger.handlers:  # Add handler only if no handlers are configured yet
        app.logger.addHandler(file_handler)
    elif not any(isinstance(h, logging.FileHandler) and h.baseFilename == FLASK_LOG_FILE for h in app.logger.handlers):
        # Or add if our specific file handler isn't already present
        app.logger.addHandler(file_handler)
    # Also configure Werkzeug logger (handles request logs) if desired
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(log_level)  # Match app level or set differently
    # Add the same handler or a different one if needed
    if not any(
            isinstance(h, logging.FileHandler) and h.baseFilename == FLASK_LOG_FILE for h in werkzeug_logger.handlers):
        werkzeug_logger.addHandler(file_handler)
    app.logger.info('Flask application logging configured.')
    app.logger.info(f'Logging to file: {FLASK_LOG_FILE}')
