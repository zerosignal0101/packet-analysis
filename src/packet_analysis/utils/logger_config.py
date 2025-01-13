# logger_config.py
import logging
import logging.config
import os

# 确保日志目录存在
log_dir = 'results/logs'
os.makedirs(log_dir, exist_ok=True)

# 配置日志记录
logging.config.dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        },
    },
    'handlers': {
        'file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': os.path.join(log_dir, 'app.log'),
            'when': 'midnight',  # 每天午夜滚动日志
            'interval': 1,  # 每天滚动一次
            'backupCount': 7,  # 保留最近7天的日志
            'formatter': 'standard',
        },
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'standard',
        },
    },
    'loggers': {
        '': {
            'handlers': ['file', 'console'],
            'level': 'DEBUG',
            'propagate': True,
        },
    },
})

# 获取日志记录器
logger = logging.getLogger(__name__)
