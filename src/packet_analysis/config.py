import os
from typing import Optional
import rootutils

# 查找项目根目录
project_path = rootutils.find_root(search_from=__file__, indicator=".project-root")


class Config:
    """应用配置类"""

    # Flask 基础配置
    FLASK_HOST: str = '0.0.0.0'
    FLASK_PORT: int = 5000
    SECRET_KEY: Optional[str] = None
    DEBUG: bool = True
    MAX_CONTENT_LENGTH: int = 16 * 1024 * 1024  # 16MB 文件上传限制

    # Celery 基础配置
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None
    CACHE_RESULT_BACKEND: Optional[str] = None
    ENABLE_CELERY_BEAT: bool = False  # 是否启用定时任务

    # Celery 性能配置
    CELERY_WORKER_CONCURRENCY: int = os.cpu_count() or 4
    CELERY_TASK_TIME_LIMIT: int = 3600  # 任务超时时间(秒)
    CELERY_RESULT_EXPIRES: int = 3600  # 任务结果过期时间(秒)

    # 日志配置
    LOG_LEVEL: str = 'INFO'

    # 回调 URL 配置
    CALLBACK_URL: Optional[str] = None

    # 缓存相关配置
    CHUNK_PCAP_STORAGE_DIR: str = os.path.join(project_path, "results/pcap_chunks")
    CACHE_TTL_SECONDS: int = 3600 * 24
    LOCK_TIMEOUT_SECONDS: int = 1800
    PARQUET_STORAGE_DIR: str = os.path.join(project_path, "results/parquet_data")

    @classmethod
    def load_config(cls):
        """加载配置，优先级: 实例属性 > 环境变量 > 默认值"""
        # Flask 配置
        cls.FLASK_HOST = cls._get_setting('FLASK_HOST')
        cls.FLASK_PORT = cls._get_setting('FLASK_PORT', convert_type=int)
        cls.SECRET_KEY = cls._get_setting('SECRET_KEY', default='dev-secret-key')
        cls.DEBUG = cls._get_setting('DEBUG', default=False, convert_type=bool)
        cls.MAX_CONTENT_LENGTH = cls._get_setting(
            'MAX_CONTENT_LENGTH',
            default=16 * 1024 * 1024,
            convert_type=int
        )

        # Celery 配置
        cls.CELERY_BROKER_URL = cls._get_setting(
            'CELERY_BROKER_URL',
            default='redis://localhost:6379/0'
        )
        cls.CELERY_RESULT_BACKEND = cls._get_setting(
            'CELERY_RESULT_BACKEND',
            default='redis://localhost:6379/0'
        )
        cls.CACHE_RESULT_BACKEND = cls._get_setting(
            'CACHE_RESULT_BACKEND',
            default='redis://localhost:6379/1'
        )
        cls.ENABLE_CELERY_BEAT = cls._get_setting(
            'ENABLE_CELERY_BEAT',
            default=False,
            convert_type=bool
        )
        cls.CELERY_WORKER_CONCURRENCY = cls._get_setting(
            'CELERY_WORKER_CONCURRENCY',
            default=os.cpu_count() or 4,
            convert_type=int
        )
        cls.CELERY_TASK_TIME_LIMIT = cls._get_setting(
            'CELERY_TASK_TIME_LIMIT',
            default=3600,
            convert_type=int
        )
        cls.CELERY_RESULT_EXPIRES = cls._get_setting(
            'CELERY_RESULT_EXPIRES',
            default=3600,
            convert_type=int
        )

        # 日志配置
        cls.LOG_LEVEL = cls._get_setting('LOG_LEVEL', default='INFO')

        cls.CALLBACK_URL = cls._get_setting('CALLBACK_URL', default=None)

        # 缓存相关
        cls.CACHE_TTL_SECONDS = cls._get_setting(
            'CACHE_TTL_SECONDS',
            default=3600 * 24,
            convert_type=int
        )
        cls.LOCK_TIMEOUT_SECONDS = cls._get_setting(
            'LOCK_TIMEOUT_SECONDS',
            default=60,
            convert_type=int
        )
        cls.PARQUET_STORAGE_DIR = cls._get_setting('PARQUET_STORAGE_DIR', default='/tmp/parquet_data')

    @staticmethod
    def _get_setting(name: str, default=None, convert_type=str):
        """获取配置项的优先级: 实例属性 > 环境变量 > 默认值"""
        # 1. 首先检查是否在 Config 类中被显式设置
        if hasattr(Config, name) and getattr(Config, name) is not None:
            return getattr(Config, name)

        # 2. 检查环境变量
        env_value = os.getenv(name)
        if env_value is not None:
            try:
                return convert_type(env_value) if convert_type else env_value
            except (TypeError, ValueError) as e:
                print(f"Warning: Failed to convert env var {name}={env_value} to {convert_type}: {e}")
                return default

        # 3. 返回默认值
        return default


# 加载配置
Config.load_config()
