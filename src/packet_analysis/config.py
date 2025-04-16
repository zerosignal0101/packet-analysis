# config.py

import os
from typing import Optional


class Config:
    """应用配置类"""

    # Celery 配置
    CELERY_BROKER_URL: Optional[str] = None
    CELERY_RESULT_BACKEND: Optional[str] = None
    CACHE_RESULT_BACKEND: Optional[str] = None

    # 其他配置...
    SECRET_KEY: Optional[str] = None
    DEBUG: bool = False

    @classmethod
    def load_config(cls):
        """加载配置，优先级: 实例属性 > 环境变量 > 默认值"""
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

        # 其他配置
        cls.SECRET_KEY = cls._get_setting(
            'SECRET_KEY',
            default='dev-secret-key'
        )
        cls.DEBUG = cls._get_setting(
            'DEBUG',
            default=False,
            convert_type=bool
        )

    @staticmethod
    def _get_setting(name: str, default=None, convert_type=str):
        """获取配置项的优先级: 实例属性 > 环境变量 > 默认值"""
        # 1. 首先检查是否在 config.py 中被显式设置
        if hasattr(Config, name) and getattr(Config, name) is not None:
            return getattr(Config, name)

        # 2. 检查环境变量
        env_value = os.getenv(name)
        if env_value is not None:
            return convert_type(env_value) if convert_type else env_value

        # 3. 返回默认值
        return default


# 加载配置
Config.load_config()
