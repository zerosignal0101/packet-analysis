# redis_utils.py (or wherever these reside)
import os
import redis
import hashlib
import time
import logging
from functools import wraps
from redis.exceptions import LockError
from enum import Enum

# Project imports
from src.packet_analysis.config import Config  # Make sure this path is correct

logger = logging.getLogger(__name__)  # It's good practice to add logging


class CacheStatus(str, Enum):
    READ_LOCKED = "read_locked"       # 读取锁定（防止多个进程同时重建缓存）
    WRITE_LOCKED = "write_locked"     # 写入锁定（防止并发写入）
    CACHE_READY = "cache_ready"       # 缓存可用（可正常读取）
    CACHE_PENDING = "cache_pending"   # 缓存不存在，但有写入任务进行中
    CACHE_MISSING = "cache_missing"   # 缓存不存在，且无写入任务安排


class RedisClient:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(RedisClient, cls).__new__(cls)
            # Move initialization logic to __init__ to ensure it runs every time
            # __new__ is called before __init__ checks initialized flag.
            # Let's simplify: Use a flag to ensure __init__ runs only once.
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        # Ensure __init__ runs only once for the singleton instance
        if not hasattr(self, '_initialized') or not self._initialized:
            try:
                self.redis = redis.Redis.from_url(Config.CACHE_RESULT_BACKEND,
                                                  decode_responses=True)  # Decode responses for easier handling
                self.redis.ping()  # Test connection during initialization
                logger.info("Redis client initialized successfully.")
                self._initialized = True
            except redis.exceptions.ConnectionError as e:
                logger.error(f"Failed to connect to Redis: {e}")
                # Depending on requirements, you might want to raise an exception
                # or allow the application to continue without caching/locking
                self.redis = None  # Ensure redis attribute exists but is None
                self._initialized = False  # Mark as not successfully initialized
            except Exception as e:
                logger.error(f"An unexpected error occurred during Redis initialization: {e}")
                self.redis = None
                self._initialized = False

    def set_cache_status(self, cache_key, value, expire=None):
        """标识缓存状态"""
        if not self.redis:
            logger.warning(f"Redis client not available. Cannot set cache status for {cache_key}")
            return False
        try:
            status_key = "status:{}".format(cache_key)
            return self.redis.set(status_key, value, ex=expire)
        except redis.exceptions.RedisError as e:
            logger.error(f"Failed to set cache status for {cache_key}: {e}")
            return False

    def get_cache_status(self, cache_key):
        """获取缓存"""
        if not self.redis:
            logger.warning(f"Redis client not available. Cannot get cache status for {cache_key}")
            return None
        try:
            status_key = "status:{}".format(cache_key)
            return self.redis.get(status_key)
        except redis.exceptions.RedisError as e:
            logger.error(f"Failed to get cache status for {cache_key}: {e}")
            return None

    def check_status_exist(self, cache_key):
        status_key = "status:{}".format(cache_key)
        return self.exists(status_key)

    def set_cache(self, key, value, expire=None):
        """设置缓存"""
        if not self.redis:
            logger.warning(f"Redis client not available. Cannot set cache for key: {key}")
            return False
        try:
            return self.redis.set(key, value, ex=expire)
        except redis.exceptions.RedisError as e:
            logger.error(f"Failed to set cache for key {key}: {e}")
            return False

    def get_cache(self, key):
        """获取缓存"""
        if not self.redis:
            logger.warning(f"Redis client not available. Cannot get cache for key: {key}")
            return None
        try:
            return self.redis.get(key)
        except redis.exceptions.RedisError as e:
            logger.error(f"Failed to get cache for key {key}: {e}")
            return None

    def check_cache_exist(self, key):
        return self.exists(key)

    def exists(self, key):
        """检查键是否存在"""
        if not self.redis:
            logger.warning(f"Redis client not available. Cannot check existence for key: {key}")
            return False  # Or 0 depending on how you use the result
        try:
            return self.redis.exists(key)
        except redis.exceptions.RedisError as e:
            logger.error(f"Failed to check existence for key {key}: {e}")
            return False


# --- End of RedisClient ---
# 创建单例实例
# Ensure RedisClient() is called somewhere to initialize the instance,
# e.g., during app startup or lazily when first needed.
# Using a function can help manage initialization:
_redis_client_instance = None


def get_redis_client():
    """Gets the singleton RedisClient instance, initializing if needed."""
    global _redis_client_instance
    if _redis_client_instance is None:
        _redis_client_instance = RedisClient()
    # Check if initialization failed
    if not _redis_client_instance._initialized:
        # Maybe retry initialization or handle the failure case
        logger.warning("Accessing RedisClient but it failed to initialize.")
        # Depending on strictness, could return None or the failed instance
    return _redis_client_instance


# --- Helper function for hashing ---
def get_file_hash(file_path):
    """计算文件内容的 MD5 哈希值。"""
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            while True:
                buf = f.read(65536)  # Read in chunks
                if not buf:
                    break
                hasher.update(buf)
        return hasher.hexdigest()
    except IOError as e:
        logger.error(f"Error reading file {file_path} for hashing: {e}")
        raise  # Re-raise the exception after logging
