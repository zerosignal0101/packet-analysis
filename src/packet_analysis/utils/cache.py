# cache.py
import os
import redis
import hashlib
import time
import logging
from functools import wraps
from redis.exceptions import LockError, LockNotOwnedError, RedisError
from enum import Enum
from contextlib import contextmanager

# Project imports
from src.packet_analysis.config import Config  # Make sure this path is correct

logger = logging.getLogger(__name__)  # It's good practice to add logging


class CacheStatus(str, Enum):
    CACHE_READY = "cache_ready"  # 缓存可用（可正常读取）
    CACHE_PENDING = "cache_pending"  # 缓存不存在，但有写入任务进行中
    CACHE_MISSING = "cache_missing"  # 缓存不存在，且无写入任务安排


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

    def delete_cache_status(self, key):
        """移除缓存键值"""
        if not self.redis:
            logger.warning(f"Redis client not available. Cannot delete cache status for key: {key}")
            return False
        try:
            status_key = "status:{}".format(key)
            return self.redis.delete(status_key)
        except redis.exceptions.RedisError:
            logger.error(f"Failed to delete cache status")

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

    def delete_cache(self, key):
        """移除缓存键值"""
        if not self.redis:
            logger.warning(f"Redis client not available. Cannot delete cache for key: {key}")
            return False
        try:
            return self.redis.delete(key)
        except redis.exceptions.RedisError:
            logger.error(f"Failed to delete cache")

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

    # --- Add Acquire Lock Method (if not implicitly handled by redis_lock context manager) ---
    def acquire_lock(self, lock_name, timeout=Config.LOCK_TIMEOUT_SECONDS, blocking_timeout=None):
        if not self.redis:
            logger.warning("Redis client not available. Cannot acquire lock.")
            return None
        try:
            # Use Redis built-in Lock
            lock = self.redis.lock(lock_name, timeout=timeout)
            if lock.acquire(blocking=True, blocking_timeout=blocking_timeout):
                logger.debug(f"Acquired lock: {lock_name}")
                return lock  # Return the lock object to be released later
            else:
                logger.warning(f"Failed to acquire lock {lock_name} within timeout.")
                return None
        except RedisError as e:
            logger.error(f"Error acquiring lock {lock_name}: {e}")
            return None

    # --- Add Release Lock Method ---
    def release_lock(self, lock):
        if not self.redis or not lock:
            # logger.warning("Redis client not available or lock invalid. Cannot release lock.")
            return False  # Don't log if lock is None, already logged acquire failure
        try:
            lock.release()
            logger.debug(f"Released lock: {lock.name}")
            return True
        except LockNotOwnedError:
            logger.warning(f"Attempted to release lock {lock.name} not owned by this client.")
            return False
        except RedisError as e:
            logger.error(f"Error releasing lock {lock.name}: {e}")
            return False

    @property
    def initialized(self):
        return self._initialized


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


# --- redis_lock Context Manager ---
@contextmanager
def redis_lock(lock_name, timeout=Config.LOCK_TIMEOUT_SECONDS, blocking_timeout=None):
    """Provides a context manager for acquiring and releasing a Redis lock."""
    client = get_redis_client()
    if not client or not client._initialized:
        # If redis isn't available, maybe proceed without locking? Or raise error?
        # Let's proceed without lock but log a warning. Depending on criticality, you might raise.
        logger.warning(f"Redis not available. Proceeding without lock for '{lock_name}'. Potential race condition.")
        lock = None
        yield  # Allow the 'with' block to execute
        return  # Exit context manager
    # If Redis is available, try to acquire lock
    lock = client.acquire_lock(lock_name, timeout=timeout, blocking_timeout=blocking_timeout)
    if lock is None:
        # Failed to acquire lock (e.g., timed out waiting)
        raise LockError(f"Could not acquire lock '{lock_name}'")
    try:
        yield lock  # Pass lock object if needed, otherwise just yield control
    finally:
        if lock:
            client.release_lock(lock)


if __name__ == "__main__":
    redis_client = get_redis_client()

    file_hash = "15ab45484948"
    cache_key = f"pcap_info:{file_hash}"
    redis_client.set_cache(cache_key, 'test value')
