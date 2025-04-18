# redis_utils.py (or wherever these reside)
import os
import redis
import hashlib
import time
import logging
from functools import wraps
from redis.exceptions import LockError

# Project imports
from src.packet_analysis.config import Config  # Make sure this path is correct

logger = logging.getLogger(__name__)  # It's good practice to add logging


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

    def get_lock(self, lock_name, timeout=60, blocking=True, blocking_timeout=None):
        """获取分布式锁"""
        if not self.redis:
            logger.warning("Redis client not available. Cannot get lock.")
            # Return a dummy lock object that does nothing or raise an error
            # For simplicity, let's return None, callers must check
            return None
        return self.redis.lock(
            name=lock_name,
            timeout=timeout,
            blocking=blocking,
            blocking_timeout=blocking_timeout,
            # thread_local=False # Important for Celery tasks potentially running in different threads/processes
        )

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


# --- Simplified Decorator ---
def with_pcap_lock(lock_timeout=300, acquisition_timeout=60):
    """
    装饰器：为处理单个 pcap 文件获取基于其内容哈希的 Redis 分布式锁。
    Args:
        lock_timeout (int): 锁的持有超时时间（秒）。
        acquisition_timeout (int): 获取锁的阻塞等待超时时间（秒）。
    """

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Debug
            if Config.DEBUG:
                logger.debug(f"  参数: args={args}, kwargs={kwargs}")

            redis_client = get_redis_client()  # Get the singleton instance
            if not redis_client or not redis_client._initialized:
                logger.error("Redis not available, skipping lock acquisition. Executing function without lock.")
                return func(*args, **kwargs)  # Proceed without lock if Redis fails
            # Assume the first argument is the pcap_file path
            if not kwargs or not isinstance(kwargs['pcap_file'], str):
                logger.error(f"Decorator expects the pcap_file argument to be a pcap file path string.")
                # Or raise TypeError("First argument must be the pcap_file path")
                return func(*args, **kwargs)  # Or handle error differently
            pcap_file = kwargs['pcap_file']
            # Check file existence *before* hashing
            if not os.path.exists(pcap_file):
                logger.warning(f"PCAP file {pcap_file} not found. Proceeding without lock.")
                # The decorated function might handle this, or you could raise FileNotFoundError here.
                # Let's allow the function to proceed, maybe it has specific handling.
                return func(*args, **kwargs)
            lock = None
            acquired = False
            try:
                # Calculate file hash for the lock name
                try:
                    file_hash = get_file_hash(pcap_file)
                except (FileNotFoundError, IOError) as e:
                    logger.error(f"Cannot get hash for {pcap_file} due to error: {e}. Executing function without lock.")
                    return func(*args, **kwargs)  # Execute without lock if hashing fails
                lock_name = f"pcap_lock:{file_hash}"
                logger.debug(f"Attempting to acquire lock: {lock_name} for file {pcap_file}")
                # Get and acquire the lock
                lock = redis_client.get_lock(
                    lock_name,
                    timeout=lock_timeout,
                    blocking=True,
                    blocking_timeout=acquisition_timeout
                )
                if lock is None:  # Check if get_lock failed (e.g., Redis unavailable)
                    logger.error(f"Failed to create lock object for {lock_name}. Executing function without lock.")
                    return func(*args, **kwargs)
                acquired = lock.acquire()
                if acquired:
                    logger.info(f"Successfully acquired lock: {lock_name}")
                    # Execute the decorated function while holding the lock
                    result = func(*args, **kwargs)
                    return result
                else:
                    # Lock could not be acquired within the acquisition_timeout
                    logger.error(f"Failed to acquire lock {lock_name} for {pcap_file} within {acquisition_timeout}s.")
                    # Decide on behavior: raise error, return specific value, or maybe even proceed carefully?
                    # Raising an error is often safest to signal contention failure.
                    raise LockError(f"Could not acquire lock for {pcap_file} (hash: {file_hash})")
            except LockError as e:
                # Catch LockError explicitly if re-raised above or from redis-py internals
                logger.error(f"LockError encountered for {pcap_file}: {e}")
                raise  # Re-raise LockError to signal the issue to the caller/Celery
            except Exception as e:
                logger.exception(f"An unexpected error occurred in with_pcap_lock for {pcap_file}: {e}")
                raise  # Re-raise unexpected errors
            finally:
                # Release the lock if it was acquired
                if acquired and lock:
                    try:
                        lock.release()
                        logger.info(f"Released lock: {lock_name}")
                    except LockError:
                        # This can happen if the lock expired before release. Usually benign.
                        logger.warning(
                            f"Could not release lock {lock_name}, it may have already expired or been released.")
                    except Exception as e:
                        logger.error(f"Unexpected error releasing lock {lock_name}: {e}")

        return wrapper

    return decorator
