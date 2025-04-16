# redis_utils.py
import os
import redis
import hashlib
import time
from functools import wraps

# Project imports
from src.packet_analysis.config import Config


class RedisClient:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(RedisClient, cls).__new__(cls)
            cls._instance.initialized = False
        return cls._instance

    def __init__(self):
        if not self.initialized:
            self.redis = redis.Redis.from_url(Config.CACHE_RESULT_BACKEND)
            self.initialized = True

    def get_lock(self, lock_name, timeout=60, blocking=True, blocking_timeout=None):
        """获取分布式锁"""
        return self.redis.lock(
            name=lock_name,
            timeout=timeout,
            blocking=blocking,
            blocking_timeout=blocking_timeout
        )

    def set_cache(self, key, value, expire=None):
        """设置缓存"""
        self.redis.set(key, value, ex=expire)

    def get_cache(self, key):
        """获取缓存"""
        return self.redis.get(key)

    def exists(self, key):
        """检查键是否存在"""
        return self.redis.exists(key)


# 创建单例实例
redis_client = RedisClient()


def with_file_lock(file_hash_func):
    """装饰器：使用文件哈希作为锁"""

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # 获取文件哈希
            if isinstance(args[0], dict):
                file_hashes = list(args[0].keys())
            elif isinstance(args[0], (list, str)):
                pcap_files = args[0]
                if isinstance(pcap_files, str):
                    pcap_files = [pcap_files]
                file_hashes = [get_file_hash(f) for f in pcap_files if os.path.exists(f)]
            else:
                return func(*args, **kwargs)

            # 对每个文件哈希获取锁
            locks = []
            try:
                for file_hash in file_hashes:
                    lock_name = f"pcap_lock:{file_hash}"
                    lock = redis_client.get_lock(lock_name, timeout=300, blocking=True, blocking_timeout=60)
                    acquired = lock.acquire()
                    if acquired:
                        locks.append(lock)
                    else:
                        # 如果获取锁失败，释放已获取的锁
                        for acquired_lock in locks:
                            acquired_lock.release()
                        # 等待一段时间后重试
                        time.sleep(5)
                        return func(*args, **kwargs)

                # 获取所有锁后执行函数
                result = func(*args, **kwargs)
                return result
            finally:
                # 释放所有锁
                for lock in locks:
                    try:
                        lock.release()
                    except:
                        pass

        return wrapper

    return decorator


def get_file_hash(file_path):
    """计算文件内容的 MD5 哈希值作为缓存键"""
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        buf = f.read(65536)
        while len(buf) > 0:
            hasher.update(buf)
            buf = f.read(65536)
    return hasher.hexdigest()