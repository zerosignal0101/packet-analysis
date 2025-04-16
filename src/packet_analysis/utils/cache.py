import redis
import json
import time

# Project imports
from src.packet_analysis.config import Config

# Redis 客户端
redis_client = redis.Redis.from_url(Config.CACHE_RESULT_BACKEND)


def get_cache_key(key_type, identifier):
    """生成标准化的缓存键"""
    return f"{key_type}:{identifier}"


def get_cache(key):
    """从缓存获取数据"""
    data = redis_client.get(key)
    if data:
        try:
            return json.loads(data)
        except:
            return None
    return None


def set_cache(key, value, expire=None):
    """设置缓存数据"""
    serialized = json.dumps(value)
    if expire:
        redis_client.setex(key, expire, serialized)
    else:
        redis_client.set(key, serialized)
    return True


def delete_cache(key):
    """删除缓存"""
    return redis_client.delete(key)


def scan_keys(pattern):
    """扫描匹配特定模式的键"""
    keys = []
    cursor = 0
    while True:
        cursor, partial_keys = redis_client.scan(cursor, match=pattern)
        keys.extend(partial_keys)
        if cursor == 0:
            break
    return keys
