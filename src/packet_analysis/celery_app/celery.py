from celery import Celery
import os

# Project imports
from src.packet_analysis.config import Config

# 初始化 Celery 实例
celery_app = Celery(
    'pcap_analyzer',
    broker=Config.CELERY_BROKER_URL,
    backend=Config.CELERY_RESULT_BACKEND,
    include=[
        'src.packet_analysis.tasks.coordinator',
        'src.packet_analysis.tasks.pcap_processor',
        'src.packet_analysis.tasks.analyzer',
        'src.packet_analysis.tasks.result_handler'
    ]
)

# Celery 配置
celery_app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    # 任务结果过期时间
    result_expires=3600,
    # 并发工作进程数，根据硬件配置调整
    worker_concurrency=os.cpu_count(),
    # 启用任务事件，方便监控
    worker_send_task_events=True,
    task_send_sent_event=True,
    # 任务超时设置
    task_time_limit=3600,
    # 缓存配置
    task_ignore_result=False,
)

# 启动 Celery Beat 进行任务调度
celery_app.conf.beat_schedule = {
    'cleanup-expired-cache': {
        'task': 'src.packet_analysis.tasks.coordinator.cleanup_expired_cache',
        'schedule': 3600.0,  # 每小时执行一次
    },
}

# 配置 Celery 日志
celery_app.log.already_setup = True
