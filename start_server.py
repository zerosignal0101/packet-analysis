#!/usr/bin/env python
import os
import subprocess
from pathlib import Path
import signal
import sys
from multiprocessing import Process

# Project imports
from src.packet_analysis.config import Config

# 获取项目根目录
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def start_flask():
    """启动Flask应用"""
    from src.packet_analysis.app import create_app
    app = create_app()
    app.run(host=Config.FLASK_HOST, port=Config.FLASK_PORT)


def start_celery_worker():
    """启动Celery工作进程"""
    from src.packet_analysis.celery_app import celery_app
    celery_app.worker_main(argv=['worker', '--loglevel=info'])


def start_celery_beat():
    """启动Celery Beat调度器"""
    Path(Config.CELERY_BEAT_DIR).mkdir(parents=True, exist_ok=True)
    from src.packet_analysis.celery_app import celery_app
    celery_app.start(argv=['beat', f'--schedule={Config.CELERY_BEAT_DIR}', '--loglevel=info'])


def run():
    """启动所有服务"""
    processes = []

    # 启动Flask
    flask_process = Process(target=start_flask)
    flask_process.start()
    processes.append(flask_process)

    # 启动Celery Worker
    celery_worker_process = Process(target=start_celery_worker)
    celery_worker_process.start()
    processes.append(celery_worker_process)

    # 启动Celery Beat (如果需要定时任务)
    if Config.ENABLE_CELERY_BEAT:
        celery_beat_process = Process(target=start_celery_beat)
        celery_beat_process.start()
        processes.append(celery_beat_process)

    # 注册信号处理
    def signal_handler(sig, frame):
        print("\nShutting down services...")
        for p in processes:
            p.terminate()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Keep the main process alive efficiently waiting for signals
    try:
        signal.pause()
    except KeyboardInterrupt:
        # This might be caught if signal handler doesn't exit, but signal_handler should handle it
        pass
    except Exception as e:
        print(f"Main loop encountered an error: {e}")


if __name__ == '__main__':
    run()
