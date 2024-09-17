import asyncio
import requests
import json
import time
from src.packet_analysis.utils.logger_config import logger


def post_url(data, url):
    # 创建新的事件循环
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        # 设置请求头，指定内容类型为JSON
        headers = {
            'Content-Type': 'application/json'
        }

        # 发送POST请求
        response = requests.post(url, headers=headers, data=data)

        # 检查响应状态码
        if response.status_code == 200:
            logger.info('请求成功')
        else:
            logger.info(f'请求失败，状态码: {response.status_code}')
            logger.info(f'错误信息: {response.text}')
    except Exception as e:
        logger.info(f'请求异常: {e}')


if __name__ == '__main__':
    print("Do not run this script directly. Please run server.py instead.")
