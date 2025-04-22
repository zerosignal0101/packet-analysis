import json
from typing import Any, Union, Dict, List
import logging

# Logger
logger = logging.getLogger(__name__)


def check_json_serializable(data: Any, indent: int = 0, path: str = "") -> None:
    """
    递归检查数据结构是否可JSON序列化

    参数:
        data: 要检查的数据（可以是字典、列表、集合等）
        indent: 当前缩进级别（用于格式化输出）
        path: 当前数据的访问路径（用于错误定位）
    """
    indent_str = " " * indent * 4
    current_path = f"{path}." if path else ""

    try:
        # 先尝试直接序列化整个对象（简单类型会直接通过）
        json.dumps(data)
        logger.info(f"{indent_str}√ {current_path} (类型: {type(data).__name__}) - 可JSON序列化")
    except (TypeError, OverflowError) as e:
        # 如果是字典，递归检查每个键值对
        if isinstance(data, dict):
            logger.info(f"{indent_str}↘ 字典 {current_path} (需要检查每个键值):")
            for key, value in data.items():
                new_path = f"{current_path}{key}"
                # 检查键是否可序列化
                try:
                    json.dumps(key)
                except (TypeError, OverflowError) as e:
                    logger.error(f"{indent_str}    ! 键 '{key}' (类型: {type(key).__name__}) - 不可JSON序列化: {str(e)}")

                # 递归检查值
                check_json_serializable(value, indent + 1, new_path)

        # 如果是列表/元组，递归检查每个元素
        elif isinstance(data, (list, tuple)):
            logger.info(f"{indent_str}↘ 列表 {current_path} (需要检查每个元素):")
            for i, item in enumerate(data):
                check_json_serializable(item, indent + 1, f"{current_path}[{i}]")

        # 如果是集合，尝试转换为列表
        elif isinstance(data, set):
            logger.info(f"{indent_str}↘ 集合 {current_path} - 尝试转换为列表:")
            check_json_serializable(list(data), indent + 1, current_path)

        # 其他不可序列化类型
        else:
            logger.error(f"{indent_str}× {current_path} (类型: {type(data).__name__}) - 不可JSON序列化: {str(e)}")
