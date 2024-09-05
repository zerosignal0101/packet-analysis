import datetime
import json


# 将DCTIME转换为可读的时间格式
def convert_dctime(dctime):
    # 将13位毫秒级时间戳转换为可读的日期时间格式
    timestamp_s = dctime / 1000.0
    readable_time = datetime.datetime.fromtimestamp(timestamp_s)
    return readable_time


# 提取数据的通用函数
def extract_data(json_data):
    extracted_data = []

    # 递归函数，遍历JSON结构
    def traverse_json(data):
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, list):
                    for item in value:
                        if 'DCTIME' in item and 'VALUE' in item:
                            readable_time = convert_dctime(int(item['DCTIME']))
                            extracted_data.append({
                                'DCTIME': readable_time,
                                'VALUE': item['VALUE'],
                                'KPI_NO': item.get('KPI_NO', 'Unknown')
                            })
                else:
                    traverse_json(value)
        elif isinstance(data, list):
            for item in data:
                traverse_json(item)

    traverse_json(json_data)
    return extracted_data

# 示例使用方法：
# json_data = your_json_data  # 加载JSON数据
# extracted_info = extract_data(json_data)
# for info in extracted_info:
#     print(info)
