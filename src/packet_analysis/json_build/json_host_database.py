import datetime
import json
from src.packet_analysis.utils.logger_config import logger

# 将DCTIME转换为可读的时间格式
def convert_dctime(dctime):
    # 将13位毫秒级时间戳转换为可读的日期时间格式
    timestamp_s = dctime / 1000.0
    readable_time = datetime.datetime.fromtimestamp(timestamp_s)
    return readable_time.strftime('%Y-%m-%d %H:%M:%S')

# KPI_NO 与 采集指标名称的映射关系
kpi_mapping = {
    "20200413185029": "非root用户进程数",
    "20200413185030": "活动进程数",
    "20200413185032": "当前运行队列等待运行的进程数",
    "20200413185033": "处在非中断睡眠状态的进程数",
    "20200413185034": "CPU利用率",
    "20200413185035": "内存利用率",
    "20200413185042": "1分钟平均负载",
    "20200413185044": "CPU平均等待I0率",
    "20200413185046": "中央处理器平均系统调用率",
    "20200413185059": "交换区利用率",
    "20200413185063": "等待连接数",
    "20200413185065": "关闭连接数",
    "20200413185079": "文件系统总利用率",

    "20200415181115": "当前连接数",
    "20211118174008": "当前活动会话数",
    "20200508191078": "当前会话数",
    "20210208170202": "活动会话数",
    "202303150917015": "活动线程数",
    "202303150917017": "全部会话数",
    "202303150917018": "活动会话数",
    "1710403746551": "当前数据库的连接数",
    "20240702090703": "活动会话数(铁塔)",
    "20240702090704": "会话数（铁塔）",
    "20240702090709": "阻塞会话数",
    # 更多KPI_NO映射关系可以根据需要补充
}



def extract_data(json_data):
    extracted_data = []

    # 遍历监控类型 (如 server, databases, apm)
    for monitor_type, machines in json_data.items():
        if monitor_type in ['server', 'databases']:
            # 遍历主机或数据库类型 (如 MOD_UNIX_LINUX, mysql)
            for machine_type, ips in machines.items():
                # 确保 ips 是一个字典
                if not isinstance(ips, dict):
                    print(f"Warning: {machine_type} 的值不是字典类型, 跳过处理")
                    continue

                # 遍历IP地址 (如 192.168.49.134)
                for ip_address, metrics in ips.items():
                    # 确保 metrics 是一个字典
                    if not isinstance(metrics, dict):
                        print(f"Warning: IP地址 {ip_address} 的 metrics 不是字典, 跳过处理")
                        continue

                    # 遍历每种KPI_NO的指标信息列表
                    for kpi_no, items in metrics.items():
                        # 确保 items 是一个列表
                        if not isinstance(items, list):
                            print(f"Warning: KPI_NO {kpi_no} 的 items 不是列表, 跳过处理")
                            continue

                        for item in items:
                            # 检查 'DCTIME' 和 'VALUE' 是否存在
                            if 'DCTIME' in item and 'VALUE' in item:
                                try:
                                    readable_time = convert_dctime(int(item['DCTIME']))
                                    kpi_name = kpi_mapping.get(kpi_no, '未知指标')  # 获取对应的指标名称
                                    extracted_data.append({
                                        '监控类型': monitor_type,
                                        '主机或数据库类型': machine_type,
                                        'IP地址': ip_address,
                                        'DCTIME': readable_time,
                                        'VALUE': item['VALUE'],
                                        'KPI_NO': kpi_no,
                                        '指标名称': kpi_name  # 添加指标名称
                                    })
                                except ValueError as e:
                                    print(f"Error: DCTIME 转换失败 for item: {item}, 错误信息: {e}")
                            else:
                                print(f"Warning: 缺少 'DCTIME' 或 'VALUE' in item: {item}, 跳过此条记录")

        elif monitor_type == 'apm':
            # 对于 apm 监控类型，直接将原始数据添加到输出中
            extracted_data.append({
                '监控类型': monitor_type,
                '原始数据': machines  # 将 apm 的数据原样保存
            })

    return extracted_data


# 示例使用方法
with open('../../../raw_data/生产采集collect_20240829_08301130.json', 'r', encoding='utf-8') as f:
    json_data = json.load(f)

# 提取数据
extracted_info = extract_data(json_data)

print(extracted_info)
# 输出提取到的数据
# for info in extracted_info:
#     logger.info(f'Info: {info}')
