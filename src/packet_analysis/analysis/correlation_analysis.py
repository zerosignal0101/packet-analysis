import pandas as pd
import numpy as np


# 读取CSV文件
def read_csv(file_path):
    df = pd.read_csv(file_path)
    return df


# 构建路径树结构，使用setdefault避免KeyError
def build_path_tree(df):
    # 定义一个默认的树结构
    path_tree = {'requests': [], 'children': {}}
    # 依次对每个路径做处理 每个路径来都重新走一步树结构
    for _, row in df.iterrows():
        # 跳过缺失值
        if pd.isna(row['Path']) or pd.isna(row['Time_since_request']):
            continue

        # 将路径标准化并分割成各部分 使用strip方法移除字符串两端的斜杠'/'
        path = row['Path'].strip('/').replace('//', '/').split('/')
        current_level = path_tree

        # 逐层插入路径，使用 setdefault 确保每个节点存在
        for part in path:
            current_level = current_level['children'].setdefault(part, {'requests': [], 'children': {}})
            # dict字典对象的setdefault方法。这个方法接受两个参数：键和默认值。如果字典中不存在该键，则设置该键的值为默认值
            # {'requests': [], 'children': {}}，并返回该值。如果键已经存在，则不更新字典，直接返回该键对应的值

        # 将时延信息'Time_since_request' 值添加到路径的末端节点的 requests 列表中
        current_level['requests'].append(row['Time_since_request'])

    return path_tree


# 计算统计信息，包括均值、标准差和中位数，以及请求数量
def calculate_statistics(requests):
    # 去掉nan值
    valid_requests = [req for req in requests if not pd.isna(req)]

    if not valid_requests:
        return {'mean': None, 'std': None, 'median': None, 'count': 0}
    return {
        'mean': np.mean(valid_requests) if len(valid_requests) > 0 else "no mean",
        'std': np.std(valid_requests) if len(valid_requests) > 1 else "no std",
        'median': np.median(valid_requests) if len(valid_requests) > 0 else None,
        'count': len(valid_requests)
    }


# 遍历树并计算统计信息，包括每层的累计请求数据和所有子节点的数据
def traverse_tree(path_tree, level=0, path=""):
    results = []
    # 初始化当前节点的请求数据
    current_level_requests = path_tree['requests'].copy()
    # current_level_requests变量现在持有原始列表的一个副本，对current_level_requests的修改不会影响原始的path_tree['requests']列表

    # 递归处理子节点，累积子节点的请求数据和叶子节点数量
    for child_name, child_data in path_tree['children'].items():
        # 递归遍历子树，累积子节点的请求数据
        child_results, child_requests = traverse_tree(child_data, level + 1,
                                                      f"{path}/{child_name}" if path else child_name)
        results.extend(child_results)
        current_level_requests.extend(child_requests)

    # 如果当前节点及其子节点没有任何请求数据，返回None
    if not current_level_requests:
        stats = {'mean': None, 'std': None, 'median': None, 'count': 0}
    else:
        # 计算当前节点的统计信息（基于其所有子节点的请求数据）
        stats = calculate_statistics(current_level_requests)

    current_path = path if path else '/'  # 如果路径为空，设为根路径 '/'

    # 打印调试信息
    # print(current_path)
    # print(current_level_requests)
    # print(stats)

    # 将当前路径的统计结果添加到列表
    results.append({
        'Path': current_path,
        'Level': level,
        'Mean': stats['mean'],
        'Standard Deviation': stats['std'],
        'Median': stats['median'],
        'Request Count': stats['count']
    })

    # 返回当前节点的统计结果和其所有请求数据（包括子节点的数据）
    return results, current_level_requests


# 主函数
def analyze_request_delays(file_path):
    df = read_csv(file_path)
    path_tree = build_path_tree(df)
    results, _ = traverse_tree(path_tree)

    # 转换为DataFrame并返回
    results_df = pd.DataFrame(results)
    return results_df


# 调用分析函数
file_path = '../../../results/extracted_replay_data_0.csv'
result_df = analyze_request_delays(file_path)

# 保存结果到CSV文件
result_df.to_csv('../../../results/request_delay_tree_analysis.csv', index=False)
