import pandas as pd
from datetime import datetime, timedelta

def parse_time(sniff_time):
    """
    尝试解析时间字符串，支持两种格式:
    - "%Y-%m-%d %H:%M:%S"
    - "%M:%S.%f"
    """
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%M:%S.%f"):
        try:
            return datetime.strptime(sniff_time, fmt)
        except ValueError:
            continue
    raise ValueError(f"时间格式不匹配: {sniff_time}")

def alignment_two_paths(csv_production_output, csv_back_output, alignment_csv_file_path):
    # 读取CSV文件
    production_df = pd.read_csv(csv_production_output)
    back_df = pd.read_csv(csv_back_output)
    # 创建新的DataFrame用于存储对齐后的数据
    aligned_data = {
        'Path': [],
        'Query': [],
        'Src_Port': [],
        'Request_Method': [],
        # 生产环境
        'Production_Sniff_time': [],
        'Production_Time_since_request': [],
        'Production_Request_Index': [],
        'Production_Response_Index': [],
        'Production_Request_Packet_Length': [],
        'Production_Response_Packet_Length': [],
        'Production_Response_Total_Length': [],
        'Production_Match_Status': [],

        'Back_Sniff_time': [],
        'Back_Time_since_request': [],
        'Back_Request_Index': [],
        'Back_Response_Index': [],
        'Back_Request_Packet_Length': [],
        'Back_Response_Packet_Length': [],
        'Back_Response_Total_Length': [],
        'Back_Match_Status': [],

        'Time_since_request_ratio': [],
        'state': []
    }

    # 用于存储每次成功匹配的回放请求时间
    back_match_times = []

    # 遍历 production_df 的每一对相邻请求
    for index in range(len(production_df) - 1):
        path1 = production_df.iloc[index]['Path']
        query1 = production_df.iloc[index]['Query']
        src_port1 = production_df.iloc[index]['Src_Port']
        request_method1 = production_df.iloc[index]['Request_Method']
        sniff_time1 = production_df.iloc[index]['Sniff_time']
        time_since_request1 = production_df.iloc[index]['Time_since_request']

        path2 = production_df.iloc[index + 1]['Path']
        query2 = production_df.iloc[index + 1]['Query']
        src_port2 = production_df.iloc[index + 1]['Src_Port']
        request_method2 = production_df.iloc[index + 1]['Request_Method']
        sniff_time2 = production_df.iloc[index + 1]['Sniff_time']
        time_since_request2 = production_df.iloc[index + 1]['Time_since_request']

        # 计算生产请求1和请求2之间的时间差，并取绝对值
        time_diff_production = abs(parse_time(sniff_time2) - parse_time(sniff_time1))
        time_threshold = min(time_diff_production * 100000000, timedelta(seconds=5))

        # 查找回放环境中生产请求2的匹配项 根据有无参数值来寻找
        if pd.isna(query2):
            back_match = back_df[(back_df['Path'] == path2) & (back_df['Src_Port'] == src_port2)]
        else:
            back_match = back_df[(back_df['Path'] == path2) & (back_df['Query'] == query2) & (back_df['Src_Port'] == src_port2)]

        # 先初始化没有最佳匹配，时间间隔为最大
        if not back_match.empty:
            best_match = None
            smallest_time_diff = timedelta.max

            if not back_match_times:    # 如果 back_match_times 为空，直接将 back_match 数据集的第一行作为最佳匹配（因为没有其他记录可以比较）
                best_match = back_match.iloc[0]
            else:
                recent_back_match_times = back_match_times[-10:]
                for back_index, back_row in back_match.iterrows():
                    back_sniff_time = back_row['Sniff_time']
                    back_sniff_time_parsed = parse_time(back_sniff_time)

                    for previous_back_sniff_time in reversed(recent_back_match_times):
                        # 计算时间差，并取绝对值
                        time_diff_to_last = abs(back_sniff_time_parsed - previous_back_sniff_time)

                        if time_diff_to_last <= time_threshold and time_diff_to_last < smallest_time_diff:
                            smallest_time_diff = time_diff_to_last
                            best_match = back_row
                            break

                    if best_match is not None:
                        break

            if best_match is not None:
                back_sniff_time2 = best_match['Sniff_time']
                back_time_since_request2 = best_match['Time_since_request']
                ratio = time_since_request2 / back_time_since_request2 if back_time_since_request2 != 0 else 'Infinity'

                # 保存匹配结果到 aligned_data
                aligned_data['Path'].append(path2)
                aligned_data['Query'].append(query2)
                aligned_data['Src_Port'].append(src_port2)
                aligned_data['Request_Method'].append(request_method2)

                aligned_data['Production_Sniff_time'].append(sniff_time2)
                aligned_data['Production_Time_since_request'].append(time_since_request2)
                aligned_data['Production_Request_Index'].append(production_df.iloc[index + 1]['Request_Index'])
                aligned_data['Production_Response_Index'].append(production_df.iloc[index + 1]['Response_Index'])
                aligned_data['Production_Request_Packet_Length'].append(production_df.iloc[index + 1]['Request_Packet_Length'])
                aligned_data['Production_Response_Packet_Length'].append(production_df.iloc[index + 1]['Response_Packet_Length'])
                aligned_data['Production_Response_Total_Length'].append(production_df.iloc[index + 1]['Response_Total_Length'])
                aligned_data['Production_Match_Status'].append(production_df.iloc[index + 1]['Match_Status'])

                aligned_data['Back_Sniff_time'].append(back_sniff_time2)
                aligned_data['Back_Time_since_request'].append(back_time_since_request2)
                aligned_data['Back_Request_Index'].append(best_match['Request_Index'])
                aligned_data['Back_Response_Index'].append(best_match['Response_Index'])
                aligned_data['Back_Request_Packet_Length'].append(best_match['Request_Packet_Length'])
                aligned_data['Back_Response_Packet_Length'].append(best_match['Response_Packet_Length'])
                aligned_data['Back_Response_Total_Length'].append(best_match['Response_Total_Length'])
                aligned_data['Back_Match_Status'].append(best_match['Match_Status'])

                aligned_data['Time_since_request_ratio'].append(ratio)
                aligned_data['state'].append("success")

                back_match_times.append(parse_time(back_sniff_time2))
                back_df = back_df.drop(best_match.name)
            else:
                # 记录没有找到匹配项
                aligned_data['Path'].append(path2)
                aligned_data['Query'].append(query2)
                aligned_data['Src_Port'].append(src_port2)
                aligned_data['Request_Method'].append(request_method2)

                aligned_data['Production_Sniff_time'].append(sniff_time2)
                aligned_data['Production_Time_since_request'].append(time_since_request2)
                aligned_data['Production_Request_Index'].append(production_df.iloc[index + 1]['Request_Index'])
                aligned_data['Production_Response_Index'].append(production_df.iloc[index + 1]['Response_Index'])
                aligned_data['Production_Request_Packet_Length'].append(production_df.iloc[index + 1]['Request_Packet_Length'])
                aligned_data['Production_Response_Packet_Length'].append(production_df.iloc[index + 1]['Response_Packet_Length'])
                aligned_data['Production_Response_Total_Length'].append(production_df.iloc[index + 1]['Response_Total_Length'])
                aligned_data['Production_Match_Status'].append(production_df.iloc[index + 1]['Match_Status'])

                aligned_data['Back_Sniff_time'].append('No match found')
                aligned_data['Back_Time_since_request'].append('No match found')
                aligned_data['Back_Request_Index'].append('No match found')
                aligned_data['Back_Response_Index'].append('No match found')
                aligned_data['Back_Request_Packet_Length'].append('No match found')
                aligned_data['Back_Response_Packet_Length'].append('No match found')
                aligned_data['Back_Response_Total_Length'].append('No match found')
                aligned_data['Back_Match_Status'].append('No match found')

                aligned_data['Time_since_request_ratio'].append('No match found')
                aligned_data['state'].append("fail1 no best match but has match")

        else:
            aligned_data['Path'].append(path2)
            aligned_data['Query'].append(query2)
            aligned_data['Src_Port'].append(src_port2)
            aligned_data['Request_Method'].append(request_method2)

            aligned_data['Production_Sniff_time'].append(sniff_time2)
            aligned_data['Production_Time_since_request'].append(time_since_request2)
            aligned_data['Production_Request_Index'].append(production_df.iloc[index + 1]['Request_Index'])
            aligned_data['Production_Response_Index'].append(production_df.iloc[index + 1]['Response_Index'])
            aligned_data['Production_Request_Packet_Length'].append(production_df.iloc[index + 1]['Request_Packet_Length'])
            aligned_data['Production_Response_Packet_Length'].append(production_df.iloc[index + 1]['Response_Packet_Length'])
            aligned_data['Production_Response_Total_Length'].append(production_df.iloc[index + 1]['Response_Total_Length'])
            aligned_data['Production_Match_Status'].append(production_df.iloc[index + 1]['Match_Status'])

            aligned_data['Back_Sniff_time'].append('No match found')
            aligned_data['Back_Time_since_request'].append('No match found')
            aligned_data['Back_Request_Index'].append('No match found')
            aligned_data['Back_Response_Index'].append('No match found')
            aligned_data['Back_Request_Packet_Length'].append('No match found')
            aligned_data['Back_Response_Packet_Length'].append('No match found')
            aligned_data['Back_Response_Total_Length'].append('No match found')
            aligned_data['Back_Match_Status'].append('No match found')

            aligned_data['Time_since_request_ratio'].append('No match found')
            aligned_data['state'].append("fail2 no match")

    aligned_df = pd.DataFrame(aligned_data)
    aligned_df.to_csv(alignment_csv_file_path, index=False)
    print(f'File saved to {alignment_csv_file_path}')
    return alignment_csv_file_path

# Main
if __name__ == '__main__':
    print('Do not run this script directly. Please run run.py instead.')
