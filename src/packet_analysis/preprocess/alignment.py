import pandas as pd
from datetime import datetime, timedelta
from src.packet_analysis.utils.logger_config import logger
from datetime import datetime


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


def classify_path(path):
    if 'post' in path.lower() or path == '/portal_todo_moa/api/getDataByUserId':
        return 'api_post'
    elif 'get' in path.lower():
        return 'api_get'
    elif '/static/' in path or path.endswith(('.css', '.js', '.png', '.jpg', '.gif')):
        return 'static_resource'
    elif path.endswith(('.php', '.asp', '.jsp', '.html')):
        return 'dynamic_resource'
    else:
        return 'other'


def alignment_two_paths(csv_production_output, csv_back_output, alignment_csv_file_path):
    # 读取CSV文件
    now = datetime.now().time()
    logger.info(f'alignment start {alignment_csv_file_path}')
    logger.info(f"当前开始时间: {now}")
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
        'Production_Relative_time': [],  #hyf
        'Production_Time_since_request': [],
        'Production_Processing_delay': [],  #hyf
        'Production_Transmission_delay': [],  #hyf
        'Production_Request_Packet_Length': [],
        'Production_Response_Packet_Length': [],
        'Production_Response_Total_Length': [],
        'Production_Is_zero_window': [],  #hyf
        'Production_Is_tcp_reset': [],  #hyf
        'Production_Response_Code': [],

        'Back_Sniff_time': [],
        'Back_Relative_time': [],  #hyf
        'Back_Time_since_request': [],
        'Back_Processing_delay': [],  #hyf
        'Back_Transmission_delay': [],  #hyf
        'Back_Request_Packet_Length': [],
        'Back_Response_Packet_Length': [],
        'Back_Response_Total_Length': [],
        'Back_Is_zero_window': [],  #hyf
        'Back_Is_tcp_reset': [],  #hyf
        'Back_Response_Code': [],

        'Request_type':[],
        'Time_since_request_ratio': [],
        'state': []
    }

    # 用于存储每次成功匹配的回放请求时间
    back_match_times = []
    fail1_no_best_match_requests = []
    fail2_no_match_requests = []

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
        time_threshold = min(time_diff_production * 1000000, timedelta(seconds=5))

        aligned_data['Path'].append(path2)
        aligned_data['Query'].append(query2)
        aligned_data['Src_Port'].append(src_port2)
        aligned_data['Request_Method'].append(request_method2)

        aligned_data['Production_Sniff_time'].append(sniff_time2)
        aligned_data['Production_Relative_time'].append(
            production_df.iloc[index + 1]['Relative_time'])  #hyf
        aligned_data['Production_Time_since_request'].append(time_since_request2)
        aligned_data['Production_Processing_delay'].append(
            production_df.iloc[index + 1]['Processing_delay'])  #hyf
        aligned_data['Production_Transmission_delay'].append(
            production_df.iloc[index + 1]['Transmission_delay'])  #hyf
        aligned_data['Production_Request_Packet_Length'].append(
            production_df.iloc[index + 1]['Request_Packet_Length'])
        aligned_data['Production_Response_Packet_Length'].append(
            production_df.iloc[index + 1]['Response_Packet_Length'])
        aligned_data['Production_Response_Total_Length'].append(
            production_df.iloc[index + 1]['Response_Total_Length'])
        aligned_data['Production_Is_zero_window'].append(
            production_df.iloc[index + 1]['Is_zero_window'])  #hyf
        aligned_data['Production_Is_tcp_reset'].append(
            production_df.iloc[index + 1]['Is_tcp_reset'])  #hyf
        aligned_data['Production_Response_Code'].append(production_df.iloc[index + 1]['Response_code'])
        aligned_data['Request_type'].append(classify_path(path2)) #添加分类列

       #随着包数量的增减，回放环境中未配对的请求累计会越来越多，需要调整读取的数量
       #方法一 if判断条件 由包的数量决定读取的数量
        # if index < 100000:
        #     subset_back_df = back_df.iloc[:5000]
        # elif index < 200000:
        #     subset_back_df = back_df.iloc[:10000]
        # elif index < 300000:
        #     subset_back_df = back_df.iloc[:12000]
        # elif index < 400000:
        #     subset_back_df = back_df.iloc[:16000]
        # else:
        #     subset_back_df = back_df.iloc[:20000]  # 只取前20000行 结果ok、前5000测试

        #方法二 匹配失败的数量+固定5000个
        rows_to_select = len(fail1_no_best_match_requests) + len(fail2_no_match_requests) + 500
        subset_back_df = back_df.iloc[:rows_to_select]
        

        #场景一 生产和回放的源端口号一致，可以作为精准对齐的条件
        # if pd.isna(query2):
        #     back_match = subset_back_df[(subset_back_df['Path'] == path2) & (subset_back_df['Src_Port'] == src_port2)]
        # else:
        #     back_match = subset_back_df[(subset_back_df['Path'] == path2) & (subset_back_df['Query'] == query2) & (
        #             subset_back_df['Src_Port'] == src_port2)]

        #场景二 生产和回放的源端口号不一致，无法精准对齐，只能基于path+query粗略对齐
        if pd.isna(query2):
            back_match = subset_back_df[subset_back_df['Path'] == path2]
        else:
            back_match = subset_back_df[(subset_back_df['Path'] == path2) & (subset_back_df['Query'] == query2)]

        # 如果生产回放对齐有匹配，先初始化没有最佳匹配，时间间隔为最大
        if not back_match.empty:
            best_match = None
            no_best_match = None #hyf
            smallest_time_diff = timedelta.max

            if not back_match_times:  # 如果 back_match_times 为空，直接将 back_match 数据集的第一行作为最佳匹配（因为没有其他记录可以比较）
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
                        elif time_diff_to_last < smallest_time_diff: #hyf elif
                            smallest_time_diff = time_diff_to_last
                            no_best_match = back_row

                    if best_match is not None:
                        break
           
            #情况1 生产请求有匹配，且在时间范围内，是最佳匹配
            if best_match is not None:
                back_sniff_time2 = best_match['Sniff_time']
                back_time_since_request2 = best_match['Time_since_request']
                ratio = back_time_since_request2 / time_since_request2 if time_since_request2 != 0 else 'Infinity'

                aligned_data['Back_Sniff_time'].append(back_sniff_time2)
                aligned_data['Back_Relative_time'].append(best_match['Relative_time']) #hyf
                aligned_data['Back_Time_since_request'].append(back_time_since_request2)
                aligned_data['Back_Processing_delay'].append(best_match['Processing_delay']) #hyf
                aligned_data['Back_Transmission_delay'].append(best_match['Transmission_delay']) #hyf
                aligned_data['Back_Request_Packet_Length'].append(best_match['Request_Packet_Length'])
                aligned_data['Back_Response_Packet_Length'].append(best_match['Response_Packet_Length'])
                aligned_data['Back_Response_Total_Length'].append(best_match['Response_Total_Length'])
                aligned_data['Back_Is_zero_window'].append(best_match['Is_zero_window']) #hyf
                aligned_data['Back_Is_tcp_reset'].append(best_match['Is_tcp_reset']) #hyf
                aligned_data['Back_Response_Code'].append(best_match['Response_code'])

                aligned_data['Time_since_request_ratio'].append(ratio)
                aligned_data['state'].append("success")

                back_match_times.append(parse_time(back_sniff_time2))
                back_df = back_df.drop(best_match.name)
            else:
                # 情况2：回放环境有匹配，但没有在时间范围内的最佳匹配
                back_time_since_request2 = no_best_match['Time_since_request']
                ratio = back_time_since_request2 / time_since_request2 if time_since_request2 != 0 else 'Infinity'

                aligned_data['Back_Sniff_time'].append(no_best_match['Sniff_time'])
                aligned_data['Back_Relative_time'].append(no_best_match['Relative_time']) #hyf
                aligned_data['Back_Time_since_request'].append(no_best_match['Time_since_request'])
                aligned_data['Back_Processing_delay'].append(no_best_match['Processing_delay']) #hyf
                aligned_data['Back_Transmission_delay'].append(no_best_match['Transmission_delay']) #hyf
                aligned_data['Back_Request_Packet_Length'].append(no_best_match['Request_Packet_Length'])
                aligned_data['Back_Response_Packet_Length'].append(no_best_match['Response_Packet_Length'])
                aligned_data['Back_Response_Total_Length'].append(no_best_match['Response_Total_Length'])
                aligned_data['Back_Is_zero_window'].append(no_best_match['Is_zero_window']) #hyf
                aligned_data['Back_Is_tcp_reset'].append(no_best_match['Is_tcp_reset']) #hyf
                aligned_data['Back_Response_Code'].append(no_best_match['Response_code'])

                aligned_data['Time_since_request_ratio'].append(ratio)
                aligned_data['state'].append("fail1 no best match but has match")
                fail1_no_best_match_requests.append(path2)  #hyf

        else:
            #情况3：回放环境没有匹配 未对齐的选项列为空 hyf
            aligned_data['Back_Sniff_time'].append('')
            aligned_data['Back_Relative_time'].append('') #hyf
            aligned_data['Back_Time_since_request'].append('')
            aligned_data['Back_Processing_delay'].append('') #hyf
            aligned_data['Back_Transmission_delay'].append('') #hyf
            aligned_data['Back_Request_Packet_Length'].append('')
            aligned_data['Back_Response_Packet_Length'].append('')
            aligned_data['Back_Response_Total_Length'].append('')
            aligned_data['Back_Is_zero_window'].append('') #hyf
            aligned_data['Back_Is_tcp_reset'].append('') #hyf
            aligned_data['Back_Response_Code'].append('')

            aligned_data['Time_since_request_ratio'].append('')
            aligned_data['state'].append("fail2 no match")
            fail2_no_match_requests.append(path2) #hyf

    aligned_df = pd.DataFrame(aligned_data)
    aligned_df.to_csv(alignment_csv_file_path, index=False)
    logger.info(f'File saved to {alignment_csv_file_path}')

    now = datetime.now().time()
    logger.info(f"当前结束时间: {now}")
    return alignment_csv_file_path


# Main
if __name__ == '__main__':
    print('Do not run this script directly. Please run run.py instead.')
