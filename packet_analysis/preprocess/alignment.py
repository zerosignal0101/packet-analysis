import os.path

import pandas as pd


def alignment_path_query(csv_production_output, csv_back_output, alignment_csv_file_path):
    # 读取CSV文件
    production_df = pd.read_csv(csv_production_output)
    back_df = pd.read_csv(csv_back_output)

    # 创建新的DataFrame用于存储对齐后的数据
    aligned_data = {
        'Path': [],
        'Query': [],
        'Src_Port': [],
        'Request_Method': [],
        'Production_Sniff_time': [],
        'Production_Time_since_request': [],
        'Production_Request_Packet_Length': [],
        'Production_Response_Total_Length': [],
        'Production_Match_Status': [],
        'Back_Sniff_time': [],
        'Back_Time_since_request': [],
        'Back_Request_Packet_Length': [],
        'Back_Response_Total_Length': [],
        'Back_Match_Status': [],
        'Time_since_request_ratio': []  # 新增比值字段
    }

    # 遍历production_df的Path+Query+Src_Port列
    for index, row in production_df.iterrows():
        path = row['Path']
        query = row['Query']
        src_port = row['Src_Port']
        request_method = row['Request_Method']
        sniff_time = row['Sniff_time']
        time_since_request = row['Time_since_request']
        request_packet_length = row['Request_Packet_Length']
        response_total_length = row['Response_Total_Length']
        packet_match_status = row['Match_Status']

        if pd.isna(query):  # 检测query是否为空，如为空则仅仅基于path和src_port匹配
            # 在back_df中找到匹配的Path和Src_Port
            back_match = back_df[(back_df['Path'] == path) & (back_df['Src_Port'] == src_port)]
        else:
            # 在back_df中找到匹配的Path、Query和Src_Port
            back_match = back_df[
                (back_df['Path'] == path) & (back_df['Query'] == query) & (back_df['Src_Port'] == src_port)]

        if not back_match.empty:
            # 取第一个匹配的行
            back_index = back_match.index[0]
            back_row = back_match.iloc[0]

            # 计算Time_since_request的比值
            back_time_since_request = back_row['Time_since_request']
            if back_time_since_request != 0:  # 避免除以零
                ratio = time_since_request / back_time_since_request
            else:
                ratio = 'Infinity'  # 如果回放时间为零，用“Infinity”表示

            # 添加到对齐后的数据
            aligned_data['Path'].append(path)
            aligned_data['Query'].append(query)
            aligned_data['Src_Port'].append(src_port)
            aligned_data['Request_Method'].append(request_method)
            aligned_data['Production_Sniff_time'].append(sniff_time)
            aligned_data['Production_Time_since_request'].append(time_since_request)
            aligned_data['Production_Request_Packet_Length'].append(request_packet_length)
            aligned_data['Production_Response_Total_Length'].append(response_total_length)
            aligned_data['Production_Match_Status'].append(packet_match_status)
            aligned_data['Back_Sniff_time'].append(back_row['Sniff_time'])
            aligned_data['Back_Time_since_request'].append(back_row['Time_since_request'])
            aligned_data['Back_Request_Packet_Length'].append(back_row['Request_Packet_Length'])
            aligned_data['Back_Response_Total_Length'].append(back_row['Response_Total_Length'])
            aligned_data['Back_Match_Status'].append(back_row['Match_Status'])
            aligned_data['Time_since_request_ratio'].append(ratio)

            # 从back_df中删除已匹配的行，以避免重复匹配
            back_df = back_df.drop(back_index)
        else:
            # 如果back_match为空，则添加提示信息到对齐后的数据
            aligned_data['Path'].append(path)
            aligned_data['Query'].append(query)
            aligned_data['Src_Port'].append(src_port)
            aligned_data['Request_Method'].append(request_method)
            aligned_data['Production_Sniff_time'].append(sniff_time)
            aligned_data['Production_Time_since_request'].append(time_since_request)
            aligned_data['Production_Request_Packet_Length'].append(request_packet_length)
            aligned_data['Production_Response_Total_Length'].append(response_total_length)
            aligned_data['Production_Match_Status'].append(packet_match_status)
            aligned_data['Back_Sniff_time'].append('No match found')
            aligned_data['Back_Time_since_request'].append('No match found')
            aligned_data['Back_Request_Packet_Length'].append('No match found')
            aligned_data['Back_Response_Total_Length'].append('No match found')
            aligned_data['Back_Match_Status'].append('No match found')
            aligned_data['Time_since_request_ratio'].append('No match found')

    # 创建DataFrame保存对齐后的数据
    aligned_df = pd.DataFrame(aligned_data)

    # 保存到新的CSV文件
    aligned_df.to_csv(alignment_csv_file_path, index=False)

    print(f'File saved to {alignment_csv_file_path}')

    return alignment_csv_file_path


# Main
if __name__ == '__main__':
    print('Do not run this script directly. Please run run.py instead.')
