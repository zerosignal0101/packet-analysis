import os.path
import pandas as pd


def alignment_path_query(csv_production_output, csv_back_output, folder_output):
    # 读取CSV文件
    production_df = pd.read_csv(csv_production_output)
    back_df = pd.read_csv(csv_back_output)

    # 创建新的DataFrame用于存储对齐后的数据
    aligned_data = {
        'Path': [],
        'Query': [],
        'Production_Sniff_time': [],
        'Production_Time_since_request': [],
        'Production_source': [],
        'Back_Sniff_time': [],
        'Back_Time_since_request': [],
        'Back_source': []
    }

    # 遍历production_df的Path+Query列
    for index, row in production_df.iterrows():
        path = row['Path']
        query = row['Query']
        sniff_time = row['Sniff_time']
        time_since_request = row['Time_since_request']
        packet_source = row['Source']

        if pd.isna(query):  # 检测query是否为空，如为空则仅仅基于path匹配
            # 在back_df中找到匹配的Path
            back_match = back_df[back_df['Path'] == path]
        else:
            # 在back_df中找到匹配的Path+Query
            back_match = back_df[(back_df['Path'] == path) & (back_df['Query'] == query)]

        if not back_match.empty:
            # 取第一个匹配的行
            back_index = back_match.index[0]
            back_row = back_match.iloc[0]

            # 添加到对齐后的数据
            aligned_data['Path'].append(path)
            aligned_data['Query'].append(query)
            aligned_data['Production_Sniff_time'].append(sniff_time)
            aligned_data['Production_Time_since_request'].append(time_since_request)
            aligned_data['Production_source'].append(packet_source)
            aligned_data['Back_Sniff_time'].append(back_row['Sniff_time'])
            aligned_data['Back_Time_since_request'].append(back_row['Time_since_request'])
            aligned_data['Back_source'].append(back_row['Source'])

            # 从back_df中删除已匹配的行，以避免重复匹配
            back_df = back_df.drop(back_index)
        else:
            # 如果back_match为空，则添加提示信息到对齐后的数据
            aligned_data['Path'].append(path)
            aligned_data['Query'].append(query)
            aligned_data['Production_Sniff_time'].append(sniff_time)
            aligned_data['Production_Time_since_request'].append(time_since_request)
            aligned_data['Production_source'].append(packet_source)
            aligned_data['Back_Sniff_time'].append('No match found')
            aligned_data['Back_Time_since_request'].append('No match found')
            aligned_data['Back_source'].append('No match found')

    # 创建DataFrame保存对齐后的数据
    aligned_df = pd.DataFrame(aligned_data)

    # 保存到新的CSV文件
    # csv_aligned_output = os.path.join(os.path.dirname(csv_production_output), 'aligned_output.csv')
    csv_aligned_output = os.path.join(folder_output, 'aligned_output.csv')
    aligned_df.to_csv(csv_aligned_output, index=False)

    print(f'File saved to {csv_aligned_output}')

    return csv_aligned_output

# Main
if __name__ == '__main__':
    print('Do not run this script directly. Please run run.py instead.')
