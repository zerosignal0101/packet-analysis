# from packet_analysis.analysis import cluster
#
#
# index = 0
# production_csv_file_path = f"results/extracted_production_data_{index}.csv"
# # production cluster
# folder_output_pro = f"results/cluster_pro_{index}"
# a,b=cluster.analysis(production_csv_file_path, folder_output_pro)
# print(a,b,type(a))
import pandas as pd

def get_anomalies(file, environment):
    df = pd.read_csv(file, encoding='utf-8')
    average = df['Time_since_request'].mean()
    details = []

    for index, row in df.iterrows():
        df_row = {}
        df_row['request_url'] = row['Path']
        df_row['request_method'] = row['Request_Method']
        df_row['env'] = environment  # 使用传入的环境参数
        df_row['class_method'] = row['request_type']
        df_row['anomaly_delay'] = row['Time_since_request']
        df_row['average_delay'] = average
        df_row['anomaly_time'] = row['Sniff_time']
        df_row['packet_position'] = "Packet " + str(row['Request_Index'])
        details.append(df_row)

    return details

def process_anomalies(file_paths, environment):
    all_details = []

    for file_path in file_paths:
        if file_path and 'anomalies' in file_path:
            print(f"Processing file: {file_path}")
            details = get_anomalies(file_path, environment)
            all_details.extend(details)
        else:
            print(f"Skipping file: {file_path}")

    return all_details

# 示例主程序
if __name__ == "__main__":
    # 输入的CSV文件路径列表和环境参数
    file_paths = [
        'results/cluster_pro_0/cluster_csv/classified_requests.csv',
        'results/cluster_pro_0/cluster_csv/api_post_anomalies.csv',
        'results/cluster_pro_0/cluster_csv/static_resource_anomalies.csv',
        'results/cluster_pro_0/cluster_csv/api_get_anomalies.csv',
        None,
        'results/cluster_pro_0/cluster_csv/other_anomalies.csv'
    ]
    environment = 'prod'  # 或 'back'

    # 处理异常数据
    all_details = process_anomalies(file_paths, environment)
    print(all_details,type(all_details))

    # 将汇总的details保存到CSV文件中
    # details_df = pd.DataFrame(all_details)
    # details_df.to_csv('all_anomalies_details.csv', index=False)
    print("Details saved to 'all_anomalies_details.csv'.")
