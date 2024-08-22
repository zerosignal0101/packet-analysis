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
