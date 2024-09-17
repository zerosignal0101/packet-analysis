import pandas as pd
from src.packet_analysis.utils.logger_config import logger


def get_anomalies(file, environment, host_ip):
    df = pd.read_csv(file, encoding='utf-8')
    average = df['Time_since_request'].mean()
    details = []

    for index, row in df.iterrows():
        df_row = {'request_url': row['Path'], 'request_method': row['Request_Method'], 'env': environment,
                  'hostip': host_ip, 'class_method': row['request_type'],
                  'anomaly_delay': "{:.6f}".format(row['Time_since_request']),
                  'average_delay': "{:.6f}".format(average), 'anomaly_time': row['Sniff_time'],
                  'packet_position': "Packet " + str(row['Request_Index'])}
        details.append(df_row)

    return details


def process_anomalies(file_paths, environment, host_ip):
    all_details = []

    for file_path in file_paths:
        if file_path and 'anomalies' in file_path:
            logger.info(f"Processing file: {file_path}")
            details = get_anomalies(file_path, environment, host_ip)
            all_details.extend(details)
        else:
            logger.info(f"Skipping file: {file_path}")

    return all_details
