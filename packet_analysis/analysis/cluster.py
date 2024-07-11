import os.path

import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt
import numpy as np


# 请求路径分类函数
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


# 特征提取与标准化
def extract_and_standardize_features(df):
    if df.empty:
        return df
    features = ['Time_since_request']
    scaler = StandardScaler()
    df.loc[:, features] = scaler.fit_transform(df[features])
    return df


# 聚类分析
def cluster_data(df):
    if df.empty:
        return df
    features = ['Time_since_request']
    kmeans = KMeans(n_clusters=3, n_init=10, random_state=42)
    df['cluster'] = kmeans.fit_predict(df[features])
    return df


# 异常点检测并保存异常点信息
def detect_anomalies(df, original_df, category):
    if df.empty:
        return df
    features = ['Time_since_request']
    isolation_forest = IsolationForest(contamination=0.05, random_state=42)
    df['anomaly'] = isolation_forest.fit_predict(df[features])
    anomaly_data = original_df.loc[df[df['anomaly'] == -1].index]
    anomaly_data.to_csv(f'{category}_anomalies.csv', index=False)
    return df


# 结果可视化
def plot_clusters(df, title, filename, plot_folder_output):
    if df.empty:
        print(f"No data to plot for {title}")
        return
    plt.figure(figsize=(14, 7))
    plt.scatter(df.index, df['Time_since_request'], c=df['cluster'], cmap='viridis', marker='o')
    plt.title(title)
    plt.xlabel('Index')
    plt.ylabel('Time Since Request')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(plot_folder_output, f'{filename}.png'), dpi=300)
    # plt.show()


def plot_anomalies(df, title, filename, plot_folder_output):
    if df.empty:
        print(f"No data to plot for {title}")
        return
    plt.figure(figsize=(14, 7))
    markers = {1: 'o', -1: 'x'}
    colors = {1: 'blue', -1: 'red'}
    for anomaly, marker in markers.items():
        subset = df[df['anomaly'] == anomaly]
        plt.scatter(subset.index, subset['Time_since_request'], c=colors[anomaly], marker=marker,
                    label=('Normal' if anomaly == 1 else 'Anomaly'))

    # 添加统计指标
    mean_value = df['Time_since_request'].mean()
    median_value = df['Time_since_request'].median()
    variance_value = df['Time_since_request'].var()

    plt.axhline(y=mean_value, color='g', linestyle='-', label=f'Mean: {mean_value:.2f}')
    plt.axhline(y=median_value, color='orange', linestyle='--', label=f'Median: {median_value:.2f}')
    plt.axhline(y=mean_value + variance_value ** 0.5, color='r', linestyle=':',
                label=f'Std Dev: {variance_value ** 0.5:.2f}')
    plt.axhline(y=mean_value - variance_value ** 0.5, color='r', linestyle=':')

    plt.title(title)
    plt.xlabel('Index')
    plt.ylabel('Time Since Request')
    plt.legend(loc='upper right')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(plot_folder_output, f'{filename}_anomalies.png'), dpi=300)
    # plt.show()


def analysis(csv_production_output, csv_back_output, folder_output):
    # 读取CSV文件 当前使用这一版
    data = pd.read_csv(csv_production_output)

    # 数据清洗，确保关键列没有缺失值
    data = data.dropna(subset=['Path', 'Request_Method', 'Time_since_request', 'Sniff_time'])

    # 添加分类列
    data['request_type'] = data['Path'].apply(classify_path)

    # 保存分类后的数据
    data.to_csv('classified_requests.csv', index=False)

    # 对每一类请求分别提取特征并标准化
    api_post_data = extract_and_standardize_features(data[data['request_type'] == 'api_post'].copy())
    static_resource_data = extract_and_standardize_features(data[data['request_type'] == 'static_resource'].copy())
    api_get_data = extract_and_standardize_features(data[data['request_type'] == 'api_get'].copy())
    dynamic_resource_data = extract_and_standardize_features(data[data['request_type'] == 'dynamic_resource'].copy())
    other_data = extract_and_standardize_features(data[data['request_type'] == 'other'].copy())

    # 对每一类请求分别进行聚类分析
    api_post_data = cluster_data(api_post_data)
    static_resource_data = cluster_data(static_resource_data)
    api_get_data = cluster_data(api_get_data)
    dynamic_resource_data = cluster_data(dynamic_resource_data)
    other_data = cluster_data(other_data)

    # 对每一类请求分别进行异常点检测
    api_post_data = detect_anomalies(api_post_data, data[data['request_type'] == 'api_post'], 'api_post')
    static_resource_data = detect_anomalies(static_resource_data, data[data['request_type'] == 'static_resource'],
                                            'static_resource')
    api_get_data = detect_anomalies(api_get_data, data[data['request_type'] == 'api_get'], 'api_get')
    dynamic_resource_data = detect_anomalies(dynamic_resource_data, data[data['request_type'] == 'dynamic_resource'],
                                             'dynamic_resource')
    other_data = detect_anomalies(other_data, data[data['request_type'] == 'other'], 'other')

    # 可视化聚类结果和异常点检测结果
    plot_folder_output = os.path.join(folder_output, 'cluster_plots')

    # check if output folder exists
    if not os.path.exists(plot_folder_output):
        os.makedirs(plot_folder_output)

    plot_clusters(api_post_data, 'API POST Request Clusters', 'api_post_clusters', plot_folder_output)
    plot_anomalies(api_post_data, 'API POST Request Anomalies', 'api_post_anomalies', plot_folder_output)

    plot_clusters(static_resource_data,
                  'Static Resource Request Clusters', 'static_resource_clusters', plot_folder_output)
    plot_anomalies(static_resource_data,
                   'Static Resource Request Anomalies', 'static_resource_anomalies', plot_folder_output)

    plot_clusters(api_get_data, 'API GET Request Clusters', 'api_get_clusters', plot_folder_output)
    plot_anomalies(api_get_data, 'API GET Request Anomalies', 'api_get_anomalies', plot_folder_output)

    plot_clusters(dynamic_resource_data,
                  'Dynamic Resource Request Clusters', 'dynamic_resource_clusters', plot_folder_output)
    plot_anomalies(dynamic_resource_data,
                   'Dynamic Resource Request Anomalies', 'dynamic_resource_anomalies', plot_folder_output)

    plot_clusters(other_data, 'Other Request Clusters', 'other_clusters', plot_folder_output)
    plot_anomalies(other_data, 'Other Request Anomalies', 'other_anomalies', plot_folder_output)


# Main
if __name__ == '__main__':
    print('Do not run this script directly. Please run run.py instead.')
