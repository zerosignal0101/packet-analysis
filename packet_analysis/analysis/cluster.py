import os.path

import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.ensemble import IsolationForest
import matplotlib.pyplot as plt


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
    features = ['Time_since_request', 'Response_Total_Length']
    scaler = StandardScaler()
    df.loc[:, features] = scaler.fit_transform(df[features])
    return df


# 聚类分析
def cluster_data(df):
    if df.empty:
        return df
    features = ['Time_since_request', 'Response_Total_Length']
    kmeans = KMeans(n_clusters=3, n_init=10, random_state=42)
    df['cluster'] = kmeans.fit_predict(df[features])
    return df


# 异常点检测并保存异常点信息
def detect_anomalies(df, original_df, category, csv_folder_output):
    if df.empty:
        return df, None
    features = ['Time_since_request', 'Response_Total_Length']
    isolation_forest = IsolationForest(contamination=0.05, random_state=42)
    df['anomaly'] = isolation_forest.fit_predict(df[features])
    anomaly_data = original_df.loc[df[df['anomaly'] == -1].index]
    csv_save_path = os.path.join(csv_folder_output, f'{category}_anomalies.csv')
    anomaly_data.to_csv(csv_save_path, index=False)
    return df, csv_save_path


# 结果可视化
def plot_clusters(df, title, filename, plot_folder_output):
    if df.empty:
        print(f"No data to plot for {title}")
        return None
    plt.figure(figsize=(14, 7))
    scatter = plt.scatter(df['Time_since_request'], df['Response_Total_Length'],
                          c=df['cluster'], cmap='viridis', marker='o')
    plt.colorbar(scatter)
    plt.title(title)
    plt.xlabel('Time Since Request')
    plt.ylabel('Response Total Length')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plot_save_path = os.path.join(plot_folder_output, f'{filename}.png')
    plt.savefig(plot_save_path, dpi=300)
    # plt.show()
    return plot_save_path


def plot_anomalies(df, title, filename, plot_folder_output):
    if df.empty:
        print(f"No data to plot for {title}")
        return None
    plt.figure(figsize=(14, 7))
    markers = {1: 'o', -1: 'x'}
    colors = {1: 'blue', -1: 'red'}
    for anomaly, marker in markers.items():
        subset = df[df['anomaly'] == anomaly]
        plt.scatter(subset['Relative_time'], subset['Time_since_request'], c=colors[anomaly],
                    marker=marker, label=('Normal' if anomaly == 1 else 'Anomaly'))

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
    plt.xlabel('Relative Time')
    plt.ylabel('Time Since Request')
    plt.legend(loc='upper right')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plot_save_path = os.path.join(plot_folder_output, f'{filename}_anomalies.png')
    plt.savefig(plot_save_path, dpi=300)
    # plt.show()
    return plot_save_path


def analysis(csv_input, folder_output):
    ret_csv_list = []
    ret_plot_list = []
    # 读取CSV文件 当前使用这一版
    data = pd.read_csv(csv_input)

    # 数据清洗，确保关键列没有缺失值
    data = data.dropna(subset=['Path', 'Request_Method', 'Time_since_request', 'Sniff_time'])

    # 添加分类列
    data['request_type'] = data['Path'].apply(classify_path)

    # 保存分类后的数据
    csv_folder_output = os.path.join(folder_output, 'cluster_csv')

    # 检查输出文件夹是否存在
    if not os.path.exists(csv_folder_output):
        os.makedirs(csv_folder_output)

    classified_requests_csv_path = os.path.join(csv_folder_output, 'classified_requests.csv')
    data.to_csv(classified_requests_csv_path, index=False)

    # 路径返回到ret_csv_list
    ret_csv_list.append(classified_requests_csv_path)

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
    api_post_data, csv_api_post_path = detect_anomalies(api_post_data,
                                                        data[data['request_type'] == 'api_post'], 'api_post',
                                                        csv_folder_output)
    static_resource_data, csv_static_path = detect_anomalies(static_resource_data,
                                                             data[data['request_type'] == 'static_resource'],
                                                             'static_resource',
                                                             csv_folder_output)
    api_get_data, csv_api_get_path = detect_anomalies(api_get_data, data[data['request_type'] == 'api_get'], 'api_get',
                                                      csv_folder_output)
    dynamic_resource_data, csv_dynamic_path = detect_anomalies(dynamic_resource_data,
                                                               data[data['request_type'] == 'dynamic_resource'],
                                                               'dynamic_resource', csv_folder_output)
    other_data, csv_other_path = detect_anomalies(other_data, data[data['request_type'] == 'other'], 'other',
                                                  csv_folder_output)

    # 路径返回到ret_csv_list
    ret_csv_list.append(csv_api_post_path)
    ret_csv_list.append(csv_static_path)
    ret_csv_list.append(csv_api_get_path)
    ret_csv_list.append(csv_dynamic_path)
    ret_csv_list.append(csv_other_path)

    # 可视化聚类结果和异常点检测结果
    plot_folder_output = os.path.join(folder_output, 'cluster_plots')

    # check if output folder exists
    if not os.path.exists(plot_folder_output):
        os.makedirs(plot_folder_output)

    ret_plot_list.append(plot_clusters(api_post_data, 'API POST Request Clusters', 'api_post_clusters', plot_folder_output))
    ret_plot_list.append(
        plot_anomalies(api_post_data, 'API POST Request Anomalies', 'api_post_anomalies', plot_folder_output))

    ret_plot_list.append(
        plot_clusters(static_resource_data, 'Static Resource Request Clusters', 'static_resource_clusters',
                      plot_folder_output))
    ret_plot_list.append(
        plot_anomalies(static_resource_data, 'Static Resource Request Anomalies', 'static_resource_anomalies',
                       plot_folder_output))

    ret_plot_list.append(
        plot_clusters(api_get_data, 'API GET Request Clusters', 'api_get_clusters', plot_folder_output))
    ret_plot_list.append(
        plot_anomalies(api_get_data, 'API GET Request Anomalies', 'api_get_anomalies', plot_folder_output))

    ret_plot_list.append(
        plot_clusters(dynamic_resource_data, 'Dynamic Resource Request Clusters', 'dynamic_resource_clusters',
                      plot_folder_output))
    ret_plot_list.append(
        plot_anomalies(dynamic_resource_data, 'Dynamic Resource Request Anomalies', 'dynamic_resource_anomalies',
                       plot_folder_output))

    ret_plot_list.append(plot_clusters(other_data, 'Other Request Clusters', 'other_clusters', plot_folder_output))
    ret_plot_list.append(plot_anomalies(other_data, 'Other Request Anomalies', 'other_anomalies', plot_folder_output))

    return ret_csv_list, ret_plot_list


# Main
if __name__ == '__main__':
    print('Do not run this script directly. Please run run.py instead.')
