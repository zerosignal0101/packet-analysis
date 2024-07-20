import shutil

import gradio as gr
import os
from packet_analysis.preprocess import extract_to_csv, alignment
from packet_analysis.analysis import cluster


def process_files(file1, file2):
    print(f"File 1 path: {file1.name}")
    print(f"File 2 path: {file2.name}")

    # 设置输出目录
    folder_output = 'results'

    # 若没有目录，则创建
    if not os.path.exists(folder_output):
        os.makedirs(folder_output)

    # 判断类型
    file1_extension = os.path.splitext(file1.name)[1]
    file2_extension = os.path.splitext(file2.name)[1]

    csv_production_output = os.path.join(folder_output, "extracted_production_data.csv")
    csv_back_output = os.path.join(folder_output, "extracted_back_data.csv")

    if file2_extension == '.pcap' and file1_extension == '.pcap':
        # 处理数据并生成CSV文件
        extract_to_csv.preprocess_data(file1.name, csv_production_output)
        extract_to_csv.preprocess_data(file2.name, csv_back_output)
    elif file2_extension == '.csv' and file1_extension == '.csv':
        try:
            shutil.move(file1.name, csv_production_output)
            shutil.move(file2.name, csv_back_output)
        except FileNotFoundError:
            print(f"源文件未找到")
        except PermissionError:
            print(f"权限不足，无法移动文件")
        except Exception as e:
            print(f"发生错误: {e}")

    csv_aligned_path = alignment.alignment_path_query(csv_production_output, csv_back_output, folder_output)

    cluster_folder_output = os.path.join(folder_output, 'cluster_output')

    # 如果存在cluster_folder_output，则删除
    if os.path.exists(cluster_folder_output):
        shutil.rmtree(cluster_folder_output)

    cluster_csv_production_list, cluster_plot_production_list = (
        cluster.analysis(csv_production_output, os.path.join(cluster_folder_output, 'production')))
    cluster_csv_back_list, cluster_plot_back_list = (
        cluster.analysis(csv_back_output, os.path.join(cluster_folder_output, 'back')))

    # 压缩results文件夹，并且把路径写入到compressed_path
    shutil.make_archive(folder_output, 'zip', folder_output)
    compressed_path = f'{folder_output}.zip'

    print(cluster_plot_production_list)
    print(cluster_plot_back_list)

    # 返回CSV文件路径
    return (compressed_path, csv_aligned_path, csv_production_output, csv_back_output,
            cluster_csv_production_list[0], cluster_csv_production_list[1], cluster_csv_production_list[2],
            cluster_csv_production_list[3], cluster_csv_production_list[4], cluster_csv_production_list[5],
            cluster_csv_back_list[0], cluster_csv_back_list[1], cluster_csv_back_list[2],
            cluster_csv_back_list[3], cluster_csv_back_list[4], cluster_csv_back_list[5],
            cluster_plot_production_list[0],
            cluster_plot_production_list[1], cluster_plot_production_list[2], cluster_plot_production_list[3],
            cluster_plot_production_list[4], cluster_plot_production_list[5], cluster_plot_production_list[6],
            cluster_plot_production_list[7], cluster_plot_production_list[8], cluster_plot_production_list[9],
            cluster_plot_back_list[0], cluster_plot_back_list[1],
            cluster_plot_back_list[2], cluster_plot_back_list[3], cluster_plot_back_list[4],
            cluster_plot_back_list[5], cluster_plot_back_list[6], cluster_plot_back_list[7],
            cluster_plot_back_list[8], cluster_plot_back_list[9])


with gr.Blocks() as demo:
    gr.Markdown("# Pcap File Processor")
    gr.Markdown("Upload two files to process (pcap or csv)")

    with gr.Row():
        file1_input = gr.File(label="Upload file 1 (pcap or csv)")
        file2_input = gr.File(label="Upload file 2 (pcap or csv)")

    process_button = gr.Button("Process Files")

    with gr.Row():
        with gr.Column():
            output_compressed_file = gr.File(label="Download compressed results")
            output_csv_aligned = gr.File(label="Download aligned csv results")
            output_csv_production = gr.File(label="Download extracted production csv")
            output_csv_back = gr.File(label="Download extracted back csv")
            classified_requests_production_csv = gr.File(label="Download classified requests csv (Production)")
            classified_requests_back_csv = gr.File(label="Download classified requests csv (Back)")
        with gr.Column():
            csv_production_api_post = gr.File(label="Download api post cluster csv (Production)")
            csv_production_static = gr.File(label="Download static resource cluster csv (Production)")
            csv_production_api_get = gr.File(label="Download api get cluster csv (Production)")
            csv_production_dynamic = gr.File(label="Download dynamic resource cluster csv (Production)")
            csv_production_other = gr.File(label="Download other cluster csv (Production)")
        with gr.Column():
            csv_back_api_post = gr.File(label="Download api post cluster csv (Back)")
            csv_back_static = gr.File(label="Download static resource cluster csv (Back)")
            csv_back_api_get = gr.File(label="Download api get cluster csv (Back)")
            csv_back_dynamic = gr.File(label="Download dynamic resource cluster csv (Back)")
            csv_back_other = gr.File(label="Download other cluster csv (Back)")

    # Plots for production data
    gr.Markdown("Plots for production data")
    with gr.Row():
        with gr.Column():
            plot_image_cluster_production_api_post = gr.Image(label="Production api post Cluster Plot")
            plot_image_anomalies_production_api_post = gr.Image(label="Production api post Anomalies Plot")
        with gr.Column():
            plot_image_cluster_production_static = gr.Image(label="Production static resource Cluster Plot")
            plot_image_anomalies_production_static = gr.Image(label="Production static resource Anomalies Plot")
    with gr.Row():
        with gr.Column():
            plot_image_cluster_production_api_get = gr.Image(label="Production api get Cluster Plot")
            plot_image_anomalies_production_api_get = gr.Image(label="Production api get Anomalies Plot")
        with gr.Column():
            plot_image_cluster_production_dynamic = gr.Image(label="Production dynamic resource Cluster Plot")
            plot_image_anomalies_production_dynamic = gr.Image(label="Production dynamic resource Anomalies Plot")
    with gr.Row():
        with gr.Column():
            plot_image_cluster_production_other = gr.Image(label="Production other Cluster Plot")
            plot_image_anomalies_production_other = gr.Image(label="Production other Anomalies Plot")

    # Plots for back data
    gr.Markdown("Plots for back data")
    with gr.Row():
        with gr.Column():
            plot_image_cluster_back_api_post = gr.Image(label="Back api post Cluster Plot")
            plot_image_anomalies_back_api_post = gr.Image(label="Back api post Anomalies Plot")
        with gr.Column():
            plot_image_cluster_back_static = gr.Image(label="Back static resource Cluster Plot")
            plot_image_anomalies_back_static = gr.Image(label="Back static resource Anomalies Plot")
    with gr.Row():
        with gr.Column():
            plot_image_cluster_back_api_get = gr.Image(label="Back api get Cluster Plot")
            plot_image_anomalies_back_api_get = gr.Image(label="Back api get Anomalies Plot")
        with gr.Column():
            plot_image_cluster_back_dynamic = gr.Image(label="Back dynamic resource Cluster Plot")
            plot_image_anomalies_back_dynamic = gr.Image(label="Back dynamic resource Anomalies Plot")
    with gr.Row():
        with gr.Column():
            plot_image_cluster_back_other = gr.Image(label="Back other Cluster Plot")
            plot_image_anomalies_back_other = gr.Image(label="Back other Anomalies Plot")

    process_button.click(process_files, inputs=[file1_input, file2_input],
                         outputs=[output_compressed_file, output_csv_aligned, output_csv_production, output_csv_back,
                                  classified_requests_production_csv, csv_production_api_post, csv_production_static,
                                  csv_production_api_get, csv_production_dynamic, csv_production_other,
                                  classified_requests_back_csv, csv_back_api_post, csv_back_static, csv_back_api_get,
                                  csv_back_dynamic, csv_back_other,
                                  plot_image_cluster_production_api_post, plot_image_anomalies_production_api_post,
                                  plot_image_cluster_production_static, plot_image_anomalies_production_static,
                                  plot_image_cluster_production_api_get, plot_image_anomalies_production_api_get,
                                  plot_image_cluster_production_dynamic, plot_image_anomalies_production_dynamic,
                                  plot_image_cluster_production_other, plot_image_anomalies_production_other,
                                  plot_image_cluster_back_api_post, plot_image_anomalies_back_api_post,
                                  plot_image_cluster_back_static, plot_image_anomalies_back_static,
                                  plot_image_cluster_back_api_get, plot_image_anomalies_back_api_get,
                                  plot_image_cluster_back_dynamic, plot_image_anomalies_back_dynamic,
                                  plot_image_cluster_back_other, plot_image_anomalies_back_other
                                  ])


def run():
    demo.launch(share=True)


# Main
if __name__ == '__main__':
    print('Do not run this script directly. Please run webui.py instead.')