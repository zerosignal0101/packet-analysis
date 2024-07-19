import gradio as gr
import os
import tempfile
from packet_analysis.preprocess import extract_to_csv  # 假设这是你的数据处理函数模块


def process_files(file1, file2):
    print(f"File 1 path: {file1.name}")
    print(f"File 2 path: {file2.name}")

    # 设置输出目录
    folder_output = 'csv_output'

    # 若没有目录，则创建
    if not os.path.exists(folder_output):
        os.makedirs(folder_output)

    # 处理数据并生成CSV文件
    csv_production_output = os.path.join(folder_output, "extracted_production_data.csv")
    csv_back_output = os.path.join(folder_output, "extracted_back_data.csv")
    extract_to_csv.preprocess_data(file1.name, csv_production_output)
    extract_to_csv.preprocess_data(file2.name, csv_back_output)

    # 返回CSV文件路径
    return csv_production_output, csv_back_output


with gr.Blocks() as demo:

    gr.Markdown("# Pcap File Processor")
    gr.Markdown("Upload two pcap files to process.")

    with gr.Row():
        file1_input = gr.File(label="Upload pcap file 1")
        file2_input = gr.File(label="Upload pcap file 2")

    process_button = gr.Button("Process Files")

    with gr.Row():
        output_production_csv = gr.File(label="Download Production CSV")
        output_back_csv = gr.File(label="Download Back CSV")

    process_button.click(process_files, inputs=[file1_input, file2_input],
                         outputs=[output_production_csv, output_back_csv])

demo.launch()
