from packet_analysis.preprocess import alignment
from packet_analysis.json_build import alignment_analysis

# 指定 CSV 文件路径
file_path = 'src/test_result/aligned_data_0829test1_121012_fail1补全.csv'
save_path = 'src/test_result/1210_'


# 需要添加的内容1
# 调用 回放除以生产的处理时延，默认取前10%
# alignment_analysis.analyze_ratio_top_percentage(file_path,save_path,top_percent=0.1)

# 需要添加的内容2
# 分析状态码是否异常的函数，输出是一个txt文件，txt里面的信息需要保存到json中
# alignment_analysis.analyze_status_code(file_path, output_prefix="src/test_result/test_status_code_analysis")

# 需要添加的内容3
# 分析响应包是否有内容，是否为空
# alignment_analysis.analyze_empty_responses(file_path, output_prefix="src/test_result/empty_responses_analysis")

# 需要添加的内容3
# 分析两环境是否存在传输窗口已满的问题
# alignment_analysis.analyze_zero_window_issues(file_path, output_prefix="src/test_result/zero_window_analysis")



#对齐0829的文件
# production_csv_file_path="results/d884a3ac-e75f-494d-b79f-d2cc84eec4f9/extracted_production_data_0.csv"
# replay_csv_file_path="results/d884a3ac-e75f-494d-b79f-d2cc84eec4f9/extracted_replay_data_0.csv"
# alignment_csv_file_path="src/test_result/aligned_data_0829test1_121012_fail1补全.csv"
# alignment.alignment_two_paths(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path)

#对齐0605的文件
production_csv_file_path="results/7746e0d9-2c17-4b1b-b66c-7991d6a4c59f/extracted_production_data_0.csv"
replay_csv_file_path="results/7746e0d9-2c17-4b1b-b66c-7991d6a4c59f/extracted_replay_data_0.csv"
alignment_csv_file_path="src/test_result/aligned_data_0605test3_121215_生产直接写入-添加分类.csv"
alignment.alignment_two_paths(production_csv_file_path, replay_csv_file_path, alignment_csv_file_path)