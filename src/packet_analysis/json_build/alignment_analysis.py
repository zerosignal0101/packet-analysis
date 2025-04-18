import pandas as pd
import matplotlib.pyplot as plt
from scipy.stats import pearsonr

# Project imports
from src.packet_analysis.utils.logger_config import logger


def analyze_ratio_top_percentage(file_path, save_path,top_percent=0.1, time_column='Time_since_request_ratio', back_time_column='Back_Sniff_time', path_column='Path'):
    """
    分析指定数据列的前百分比数据规律并可视化分布。
    
    参数：
        file_path: str，输入数据文件的路径。
        save_path:str,保存文件路径
        time_column: str，用于筛选的列名（数值型）。
        back_time_column: str，时间列名（用于绘制时间分布图）。
        path_column: str，表示路径的列名。
        top_percent: float，筛选的前百分比（默认10%）。        
    """
    # 第一步：读取数据文件
    data = pd.read_csv(file_path)
    
    # 第二步：清理数据，确保 time_column 为浮点数类型
    data[time_column] = pd.to_numeric(data[time_column], errors='coerce')
    data = data.dropna(subset=[time_column])  # 移除无法转换为数值的行
    
    # 第三步：计算前 top_percent 数据的行数
    top_n = int(len(data) * top_percent)
    
    # 第四步：取出 time_column 最大的前 top_n 行数据
    top_data = data.nlargest(top_n, time_column)
    
    # 第五步：分析这些数据的 Path 分布规律
    path_counts = top_data[path_column].value_counts()
    total_path_counts = data[path_column].value_counts()
    top_path_ratio = (path_counts / total_path_counts).fillna(0)
    
    top_path_ratio_with_count = pd.DataFrame({
        'total_count': total_path_counts,
        'top_count':path_counts,
        'ratio': top_path_ratio
    }).sort_values(by='ratio', ascending=False)
    # 控制台显示前 10 个结果
    top_n_display = 10  # 设置显示的条目数
    logger.info("每种 Path 中前 {0:.0%} {1} 数据的数量和占比（前 {2} 项）：".format(top_percent, time_column, top_n_display))
    logger.info(top_path_ratio_with_count.head(top_n_display))
    # 将完整数据保存到 CSV 文件
    top_path_ratio_with_count.to_csv(f'{save_path}top_path_ratio_with_count.csv', header=True)
    logger.info(f"完整数量和占比数据已保存到 {f'{save_path}top_path_ratio_with_count.csv'}")
  
    # 第七步：绘制时间分布图
    top_data[back_time_column] = pd.to_datetime(top_data[back_time_column], errors='coerce')
    top_data = top_data.dropna(subset=[back_time_column])  # 移除无效时间数据
    plt.figure(figsize=(12, 6))
    plt.scatter(top_data[back_time_column], top_data[time_column], alpha=0.7, label="Top {0:.0%} Data".format(top_percent))
    plt.title("Time Distribution of Top {0:.0%} {1}".format(top_percent, time_column))
    plt.xlabel(back_time_column)
    plt.ylabel(time_column)
    plt.legend()
    plt.grid()
    # plt.show()
    # 保存图片到指定路径
    plt.savefig(f'{save_path}top_percentage_analysis.png', dpi=300, bbox_inches='tight')  # 保存图片
    plt.close()  # 关闭绘图对象



    # 将时间转换为分钟级别，减少横轴数据点
    top_data['time_group'] = top_data[back_time_column].dt.floor('5T')  # 按分钟聚合

    # 按时间分组统计数据点数和平均值
    time_distribution = top_data.groupby('time_group')[time_column].agg(['count', 'mean']).reset_index()

    # 绘制直方图和折线图
    plt.figure(figsize=(14, 7))

    # 子图 1：直方图显示每分钟的数据点数量
    plt.subplot(2, 1, 1)
    plt.bar(time_distribution['time_group'], time_distribution['count'], color='skyblue', alpha=0.7)
    plt.title("Data Point Count Over Time (Grouped by Minute)")
    plt.xlabel("Time (Minute)")
    plt.ylabel("Data Point Count")
    plt.xticks(rotation=45)

    # 子图 2：折线图显示每分钟的平均比值
    plt.subplot(2, 1, 2)
    plt.plot(time_distribution['time_group'], time_distribution['mean'], marker='o', color='orange')
    plt.title("Average Time_since_request_ratio Over Time (Grouped by Minute)")
    plt.xlabel("Time (Minute)")
    plt.ylabel("Average Time_since_request_ratio")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(f'{save_path}time_distribution_analysis.png', dpi=300)
    # plt.show()

status_code_descriptions = {
    206: "客户端请求一个资源的部分数据，而不是整个资源，响应的body数据是整块数据的片段,服务器返回206状态码",
    302: "指示所请求的资源已移动到由Location响应头给定的 URL，浏览器会自动重新访问到这个页面",
    304: "客户端请求的资源至上次取得后，服务端并未更改，直接用本地缓存。生产环境多是静态资源类请求，采取了缓存机制；回放环境则是采取了gzip压缩来传输静态资源，没有缓存",
    400: "客户端请求有语法错误，不能被服务器所理解",
    403: "禁止访问，服务器收到请求，但是拒绝提供服务，比如：没有权限访问相关资源",
    404: "找不到网页,请求资源不存在，一般是URL输入有误，或者网站资源被删除了",
    405: "请求方式有误，比如应该用GET请求方式的资源，用了POST",
    428: "服务器要求有条件的请求，告诉客户端要想访问该资源，必须携带特定的请求头",
    429: "指示用户在给定时间内发送了太多请求（“限速”），配合 Retry-After(多长时间后可以请求)响应头一起使用",
    431: "请求头太大，服务器不愿意处理请求，因为它的头部字段太大。请求可以在减少请求头域的大小后重新提交。",
    500: "服务器发生不可预期的错误。建议查看日志",
    502: "服务器作为网关或者代理时出现的错误，服务器本身服务正常，但访问的后端服务器发生了错误",
    503: "服务器尚未准备好处理请求，服务器刚刚启动，还未初始化好",
    
    # 添加其他状态码
}

status_code_solutions = {
    206: "如果服务器配置不正确，可能导致只返回部分内容。检查服务器配置，确保响应头`Accept-Ranges`设置正确，并且客户端请求包含`Range`请求头。",
    302: "检查重定向链是否过长或循环重定向。优化URL重写规则，确保重定向目标URL是正确的，并且客户端能够正确处理重定向。",
    304: "检查服务器配置，确保`Last-Modified`或`ETag`响应头正确设置。对于回放环境，检查是否正确配置了gzip压缩和缓存策略。",
    400: "审查API文档，确保客户端请求与API要求一致。如果问题持续存在，考虑增加输入验证和错误处理逻辑。",
    403: "检查权限配置，确保正确的用户和角色权限设置。对于敏感资源，增加审计日志以追踪权限问题。",
    404: "审查网站地图和路由配置，确保所有资源都正确映射。对于动态内容，确保数据库和后端服务能够正确响应请求。",
    405: "检查路由和控制器配置，确保正确的HTTP方法被允许。对于RESTful API，确保方法正确映射到资源。",
    428: "检查客户端请求头，确保包含正确的`If-Match`或`If-None-Match`。服务器端，确保正确处理条件请求。",
    429: "优化限流策略，确保`Retry-After`响应头提供明确的重试时间。对于客户端，实现重试机制和速率限制。",
    431: "减少请求头大小，避免发送不必要的大请求头。服务器端，配置请求头大小限制。",
    500: "检查应用和系统日志，定位具体错误。优化错误处理和异常捕获，确保问题能够被正确记录和处理。",
    502: "检查后端服务健康检查机制，确保网关能够正确处理后端服务失败。优化超时设置和故障转移策略。",
    503: "优化服务器启动脚本，确保依赖服务按顺序启动。对于高流量服务，考虑增加服务器预热和负载均衡。",
}

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


def analyze_status_code(file_path, output_prefix):
    """
    分析状态码异常的请求，检查异常请求的类型、数量、分布以及详细问题总结。

    参数：
        file_path: str，输入数据文件的路径。
        output_prefix: str，输出文件的前缀名。
        status_code_descriptions: dict，状态码与其含义的映射表。
    """
    data = pd.read_csv(file_path)

    # 筛选异常状态码的请求，同时排除空值状态码
    prod_abnormal = data[(data['Production_Response_Code'] != 200) & (data['Production_Response_Code'].notna())]
    back_abnormal = data[(data['Back_Response_Code'] != 200) & (data['Back_Response_Code'].notna())]
    both_abnormal = data[
        (data['Production_Response_Code'] != 200) & 
        (data['Back_Response_Code'] != 200) & 
        (data['Production_Response_Code'].notna()) & 
        (data['Back_Response_Code'].notna())
    ]

    # 生成异常状态码的文字总结
    def summarize_abnormal(env_name, abnormal_data, response_code_column, sniff_time_column):
        summary = []
        dics = {
            "class_name":f"{env_name}异常状态码分析",
            "details":[],

        }

        # 如果 abnormal_data 为空，表示没有异常状态码
        if abnormal_data.empty:
            detail_entry = {
                "bottleneck_type": "响应状态码200，全部正常",
                "cause": "全部正常",
                "count": 0,
                "total_count": 0,
                "ratio": 0.0,
                "solution": "全部正常，无需处理",
                "request_paths": []
            }
            dics["details"].append(detail_entry)
            summary.append(f"\n环境：{env_name}\n状态码：全部正常，无异常状态码。\n")
            return "".join(summary), dics

        for code, group in abnormal_data.groupby(response_code_column):
            description = status_code_descriptions.get(code, "未知状态码")
            request_counts = group['Path'].value_counts()
            total_requests = len(abnormal_data)   

            detail_entry = {
                "bottleneck_type": str(code),
                "cause": description,
                "count": len(group),
                "total_count": total_requests,
                "ratio": round(len(group) / total_requests, 6) if total_requests > 0 else 0.0,
                "solution":status_code_solutions.get(code, "未知解决方案"),
                "request_paths": []
            }
                   
            summary.append(f"\n环境：{env_name}\n状态码 {code} ({description})：\n共有 {len(group)} 条异常请求，占总异常数的比例为 {detail_entry['ratio']}。\n")
            
            for path, count in request_counts.items():
                path_total = len(data[data['Path'] == path])
                proportion = round(count / path_total, 6) if path_total > 0 else 0.0

                detail_entry["request_paths"].append({
                    "request_url": path,
                    "class_method": classify_path(path),  # 如果有具体方法信息，可以替换此值
                    "path_abnormal_count": count,
                    "path_request_total_count": path_total,
                    "abnormal_ratio": proportion
                })

                summary.append(f"  请求路径：{path}，异常次数：{count}，占该请求总数的比例：{proportion:.2%}。\n")
            
            dics["details"].append(detail_entry)

        # 时间分布分析
        abnormal_data = abnormal_data.copy()
        abnormal_data[sniff_time_column] = pd.to_datetime(abnormal_data[sniff_time_column])
        abnormal_data['time_group'] = abnormal_data[sniff_time_column].dt.floor('5min')
        time_distribution = abnormal_data.groupby('time_group').size()
        time_distribution.to_csv(f"{output_prefix}_{env_name}_time_distribution.csv")

        return "".join(summary), dics

    # 生成生产和回放环境的异常总结
    prod_summary, pro_json = summarize_abnormal("生产环境", prod_abnormal, 'Production_Response_Code', 'Production_Sniff_time')
    back_summary, back_json = summarize_abnormal("回放环境", back_abnormal, 'Back_Response_Code', 'Back_Sniff_time')
    pro_json['env'] = 'production'
    back_json['env'] = 'replay'
    response_code=[]
    response_code.append(pro_json)
    response_code.append(back_json)


    # # 两环境均异常请求统计
    # both_summary_text = []
    # for (prod_code, back_code), group in both_abnormal.groupby(['Production_Response_Code', 'Back_Response_Code']):
    #     prod_description = status_code_descriptions.get(prod_code, "未知状态码")
    #     back_description = status_code_descriptions.get(back_code, "未知状态码")
    #     paths = group['Path'].value_counts()
    #     both_summary_text.append(f"生产环境状态码 {prod_code}  和回放环境状态码 {back_code}  同时异常，共有 {len(group)} 条请求。\n")
    #     both_summary_text.append("具体请求路径及异常次数：\n")
    #     for path, count in paths.items():
    #         both_summary_text.append(f"  请求路径：{path}，异常次数：{count}\n")
    #
    # both_summary_text = "".join(both_summary_text)
    # with open(f"{output_prefix}_summary.txt", "w", encoding="utf-8") as f:
    #     f.write(prod_summary + "\n" + back_summary + "\n两环境均异常的请求总结：\n" + both_summary_text)
    #
    # # 检查异常状态码与请求比例综合评估
    # path_summary = []
    # for path in data['Path'].unique():
    #     total_requests = len(data[data['Path'] == path])
    #     prod_issues = len(prod_abnormal[prod_abnormal['Path'] == path])
    #     back_issues = len(back_abnormal[back_abnormal['Path'] == path])
    #     both_issues = len(both_abnormal[both_abnormal['Path'] == path])
    #
    #     path_summary.append({
    #         "请求": path,
    #         "总请求数": total_requests,
    #         "生产环境异常数": prod_issues,
    #         "回放环境异常数": back_issues,
    #         "两环境均异常数": both_issues,
    #         "生产异常比例": prod_issues / total_requests if total_requests > 0 else 0,
    #         "回放异常比例": back_issues / total_requests if total_requests > 0 else 0
    #     })
    #
    # path_summary_df = pd.DataFrame(path_summary)
    # path_summary_df['异常综合指数'] = (
    #     path_summary_df['生产环境异常数'] + path_summary_df['回放环境异常数']
    # ) * (
    #     path_summary_df['生产异常比例'] + path_summary_df['回放异常比例']
    # )
    # path_summary_df.sort_values(by='异常综合指数', ascending=False, inplace=True)
    # path_summary_df.to_csv(f"{output_prefix}_path_summary.csv", index=False)
    # res = {
    #     "class_name": "response_code",
    #     "cause": prod_summary,
    #     "criteria": back_summary,
    #     "solution": both_summary_text
    # }
    # logger.info(f"文字总结已保存至 {output_prefix}_summary.txt，异常路径分析已保存至文件。")
    # # # Debug
    # # print(type(res))
    # # print(res)
    # # return res #hyf
    return response_code



def analyze_empty_responses(file_path, output_prefix, result_dict=None, result_key=None):
    """
    分析响应包为空的请求，并生成文字性结论。

    参数：
        file_path (str): 输入数据文件路径。
        output_prefix (str): 输出文件的前缀名。
        result_dict (dict, optional): 用于存储分析结果的字典。
        result_key (str, optional): 字典中存储结果的键。
    """
    data = pd.read_csv(file_path)

    # 筛选响应包为空的请求
    prod_empty = data[data['Production_Response_Total_Length'] == 0]
    back_empty = data[data['Back_Response_Total_Length'] == 0]

    conclusions = []
    empty_response = []


    for env, empty_data, sniff_time_column, response_column in [
        ("生产环境", prod_empty, 'Production_Sniff_time', 'Production_Response_Total_Length'),
        ("回放环境", back_empty, 'Back_Sniff_time', 'Back_Response_Total_Length')
    ]:

        dics = {
            "class_name": f"{env}存在某请求的响应包为空分析",
            "details": [],
        }

        # 总结总数
        total_empty = int(len(empty_data))
        total_requests = int(len(data))
        empty_ratio = float(round(total_empty / total_requests, 6)) if total_requests > 0 else 0.0
        conclusions.append(f"{env}中共有 {total_empty} 条请求响应包为空，占总请求数的 {empty_ratio}。")
        
        detail_entry = {
            "bottleneck_type": "服务器HTTP响应包异常，返回内容为空",
            "cause": "服务器内部的错误或配置问题可能导致回包为空。可能由以下情况引发：服务未启动或异常终止，路由配置错误，数据库权限限制" if total_empty > 0 else "服务器的HTTP响应包信息全部完整，不存在信息缺失的情况",
            "count": total_empty,
            "total_count": total_requests,
            "ratio": empty_ratio,
            "solution":"1. 检查对应路径的服务端日志，确认是否因为程序错误、超时或配置导致返回空响应包。\n2. 对于生产环境，建议重点排查登录和权限问题，有没有和数据库建立连接\n3. 在回放环境中，验证是否有因数据回放设置不完整导致的空响应包情况。" if total_empty > 0 else "HTTP响应数据全部完整，无需特别处理。",
            "request_paths": []
        }

        # 按请求路径统计
        path_counts = empty_data['Path'].value_counts()
        total_path_counts = data['Path'].value_counts()
        detailed_summary = []
        for path, count in path_counts.items():
            total_count = total_path_counts.get(path, 0)
            percentage = round(count / total_count, 6) if total_count > 0 else 0.0
            detailed_summary.append(f"请求路径 {path}: {count} 条，占该路径总请求数的 {percentage:.2%}。")
            detail_entry["request_paths"].append({
                "request_url": path,
                "class_method": classify_path(path),  # 如果有具体方法信息，可以替换此值
                "path_abnormal_count": int(count),
                "path_request_total_count": int(total_count),
                "abnormal_ratio": float(percentage)
            })
        dics["details"].append(detail_entry)

        empty_response.append(dics)

        conclusions.append(f"{env}中响应包为空的请求分布情况如下：\n" + "\n".join(detailed_summary))

        # 保存统计数据到文件
        path_counts.to_csv(f"{output_prefix}_{env}_empty_response_counts.csv")
        empty_data[sniff_time_column] = pd.to_datetime(empty_data[sniff_time_column])
        empty_data['time_group'] = empty_data[sniff_time_column].dt.floor('5min')
        time_distribution = empty_data.groupby('time_group').size()
        time_distribution.to_csv(f"{output_prefix}_{env}_empty_response_time_distribution.csv")

    # 添加建议
    conclusions.append("\n**建议：**")
    conclusions.append("1. 检查对应路径的服务端日志，确认是否因为程序错误、超时或配置导致返回空响应包。")
    conclusions.append("2. 对于生产环境，建议重点排查登录和权限问题，有没有和数据库建立连接")
    conclusions.append("3. 在回放环境中，验证是否有因数据回放设置不完整导致的空响应包情况。")

    # 输出总结到文件
    summary_path = f"{output_prefix}_empty_response_summary.txt"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(conclusions))
    logger.info(f"文字总结已保存至 {summary_path}。")

    # 如果指定了结果字典和键，更新字典
    if result_dict is not None and result_key is not None:
        result_dict[result_key] = "\n".join(conclusions)
        logger.info(f"分析结果已填充到字典键 {result_key} 中。")

    res = {
        "class_name": "响应包为空",
        "cause": '没有响应数据',
        "criteria": "\n".join(conclusions),
        "solution": "1. 检查对应路径的服务端日志,确认是否因为程序错误、超时或配置导致返回空响应包。2. 对于生产环境,建议重点排查登录和权限问题,有没有和数据库建立连接3. 在回放环境中，验证是否有因数据回放设置不完整导致的空响应包情况。"
    }
    # return res #hyf
    return empty_response



def analyze_zero_window_issues(file_path, output_prefix, result_dict=None, result_key=None):
    """
    分析传输窗口已满问题，结合回放时延与生产时延比值进行验证，并生成文字性结论。

    参数：
        file_path (str): 输入数据文件路径。
        output_prefix (str): 输出文件的前缀名。
        result_dict (dict, optional): 用于存储分析结果的字典。
        result_key (str, optional): 字典中存储结果的键。
    """
    data = pd.read_csv(file_path)

    # 筛选生产环境和回放环境中传输窗口已满的问题
    prod_zero_window = data[data['Production_Is_zero_window'] == True]
    back_zero_window = data[data['Back_Is_zero_window'] == True]

    conclusions = []
    transmission_window = []

    for env, zero_window_data, time_ratio_column in [
        ("生产环境", prod_zero_window, 'Time_since_request_ratio'),
        ("回放环境", back_zero_window, 'Time_since_request_ratio')
    ]:
        # 总结总数
        total_zero_window = int(len(zero_window_data))
        total_requests = int(len(data))
        zero_window_ratio = float(round(total_zero_window / total_requests, 6)) if total_requests > 0 else 0.0
        conclusions.append(f"{env}中共有 {total_zero_window} 次传输窗口已满问题，占总请求数的 {zero_window_ratio}。")
        dics = {
            "class_name": f"{env}是否存在TCP传输窗口，导致响应时间变长的分析",
            "details": [],
        }
        detail_entry = {
            "bottleneck_type": "网络传输异常,TCP传输窗口为0",
            "cause": "TCP连接中接收方的接收缓冲区已满,无法接收更多数据,导致发送方停止发送数据的情况‌,会造成传输时延增大,服务器响应时间受到影响" if total_zero_window > 0 else "没有出现TCP传输窗口为0的问题",
            "count": total_zero_window,
            "total_count": total_requests,
            "ratio": zero_window_ratio,
            "solution":"1. 检查对应路径的网络状况，确认是否因带宽、负载或硬件问题导致传输窗口已满。\n2. 对生产环境，建议优化服务器端响应机制，避免发送过多数据超过接收端处理能力。\n3. 在回放环境中，确认回放机制是否准确模拟生产环境流量，并排查可能的配置问题。" if total_zero_window > 0 else "没有出现TCP传输窗口为0的问题，无需特别处理。",
            "request_paths": []
        }

        # 按请求路径统计
        path_counts = zero_window_data['Path'].value_counts()
        total_path_counts = data['Path'].value_counts()
        detailed_summary = []
        for path, count in path_counts.items():
            total_count = total_path_counts.get(path, 0)
            percentage = round(count / total_count, 6) if total_count > 0 else 0.0
            detailed_summary.append(f"请求路径 {path}: {count} 次，占该路径总请求数的 {percentage:.2%}。")
            detail_entry["request_paths"].append({
                "request_url": path,
                "class_method": classify_path(path),  # 如果有具体方法信息，可以替换此值
                "path_abnormal_count": int(count),
                "path_request_total_count": int(total_count),
                "abnormal_ratio": float(percentage)
            })
        dics["details"].append(detail_entry)
        transmission_window.append(dics)

        conclusions.append(f"{env}中传输窗口已满问题的请求分布情况如下：\n" + "\n".join(detailed_summary))

        # 检查时延比值的影响
        if not zero_window_data[time_ratio_column].empty:
            avg_time_ratio = zero_window_data[time_ratio_column].mean()
            conclusions.append(f"在发生传输窗口已满问题时，{env}中回放时延与生产时延的比值平均值为 {avg_time_ratio:.2f}。")

        # 保存统计数据到文件
        path_counts.to_csv(f"{output_prefix}_{env}_zero_window_counts.csv")
        zero_window_data[time_ratio_column].to_csv(f"{output_prefix}_{env}_time_ratio.csv", index=False)

    # 添加建议
    conclusions.append("\n**建议：**")
    conclusions.append("1. 检查对应路径的网络状况，确认是否因带宽、负载或硬件问题导致传输窗口已满。")
    conclusions.append("2. 对生产环境，建议优化服务器端响应机制，避免发送过多数据超过接收端处理能力。")
    conclusions.append("3. 在回放环境中，确认回放机制是否准确模拟生产环境流量，并排查可能的配置问题。")

    # 输出总结到文件
    summary_path = f"{output_prefix}_zero_window_summary.txt"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("\n".join(conclusions))
    logger.info(f"文字总结已保存至 {summary_path}。")

    # 如果指定了结果字典和键，更新字典
    if result_dict is not None and result_key is not None:
        result_dict[result_key] = "\n".join(conclusions)
        logger.info(f"分析结果已填充到字典键 {result_key} 中。")

    res = {
        "class_name": "网络传输瓶颈",
        "cause": '传输窗口已满使得传输等待，造成时延偏大',
        "criteria": "\n".join(conclusions),
        "solution": "1. 检查对应路径的网络状况，确认是否因带宽、负载或硬件问题导致传输窗口已满。2. 对生产环境，建议优化服务器端响应机制，避免发送过多数据超过接收端处理能力。3. 在回放环境中，确认回放机制是否准确模拟生产环境流量，并排查可能的配置问题。"
    }
    # return res #hyf
    return transmission_window




def main():
    """
    主函数，用于运行分析逻辑并接收外部参数。
    """
    # 示例参数，可以通过外部调用时传入具体值
    file_path = 'src/test_result/aligned_data_0829test1_120916_just500.csv'  # 文件路径
    time_column = 'Time_since_request_ratio'  # 筛选列
    back_time_column = 'Back_Sniff_time'  # 时间列
    path_column = 'Path'  # 路径列
    top_percent = 0.1  # 百分比筛选，默认前10%
    save_path = 'src/test_result/1210_'
    
    # 调用分析函数
    analyze_ratio_top_percentage(
        file_path=file_path,
        save_path=save_path,
        time_column=time_column,
        back_time_column=back_time_column,
        path_column=path_column,
        top_percent=top_percent
    )


# 允许此脚本直接运行时执行 main 函数
if __name__ == "__main__":
    main()
