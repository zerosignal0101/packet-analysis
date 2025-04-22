import json
import os.path
import time
from pathlib import Path
from typing import List, Dict, Any
import logging

import pandas as pd

# Logger
logger = logging.getLogger(__name__)


def merge_analysis_results(pair_results, options) -> Dict[str, Any]:
    """
    - Combine multiple pair analysis results into a unified format
    - Calculate aggregated metrics across all pairs
    - Handle potential data format inconsistencies
    - Return merged results with comprehensive statistics

    Args:
        pair_results: List of individual pair analysis results
        options: options

    Returns:
        Merged analysis results dictionary
    """
    task_id = options.get('task_id')
    pair_num: int = options.get('pair_num')
    logger.debug(f"Options in merge process: {options}")
    # Initialize the global response with predefined values
    response = {
        "task_id": task_id,
        "individual_analysis_info": [
            {}
            for _ in range(pair_num)
        ],
        "overall_analysis_info": {
            "summary": {
                "performance_trends": "整体性能趋势，重放环境与生产相比通常表现出更高还是更低的延迟。",
                "common_bottlenecks": "识别在多次分析中观察到的任何反复出现的瓶颈（例如网络问题、数据库减速）例如：网络带宽限制和数据库查询性能是多个任务中经常出现的瓶颈。优化这些方面可显著提高性能。",
                "anomalies": "突出显示在多个单独分析中出现的任何显著异常，并注意它们是孤立的还是更广泛趋势的一部分。讨论这些异常的可能系统性原因。例如：文件上传过程中最常出现异常，表明服务器端处理或网络稳定性存在潜在问题",
                "recommendations": "根据单独的发现提供综合建议，例如应优先考虑优化工作的领域。例如：建议优先考虑数据库索引和查询优化，并探索升级网络基础设施。"
            },
            "overview": [
                {
                    "replay_task_id": result_options.get('replay_task_id'),
                    "replay_id": result_options.get('replay_id'),
                    # "text": "回放存在显著性能差异" if info.replay_task_id % 2 == 0 else "回放正常"
                    "text": generate_overview_conclusion(result_options)
                    # TODO: Add logic to determine if replay is normal or not
                }
                for result_options in pair_results
            ]
        }
    }
    try:
        production_faster_count = 0
        replay_faster_count = 0
        production_faster_modules = []
        replay_faster_modules = []
        for result_options in pair_results:
            logger.debug(f"result_options: {result_options}")
            if result_options is not None:
                index = result_options.get('pcap_info_idx')
                res = result_options.get('res')
                contrast_delay_conclusion = result_options.get('contrast_delay_conclusion')
                response['individual_analysis_info'][index] = res
                response['overall_analysis_info']['overview'][index]['text'] += contrast_delay_conclusion  # 这里是额外的内容

                # 统计时延情况
                if "生产环境整体时延较低" in contrast_delay_conclusion:
                    production_faster_count += 1
                    production_faster_modules.append(index)
                elif "回放环境整体时延较低" in contrast_delay_conclusion:
                    replay_faster_count += 1
                    replay_faster_modules.append(index)
        # 生成总结性结论
        total_modules = len(pair_results)
        trends_conclusion = f"此次任务共有{total_modules}个模块，"
        if production_faster_modules:
            trends_conclusion += f"其中模块{', '.join(map(str, production_faster_modules))}生产环境平均时延较低，"
        if replay_faster_modules:
            trends_conclusion += f"模块{', '.join(map(str, replay_faster_modules))}回放环境平均时延较低，"
        if production_faster_count > replay_faster_count:
            trends_conclusion += "整体性能对比上，生产环境快的模块较多，回放环境还需优化。"
        elif production_faster_count < replay_faster_count:
            trends_conclusion += "整体性能对比上，回放环境快的模块较多。"
        else:
            trends_conclusion += "整体性能对比上，生产和回放环境时延相当。"
        response['overall_analysis_info']['summary']['performance_trends'] = trends_conclusion
    except Exception as e:
        logger.error(f"Error occurred: {e}", exc_info=True)

    try:
        outputs_path = Path(options['task_result_path'])
        response_json_path = os.path.join(outputs_path, 'response.json')
        outputs_path.mkdir(parents=True, exist_ok=True)
        with open(response_json_path, "w", encoding="utf-8") as file:
            json.dump(response, file, ensure_ascii=False, indent=4)
        logger.info(f"Response successfully saved to {response_json_path}")
    except Exception as e:
        logger.warning(f"Failed to save response: {e}")

    return response


def generate_overview_conclusion(result_options):
    """
    生成结论信息。

    参数:
        result_options: 数据来源 options

    返回:
        str: 生成的结论信息。
    """
    # 读取生产环境和回放环境的 CSV 文件
    producer_parquet_file_path = result_options.get('producer_parquet_file_path')
    playback_parquet_file_path = result_options.get('playback_parquet_file_path')
    alignment_parquet_file_path = result_options.get('alignment_parquet_file_path')

    try:
        # 获取生产环境和回放环境的请求数量
        production_df = pd.read_parquet(producer_parquet_file_path)
        replay_df = pd.read_parquet(playback_parquet_file_path)
        production_count = len(production_df)
        replay_count = len(replay_df)

        # 生成请求数量结论
        count_conclusion = f"生产环境有 {production_count} 个请求，回放环境有 {replay_count} 个请求。"
        if max(production_count, replay_count) / min(production_count, replay_count) >= 1.2:
            count_conclusion += " 生产环境和回放环境请求数量上存在显著差异，请检查回放时间是否足够"
        else:
            count_conclusion += " 生产环境和回放环境数量上差异不大。"

        # 获取对齐结果
        aligned_df = pd.read_parquet(alignment_parquet_file_path)
        success_count = len(aligned_df[aligned_df['state'].isin(['fail1 no best match but has match', 'success'])])
        fail_count = len(aligned_df[aligned_df['state'] == 'failed'])
        total_count = success_count + fail_count
        success_ratio = success_count / total_count if total_count > 0 else 0

        # 生成对齐结论
        alignment_conclusion = f"生产环境和回放环境对齐了 {success_count} 个，失败了 {fail_count} 个，对齐成功的比例是 {success_ratio:.2%}。"
        if success_ratio >= 0.9:
            alignment_conclusion += " 生产环境和回放环境相同请求数据匹配，基本对齐。"
        else:
            alignment_conclusion += " 生产环境和回放环境相同请求数据匹配度不高，建议重新查看该模块的回放数据。"

        # 返回完整结论
        return count_conclusion + " " + alignment_conclusion

    except Exception as e:
        return f"生成结论时出错: {str(e)}"
