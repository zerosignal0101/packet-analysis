import os
from collections import defaultdict
from typing import Dict, Any
import logging
import pandas as pd

# Project imports
from src.packet_analysis.services.json_build.correlation import calc_correlation, safe_format
from src.packet_analysis.services.json_build.database import load_database_logs, match_database_logs
from src.packet_analysis.services.json_build.exception import load_exception_logs, match_exception_logs
from src.packet_analysis.services.json_build.random_forest import calc_forest_model
from src.packet_analysis.services.json_build.suggestions import (
    optimization_suggestions_correlation,
    optimization_suggestions_random_forest
)

# Logger
logger = logging.getLogger(__name__)


def general_data_analyzer(result_df: pd.DataFrame, options: Dict[str, Any]) -> Dict[str, Any]:
    side = options["side"]
    host_ip_list = options["host_ip_list"]
    host_ip_str = ", ".join(host_ip_list)
    env_en_name = "production" if side == "producer" else "replay"
    env_name = '生产' if side == 'producer' else '回放'
    json_path = options['collect_log' if side == 'producer' else 'replay_log']
    # Result
    result = {}

    # 相关性分析计算
    analysis_result_correlation = {
            "env": env_en_name,
            "hostip": host_ip_str,
            "description": f"{env_name}环境采集点的性能数据与服务器平均处理时延的相关系数",  # 新增 关于介绍谁和谁的相关系数的描述字段
            "conclusion": f"{env_name}环境中与平均处理时延相关性最强的指标是xxx",  # 新增 通过计算相关系数，给出分析结论
            "solution": "优化建议是xxx",  # 新增给出优化建议的字段
            "correlation_data": [{
                "index_id": f"{env_name}环境采集的性能数据json文件与pcap包时间不匹配，无法计算相关系数",
                "value": 9999
            }
            ]
        }
    # 路径获取
    pcap_info_idx = options["pcap_info_idx"]
    task_result_path = options["task_result_path"]
    try:
        correlation_analysis_path = os.path.join(task_result_path, f"correlation_analysis_{pcap_info_idx}")
        if not os.path.exists(correlation_analysis_path):
            os.mkdir(correlation_analysis_path)
        correlation_result_file_path = os.path.join(correlation_analysis_path, f'{env_en_name}_correlation.csv')
        kpi_result_file_path = os.path.join(correlation_analysis_path, f'{env_en_name}_kpi.csv')
        correlation_result_df = calc_correlation(json_path,
                                                 result_df,
                                                 correlation_result_file_path,
                                                 kpi_result_file_path)
        # 将 corr_df 中的 KPI名称 和 相关系数 对应到 index_id 和 value
        if not correlation_result_df.empty:
            if '相关系数' in correlation_result_df.columns and 'KPI名称' in correlation_result_df.columns:
                for index, row in correlation_result_df.iterrows():
                    if pd.notna(row['相关系数']):  # 只处理非 NaN 的相关系数
                        correlation_data = {
                            "index_id": row['KPI名称'],
                            "value": row['相关系数']
                        }
                        # 检查是否需要清除默认值
                        if len(analysis_result_correlation['correlation_data']) == 1 and \
                                analysis_result_correlation['correlation_data'][0]['value'] == 9999:
                            # 如果列表中只有默认值，清空它
                            analysis_result_correlation['correlation_data'].clear()
                            analysis_result_correlation['conclusion'] = f"{env_name}环境中与平均处理时延相关性最强的指标是{row['KPI名称']}"
                            analysis_result_correlation['solution'] = optimization_suggestions_correlation.get(row['KPI名称'],
                                                                                                       '该项指标暂无更好的优化建议')

                        # 将数据添加到 production 和 replay 的 correlation_data 中
                        analysis_result_correlation['correlation_data'].append(correlation_data)
            else:
                logger.warning(f"列 '相关系数' 或 'KPI名称' 不存在于 {env_name} DataFrame 中")
        logger.info("Correlation analysis completed")
    except Exception as e:
        logger.error(f"Correlation analysis failed: {e}")
    finally:
        result["analysis_result_correlation"] = analysis_result_correlation
    # 随机森林分析计算
    analysis_result_random_forest = {
        "env": env_en_name,
        "hostip": host_ip_str,
        "description": f"{env_name}环境采集点的性能数据与服务器平均处理时延的相关系数",  # 新增 关于介绍谁和谁的相关系数的描述字段
        "conclusion": f"{env_name}环境中与平均处理时延相关性最强的指标是xxx",  # 新增 通过计算相关系数，给出分析结论
        "solution": "优化建议是xxx",  # 新增给出优化建议的字段
        "importance_data": [{
            "index_id": "生产环境采集的性能数据json文件与pcap包时间不匹配，无法计算相关系数",
            "value": 9999
        }
        ]
    }
    performance_bottleneck_analysis = {
        "env": env_en_name,
        "hostip": host_ip_str,
        "class_name": "error warning",
        "cause": f"{env_name}环境随机森林模型建立失败，为确保顺利返回，当前为预设值，具体原因请排查",
        "criteria": f"可能是{env_name}环境采集时间不足，日志文件和数据包文件时间不匹配",
        "solution": "具体原因可以结合输出日志分析"
    }
    try:
        mse_df, importance_df = calc_forest_model(kpi_result_file_path, correlation_analysis_path, env_en_name)
        logger.info(f"{env_name}计算随机森林模型ok")
        if not importance_df.empty:
            if 'Importance' in importance_df.columns and 'KPI' in importance_df.columns:
                for index, row in importance_df.iterrows():
                    if pd.notna(row['Importance']):  # 只处理非 NaN 的相关系数
                        importance_data = {
                            "index_id": row['KPI'],
                            "value": safe_format(row['Importance'])
                        }
                        # 检查是否需要清除默认值
                        if len(analysis_result_random_forest['importance_data']) == 1 and \
                                analysis_result_random_forest['importance_data'][0]['value'] == 9999:
                            # 如果列表中只有默认值，清空它
                            analysis_result_random_forest['importance_data'].clear()
                            analysis_result_random_forest['conclusion'] = f"生产环境中重要性排序最强的指标是{row['KPI']}"
                            analysis_result_random_forest['solution'] = optimization_suggestions_random_forest.get(row['KPI'],
                                                                                                           '该项指标暂无更好的优化建议')

                        # 将数据添加到 production 和 replay 的 correlation_data 中
                        analysis_result_random_forest['importance_data'].append(importance_data)
            else:
                logger.warning("列 'Importance' 或 'KPI' 不存在于 生产 DataFrame 中")

        performance_bottleneck_analysis = {
                "env": f"瓶颈发生的环境{env_en_name}",
                "hostip": host_ip_str,
                "class_name": "该部分为扩展用的备用瓶颈结论接口，暂无输出",
                "cause": "扩展用的瓶颈原因",
                "criteria": "判断为该瓶颈的标准",
                "solution": "该瓶颈的解决方案"
            }
    except Exception as e:
        logger.error(f"Random forest analysis failed: {e}")
    finally:
        result["analysis_result_random_forest"] = analysis_result_random_forest
        result["performance_bottleneck_analysis"] = performance_bottleneck_analysis

    # 数据库异常分析
    df_list = result_df.Dataframe.to_dict()
    bottleneck_analysis_database = {
        "hostip": host_ip_str,
        "env": env_en_name,
        "class_name": f"{env_name}环境数据库日志分析",
        "details": [
            {
                "bottleneck_type": "无法正确分析",
                "cause": "可能输入数据损坏",
                "count": 9999,
                "total_count": 9999,
                "ratio": 0,
                "solution": "排查算法或数据输入问题",
                "request_paths": []
            }
        ]
    }
    # 设置执行时间阈值（单位：毫秒）
    exec_time_threshold = 400
    try:
        database_logs, database_logs_count = load_database_logs(json_path, exec_time_threshold)
        logger.info(f"{env_en_name} database logs count: {database_logs_count}")
        analysis_database_logs = match_database_logs(
            database_logs,
            df_list
        )
        database_logs_ratio = (len(analysis_database_logs) / database_logs_count) if database_logs_count else 0
        bottleneck_analysis_database = {
                "hostip": host_ip_str,
                "env": env_en_name,
                "class_name": f"{env_name}环境数据库日志分析",
                "details": [
                    {
                        "bottleneck_type": "数据库查询时间异常" if database_logs_ratio > 0.01 else "数据库部分无明显异常",
                        "cause": "异常请求影响" if database_logs_ratio > 0.01 else "-",
                        "count": len(analysis_database_logs),
                        "total_count": database_logs_count,
                        "ratio": database_logs_ratio,
                        "solution": "排查对应请求的数据库查询性能" if database_logs_ratio > 0.01 else "-",
                        "request_paths": analysis_database_logs
                    }
                ]
            }
    except Exception as e:
        logger.error(f"Database analysis failed: {e}")
    finally:
        result['bottleneck_analysis_database'] = bottleneck_analysis_database

    # Exception 异常分析
    bottleneck_analysis_exception = {
        "hostip": host_ip_str,
        "env": env_en_name,
        "class_name": f"{env_name}环境异常日志分析",
        "details": [
            {
                "bottleneck_type": "分析模块出错",
                "cause": "异常输入或算法错误",
                "total_count": 0,
                "solution": "排查算法日志或检查输入格式",
                "request_paths": []
            }
        ]
    }
    try:
        exception_logs, exception_logs_count \
            = load_exception_logs(json_path)
        analysis_exception_logs = match_exception_logs(
            exception_logs,
            df_list
        )
        logger.info(f"{env_en_name} exception logs count: {exception_logs_count}")
        bottleneck_analysis_exception = {
            "hostip": host_ip_str,
            "env": env_en_name,
            "class_name": f"{env_name}环境异常日志分析",
            "details": [
                {
                    "bottleneck_type": "数据库或模块报错",
                    "cause": "异常请求影响",
                    "total_count": exception_logs_count,
                    "solution": "排查对应程序模块功能",
                    "request_paths": analysis_exception_logs
                }
            ]
        }
    except Exception as e:
        logger.error(f"Exception analysis failed: {e}")
    finally:
        result['bottleneck_analysis_exception'] = bottleneck_analysis_exception

    # Result return
    return result
