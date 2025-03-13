import pandas as pd
import matplotlib.pyplot as plt

# Project imports
from src.packet_analysis.utils.logger_config import logger


class df:
    def __init__(self, url, request_method, back_dataframe, production_dataframe):
        self.url = url
        self.request_method = request_method
        self.data_back = back_dataframe
        self.data_production = production_dataframe

    def get_production_delay_mean(self):
        return round(self.data_production['Time_since_request'].mean(), 6)

    def get_replay_delay_mean(self):
        return round(self.data_back['Time_since_request'].mean(), 6)

    def get_replay_delay_median(self):
        return round(self.data_back['Time_since_request'].median(), 6)

    def get_production_delay_median(self):
        return round(self.data_production['Time_since_request'].median(), 6)

    def get_production_delay_max(self):
        return round(self.data_production['Time_since_request'].max(), 6)

    def get_replay_delay_max(self):
        return round(self.data_back['Time_since_request'].max(), 6)

    def get_production_delay_min(self):
        return round(self.data_production['Time_since_request'].min(), 6)

    def get_replay_delay_min(self):
        return round(self.data_back['Time_since_request'].min(), 6)

    def get_request_count(self):
        return self.data_production.shape[0]

    def get_request_count_replay(self):
        return self.data_back.shape[0]

    def get_difference_ratio(self):
        return round(self.get_replay_delay_mean() / self.get_production_delay_mean(), 6)


def load_kpi_mapping(file_path):
    kpi_mapping = {}
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            # 跳过空行和注释行
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # 按照冒号分割行内容，并去除多余空格
            kpi_no, description = map(str.strip, line.split(":", 1))
            kpi_mapping[kpi_no] = description
    return kpi_mapping


class DB:
    def __init__(self, csv_production, csv_back):
        pd.options.display.float_format = '{:.6f}'.format  # 保证数值不使用科学计数法
        self.csv_production = csv_production  # 保存文件路径
        self.csv_back = csv_back
        self.df_product = pd.read_csv(csv_production, encoding='utf-8')
        self.df_back = pd.read_csv(csv_back, encoding='utf-8')
        self.request_info_dict = load_kpi_mapping('src/packet_analysis/preprocess/api_config.txt')

        # # Debug
        # logger.info("默认请求 KPI 信息字典如下：")
        # for key, value in self.request_info_dict.items():
        #     logger.info(f"{key}: {value}")

        # self.request_info_dict = {
        #     "/portal_todo/api/getAllUserTodoData": "接口说明：获取当前用户待办数据，需要调用OA公文查询OA公文待办，并调用待办系统获取其他系统待办",
        #     "/portal_todo/api/login/apmConfig": "获取APM监控配置数据(环境不同配置不同)",
        #     "/portal_todo/api/login/indicatorDial": "拨测接口",
        #     "/portal_todo/api/login/userLoginPost": "单点登录接口，门户单点待办服务，调用4A进行token认证",
        #     "/portal_todo/getFanweiMoreLink": "跳转OA公文更多页面，需要调用4A服务获取token",
        #     "/portal_todo/getIsRemarkOfTodoDataById": "获取当前待办数据状态，用于用户处理待办后回刷逻辑",
        #     "/portal_todo/getLinkToDataDetail": "待办跳转，获取待办详细数据，需要调用4A服务获取token",
        #     "/portal_todo/getSysInfoData": "页签展示，需调用OA公文接口，查看OA公文是否有待办数据",
        #     "/portal_todo/getUserDoneData": "调用OA公文接口获取已办数据",
        #     "/portal_todo/getUserRewindTime": "获取数据库配置的待办刷新时间",
        #     "/portal_todo/getWorkArrangementData": "调用OA公文接口获取工作安排数据",
        #     "/portal_todo/moa/api/countAll": "给MOA提供待办总数接口服务",
        #     "/portal_todo/searchDetailTodoData": "条件查询待办数据",
        #     "/portal_todo/static/css/db_home.css": "前端静态资源",
        #     "/portal_todo/static/db_home.html": "前端静态资源",
        #     "/portal_todo/static/img/favicon.ico": "前端静态资源",
        #     "/portal_todo/static/img/more_img.png": "前端静态资源",
        #     "/portal_todo/static/img/refresh/todo.png": "前端静态资源",
        #     "/portal_todo/static/js/db_home.js": "前端静态资源",
        #     "/portal_todo/static/js/jq/jquery-3.7.1.js": "前端静态资源",
        #     "/portal_todo/static/js/paging/BonreeSDK/JS.min.js": "前端静态资源",
        #     "/portal_todo/static/js/setting/home.js": "前端静态资源",
        #     "/portal_todo/static/js/Urlconf.js": "前端静态资源",
        #     "/portal_todo/static/setting/home.html": "前端静态资源",
        #     "/customerManager/addCustomerManagerInfo": "添加客户经理信息",
        #     "/customerManager/getCustomerManagerInfo": "获取客户经理信息",
        #     "/custrela/getAllCustRelationshipByCustId": "根据客户ID获取所有客户关系信息",
        #     "/custrela/getCustomerBeanTree": "获取客户的层级树形结构",
        #     "/custrela/getCustomerTreeByName": "根据客户名称获取客户树形结构",
        #     "/custrela/getCustTowerOrg": "获取客户的塔式组织结构",
        #     "/custService/custAscriptionOpen": "开启客户归属相关服务",
        #     "/custService/custIsExist": "检查客户是否存在",
        #     "/custService/getBankInfo": "获取客户的银行信息",
        #     "/custService/getCustInfoDetail": "获取客户的详细信息",
        #     "/custService/getCustInfoTable": "获取客户信息的表格数据",
        #     "/custService/getCustInfoTableByBusinessName": "根据业务名称获取客户信息表格数据",
        #     "/custService/getCustInfoTableByCustName": "根据客户名称获取客户信息表格数据",
        #     "/custService/getCustRelationShip": "获取客户的关系信息",
        #     "/custService/insert": "插入新的客户信息",
        #     "/custService/modifyStatus": "修改客户状态",
        #     "/custService/queryCustContacApplyList": "查询客户联系人申请列表",
        #     "/custService/queryCustContacApprovalList": "查询客户联系人审批列表",
        #     "/custService/update": "更新客户信息",
        #     "/fileService/fileUpload": "上传文件",
        #     "/getDialSurveyStatus": "获取拨测调查状态",
        #     "/potentialService/insert": "插入潜在客户服务数据",
        #     "/account/addAccount": "添加账户",
        #     "/account/deleteAccount": "删除账户",
        #     "/account/getAccount": "获取账户信息",
        #     "/account/updateAccount": "更新账户信息",
        #     "/accountRole/addAccountRole": "添加账户角色",
        #     "/external/getTrustControl": "获取信任控制相关信息",
        #     "/system/checkBwdaToken": "检查 BWDA Token 是否有效",
        #     "/account/createAccountInfo": "创建账户信息",
        #     "/account/createAccountInfoForEnergy": "为能源业务创建账户信息",
        #     "/account/getAccountInfo": "获取账户信息",
        #     "/area/getArea": "获取区域信息",
        #     "/businessService/potentialBusinessAdd": "添加潜在业务信息",
        #     "/custrela/getAllCustRelationshipByCustId": "根据客户ID获取所有客户关系信息",
        #     "/custService/getBankInfo": "获取客户的银行信息",
        #     "/custService/getCustByLogno": "根据登录号获取客户信息",
        #     "/custService/getCustInfoDetail": "获取客户的详细信息",
        #     "/custService/getCustInfoTable": "获取客户信息的表格数据",
        #     "/custService/getCustInfoTableByBusinessName": "根据业务名称获取客户信息表格数据",
        #     "/custService/getCustInfoTableByCustName": "根据客户名称获取客户信息表格数据",
        #     "/custService/insert": "插入新的客户信息",
        #     "/custService/insertToc": "插入TOC类型的客户信息",
        #     "/custService/modify": "修改客户信息",
        #     "/custService/modifyStatus": "修改客户状态",
        #     "/custService/update": "更新客户信息",
        #     "/fileService/fileUpload": "上传文件",
        #     "/fourA/accountInfoSynchronization": "同步4A账户信息",
        #     "/fourA/accountRoleSynchronization": "同步4A账户角色信息",
        #     "/getDialSurveyStatus": "获取拨测调查状态",
        #     "/user/createUserInfo": "创建用户信息",
        #     "/user/getUserId": "获取用户ID",
        #     "/user/getUserIdForEnergy": "为能源业务获取用户ID"
        # }
        # self.request_info_df = pd.read_csv(request_info_file,encoding='utf-8')

    def get_all_path(self):
        unique_values = self.df_product['Path'].unique()
        unique_values_list = list(unique_values)
        return unique_values_list

    def built_df(self, url):
        df_product = self.df_product[self.df_product['Path'] == url]
        df_back = self.df_back[self.df_back['Path'] == url]

        # Extract the most frequent Request_Method for this URL
        if not df_product.empty:
            request_method = df_product['Request_Method'].mode()[0]
        else:
            request_method = None

        dataframe = df(url, request_method, df_back, df_product)
        production_delay_mean = dataframe.get_production_delay_mean()

        replay_delay_mean = dataframe.get_replay_delay_mean()

        return dataframe, production_delay_mean, replay_delay_mean

    # def get_function_description(self, url, count_pro, count_replay):
    #     """
    #     查询路径的功能描述信息，返回对应的详细说明。
    #     """
    #     if url in self.request_info_dict:
    #         return {"function_description": self.request_info_dict[url]}
    #     else:
    #         return {"function_description": "未查询到功能介绍"}

    def get_function_description(self, url, count_pro, count_replay):
        """
        查询路径的功能描述信息，返回对应的详细说明。
        参数:
            url (str): 请求的 URL 路径。
            count_pro (int): 生产环境中该 URL 请求的数量。
            count_replay (int): 回放环境中该 URL 请求的数量。
        返回:
            dict: 包含功能描述和请求数量信息的字典。
        """
        # 基础信息
        base_info = f"生产环境请求了 {count_pro} 次，回放环境请求了 {count_replay} 次。"

        # 判断是否存在功能描述
        if url in self.request_info_dict:
            description = f"该请求的功能介绍：{self.request_info_dict[url]}"
        else:
            description = "未查询到功能介绍"
        # 判断是否需要增加额外提示
        additional_info = ""
        if count_pro > 0 and count_replay > 0 and count_pro / count_replay > 2:
            additional_info = " 该请求回放环境的数据量远远不够，请仔细检查相关信息。"
        elif count_pro > 0 and count_replay > 0 and count_pro / count_replay <= 2:
            additional_info = " 该请求生产环境和回放环境数据量基本正常"

        # 返回最终信息
        return {
            "function_description": base_info + description + additional_info
        }

    # def built_single_dict(self, df: df):
    #     df_dict = {}
    #     production_delay_mean = "{:.6f}".format(df.get_production_delay_mean())
    #     replay_delay_mean = "{:.6f}".format(df.get_replay_delay_mean())
    #     replay_delay_median = "{:.6f}".format(df.get_replay_delay_median())
    #     production_delay_median = "{:.6f}".format(df.get_production_delay_median())
    #     production_delay_max = "{:.6f}".format(df.get_production_delay_max())
    #     replay_delay_max = "{:.6f}".format(df.get_replay_delay_max())
    #     production_delay_min = "{:.6f}".format(df.get_production_delay_min())
    #     replay_delay_min = "{:.6f}".format(df.get_replay_delay_min())
    #     request_count = df.get_request_count()
    #     difference_ratio = "{:.6f}".format(df.get_difference_ratio())

    #     # Get additional information from the function description file
    #     description_info = self.get_function_description(df.url)

    #     df_dict['url'] = df.url
    #     df_dict['request_method'] = df.request_method
    #     df_dict['production_delay_mean'] = production_delay_mean
    #     df_dict['replay_delay_mean'] = replay_delay_mean
    #     df_dict['production_delay_median'] = production_delay_median
    #     df_dict['replay_delay_median'] = replay_delay_median
    #     df_dict['production_delay_min'] = production_delay_min
    #     df_dict['replay_delay_min'] = replay_delay_min
    #     df_dict['production_delay_max'] = production_delay_max
    #     df_dict['replay_delay_max'] = replay_delay_max
    #     df_dict['mean_difference_ratio'] = difference_ratio
    #     df_dict['request_count'] = request_count
    #     df_dict.update(description_info)

    #     return df_dict

    def built_single_dict(self, df: df):
        def safe_format(value):
            # 如果值是 NaN 或 None，则返回 0 或其他默认值
            if pd.isna(value):
                return "0"  # 或者根据需求返回 None
            return "{:.6f}".format(value)

        df_dict = {}
        production_delay_mean = safe_format(df.get_production_delay_mean())
        replay_delay_mean = safe_format(df.get_replay_delay_mean())
        replay_delay_median = safe_format(df.get_replay_delay_median())
        production_delay_median = safe_format(df.get_production_delay_median())
        production_delay_max = safe_format(df.get_production_delay_max())
        replay_delay_max = safe_format(df.get_replay_delay_max())
        production_delay_min = safe_format(df.get_production_delay_min())
        replay_delay_min = safe_format(df.get_replay_delay_min())
        difference_ratio = safe_format(df.get_difference_ratio())

        request_count = df.get_request_count()
        request_count_replay = df.get_request_count_replay()

        # Get additional information from the function description file
        description_info = self.get_function_description(df.url, request_count, request_count_replay)

        df_dict['url'] = df.url
        df_dict['request_method'] = df.request_method
        df_dict['production_delay_mean'] = production_delay_mean
        df_dict['replay_delay_mean'] = replay_delay_mean
        df_dict['production_delay_median'] = production_delay_median
        df_dict['replay_delay_median'] = replay_delay_median
        df_dict['production_delay_min'] = production_delay_min
        df_dict['replay_delay_min'] = replay_delay_min
        df_dict['production_delay_max'] = production_delay_max
        df_dict['replay_delay_max'] = replay_delay_max
        df_dict['mean_difference_ratio'] = difference_ratio
        df_dict['request_count'] = request_count
        df_dict.update(description_info)

        return df_dict

    def get_difference_ratio_weighted(self, all_df_list):
        # 用来统计总请求数、回放时延较低的请求数和生产时延较低的请求数
        total_requests = 0
        replay_lower_count = 0
        production_lower_count = 0

        total_weighted_production_delay = 0
        total_weighted_replay_delay = 0

        # 用来加权计算
        weighted_replay = 0
        weighted_production = 0

        for df_dict in all_df_list:
            # 获取每个 URL 的信息
            difference_ratio = float(df_dict['mean_difference_ratio'])  # difference_ratio
            request_count = df_dict['request_count']  # 每种请求的数量
            production_delay_mean = float(df_dict["production_delay_mean"])
            replay_delay_mean = float(df_dict["replay_delay_mean"])

            total_requests += request_count  # 累加总请求数

            # 如果该url不存在回放请求，为保证加权平均时延的一致性，生产的也不计算了
            if replay_delay_mean != 0.0:
                total_weighted_production_delay += production_delay_mean * request_count
                total_weighted_replay_delay += replay_delay_mean * request_count
            else:
                total_weighted_production_delay += 0
                total_weighted_replay_delay += 0

            if difference_ratio >= 1:
                production_lower_count += request_count  # 生产时延较低
                weighted_production += request_count * difference_ratio  # 加权计算生产时延

            else:
                replay_lower_count += request_count  # 回放时延较低
                if difference_ratio != 0.0:
                    weighted_replay += request_count * (1 / difference_ratio)  # 加权计算回放时延
                else:
                    weighted_replay += 0

        # 计算整体加权
        weighted_average_production = weighted_production / total_requests
        weighted_average_replay = weighted_replay / total_requests

        overall_production_delay = total_weighted_production_delay / total_requests
        overall_replay_delay = total_weighted_replay_delay / total_requests

        # 得出结论
        if overall_replay_delay > overall_production_delay:
            contrast_delay_conclusion = f"生产环境整体时延较低,生产环境加权平均时延为{round(overall_production_delay, 6)}s,回放环境加权平均时延为{round(overall_replay_delay, 6)}s,生产环境时延低的权重为：{weighted_average_production}, 回放环境时延低的权重为：{weighted_average_replay},生产较快的请求数为{production_lower_count},回放较快的请求数为{replay_lower_count},总请求数为{total_requests}"
        else:
            contrast_delay_conclusion = f"回放环境整体时延较低,回放环境加权平均时延为{round(overall_replay_delay, 6)}s,生产环境加权平均时延为{round(overall_production_delay, 6)}s,回放环境时延低的权重为：{weighted_average_replay}, 生产环境时延低的权重为：{weighted_average_production},回放较快的请求数为{replay_lower_count},生产较快的请求数为{production_lower_count},总请求数为{total_requests}"

        return contrast_delay_conclusion

    def built_all_dict(self):
        all_df_list = []
        path_delay_dict = {}
        for url in self.get_all_path():
            df, production_delay_mean, replay_delay_mean = self.built_df(url)  # 先构建了一个df结构
            all_df_list.append(self.built_single_dict(df))
            path_delay_dict[url] = {
                "production_delay_mean": production_delay_mean,

                "replay_delay_mean": replay_delay_mean,

            }
        contrast_delay_conclusion = self.get_difference_ratio_weighted(all_df_list)
        return all_df_list, path_delay_dict, contrast_delay_conclusion

    def add_delay_to_df(self):
        _, path_delay_dict, _ = self.built_all_dict()

        # 遍历 path，给 self.df_product 和 self.df_back 添加平均值
        self.df_product['average_delay'] = self.df_product['Path'].map(
            lambda path: path_delay_dict.get(path, {}).get("production_delay_mean", None)
        )

        self.df_back['average_delay'] = self.df_back['Path'].map(
            lambda path: path_delay_dict.get(path, {}).get("replay_delay_mean", None)
        )

    def save_to_csv(self, file_name):
        self.add_delay_to_df()
        self.df_product.to_csv(self.csv_production, encoding='utf-8-sig', index=False)
        self.df_back.to_csv(self.csv_back, encoding='utf-8-sig', index=False)

        all_dicts, _, _ = self.built_all_dict()
        df_result = pd.DataFrame(all_dicts)
        df_result.to_csv(file_name, encoding='utf-8-sig', index=False)  # 使用'utf-8-sig'编码保证中文不乱码

    def plot_mean_difference_ratio(self, file_name):
        all_dicts, _, _ = self.built_all_dict()
        df_result = pd.DataFrame(all_dicts)

        # 将'mean_difference_ratio'转为浮点数
        df_result['mean_difference_ratio'] = df_result['mean_difference_ratio'].astype(float)

        plt.figure(figsize=(14, 8))  # 调整图片尺寸

        # 颜色：如果mean_difference_ratio小于1，则柱状图为红色，否则为蓝色
        colors = ['red' if ratio < 1 else 'blue' for ratio in df_result['mean_difference_ratio']]

        bars = plt.bar(df_result['url'], df_result['mean_difference_ratio'], color=colors)

        plt.xlabel('URL', fontsize=10)  # 调整x轴标签字体大小
        plt.ylabel('Mean Difference Ratio', fontsize=10)  # 调整y轴标签字体大小
        plt.title('Mean Difference Ratio for Each Request', fontsize=12)  # 调整标题字体大小

        plt.xticks(rotation=45, ha='right', fontsize=8)  # 旋转x轴标签并调整字体大小
        plt.tight_layout()  # 自动调整布局防止重叠

        # 在柱状图上方显示数值，调整字体大小
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width() / 2.0, height, f'{height:.2f}', ha='center', va='bottom', fontsize=8)

        plt.savefig(file_name)
        # plt.show()
