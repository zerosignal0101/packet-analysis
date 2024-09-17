import pandas as pd


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

    def get_difference_ratio(self):
        return round(self.get_production_delay_mean() / self.get_replay_delay_mean(), 6)


class DB:
    def __init__(self, csv_production, csv_back):
        pd.options.display.float_format = '{:.6f}'.format  # 保证数值不使用科学计数法
        self.df_product = pd.read_csv(csv_production, encoding='utf-8')
        self.df_back = pd.read_csv(csv_back, encoding='utf-8')
        self.request_info_dict = {
            "/portal_todo/api/getAllUserTodoData": "接口说明：获取当前用户待办数据，需要调用OA公文查询OA公文待办，并调用待办系统获取其他系统待办",
            "/portal_todo/api/login/apmConfig": "获取APM监控配置数据(环境不同配置不同)",
            "/portal_todo/api/login/indicatorDial": "拨测接口",
            "/portal_todo/api/login/userLoginPost": "单点登录接口，门户单点待办服务，调用4A进行token认证",
            "/portal_todo/getFanweiMoreLink": "跳转OA公文更多页面，需要调用4A服务获取token",
            "/portal_todo/getIsRemarkOfTodoDataById": "获取当前待办数据状态，用于用户处理待办后回刷逻辑",
            "/portal_todo/getLinkToDataDetail": "待办跳转，获取待办详细数据，需要调用4A服务获取token",
            "/portal_todo/getSysInfoData": "页签展示，需调用OA公文接口，查看OA公文是否有待办数据",
            "/portal_todo/getUserDoneData": "调用OA公文接口获取已办数据",
            "/portal_todo/getUserRewindTime": "获取数据库配置的待办刷新时间",
            "/portal_todo/getWorkArrangementData": "调用OA公文接口获取工作安排数据",
            "/portal_todo/moa/api/countAll": "给MOA提供待办总数接口服务",
            "/portal_todo/searchDetailTodoData": "条件查询待办数据",
            "/portal_todo/static/css/db_home.css": "前端静态资源",
            "/portal_todo/static/db_home.html": "前端静态资源",
            "/portal_todo/static/img/favicon.ico": "前端静态资源",
            "/portal_todo/static/img/more_img.png": "前端静态资源",
            "/portal_todo/static/img/refresh/todo.png": "前端静态资源",
            "/portal_todo/static/js/db_home.js": "前端静态资源",
            "/portal_todo/static/js/jq/jquery-3.7.1.js": "前端静态资源",
            "/portal_todo/static/js/paging/BonreeSDK/JS.min.js": "前端静态资源",
            "/portal_todo/static/js/setting/home.js": "前端静态资源",
            "/portal_todo/static/js/Urlconf.js": "前端静态资源",
            "/portal_todo/static/setting/home.html": "前端静态资源"
        }
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
        return dataframe

    def get_function_description(self, url):
        """
        查询路径的功能描述信息，返回对应的详细说明。
        """
        if url in self.request_info_dict:
            return {"function_description": self.request_info_dict[url]}
        else:
            return {"function_description": "未查询到功能介绍"}

    def built_single_dict(self, df: df):
        df_dict = {}
        production_delay_mean = "{:.6f}".format(df.get_production_delay_mean())
        replay_delay_mean = "{:.6f}".format(df.get_replay_delay_mean())
        replay_delay_median = "{:.6f}".format(df.get_replay_delay_median())
        production_delay_median = "{:.6f}".format(df.get_production_delay_median())
        production_delay_max = "{:.6f}".format(df.get_production_delay_max())
        replay_delay_max = "{:.6f}".format(df.get_replay_delay_max())
        production_delay_min = "{:.6f}".format(df.get_production_delay_min())
        replay_delay_min = "{:.6f}".format(df.get_replay_delay_min())
        request_count = df.get_request_count()
        difference_ratio = "{:.6f}".format(df.get_difference_ratio())

        # Get additional information from the function description file
        description_info = self.get_function_description(df.url)

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

    def built_all_dict(self):
        all_df_list = []
        for url in self.get_all_path():
            df = self.built_df(url)
            all_df_list.append(self.built_single_dict(df))
        return all_df_list
