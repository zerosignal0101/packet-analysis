import pandas as pd


class df:
    def __init__(self, url, back_dataframe, production_dataframe):
        self.url = url
        self.data_back = back_dataframe
        self.data_production = production_dataframe

    def get_production_delay_mean(self):
        return self.data_production['Time_since_request'].mean()

    def get_replay_delay_mean(self):
        return self.data_back['Time_since_request'].mean()

    def get_replay_delay_median(self):
        return self.data_back['Time_since_request'].median()

    def get_production_delay_median(self):
        return self.data_production['Time_since_request'].median()

    def get_production_delay_max(self):
        return self.data_production['Time_since_request'].max()

    def get_replay_delay_max(self):
        return self.data_back['Time_since_request'].max()

    def get_production_delay_min(self):
        return self.data_production['Time_since_request'].min()

    def get_replay_delay_min(self):
        return self.data_back['Time_since_request'].min()

    def get_request_count(self):
        return self.data_production.shape[0]

    def get_difference_ratio(self):
        return self.get_production_delay_mean() / self.get_replay_delay_mean()


class DB:
    def __init__(self, csv_production, csv_back):
        self.df_product = pd.read_csv(csv_production, encoding='utf-8')
        self.df_back = pd.read_csv(csv_back, encoding='utf-8')

    def get_all_path(self):
        unique_values = self.df_product['Path'].unique()
        unique_values_list = list(unique_values)
        return unique_values_list

    def built_df(self, url):
        df_product = self.df_product[self.df_product['Path'] == url]
        df_back = self.df_back[self.df_back['Path'] == url]
        dataframe = df(url, df_back, df_product)
        return dataframe

    def built_single_dict(self, df: df):
        df_dict = {}
        production_delay_mean = df.get_production_delay_mean()
        replay_delay_mean = df.get_replay_delay_mean()
        replay_delay_median = df.get_replay_delay_median()
        production_delay_median = df.get_production_delay_median()
        production_delay_max = df.get_production_delay_max()
        replay_delay_max = df.get_replay_delay_max()
        production_delay_min = df.get_production_delay_min()
        replay_delay_min = df.get_replay_delay_min()
        request_count = df.get_request_count()
        difference_ratio = df.get_difference_ratio()

        df_dict['url'] = df.url
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

        return df_dict

    def built_all_dict(self):
        all_df_list = []
        for url in self.get_all_path():
            df = self.built_df(url)
            all_df_list.append(self.built_single_dict(df))
        return all_df_list
