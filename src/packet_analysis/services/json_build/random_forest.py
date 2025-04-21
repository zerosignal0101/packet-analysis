import os
import logging
import pandas as pd
from sklearn.ensemble import RandomForestRegressor
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error
from sklearn.preprocessing import StandardScaler

# Logger
logger = logging.getLogger(__name__)


def calc_forest_model(file_path, results_path='results/', csv_prefix=''):
    # Step 1: 加载数据并处理特征和目标变量
    df = pd.read_csv(file_path)

    # 选择奇数列作为特征，最后一列作为目标变量
    X = df.iloc[:, ::2]  # 奇数列
    y = df.iloc[:, -1]  # 最后一列

    # 去除缺失值，以确保特征和目标变量维度一致
    data = pd.concat([X, y], axis=1).dropna()
    X = data.iloc[:, :-1]  # 更新后的特征矩阵
    y = data.iloc[:, -1]  # 更新后的目标变量

    # Step 2: 数据归一化
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Step 3: 分割训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.2, random_state=42)

    # Step 4: 创建随机森林回归模型并进行训练
    rf_model = RandomForestRegressor(n_estimators=100, random_state=42)
    rf_model.fit(X_train, y_train)

    # Step 5: 计算特征重要性
    feature_importances = rf_model.feature_importances_
    importances_df = pd.DataFrame({'KPI': X.columns, 'Importance': feature_importances})
    importances_df = importances_df.sort_values(by='Importance', ascending=False)

    # 打印特征重要性
    logger.info("KPI 随机森林模型计算结果：")
    for index, row in importances_df:
        logger.info(f"KPI: {row['KPI']}, Importance: {row['Importance']}")

    # Step 6: 评估模型性能
    y_pred_rf = rf_model.predict(X_test)
    mse_rf = mean_squared_error(y_test, y_pred_rf)
    logger.info(f"随机森林的均方误差(MSE): {mse_rf}")

    # Step 7: 保存特征重要性和MSE到CSV文件
    importances_df.to_csv(os.path.join(results_path, f'{csv_prefix}_kpi_feature_importances.csv'), index=False, float_format='%.6f',
                          encoding='utf-8-sig')

    # 将MSE写入一个单独的CSV文件
    mse_df = pd.DataFrame({'Metric': ['Mean Squared Error (MSE)'], 'Value': [mse_rf]})
    mse_df.to_csv(os.path.join(results_path, f'{csv_prefix}_kpi_forest_mse_df.csv'), index=False, float_format='%.6f',
                  encoding='utf-8-sig')

    # # Step 8: 可视化特征重要性并保存图表
    # # 设置字体以防止中文乱码
    # plt.rcParams['font.sans-serif'] = ['SimHei']  # 使用黑体
    # plt.rcParams['axes.unicode_minus'] = False  # 解决负号显示问题
    #
    # # 绘制特征重要性的柱状图
    # plt.figure(figsize=(10, 6))
    # plt.barh(importances_df['KPI'], importances_df['Importance'])
    # plt.xlabel('Importance')
    # plt.ylabel('KPI')
    # plt.title('随机森林特征重要性')
    # plt.gca().invert_yaxis()  # 使重要性高的特征排在最上面
    #
    # # 保存图表
    # plt.savefig(os.path.join(results_path, f'{csv_prefix}_kpi_feature_importances.png'), format='png', dpi=300)
    # # plt.show()
    logger.info("随机森林模块已跳过 Plot 过程")

    return mse_rf, importances_df
