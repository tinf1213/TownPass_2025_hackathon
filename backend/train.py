import arff
import pandas as pd
import os
from pandas.core.frame import DataFrame
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib

trainDataPath = 'Training Dataset.arff'

def loadFile():
    # 讀取檔案
    data = arff.load(open(trainDataPath, "r"))
    # 轉成 pandas DataFrame
    df = pd.DataFrame(data['data'], columns=[attr[0] for attr in data['attributes']])
    # 顯示前幾列確認
    # print(df.head())
    
    return df

def PreProcessing(dataset:DataFrame):
    print(f'columns before: {len(dataset.columns)}')
    dataset = dataset.drop(columns=['web_traffic', 'Page_Rank', 'Google_Index', 'Links_pointing_to_page', 'Statistical_report'])
    print(f'columns after: {len(dataset.columns)}')
    return dataset

def TrainTestSplit(dataset:DataFrame):
    X = dataset.drop(columns=['Result'])
    y = dataset['Result']
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,        # 測試集佔 20%
        random_state=42,      # 固定隨機種子，確保結果可重現
        # stratify=y_train      # 若分類資料不均衡，建議加上這個參數
    )

    return X_train, X_test, y_train, y_test

def Modele(X_train:DataFrame, y_train:DataFrame, X_test:DataFrame):
    # randomforest model
    # model = RandomForestClassifier(n_jobs=-1, random_state=42)
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=None,
        n_jobs=-1,
        random_state=42,
        class_weight="balanced",
    )
    # y_train = y_train.copy()
    # y_train = [y_train==-1] = 0
    # model = XGBClassifier(n_jobs=-1, random_state=42)

    model.fit(X_train, y_train)
    print(f'feature importance: \n{model.feature_importances_}')
    y_pred = model.predict(X_test)

    return y_pred, model

def testResult(y_pred, y_test):
    print("Accuracy:", accuracy_score(y_test, y_pred))
    print(classification_report(y_test, y_pred))

def storeModel(model):
    joblib.dump(model, "phishing_model.joblib")
    print("Model saved to phishing_model.joblib")

if __name__ == '__main__':
    dataset = loadFile()
    dataset = PreProcessing(dataset)
    TrainTestSplit(dataset)
    X_train, X_test, y_train, y_test = TrainTestSplit(dataset)
    y_pred, model = Modele(X_train, y_train, X_test)
    testResult(y_pred, y_test)
    storeModel(model)