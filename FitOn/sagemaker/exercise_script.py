

from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier, KNeighborsRegressor
from sklearn.model_selection import validation_curve, train_test_split

from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, precision_score, recall_score, f1_score, roc_curve, auc
import sklearn
import joblib
import boto3
import pathlib
from io import StringIO 
import argparse
import joblib
import os
import numpy as np
import pandas as pd
import boto3

s3 = boto3.client("s3")
train_file = 'train-V-1.csv'
train_path = os.path.join("./", train_file)
s3.download_file("fiton-static-files", "sagemaker/exercise-data/sklearncontainer/" + train_file, train_path)
train_df = pd.read_csv(train_path)
y_train = train_df["exercise_id"]

# inference functions ---------------

def input_fn(request_body, request_content_type):
    print(request_body)
    print(request_content_type)
    if request_content_type == "text/csv":
        request_body = request_body.strip()
        try:
            df = pd.read_csv(StringIO(request_body), header=None)
            return df
        
        except Exception as e:
            print(e)
    else:
        return """Please use Content-Type = 'text/csv' and, send the request!!""" 
 
    
def model_fn(model_dir):
    clf = joblib.load(os.path.join(model_dir, "model.joblib"))
    return clf

def predict_fn(input_data, model):
    if type(input_data) != str:
        distances, indices = model.kneighbors(input_data)
        y_pred_test = []
        for n_idx in indices:
            y_pred_test.append(y_train[n_idx])
        print(y_pred_test)
        return y_pred_test
    else:
        return input_data
        
    
if __name__ == "__main__":

    print("[INFO] Extracting arguments")
    parser = argparse.ArgumentParser()

    # hyperparameters sent by the client are passed as command-line arguments to the script.
    parser.add_argument("--n_estimators", type=int, default=100)
    parser.add_argument("--random_state", type=int, default=0)

    # Data, model, and output directories
    parser.add_argument("--model-dir", type=str, default=os.environ.get("SM_MODEL_DIR"))
    parser.add_argument("--train", type=str, default=os.environ.get("SM_CHANNEL_TRAIN"))
    parser.add_argument("--test", type=str, default=os.environ.get("SM_CHANNEL_TEST"))
    parser.add_argument("--train-file", type=str, default="train-V-1.csv")
    parser.add_argument("--test-file", type=str, default="test-V-1.csv")
    parser.add_argument("--s3-bucket", type=str, default="fiton-static-files")
    parser.add_argument("--s3-data-key", type=str, default="sagemaker/exercise-data/sklearncontainer/")
    parser.add_argument("--s3-model-key", type=str, default="sagemaker/exercise-models/")

    args, _ = parser.parse_known_args()
    
    print("SKLearn Version: ", sklearn.__version__)
    print("Joblib Version: ", joblib.__version__)

    print("[INFO] Reading data")
    print()
    
    train_path = os.path.join(args.train, args.train_file)
    test_path = os.path.join(args.test, args.test_file)
    s3.download_file(args.s3_bucket, args.s3_data_key + args.train_file, train_path)
    s3.download_file(args.s3_bucket, args.s3_data_key + args.test_file, test_path)
    
    train_df = pd.read_csv(train_path)
    test_df = pd.read_csv(test_path)
    
    print(train_df.head())
    print(test_df.head())
    
    features = list(train_df.columns)
    label = features.pop(-1)
    
    print("Building training and testing datasets")
    print()
    X_train = train_df[features]
    X_test = test_df[features]
    y_train = train_df[label]
    y_test = test_df[label]

    print('Column order: ')
    print(features)
    print()
    
    print("Label column is: ",label)
    print()
    
    print("Data Shape: ")
    print()
    print("---- SHAPE OF TRAINING DATA (85%) ----")
    print(X_train.shape)
    print(y_train.shape)
    print()
    print("---- SHAPE OF TESTING DATA (15%) ----")
    print(X_test.shape)
    print(y_test.shape)
    print()
    
    
    max_k = 4
    n_fold = 10
    target = 0.1

    model = KNeighborsRegressor(max_k)
#     model = joblib.load(model_path)
    model.fit(X_train, y_train)
    

    model_path = os.path.join(args.model_dir, "model.joblib")
    joblib.dump(model,model_path)
    s3.upload_file(model_path, args.s3_bucket, args.s3_model_key + "model.joblib")
    print("Model persisted at " + args.s3_bucket + args.s3_model_key + "model.joblib")
    print()

    
    distances, indices = model.kneighbors(X_test)
    y_pred_test = []
    for n_idx in indices:
        y_pred_test.append(y_train[n_idx])
    

#     print()
#     print("---- METRICS RESULTS FOR TESTING DATA ----")
#     print()
#     print("Total Rows are: ", X_test.shape[0])
#     print('[TESTING] Model Accuracy is: ', test_acc)
#     print('[TESTING] Testing Report: ')
#     print(test_rep)
