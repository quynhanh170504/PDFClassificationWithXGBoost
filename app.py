# sample request body (31 col)
# {
#   "features": [1,1,0.0,1,0.0,0.0,443,98,10,19,1,2,2,1,268.0,443,0.0,2,2,1.0,211.0,1,2,2.0,3,0.0,1.0,1,2,63.0,0.0]
# }
from flask import Flask, redirect, url_for, render_template, request, session, jsonify
from pydantic import BaseModel
import numpy as np
import joblib
import os
import PyPDF2
import pdfplumber
import fitz  # PyMuPDF
import pdfminer
import json

# Load trained model
model = joblib.load("./xgb_model.joblib")  # make sure correct path
model1 = joblib.load("./xgb_model_1.joblib")  # make sure correct path
model10 = joblib.load("./xgb_model_10.joblib")  # make sure correct path
model50 = joblib.load("./xgb_model_50.joblib")  # make sure correct path
model100 = joblib.load("./xgb_model_100.joblib")  # make sure correct path
model200 = joblib.load("./xgb_model_200.joblib")  # make sure correct path

app = Flask(__name__)

# Define structure of request body
class Features(BaseModel):
  features: list

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
# Đo lường hiệu quả mô hình
from sklearn.metrics import roc_auc_score, recall_score, precision_score, f1_score, accuracy_score
from sklearn.model_selection import RandomizedSearchCV, cross_val_score, KFold, train_test_split
from scipy.stats import uniform, randint

# Hàm chia dữ liệu thành các features X và target Y
def xs_y(df_, targ):
  if not isinstance(targ, list):
    xs = df_[df_.columns.difference([targ])].copy()
  else:
    xs = df_[df_.columns.difference(targ)].copy()
  y = df_[targ].copy()
  return xs, y
# Tiền xử lí dữ liệu
def data_preprocessing():
  data = pd.read_parquet('./dataset/PDFMalware2022.parquet')
  # Drop FileName col
  data.drop(columns=['FileName'], inplace=True)
  # Gán nhãn cho cột Class
  data['Class'] = data['Class'].astype('object')
  data.loc[data['Class'] == 'Malicious', 'Class'] = 1
  data.loc[data['Class'] == 'Benign', 'Class'] = 0

  data['Class'] = data['Class'].astype(dtype=np.int64)

  # Phân loại các thuộc tính
  cats = data.select_dtypes(include='category').columns
  conts = data.columns.difference(['Class'] + list(cats))

  # Chia dữ liệu --> training, test, valid (70, 20, 10)
  train, valid = train_test_split(data, test_size=0.30, random_state=0)
  test, valid = train_test_split(valid, test_size=0.33, random_state=0)
  # Chuyển các đặc trưng cấu trúc thành số
  train[cats] = train[cats].apply(lambda x: x.cat.codes)
  valid[cats] = valid[cats].apply(lambda x: x.cat.codes)
  test[cats] = test[cats].apply(lambda x: x.cat.codes)

  # Chia train, test, valid --> X_Train, y_train, X_valid, y_valid, X_test, y_test
  X_train, y_train = xs_y(train, 'Class')
  X_val, y_val = xs_y(valid, 'Class')
  X_test, y_test = xs_y(test, 'Class')

  return {
    "X_train": X_train,
    "y_train": y_train,
    "X_val": X_val,
    "y_val": y_val,
    "X_test": X_test,
    "y_test": y_test
  }

@app.route('/')
def home():
  return render_template('home.html')
@app.route('/performance')
def performance():
  return render_template('performance.html')

import subprocess
# Hàm này dùng để trích xuất giá trị tương ứng với key từ kết quả của pdfid
def get_pdf_value(output, key):
  lines = output.splitlines()
  for line in lines:
    if key in line:
      if key == 'PDF Header':
        # Tìm phần "PDF-x.y" và tách lấy giá trị "x.y"
        pdf_version = line.split()[-1]
        return pdf_version.split('-')[1] if pdf_version.startswith('%PDF-') else '0.0'
      # Lấy giá trị sau dấu cách (space)
      return int(line.split()[-1]) if line.split()[-1].isdigit() else line.split()[-1]
  return 0  # Giá trị mặc định nếu không tìm thấy
# Hàm trích xuất đặc trưng từ tệp pdf
def extract_pdf_features(file_path):
  features = {
    "AA": 0, "Acroform": 0, "Colors": 0.0, "EmbeddedFile": 0,
    "EmbeddedFiles": 0.0, "Encrypt": 0.0, "Endobj": 0, "Endstream": 0,
    "Header": 1.7, "Images": 0, "JBIG2Decode": 0, "JS": 0, "Javascript": 0,
    "Launch": 0, "MetadataSize": 0.0, "Obj": 0, "ObjStm": 0.0, "OpenAction": 0,
    "PageNo": 0, "Pages": 0.0, "PdfSize": 0.0, "RichMedia": 0, "StartXref": 0,
    "Stream": 0.0, "Text": 0, "TitleCharacters": 0.0, "Trailer": 0.0,
    "XFA": 0, "Xref": 0, "XrefLength": 0.0, "isEncrypted": 0.0
  }
    
  # Load PDF and calculate basic metadata
  with fitz.open(file_path) as pdf:
    features["Pages"] = pdf.page_count
    # features["PageNo"] = features["Pages"]
    features["PdfSize"] = os.path.getsize(file_path) / 1024  # in KB
    features["isEncrypted"] = 1.0 if pdf.is_encrypted else 0.0
    features["XrefLength"] = pdf.xref_length()
    
    # Extract text-based features, metadata, and page content
    for page_num in range(pdf.page_count):
      page = pdf.load_page(page_num)
      features["Text"] += int(bool(page.get_text()))  # Counts pages with text
      features["Images"] += len(page.get_images(full=True))  # Image count
      features["Stream"] += len(page.search_for("stream"))
      features["Endstream"] += len(page.search_for("endstream"))
    

  # Get metadata size and other properties using pdfminer
  from pdfminer.pdfparser import PDFParser
  from pdfminer.pdfdocument import PDFDocument
  from pdfminer.pdfpage import PDFPage
  from pdfminer.pdfinterp import resolve1

  with open(file_path, 'rb') as f:
    parser = PDFParser(f)
    document = PDFDocument(parser)
    features["MetadataSize"] = len(document.info[0]) if document.info else 0
    
    is_encrypted = document.encryption is not None
    features["Encrypt"] = 1.0 if is_encrypted else 0.0
    
    # Analyze object structure
    features["Obj"] = sum(1 for _ in PDFPage.create_pages(document))
    
    # features["XrefLength"] = resolve1(document.xrefs[0]) if document.xrefs else 0

    # Additional fields, if available in pdfminer
    
  pdfid_result = subprocess.run(['python', './pdfid/pdfid.py', file_path], capture_output=True, text=True)
  if pdfid_result.returncode != 0:
    raise Exception(f"Error extracting PDF features: {result.stderr}")
  pdfid_output = pdfid_result.stdout

  features['Header'] = get_pdf_value(pdfid_output, 'PDF Header')

  features['AA'] = get_pdf_value(pdfid_output, '/AA')
  features['Acroform'] = get_pdf_value(pdfid_output, '/Acroform')

  features['Colors'] = get_pdf_value(pdfid_output, '/Colors > 2^24')
  features['Endobj'] = get_pdf_value(pdfid_output, 'endobj')
  features['Endstream'] = get_pdf_value(pdfid_output, 'endstream')
  features['EmbeddedFile'] = get_pdf_value(pdfid_output, '/EmbeddedFile')
  features['Encrypt'] = get_pdf_value(pdfid_output, '/Encrypt')

  features['JS'] = get_pdf_value(pdfid_output, '/JS')
  features['Javascript'] = get_pdf_value(pdfid_output, '/JavaScript')
  features['JBIG2Decode'] = get_pdf_value(pdfid_output, '/JBIG2Decode')

  features['Launch'] = get_pdf_value(pdfid_output, '/Launch')

  features['Pages'] = get_pdf_value(pdfid_output, '/Page')

  features['Obj'] = get_pdf_value(pdfid_output, 'obj')
  features['ObjStm'] = get_pdf_value(pdfid_output, '/ObjStm')
  features['OpenAction'] = get_pdf_value(pdfid_output, '/OpenAction')
  
  features['Stream'] = get_pdf_value(pdfid_output, 'stream')
  features['StartXref'] = get_pdf_value(pdfid_output, 'startXref')

  
  features['RichMedia'] = get_pdf_value(pdfid_output, '/RichMedia')



  features['Trailer'] = get_pdf_value(pdfid_output, 'trailer')

  features['Xref'] = get_pdf_value(pdfid_output, 'xref')
  features['XFA'] = get_pdf_value(pdfid_output, '/XFA')

  
  return features
  

# import subprocess
# import xml.etree.ElementTree as ET
# def extract_pdf_features_using_pdfid(file_path):
#   features = {
#     "AA": 0, "Acroform": 0, "Colors": 0.0, "EmbeddedFile": 0,
#     "EmbeddedFiles": 0.0, "Encrypt": 0.0, "Endobj": 0, "Endstream": 0,
#     "Header": 0, "Images": 0, "JBIG2Decode": 0, "JS": 0, "Javascript": 0,
#     "Launch": 0, "MetadataSize": 0.0, "Obj": 0, "ObjStm": 0.0, "OpenAction": 0,
#     "PageNo": 0, "Pages": 0.0, "PdfSize": 0.0, "RichMedia": 0, "StartXref": 0,
#     "Stream": 0.0, "Text": 0, "TitleCharacters": 0.0, "Trailer": 0.0,
#     "XFA": 0, "Xref": 0, "XrefLength": 0.0, "isEncrypted": 0.0
#   }

#   try:
#       # Run pdfid and capture the output in XML format
#     result = subprocess.run(
#       ["pdfid", "-n", file_path, "-o", "xml"],
#       capture_output=True, text=True, check=True
#     )
#     # Parse the XML output
#     root = ET.fromstring(result.stdout)
    
#     # Extract values for each feature if available
#     for keyword in root.findall(".//keyword"):
#       name = keyword.attrib.get("name")
#       count = int(keyword.attrib.get("count", 0))
      
#       if name in features:
#         features[name] = count
    
#     # Additional metadata extraction (file size and number of pages)
#     features["PdfSize"] = os.path.getsize(file_path) / 1024  # in KB
#     features["Pages"] = int(root.find(".//pdfid/pagecount").text) if root.find(".//pdfid/pagecount") is not None else 0
#     features["isEncrypted"] = 1.0 if root.find(".//pdfid/encrypted").text == "True" else 0.0

#   except subprocess.CalledProcessError as e:
#     print(f"Error running pdfid: {e}")
#   except ET.ParseError as e:
#     print(f"Error parsing pdfid output: {e}")

#   return features

@app.route('/upload', methods=['POST'])
def upload_file():
  if 'file' not in request.files:
    return jsonify({"error": "No file part"}), 400

  file = request.files['file']
  if file.filename == '':
    return jsonify({"error": "No selected file"}), 400

  if file and file.filename.endswith('.pdf'):
    file_path = os.path.join("uploads", file.filename)
    file.save(file_path)
    
    # features = extract_pdf_features(file_path)
    features = extract_pdf_features(file_path)
    
    # Optional: keep the file after processing
    # os.remove(file_path)
    features_values = list(features.values())

    # convert features list to numpy array
    feature_array = np.array(features_values, dtype=object).reshape(1, -1)
    
    prediction = model.predict(feature_array)[0]
    prediction_prob = model.predict_proba(feature_array)[0]
    
    predict_result = {
      "Prediction": "Malicious" if prediction == 1 else "Benign",
      "Malicious Probability": float(prediction_prob[1]),
      "Benign Probability": float(prediction_prob[0]),
    }
 
    response = {
      "predict_result": predict_result,
      "features": features,
    }
    # return jsonify(predict_result)
    return jsonify(response)
    # return jsonify(features)
  else:
    return jsonify({"error": "Unsupported file type"}), 400


@app.route('/predict', methods=["POST", "GET"])
def predict_func():
  if request.method == "POST":
    data = request.json
    if "features" not in data:
      return jsonify({"error": "Missing 'features' in request body"}), 400
    # convert features list to numpy array
    feature_array = np.array(data["features"]).reshape(1, -1)        
    prediction = model.predict(feature_array)[0]
    prediction_prob = model.predict_proba(feature_array)[0]
    # return jsonify({
    #   "Prediction": "Malicious" if prediction == 1 else "Benign",
    #   "Malicious Probability": float(prediction_prob[1]),
    #   "Benign Probability": float(prediction_prob[0]),
    # })
    predict_result = {
      "Prediction": "Malicious" if prediction == 1 else "Benign",
      "Malicious Probability": float(prediction_prob[1]),
      "Benign Probability": float(prediction_prob[0]),
    }
    return render_template('result.html', predict_result=predict_result)
  else:
    return render_template('result.html')

@app.route('/result')
def result():
  return render_template('result.html')

@app.route('/chart')
def chart_drawing():
  results = [
    {
      'n_estimators': 1,
      'ROC-AUC': 0.9532597858060547,
      'Accuracy': 0.9558093346573983,
      'Precision': 0.9353146853146853,
      'Recall': 0.9861751152073732,
      'F1-Score': 0.9600717810677434
    },
    {
      'n_estimators': 10,
      'ROC-AUC': 0.9923137212105579,
      'Accuracy': 0.9925521350546177,
      'Precision': 0.9908256880733946,
      'Recall': 0.9953917050691244,
      'F1-Score': 0.993103448275862
    },
    {
      'n_estimators': 50,
      'ROC-AUC': 0.996003829498048,
      'Accuracy': 0.9960278053624627,
      'Precision': 0.9963133640552996,
      'Recall': 0.9963133640552996,
      'F1-Score': 0.9963133640552996
    },
    {
      'n_estimators': 100,
      'ROC-AUC': 0.9950047868725601,
      'Accuracy': 0.9950347567030785,
      'Precision': 0.9953917050691244,
      'Recall': 0.9953917050691244,
      'F1-Score': 0.9953917050691244
    },
    {
      'n_estimators': 200,
      'ROC-AUC': 0.9959264458587351,
      'Accuracy': 0.9960278053624627,
      'Precision': 0.9954001839926403,
      'Recall': 0.9972350230414746,
      'F1-Score': 0.996316758747698
    },
    {
      'n_estimators': 500,
      'ROC-AUC': 0.9959264458587351,
      'Accuracy': 0.9960278053624627,
      'Precision': 0.9954001839926403,
      'Recall': 0.9972350230414746,
      'F1-Score': 0.996316758747698
    }
  ]
  results_df = pd.DataFrame(results)
  #   n_estimators	  ROC-AUC	Accuracy	Precision	    Recall	F1-Score
  # 0	           1	 0.953260	0.955809	 0.935315	  0.986175	0.960072
  # 1	          10	 0.992314	0.992552	 0.990826	  0.995392	0.993103
  # 2	          50	 0.996004	0.996028	 0.996313	  0.996313	0.996313
  # 3	         100	 0.995005	0.995035	 0.995392	  0.995392	0.995392
  # 4	         200	 0.995926	0.996028	 0.995400	  0.997235	0.996317
  # 5       	 500	 0.995926	0.996028	 0.995400	  0.997235	0.996317
  return results_df


if __name__ == "__main__":
  app.run(debug=True)