import numpy as np
import pandas as pd
import re
import pickle
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.misc import AnalyzeAPK

# Load mô hình đã huấn luyện
with open("random_forest_model.pkl", "rb") as f:
    rf = pickle.load(f)

data = pd.read_csv("D:/Study/HK2 2023_2024/BTL Python/Detec/sorted_data.csv", encoding="utf-8", low_memory=False, na_values="?")
feature_df = pd.read_csv("D:/Study/HK2 2023_2024/BTL Python/Detec/dataset-features-categories.csv", header=None, names=["X", "Category"])

permissions_list = feature_df[feature_df["Category"] == "Manifest Permission"].X.unique()
api_call_signatures = feature_df[feature_df["Category"] == "API call signature"].X.unique()
intents = feature_df[feature_df["Category"] == "Intent"].X.unique()
keywords = feature_df[feature_df["Category"] == "Commands signature"].X.unique()

apk_file_path = "D:/Study/HK2 2023_2024/BTL Python/Detec/APK/F6CF794259EC3177C63C4BE132E80C79FB7929842CDF83E3ED74F491D51BEFA7.apk"

test_df = pd.DataFrame(columns=["filename"] + list(data.columns))

test_df.loc[0, "filename"] = apk_file_path

a = APK(apk_file_path)
d = DalvikVMFormat(a.get_dex())

permissions = a.get_permissions()
manifest = a.get_android_manifest_xml()
intent_filters = manifest.findall(".//intent-filter")

found_permissions = []
found_api_signatures = []
found_intents = []
found_keywords = []

for permission in permissions:
    permission = permission.split(".")[-1]
    if permission in permissions_list:
        found_permissions.append(permission)
    
for permission in permissions_list:
    if permission in found_permissions:
        test_df[permission] = 1
    else:
        test_df[permission] = 0

for method in d.get_methods():
    for api_call in api_call_signatures:
        if re.search(api_call.encode(), method.get_descriptor()):  
            found_api_signatures.append(api_call)
            
for api_call in api_call_signatures:
    if api_call in found_api_signatures:
        test_df[api_call] = 1
    else:
        test_df[api_call] = 0

for intent_filter in intent_filters:
    action_elements = intent_filter.findall(".//action")
    for action_element in action_elements:
        action_value = action_element.get("{http://schemas.android.com/apk/res/android}name").encode() 
        for intent in intents:
            if re.search(intent.encode(), action_value):
                found_intents.append(intent)

for intent in intents:
    if intent in found_intents:
        test_df[intent] = 1
    else:
        test_df[intent] = 0

for method in d.get_methods():
    for keyword in keywords:
        try:
            if re.search(keyword.encode(), method.get_code().get_instruction()):
                found_keywords.append(keyword)
        except:
            pass

for keyword in keywords:
    if keyword in found_keywords:
        test_df[keyword] = 1
    else:
        test_df[keyword] = 0

dropped = test_df.drop(columns=["class", "filename"], axis=1)
predictions = rf.predict(dropped)
print(predictions)
