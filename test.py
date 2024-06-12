import pandas as pd
import re
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

apk_file_path = 'D:/Study/HK2 2023_2024/BTL Python/Detec/APK/F6CF794259EC3177C63C4BE132E80C79FB7929842CDF83E3ED74F491D51BEFA7.apk'

feature_df = pd.read_csv("D:/Study/HK2 2023_2024/BTL Python/Detec/dataset-features-categories.csv", header=None, names=["X", "Category"])
feature_df.head()

permissions_list = feature_df[feature_df["Category"] == "Manifest Permission"].X.unique()
api_call_signatures = feature_df[feature_df["Category"] == "API call signature"].X.unique()
intents = feature_df[feature_df["Category"] == "Intent"].X.unique()
keywords = feature_df[feature_df["Category"] == "Commands signature"].X.unique()

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

for method in d.get_methods():
    for api_call in api_call_signatures:
        if re.search(api_call.encode(), method.get_descriptor()): 
            found_api_signatures.append(api_call)

for intent_filter in intent_filters:
    action_elements = intent_filter.findall(".//action")
    for action_element in action_elements:
        action_value = action_element.get("{http://schemas.android.com/apk/res/android}name").encode() 
        for intent in intents:
            if re.search(intent.encode(), action_value):
                found_intents.append(intent)

for method in d.get_methods():
    for keyword in keywords:
        try:
            if re.search(keyword.encode(), method.get_code().get_instruction()):
                found_keywords.append(keyword)
        except:
            pass

print(found_permissions)
print(found_api_signatures)
print(found_intents)
print(found_keywords)
