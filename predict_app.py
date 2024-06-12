import pandas as pd
import re
import pickle
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat

# Đọc tệp mô hình đã huấn luyện
with open('random_forest_model.pkl', 'rb') as model_file:
    rf_model = pickle.load(model_file)

# Đọc dữ liệu từ tệp APK
apk_file_path = "D:/Study/HK2 2023_2024/BTL Python/Detec/APK/F101C9260C76E9A5876835BBBE30A7BC025051FFF3FCF421C2606251B8DCDB62.apk"
a = APK(apk_file_path)
d = DalvikVMFormat(a.get_dex())

# Trích xuất các đặc trưng từ tệp APK
features = {}
permissions_list = [...] # Danh sách quyền
api_call_signatures = [...] # Danh sách chữ ký cuộc gọi API
intents = [...] # Danh sách intents
keywords = [...] # Danh sách từ khóa

permissions = a.get_permissions()
for permission in permissions:
    permission = permission.split(".")[-1]
    if permission in permissions_list:
        features[permission] = 1

for method in d.get_methods():
    for api_call in api_call_signatures:
        if re.search(api_call, method.get_descriptor()):
            features[api_call] = 1

manifest = a.get_android_manifest_xml()
intent_filters = manifest.findall(".//intent-filter")
for intent_filter in intent_filters:
    action_elements = intent_filter.findall(".//action")
    for action_element in action_elements:
        action_value = action_element.get("{http://schemas.android.com/apk/res/android}name")
        for intent in intents:
            if re.search(intent, action_value):
                features[intent] = 1

for method in d.get_methods():
    for keyword in keywords:
        try:
            if re.search(keyword, method.get_code().get_instruction()):
                features[keyword] = 1
        except:
            pass

# Tạo DataFrame từ các đặc trưng
df = pd.DataFrame(features, index=[0])

# Dự đoán sử dụng mô hình đã được huấn luyện
prediction = rf_model.predict(df)
print("Predicted class:", prediction)
