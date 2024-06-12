import csv
import random

def sort_csv(file_path):
    # Đọc dữ liệu từ file CSV và lưu vào một danh sách
    with open(file_path, 'r', newline='') as csvfile:
        reader = csv.reader(csvfile)
        data = list(reader)

    # Lấy hàng đầu tiên và loại bỏ nó khỏi danh sách
    header = data[0]
    data = data[1:]

    # Thêm một cột giá trị random vào danh sách
    for row in data:
        row.append(random.random())

    # Sắp xếp danh sách theo cột giá trị random
    sorted_data = sorted(data, key=lambda x: x[-1])

    # Loại bỏ cột giá trị random khỏi dữ liệu đã sắp xếp
    for row in sorted_data:
        del row[-1]

    # Ghi dữ liệu đã sắp xếp vào file mới
    with open('sorted_data.csv', 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(header)
        writer.writerows(sorted_data)

    print("Đã sắp xếp và ghi dữ liệu vào file sorted_data.csv")

# Thay đổi đường dẫn của file CSV theo nơi lưu trữ thực tế của bạn
file_path = 'D:/Study/HK2 2023_2024/BTL Python/Detec/drebin-215-dataset-5560malware-9476-benign.csv'
sort_csv(file_path)
