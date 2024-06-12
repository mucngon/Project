
import argparse
import os
import requests
import urllib.request
from concurrent.futures import ThreadPoolExecutor

#27787e752bcb4d015a9c2fe6fdaf0ef54a628ff16af1f19ef15ffc7fd0664fbc
# import time


def download(sha256):

    base_url = 'https://androzoo.uni.lu/api/download?apikey=26fe85459ada965ec9fea79fa1e8a9e8e5ed2b39ae82e4a09b978f4ad84adc8c&sha256='
    url = base_url + sha256
    r = requests.get(url=url)
    if r.status_code == 200:
        urllib.request.urlretrieve(url,
                                   'D:/Study/HK2 2023_2024/BTL Python/Detec/APK/'+sha256 +'.apk' )
        
        print('downloaded: '+ sha256)


parser = argparse.ArgumentParser(description='Hello World CLI',allow_abbrev=False)
parser.add_argument('--i',type=str)
args, unknown = parser.parse_known_args()
i = args.i
file_path = os.path.abspath(i)
with open(file_path, 'r') as f:
    urls = [line.rstrip() for line in f.readlines()]
num_threads = 20
with ThreadPoolExecutor(max_workers=num_threads) as executor:
    executor.map(download, urls)