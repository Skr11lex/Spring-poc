# -*- coding:utf-8 -*-
import time
import requests
import os

headers = {
'Cookie': 'UM_distinctid=17d9ee9b99ad5-08c6a2266360e7-4c3f2779-1fa400-17d9ee9b99b2b1; CNZZDATA1278305074=259968647-1640606623-%7C1643011913; PHPSESSID=kolveuasn829nk9s0jfffjg4n2'
}
getdomain = requests.get(url='http://dnslog.cn/getdomain.php', headers=headers, timeout=60)
domain = str(getdomain.text)
# 打印获取的随机域名
print(domain)


#多次刷新DNSlog平台,保证不是因为响应问题导致错过
for i in range(0,100000000000):
    refresh = requests.get(url='http://dnslog.cn/getrecords.php', headers=headers, timeout=60)
    time.sleep(1)
    if domain in refresh.text:
        print("发现dns请求,脚本停止运行")
        break
