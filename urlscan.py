# coding=utf-8

# python -m pip install requests

import requests, urllib3, argparse, traceback, random, time, os, threading
from requests.exceptions import ConnectTimeout, ConnectionError, ReadTimeout
from concurrent import futures
from datetime import datetime

# 禁用https警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

#
# =================== [ 全局设置 ] ===================
#

# 待扫描队列，由 generate_urls 函数生成
URLS_QUEUE = []

# 待扫描的URL路径，从 WORDLISTS_PATH 中读取，如：
# [
#     "/actuator",
#     "/doc.html",
#     "/swagger-ui.html"
# ]
WORDLISTS = []

# 字典路径，读取后储存到 WORDLISTS 中
WORDLISTS_PATH = [
    "dicts/common.txt", # 常规路径扫描
    "dicts/offensive.txt", # 进攻性路径扫描，可能会被WAF封禁
]

# 线程并发数
THREADS = 10

# 每个线程发起请求后暂停时长，单位秒
DELAY = 1

# 是否使用代理
USE_PROXY = False

# 设置代理
PROXIES = {
    "http": "http://127.0.0.1:8083",
    "https": "http://127.0.0.1:8083"
}

# 读取字典列表
for wordlists in WORDLISTS_PATH:
    try:
        with open(wordlists, "r", encoding="utf-8") as f:
            WORDLISTS.extend(f.readlines())
    except Exception as e:
        print(f"[x] Cannot open '{wordlists}' file {e}")
        os._exit(0)

#
# =================== [ 扫描日志 ] ===================
#

LOG_PATH = "log.txt"
LOG_LOCK = threading.Lock() # 文件互斥锁

# 写入日志，末尾的换行符需要自行处理
def log(path: str, lock, text: str):
    with lock:
        with open(path, "a", encoding="utf-8") as fout:
            fout.write(text)

#
# =================== [ 扫描函数 ] ===================
#

def run(url):
    time.sleep(DELAY)

    # 伪造 XFF
    random_ip = ".".join(str(random.randint(0,255)) for _ in range(4))
    headers = requests.utils.default_headers()
    headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
        "Connection": "close",
        "X-Forwarded-For": random_ip,
        "X-Originating-IP": random_ip,
        "X-Remote-IP": random_ip,
        "X-Remote-Addr": random_ip,
        "X-Real-IP": random_ip
    })

    # 403 Bypass
    urls = [
        url,
        url + ";",
        url + ";.js",
        url + "/..;/",
    ]

    try:
        for idx, url in enumerate(urls):
            response = requests.get(url, verify=False, headers=headers, 
                allow_redirects=False, timeout=3, proxies=PROXIES if USE_PROXY else None)
            if response.status_code != 404:
                output = f"code:{response.status_code}\tlen:{len(response.content)}\t\t{url}"
                print(f"[+] {output}")
                log(LOG_PATH, LOG_LOCK, f"{output}\n")
            if idx == 0 and response.status_code != 403:
                break
    except (ConnectTimeout, ConnectionError, ReadTimeout) as e:
        print(f"[x] {url}\tConnect error")
    except Exception as e:
        print(f"[x] {url}\tAn unknown error occurred: {e}")
        print(traceback.format_exc())

#
# =================== [ 启动多线程扫描 ] ===================
#

TASKS = set()

# 并发运行爆破函数
def concurrent_run(executor):
    global TASKS
    for url in URLS_QUEUE:
        # 如果队列过长就等待
        if len(TASKS) >= THREADS:
            _, TASKS = futures.wait(TASKS, return_when=futures.FIRST_COMPLETED)
        # 清除右边的换行
        url = url.rstrip()
        # 新建线程
        t = executor.submit(run, url)
        TASKS.add(t)

# 生成探测列表
def generate_urls(target):
    # https://example.com:8443/api/login 可拆解为两部分
    # 第一部分：https://example.com:8443
    # 第二部分：/api/login

    # 提取第一部分，url = "https://example.com:8443"
    parser = urllib3.util.parse_url(target.rstrip('/'))
    if parser.scheme:
        url = f"{parser.scheme}://{parser.host}"
    else:
        url = f"http://{parser.host}"
    if parser.port:
        url = url + f":{parser.port}"

    # 提取第二部分，paths = ["", "/api", "/api/login"]
    paths = []
    if parser.path is None:
        paths.append("")
    else:
        path = parser.path.strip("/").split('/')
        for i in range(len(path) + 1):
            paths.append("/".join(path[0:i]))

    # 将第一部分和第二部分组合，urls = [
    #     "https://example.com:8443",
    #     "https://example.com:8443/api",
    #     "https://example.com:8443/api/login"
    # ]
    urls = []
    for path in paths:
        urls.append(f"{url}/{path}")

    # 将组合结果再与字典拼接，urls_queue = [
    #     "https://example.com:8443/actuator",
    #     "https://example.com:8443/api/actuator",
    #     "https://example.com:8443/api/login/actuator"
    # ]
    urls_queue = []
    for url in urls:
        url = url.rstrip("/")
        for path in WORDLISTS:
            path = path.rstrip()
            if not path:
                continue
            elif path.startswith("/"):
                urls_queue.append(f"{url}{path}")
            else:
                urls_queue.append(f"{url}/{path}")
    return urls_queue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='URL scan tool')
    parser.add_argument("target", help="URL target or file")
    args = parser.parse_args()
    if args.target:
        # 生成探测列表
        if os.path.exists(args.target):
            with open(args.target, "r", encoding="utf-8") as f:
                for target in f.readlines():
                    URLS_QUEUE.extend(generate_urls(target.rstrip()))
        else:
            URLS_QUEUE = generate_urls(args.target)
        # 日志记录时间
        log(LOG_PATH, LOG_LOCK, f"\n# Begin at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        # 多线程扫描
        with futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
            try:
                concurrent_run(executor)
                print("[!] Wait for all threads exit.")
                futures.wait(TASKS, return_when=futures.ALL_COMPLETED)
            except KeyboardInterrupt:
                print("[!] Get Ctrl-C, wait for all threads exit.")
                futures.wait(TASKS, return_when=futures.ALL_COMPLETED)
    else:
        parser.print_help()
