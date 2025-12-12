# coding=utf-8

import argparse, os, random, threading, time, traceback
from concurrent import futures
from curl_cffi.requests.exceptions import ConnectionError, Timeout
from curl_cffi import requests
from datetime import datetime
from urllib.parse import urlparse

#
# =================== [ 全局设置 ] ===================
#

configs = \
{
    # 字典路径
    "wordlists": [
        "dicts/common.txt", # 常规路径扫描
        "dicts/offensive.txt", # 进攻性路径扫描，可能会被WAF封禁
    ],

    # 超时时间，单位秒
    "timeout": 10,

    # 线程并发数
    "threads": 10,
    
    # 每个线程发起请求后暂停时长，单位秒
    "delay": 1,

    # 排除响应码
    "ignored_status_code": [404],

    # 历史记录目录
    "history": "history",

    # 扫描日志
    "logfile": "log.txt",

    # 是否使用HEAD方法，HEAD方法看不到响应的长度
    "use_head_method": False,

    # 是否使用代理
    "use_proxy": False,

    # 设置代理
    "proxies": {
        "http": "http://127.0.0.1:8080",
        "https": "http://127.0.0.1:8080"
    },

    # 自定义headers
    "headers": {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/114.0",
        "Connection": "close",
    },

    # 自定义cookies
    "cookies": {
        # "JSESSIONID": ""
    }
}

# 互斥锁
locks = {
    "log": threading.Lock(),
    "history": threading.Lock()
}

#
# =================== [ 功能函数 ] ===================
#

# 判断URL是否合法
def is_valid_url(url):
    try:
        parser = urlparse(url)
        return all([parser.scheme, parser.netloc])
    except Exception:
        return False

# 日志输出
def log(message: str):
    with locks["log"]:
        print(message)
        with open(configs["logfile"], "a", encoding="utf-8") as fout:
            fout.write(message + "\n")

#
# =================== [ 扫描函数 ] ===================
#

def run(url, history, name):
    time.sleep(configs["delay"])

    random_ip = ".".join(str(random.randint(0,255)) for _ in range(4))
    headers = {
        **configs["headers"],
        "X-Forwarded-For": random_ip,
        "X-Originating-IP": random_ip,
        "X-Remote-IP": random_ip,
        "X-Remote-Addr": random_ip,
        "X-Real-IP": random_ip
    }
    cookies = configs["cookies"]
    method = "HEAD" if configs["use_head_method"] else "GET"
    proxies = configs["proxies"] if configs["use_proxy"] else None

    # 403 Bypass
    urls = [
        url,
        url + ";.js"
    ]

    session = requests.Session(impersonate="firefox133")
    try:
        for idx, url in enumerate(urls):
            response = session.request(method, url=url, 
                verify=False, headers=headers, cookies=cookies, allow_redirects=False, timeout=configs["timeout"], proxies=proxies)
            if response.status_code not in configs["ignored_status_code"]:
                log(f"code:{response.status_code}\tlen:{len(response.content)}\t\t{url}")
            if idx == 0 and response.status_code != 403:
                break
        with locks["history"]:
            history[name].add(url)
    except (ConnectionError, Timeout) as e:
        print(f"[x] {url}\tConnect error")
    except Exception as e:
        print(f"[x] {url}\tAn unknown error occurred: {e}")
        print(traceback.format_exc())

#
# =================== [ 启动多线程扫描 ] ===================
#

# 并发运行爆破函数
def concurrent_run(executor, tasks, scans, history):
    for name in scans.keys():
        for url in scans[name]:
            # 清除右边的换行
            url = url.rstrip()
            # 判断是否重复
            with locks["history"]:
                if url in history[name]:
                    continue
            # 如果队列过长就等待
            if len(tasks) >= configs["threads"]:
                _, tasks = futures.wait(tasks, return_when=futures.FIRST_COMPLETED)
            # 新建线程
            tasks.add(executor.submit(run, url, history, name))

# 生成探测列表
def generate_urls(target, wordlist):
    if not is_valid_url(target):
        print(f"[!] Invalid url: {target}")
        return []

    # https://example.com:8443/api/login 可拆解为两部分
    # 第一部分：https://example.com:8443
    # 第二部分：/api/login

    # 提取第一部分，url_root = "https://example.com:8443"
    parsed = urlparse(target.rstrip('/'))

    if parsed.scheme:
        url_root = f"{parsed.scheme}://{parsed.hostname}"
        if parsed.port:
            url_root = url_root + f":{parsed.port}"
    else:
        url_root = f"http://{parsed.hostname}"
        if parsed.port:
            url_root = url_root + f":{parsed.port}"

    # 提取第二部分，url_paths = ["", "api", "api/login"]
    url_paths = [""]
    if parsed.path is not None:
        url_path = parsed.path.strip("/")
        if '/' not in url_path:
            if url_path != "":
                url_paths.append(url_path)
        else:
            url_path = url_path.split('/')
            for i in range(len(url_path)):
                url_paths.append("/".join(url_path[0:i+1]))

    # 将第一部分和第二部分组合，urls = [
    #     "https://example.com:8443",
    #     "https://example.com:8443/api",
    #     "https://example.com:8443/api/login"
    # ]
    urls = []
    for path in url_paths:
        urls.append(f"{url_root}/{path}".rstrip("/"))

    # 将组合结果再与字典拼接，urls_queue = [
    #     "https://example.com:8443/actuator",
    #     "https://example.com:8443/api/actuator",
    #     "https://example.com:8443/api/login/actuator"
    # ]
    urls_queue = []
    for url in urls:
        for path in wordlist:
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
        # 读取字典列表
        wordlist = set()
        for path in configs["wordlists"]:
            try:
                with open(path, "r", encoding="utf-8") as fin:
                    for line in fin:
                        line = line.strip()
                        if not line:
                            continue
                        wordlist.add(line)
            except Exception as e:
                print(f"[x] Cannot read '{path}' wordlist file {e}")

        # 探测列表
        urls = set()
        if os.path.exists(args.target): # 参数是文件
            # 从文件中读取目标
            with open(args.target, "r", encoding="utf-8") as fin:
                for line in fin:
                    line = line.strip()
                    if not line:
                        continue
                    if not is_valid_url(line):
                        continue
                    urls.add(line)
        
        else: # 参数是URL
            if not is_valid_url(args.target):
                print(f"[x] {args.target} is not a valid url")
                os._exit(0)
            urls.add(args.target)

        # 收集history文件
        history = {}
        if not os.path.exists(configs["history"]):
            os.mkdir(configs["history"])
        for url in urls:
            # 计算url的name，http://127.0.0.1:8080 -> http_127.0.0.1_8080
            parsed = urlparse(url)
            scheme = parsed.scheme if parsed.scheme else "http"
            if parsed.port:
                name = f"{scheme}_{parsed.hostname}_{parsed.port}"
            else:
                name = f"{scheme}_{parsed.hostname}"
            # 检查url的name，避免重复加载（一次扫描可以输入多个url，可能会出现重复的name）
            if name in history:
                continue
            else:
                history[name] = set()
                file = os.path.join(configs["history"], name + ".txt")
                if os.path.exists(file):
                    try:
                        with open(file, "r", encoding="utf-8") as fin:
                            for line in fin:
                                line = line.strip()
                                if not line:
                                    continue
                                history[name].add(line)
                    except Exception as e:
                        print(f"[x] Cannot read '{file}' file {e}")

        # 生成扫描列表
        scans = {}
        for url in urls:
            # 计算url的name，http://127.0.0.1:8080 -> http_127.0.0.1_8080
            parsed = urlparse(url)
            scheme = parsed.scheme if parsed.scheme else "http"
            if parsed.port:
                name = f"{scheme}_{parsed.hostname}_{parsed.port}"
            else:
                name = f"{scheme}_{parsed.hostname}"
            # 检查url的name，避免前面的url被覆盖（一次扫描可以输入多个url，可能会出现重复的name）
            if name not in scans:
                scans[name] = generate_urls(url, wordlist)
            else:
                scans[name].extend(generate_urls(url, wordlist))

        # 日志记录时间
        log(f"\n# Begin at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        # 多线程扫描
        tasks = set()
        with futures.ThreadPoolExecutor(max_workers=configs["threads"]) as executor:
            try:
                concurrent_run(executor, tasks, scans, history)
                print("[!] Wait for all threads exit.")
                futures.wait(tasks, return_when=futures.ALL_COMPLETED)
            except KeyboardInterrupt:
                print("[!] Get Ctrl-C, wait for all threads exit.")
                futures.wait(tasks, return_when=futures.ALL_COMPLETED)
        
        # 保存历史文件
        for name in history.keys():
            file = os.path.join(configs["history"], name + ".txt")
            try:
                with open(file, "w", encoding="utf-8") as fin:
                    for line in history[name]:
                        fin.write(line + "\n")
            except Exception as e:
                print(f"[x] Cannot write '{file}' file {e}")
    else:
        parser.print_help()
