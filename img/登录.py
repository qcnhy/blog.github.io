import sys
import frida
import time
import uuid
import hashlib
import requests
import re
import subprocess
import threading

cmd = 'adb shell'
lock = threading.Lock()
lock1 = threading.Lock()


def adbforward():
    subprocess.call("adb forward tcp:27042 tcp:27042")
    subprocess.call("adb forward tcp:27043 tcp:27043")

    with open("test.log", "w") as f:

        p = subprocess.Popen(cmd,
                             shell=False,
                             stdin=subprocess.PIPE,
                             stdout=f.fileno(),
                             stderr=subprocess.PIPE)
        play_cmd = "su -c 'nohup /data/local/tmp/frida-server-15.1.1-android-arm64 </dev/null >/dev/null 2>&1 &'"
        #play_cmd = 'su -c nohup /data/local/tmp/frida-server-15.1.3-android-x86_64&'
        p.stdin.write(bytes(play_cmd, 'utf-8'))
        p.stdin.write(bytes("\n", 'utf-8'))
        p.stdin.flush()
        play_cmd = "su -c 'ps|grep frida|grep -v grep|awk '{print $2}'|xargs su -c kill -9'"
        p.stdin.write(bytes(play_cmd, 'utf-8'))
        p.stdin.write(bytes("\n", 'utf-8'))
        p.stdin.flush()

    time.sleep(1)


def on_message(message, data):  #js中执行send函数后要回调的函数
    print(ip + message)


#time.sleep(6)
def connect():
    global script
    try:
        process = frida.get_remote_device().attach(
            'CT-Young+'
        )  #得到设备并劫持进程com.example.testfrida（该开始用get_usb_device函数用来获取设备，但是一直报错找不到设备，改用get_remote_device函数即可解决这个问题）
    except frida.ServerNotRunningError:
        adbforward()
        try:
            process = frida.get_remote_device().attach(
                'CT-Young+'
            )  #得到设备并劫持进程com.example.testfrida（该开始用get_usb_device函数用来获取设备，但是一直报错找不到设备，改用get_remote_device函数即可解决这个问题）
        except frida.TransportError:
            device = frida.get_remote_device()
            pid = device.spawn(["com.cndatacom.campus.cdccportalhainan"])
            device.resume(pid)
            process = device.attach(pid)
        except frida.ProcessNotFoundError:
            device = frida.get_remote_device()
            pid = device.spawn(["com.cndatacom.campus.cdccportalhainan"])
            device.resume(pid)
            process = device.attach(pid)
        except frida.ProcessNotRespondingError:
            device = frida.get_remote_device()
            pid = device.spawn(["com.cndatacom.campus.cdccportalhainan"])
            device.resume(pid)
            process = device.attach(pid)
        except frida.TransportError:
            adbforward()
            device = frida.get_remote_device()
            pid = device.spawn(["com.cndatacom.campus.cdccportalhainan"])
            device.resume(pid)
            process = device.attach(pid)
    except frida.ProcessNotFoundError:
        device = frida.get_remote_device()
        pid = device.spawn(["com.cndatacom.campus.cdccportalhainan"])
        device.resume(pid)
        process = device.attach(pid)
    except frida.ProcessNotRespondingError:
        device = frida.get_remote_device()
        pid = device.spawn(["com.cndatacom.campus.cdccportalhainan"])
        device.resume(pid)
        process = device.attach(pid)
    jscode = open("C:\\Users\\qcnhy\\Documents\\py\\test.js",
                  encoding='utf-8').read()
    #jscode = "var by = " + str(data) + ";\n" + jscode

    script = process.create_script(jscode)  #创建js脚本
    #script.on('message',on_message) #加载回调函数，也就是js中执行send函数规定要执行的python函数
    script.load()  #加载脚本
    time.sleep(2)


def login(ip, userid, passwd):
    global lock
    httpproxy = 'http://127.0.0.1:400/'
    #httpproxy = 'http://pc.hitushen.cn:10809'
    #clientid = "41bbbecd-15a6-4552-abd1-efa5fab46264"  #跟加解密相关 需要用对应设备加解密
    clientid = str(uuid.uuid1())
    ticket = ""
    timeout = 0
    status = 0
    data = []
    AlgoID = ""

    def getdamod():
        nonlocal data, AlgoID, ticket, timeout
        #加密damod获取
        url = "http://202.100.244.173:9001/ticket.cgi"

        headers = {
            'User-Agent': 'CCTP/android3/2028',
            'Algo-ID': "00000000-0000-0000-0000-000000000000",
            'CDC-Checksum': '9f89c84a559f573636a47ff8daed0d33',
            'Client-ID': clientid,
            'Content-Type': 'application/x-www-form-urlencoded',
            'CDC-SchoolId': '10',
            'CDC-Domain': 'ctyoung',
            'CDC-Area': 'hn'
        }
        r = requests.post(url,
                          headers=headers,
                          data="00000000-0000-0000-0000-000000000000",
                          proxies={'http': httpproxy})
        print(ip + "初始化加密参数：" + str(r.status_code))
        AlgoID = re.search("\$(.*?)]", r.text)
        AlgoID = AlgoID.group(1)
        b = bytearray(r.content)

        for i in b:
            if (i > 127):
                i = i - 256
            data.append(i)
        '''
        with open("./damod.txt", "w+") as fw:
            #print(ip+userid)
            fw.write(jscode)
        '''

    def getticket():
        nonlocal data, AlgoID, ticket, timeout

        if (time.time() < timeout):
            return 1
        elif (ticket != ""):
            print("门票超时失效")
        lock.acquire()
        oldip = """adb shell "ip address show dev wlan0|grep 'inet '"""
        oldip = subprocess.check_output(oldip)
        oldip = re.search("inet (.*?)/", str(oldip))
        oldip = oldip.group(1)
        with open("test.log", "w") as f:
            p = subprocess.Popen(cmd,
                                 shell=False,
                                 stdin=subprocess.PIPE,
                                 stdout=f.fileno(),
                                 stderr=subprocess.PIPE)
            play_cmd = "su -c 'ip address add " + ip + " dev wlan0&&ip address del " + oldip + " dev wlan0'"
            p.stdin.write(bytes(play_cmd, 'utf-8'))
            p.stdin.write(bytes("\n", 'utf-8'))
            p.stdin.flush()
            time.sleep(2)
        name = "中国电信正在进行网络测试请勿登录或修改密码否则封号处理"
        parm = """<?xml version="1.0" encoding="utf-8"?><request><host-name>""" + name + """</host-name><user-agent>CCTP/android3/2028</user-agent><client-id>""" + clientid + """</client-id><ipv4></ipv4><ipv6></ipv6><mac></mac><ostag>中国电信正在进行网络测试</ostag><local-time></local-time></request>"""  #ostag只能16个中文 加密自动变成设备ipv4
        enc = script.exports.encode(data, parm)

        #登陆完毕修改回原来的ip
        with open("test.log", "w") as f:

            p = subprocess.Popen(cmd,
                                 shell=False,
                                 stdin=subprocess.PIPE,
                                 stdout=f.fileno(),
                                 stderr=subprocess.PIPE)
            play_cmd = "su -c 'ip address add " + oldip + " dev wlan0&&ip address del " + ip + " dev wlan0'"
            p.stdin.write(bytes(play_cmd, 'utf-8'))
            p.stdin.write(bytes("\n", 'utf-8'))
            p.stdin.flush()
            time.sleep(2)
            lock.release()
        #print(ip+d1)  #输出加密的内容 含有ip
        #d1 = d1.split('|', 1)
        #ipv4 = d1[1]
        #d1 = d1[0]
        '''
        url = "http://202.100.244.173:9001/index.cgi?wlanuserip=" + ipv4 + "&wlanacip=202.100.206.253"

        headers = {'User-Agent': 'CCTP/android3/2028'}

        r = requests.get(url, headers=headers, proxies={'http': httpproxy})
        print(ip+"获取服务器配置：" + str(r.status_code))
        '''
        #print(ip+r.content)# 输出服务器配置
        url = "http://202.100.244.173:9001/ticket.cgi?wlanuserip=" + ip + "&wlanacip=202.100.206.253"
        #print(ip+url) #确定ip 是否正确

        md5 = hashlib.md5(enc.encode('utf-8')).hexdigest()
        #print(ip+md5)
        headers = {
            'User-Agent': 'CCTP/android3/2028',
            'Algo-ID': AlgoID,
            'CDC-Checksum': md5,
            'Client-ID': clientid,
            'Content-Type': 'application/x-www-form-urlencoded',
            'CDC-SchoolId': '10',
            'CDC-Domain': 'ctyoung',
            'CDC-Area': 'hn'
        }

        r = requests.post(url,
                          headers=headers,
                          data=enc,
                          proxies={'http': httpproxy})

        print(ip + "获取全局门票：" + str(r.status_code))
        d = script.exports.decode(data, r.text)
        ticket = re.search("<ticket>(.*?)<\/ticket>", d)
        ticket = ticket.group(1)

        timeout = re.search("<expire>(.*?)<\/expire>", d)
        timeout = timeout.group(1)
        timeout = float(timeout)

        print(ip + "全局门票：" + ticket)  #输出ticket
        return 0

    def getquery():
        nonlocal data, AlgoID, ticket, timeout
        parm = """<?xml version="1.0" encoding="utf-8"?><request><user-agent>CCTP/android3/2028</user-agent><client-id>""" + clientid + """</client-id><local-time></local-time></request>"""
        enc = script.exports.encode(data, parm)
        md5 = hashlib.md5(enc.encode('utf-8')).hexdigest()
        headers = {
            'User-Agent': 'CCTP/android3/2028',
            'Algo-ID': AlgoID,
            'CDC-Checksum': md5,
            'Client-ID': clientid,
            'Content-Type': 'application/x-www-form-urlencoded',
            'CDC-SchoolId': '10',
            'CDC-Domain': 'ctyoung',
            'CDC-Area': 'hn'
        }
        r = requests.post("http://202.100.244.173:9001/query.cgi",
                          headers=headers,
                          data=enc,
                          proxies={'http': httpproxy})

        if (len(r.content) == 0):
            return 0
        else:
            d = script.exports.decode(data, r.text)
            matches = re.findall('<ipv4>(.*?)</ipv4>', d)
            if (matches):
                if (matches[-1] == ip):
                    return 1
                else:
                    return 0
            else:
                return 0

    def getstate():
        nonlocal data, AlgoID, ticket, timeout
        parm = """<?xml version="1.0" encoding="utf-8"?><request><user-agent>CCTP/android3/2028</user-agent><client-id>""" + clientid + """</client-id><ticket>""" + ticket + """</ticket><local-time></local-time></request>"""

        enc = script.exports.encode(data, parm)
        md5 = hashlib.md5(enc.encode('utf-8')).hexdigest()
        headers = {
            'User-Agent': 'CCTP/android3/2028',
            'Algo-ID': AlgoID,
            'CDC-Checksum': md5,
            'Client-ID': clientid,
            'Content-Type': 'application/x-www-form-urlencoded',
            'CDC-SchoolId': '10',
            'CDC-Domain': 'ctyoung',
            'CDC-Area': 'hn'
        }
        r = requests.post("http://202.100.244.173:9001/state.cgi",
                          headers=headers,
                          data=enc,
                          proxies={'http': httpproxy})

        #d = script.exports.decode(data, r.text)
        return len(r.content)

    def logout():
        nonlocal data, AlgoID, ticket, timeout
        #先退出
        getterm = """<?xml version="1.0" encoding="utf-8"?><request><user-agent>CCTP/android3/2028</user-agent><client-id>""" + clientid + """</client-id><ticket>""" + ticket + """</ticket><reason>1</reason><local-time></local-time></request>"""
        enc = script.exports.encode(data, getterm)
        url = "http://202.100.244.173:9001/term.cgi"
        #print(ip+url)

        md5 = hashlib.md5(enc.encode('utf-8')).hexdigest()
        headers = {
            'User-Agent': 'CCTP/android3/2028',
            'Algo-ID': AlgoID,
            'CDC-Checksum': md5,
            'Client-ID': clientid,
            'Content-Type': 'application/x-www-form-urlencoded',
            'CDC-SchoolId': '10',
            'CDC-Domain': 'ctyoung',
            'CDC-Area': 'hn'
        }
        r = requests.post(url,
                          headers=headers,
                          data=enc,
                          proxies={'http': httpproxy})

        print(ip + "退出登录：" + str(r.status_code))
        return len(r.content)

    def auth(userid, passwd):
        nonlocal data, AlgoID, ticket, timeout

        parm = """<?xml version="1.0" encoding="utf-8"?><request><user-agent>CCTP/android3/2028</user-agent><client-id>""" + clientid + """</client-id><userid>""" + userid + """</userid><passwd>""" + passwd + """</passwd><ticket>""" + ticket + """</ticket><local-time></local-time></request>"""
        enc = script.exports.encode(data, parm)
        url = "http://202.100.244.173:9001/auth.cgi"
        #print(ip+url)

        md5 = hashlib.md5(enc.encode('utf-8')).hexdigest()
        headers = {
            'User-Agent': 'CCTP/android3/2028',
            'Algo-ID': AlgoID,
            'CDC-Checksum': md5,
            'Client-ID': clientid,
            'Content-Type': 'application/x-www-form-urlencoded',
            'CDC-SchoolId': '10',
            'CDC-Domain': 'ctyoung',
            'CDC-Area': 'hn'
        }
        r = requests.post(url,
                          headers=headers,
                          data=enc,
                          proxies={'http': httpproxy})

        print(ip + "请求登录：" + str(r.status_code))
        #print(ip+r.content)
        s = str(r.content)

        s = s.split("'", 2)
        #print(ip+s[1])
        #d=script.exports.decode(data,s[1])  #解密返回的内容
        #print(ip+d)

        return len(r.content)  #返回最终登录返回值长度 0说明密码错误

    getdamod()
    while (True):

        #getticket()
        query = getquery()
        if (query == 0):
            print(ip + time.strftime(' %Y-%m-%d %H:%M:%S',
                                     time.localtime(time.time())) + "网络需要登录！")
            timeout = 0
            status = 0
            getticket()
            logout()
            go = auth(userid, passwd)
            if (go == 0):
                print(ip + time.strftime(' %Y-%m-%d %H:%M:%S',
                                         time.localtime(time.time())) +
                      "登陆失败，可能是密码错误")
                status = 0
                #continue
            else:
                print(ip + time.strftime(' %Y-%m-%d %H:%M:%S',
                                         time.localtime(time.time())) + "登陆成功")
        else:
            if (status == 0):
                print(ip + time.strftime(' %Y-%m-%d %H:%M:%S',
                                         time.localtime(time.time())) + "网络正常")
                status = 1
            time.sleep(2)
        time.sleep(2)


connect()


def main(ip, userid, passwd):
    disconnect = 0
    try:
        login(ip, userid, passwd)
    except frida.InvalidOperationError:
        disconnect = 1
        lock1.acquire()
        if (disconnect == 1):
            connect()
            disconnect = 0
        lock1.release()
        main(ip, userid, passwd)

threading.Thread(target=main, args=(
    "ip",
    "账号",
    "密码",
)).start()

threading.Thread(target=main,
                 args=(
                     "ip",
    "账号",
    "密码",
                 )).start()

sys.stdin.read()