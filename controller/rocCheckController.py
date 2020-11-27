#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/11/4 10:58 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : config.py.py
# @Software: PyCharm

import configparser
import re
import time
import requests
import os
import ast
import importlib

requests.packages.urllib3.disable_warnings()


class rocCheckController(object):
    def __init__(self):
        self.name = "CVE_2017_10271_weblogic"

    def runCheck(self, targetAddr, payload):
        """
        加载外部程序
        POC检测控制器
        :param targetAddr:
        :param payload:
        :return:
        """
        if payload == "CVE_2017_3248_weblogic":
            pass
            module = 'rocCheckPayload.{}'.format(payload)
            importModule = importlib.import_module(module)
            data = importModule.run.runCheck(self, targetAddr, payload)
            return data
        else:
            config = configparser.RawConfigParser()
            getCurPath = os.getcwd()
            configPath = '{}/rocCheckPayload/{}.ini'.format(getCurPath, payload)
            config.read(configPath)
            options = config.sections()
            currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            for option in options:
                if (re.match('rules', option)) is not None:
                    method = config.get(option, 'method')

                    proxies = {
                        'http': '127.0.0.1:8089',
                        'https': '127.0.0.1:8089'
                    }

                    if method == "POST":
                        header = config.get(option, 'header')
                        path = config.get(option, 'path')
                        body = config.get(option, 'body')
                        expression = config.get(option, 'expression')
                        url = targetAddr + path
                        try:
                            header_dict = ast.literal_eval(header)
                            res = requests.post(url, data=body, verify=False, timeout=5, headers=header_dict,
                                                proxies=proxies)
                            if expression in res.text:
                                status_data = '[+]{} is vulnerable! {} {}'.format(targetAddr, payload, currentTime)
                                return {'status': 20003, 'data': status_data, 'type': 'status'}
                            else:
                                status_data = '[-]{} is unvulnerable! {} {}'.format(targetAddr, payload, currentTime)
                                return {'status': 20004, 'data': status_data, 'type': 'status'}
                        except requests.exceptions.RequestException as e:
                            status_data = '[!]{} 请求超时! {}'.format(targetAddr, currentTime)
                            return {'status': 20002, 'data': status_data, 'type': 'status'}
                    elif method == "GET":
                        header = config.get(option, 'header')
                        path = config.get(option, 'path')
                        expression = config.get(option, 'expression')
                        url = targetAddr + path
                        try:
                            header_dict = ast.literal_eval(header)
                            res = requests.get(url, headers=header_dict, timeout=15, verify=False)
                            if expression in res.text:
                                status_data = '[+]{} is vulnerable! {} {}'.format(targetAddr, payload, currentTime)
                                return {'status': 20003, 'data': status_data, 'type': 'status'}
                            else:
                                status_data = '[-]{} is unvulnerable! {} {}'.format(targetAddr, payload, currentTime)
                                return {'status': 20004, 'data': status_data, 'type': 'status'}
                        except requests.exceptions.RequestException as e:
                            status_data = '[!]{} 请求超时! {}'.format(targetAddr, currentTime)
                            return {'status': 20002, 'data': status_data, 'type': 'status'}
                    else:
                        pass
