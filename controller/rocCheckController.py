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

requests.packages.urllib3.disable_warnings()


class rocCheckController(object):
    def __init__(self):
        self.name = "CVE_2017_10271_weblogic"

    def runCheck(self, targetAddr, payload):
        config = configparser.ConfigParser()
        getCurPath = os.getcwd()

        configPath = '{}/rocCheckPayload/{}.ini'.format(getCurPath,payload)
        # print(configPath)
        config.read(configPath)
        print(config.sections())
        options = config.sections()
        currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        for option in options:
            if (re.match('rules', option)) is not None:
                header = config.get(option, 'header')
                path = config.get(option, 'path')
                body = config.get(option, 'body')
                method = config.get(option, 'method')
                expression = config.get(option, 'expression')
                url = targetAddr + path

                if method == "POST":
                    try:
                        header_dict = ast.literal_eval(header)
                        res = requests.post(url, data=body, verify=False, timeout=5, headers=header_dict)
                        print(res)
                        if expression in res.text:
                            status_data = '[+]{} is vulnerable! {}'.format(targetAddr, currentTime)

                            return {'status': 20003, 'data': status_data, 'type': 'status'}
                        else:
                            status_data = '[-]{} is unvulnerable! {}'.format(targetAddr, currentTime)
                            return {'status': 20004, 'data': status_data, 'type': 'status'}
                    except requests.exceptions.RequestException as e:
                        status_data = '[!]{} 请求超时! {}'.format(targetAddr, currentTime)
                        return {'status': 20002, 'data': status_data, 'type': 'status'}



