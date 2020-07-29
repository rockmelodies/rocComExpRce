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


