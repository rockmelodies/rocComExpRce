#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/11/20 12:12 上午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : rocBattchCheckController.py
# @Software: PyCharm

import configparser
import re
import time
import requests
import os
import ast
import importlib

requests.packages.urllib3.disable_warnings()


class rocBatchCheckController(object):
    def __init__(self):
        self.name = "CVE_2017_10271_weblogic"

    def runBatchCheck(self, targetAddr, payload):

        print(targetAddr)

        _translate = QtCore.QCoreApplication.translate
        sql = SQLite_tools()
        sql.create_SQL('../database/db/database.db')
        data = sql.get_SQLtable_column_parent_id('roc_nav_exploit', 'vul_name', 0)

        for vul_name in data:
            vul_name_id = sql.get_SQLtable_vul_name_id('roc_nav_exploit', '{0}'.format(vul_name))
            topLevel = int(vul_name_id) - 1
            self.ui.treeWidget.topLevelItem(topLevel).setText(0, _translate("MainWindow", "{0}".format(vul_name)))

        pass