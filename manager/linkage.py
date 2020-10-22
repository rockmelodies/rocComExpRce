#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/9/2 4:15 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : weblogic.py
# @Software: PyCharm


import OperatingUi

class run(object):
    def __init__(self):
        self.name = "linkage"

        self.ui = OperatingUi.Ui_MainWindow

    def runlink(self):
        """
        导航栏选项卡联动索引0
        :return:
        """
        self.ui.tabWidget.setCurrentIndex(0)
