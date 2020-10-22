#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/9/3 6:44 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : linkage.py
# @Software: PyCharm

from PyQt5 import QtCore, QtGui, QtWidgets
import OperatingUi
from database.SQLite_tools import SQLite_tools


class linkAllAge(object):
    def __init__(self):
        self.name = "linkage"
        self.ui = OperatingUi.Ui_MainWindow()


    def runlink(self,vul_name):
        """
        导航栏选项卡联动索引0
        :return:
        """
        _translate = QtCore.QCoreApplication.translate
        sql = SQLite_tools()
        sql.create_SQL('./database/db/database.db')
        linkage_id = sql.get_SQLtable_vul_name_linkage('roc_nav_exploit', '{0}'.format(vul_name))
        linkage = 0
        for i in linkage_id:
            linkage = i
        return linkage

    def vul_number_options(self,vul_name):
        _translate = QtCore.QCoreApplication.translate
        sql = SQLite_tools()
        sql.create_SQL('./database/db/database.db')
        vul_hash = sql.get_SQLtable_vul_name_hash('roc_nav_exploit', '{0}'.format(vul_name))
        vul_number_data = sql.get_SQLtable_vul_number('vul_number_relation', '{0}'.format(vul_hash))

        return vul_number_data



