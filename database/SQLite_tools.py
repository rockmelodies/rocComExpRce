#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/9/7 5:30 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : SQLite_tools.py.py
# @Software: PyCharm


import sys
from PyQt5.QtSql import QSqlDatabase, QSqlQuery
from PyQt5.QtCore import *


class SQLite_tools:
    def __init__(self):
        self.name = "SQLite_tools"

    def create_SQL(self,sqlname):
        '''
        创建数据库
        :param sqlname: 数据库目录名称
        '''
        database = QSqlDatabase.addDatabase('QSQLITE')
        database.setDatabaseName(sqlname)
        database.open()

    def create_SQLtable(tbname):
        '''
        创建通用数据表，默认第一列为主键，名称:ID，类型:INTEGER, 自增
        :param tbname: 数据表名称
        '''
        # CREATE TABLE if not exists 表名 (ID INTEGER PRIMARY KEY AUTOINCREMENT);
        q = QSqlQuery()
        command = u"CREATE TABLE if not exists {} (ID INTEGER PRIMARY KEY AUTOINCREMENT);".format(tbname)
        q.exec_(command)

    def add_SQLtable_cloumn(tbname, column_name, genre):
        '''
        指定数据表添加列
        :param tbname: 表名
        :param column_name: 列名
        :param genre: 添加列类型
        '''
        # ALTER TABLE 表名 ADD 列名 列类型;
        q = QSqlQuery()
        command = u"ALTER TABLE {} ADD {} {};".format(tbname, column_name, genre)
        q.exec_(command)

    def add_SQLtable_row(tbname, row_num):
        '''
        指定数据表添加行
        :param tbname: 表格名称
        :param row_num: 行数
        '''
        # INSERT INTO 表名 (ID) VALUES (行);
        q = QSqlQuery()
        for row in range(1, row_num + 1):
            command = "INSERT INTO {} (ID) VALUES ({});".format(tbname, str(row))
            q.exec_(command)


    def add_roc_nav_exploit_data(self,vul_line_data,vul_line_page,vul_hash):
        '''
        给roc_nav_exploit_data添加表数据
        :param vul_line_data:
        :param vul_line_page:
        :param vul_hash:
        :return:
        '''
        q = QSqlQuery()
        command = 'insert into roc_nav_exploit(vul_name,linkage,vul_hash) values("{0}","{1}","{2}")'.format(vul_line_data,vul_line_page,vul_hash)
        q.exec_(command)


    def set_SQLtable_value(tbname, column, row, value):
        '''
        更新数据表指定位置的值
        :param tbname: 数据表名称
        :param row: 行数
        :param column: 列数
        :param value: 值
        '''
        # UPDATE 表名 SET 列名=值 WHERE ID=行;
        q = QSqlQuery()
        command = u"UPDATE {} SET {}='{}' WHERE ID={};".format(tbname, column, value, str(row))
        value_list = []
        if q.exec_(command):
            column_index = q.record().indexOf(column)  # 获取列索引值
            while q.next():
                value = q.value(column_index)
                value_list.append(value)
        return value_list

    def get_SQLtable_value(tbname, column, row):
        '''
        读取指定数据表的指定列行数据
        :param tbname: 数据表名称
        :param row: 数据表行
        :param column: 数据表列
        :return 返回查询到的值
        '''
        # SELECT 列名 FROM 表名 WHERE ID = 行号;
        q = QSqlQuery()
        command = "SELECT {} FROM {} WHERE ID={};".format(column, tbname, str(row))
        q.exec_(command)
        if q.next():
            result = q.value(0)
            return result

    def get_SQLtable_column(self,tbname, column):
        '''
        读取数据表指定列的所有数据
        :param tbname: 数据表名称
        :param column: 列名称
        :return 返回查询到的值列表
        '''
        # SELECT 列名 FROM 表名;
        q = QSqlQuery()
        command = "SELECT {} FROM {};".format(column, tbname)
        value_list = []
        if q.exec_(command):
            column_index = q.record().indexOf(column)  # 获取列索引值
            while q.next():
                value = q.value(column_index)
                value_list.append(value)
        return value_list

    def get_SQLtable_column_parent_id(self,tbname,column,parent_id):
        '''
        读取数据表和parent_id指定列的所有数据
        :param tbname: 数据表名称
        :param column: 列名称
        :return 返回查询到的值列表
        '''
        # SELECT 列名 FROM 表名;
        q = QSqlQuery()
        command = "SELECT {} FROM {} WHERE parent_id='{}';".format(column,tbname,parent_id)
        value_list = []
        if q.exec_(command):
            column_index = q.record().indexOf(column)  # 获取列索引值
            while q.next():
                value = q.value(column_index)
                value_list.append(value)
        return value_list

    def get_SQLtable_column_name(self,tbname):
        '''
        获取数据表字段名字
        :param tbname: 数据表名称
        :return: 返回字段(列)名称列表
        '''
        q = QSqlQuery()
        command = "pragma table_info({})".format(tbname)
        name_list = []
        if q.exec_(command):
            while q.next():
                column_name = q.value(1)
                name_list.append(column_name)
        return name_list

    def get_SQLtable_row(self,tbname, row):
        '''
        读取数据表指定行的所有数据
        :param tbname: 数据表名称
        :param column: 行名称
        :return 返回查询到的值列表
        '''
        # SELECT * FROM 表名 WHERE ID = 行号;
        name_list = self.get_SQLtable_column_name(tbname)
        num = len(name_list) - 1
        q = QSqlQuery()
        command = "SELECT * FROM {} WHERE ID={};".format(tbname, str(row))
        value_list = []
        if q.exec_(command):
            while q.next():
                for i in range(1, num):
                    value = q.value(i)
                    value_list.append(value)
        return value_list

    def get_SQLtable_vul_name_row(self,tbname, vul_name):
        '''
        读取数据表指定行vul_name的所有数据
        :param tbname: 数据表名称
        :param column: 行名称
        :return 返回查询到的值列表
        '''
        # SELECT * FROM 表名 WHERE ID = 行号;
        name_list = self.get_SQLtable_column_name(tbname)
        num = len(name_list) - 1
        q = QSqlQuery()
        command = "SELECT * FROM {} WHERE vul_name='{}';".format(tbname, str(vul_name))
        value_list = []
        if q.exec_(command):
            while q.next():
                for i in range(1, num):
                    value = q.value(i)
                    value_list.append(value)
        return value_list

    def get_SQLtable_vul_name_id(self,tbname, vul_name):
        '''
        读取数据表指定行vul_name的id数据
        :param tbname: 数据表名称
        :param column: 行名称
        :return 返回查询到的值列表
        '''
        # SELECT * FROM 表名 WHERE ID = 行号;
        name_list = self.get_SQLtable_column_name(tbname)
        num = len(name_list)
        q = QSqlQuery()
        command = "SELECT * FROM {} WHERE vul_name='{}';".format(tbname, str(vul_name))
        value_list = []
        # print(command)
        if q.exec_(command):
            while q.next():
                for i in range(0, num):
                    value = q.value(i)
                    value_list.append(value)
        return value_list[0]

    def get_SQLtable_vul_name_top_level_item_id(self,tbname, vul_name):
        '''
        读取数据表指定行vul_name的top_level_item_id-id数据
        :param tbname: 数据表名称
        :param column: 行名称
        :return 返回查询到的值列表
        '''
        # SELECT * FROM 表名 WHERE ID = 行号;
        name_list = self.get_SQLtable_column_name(tbname)
        num = len(name_list)
        q = QSqlQuery()
        command = "SELECT top_level_item FROM {} WHERE vul_name='{}';".format(tbname, str(vul_name))
        value_list = []
        # print(command)
        if q.exec_(command):
            while q.next():
                for i in range(0, num):
                    value = q.value(i)
                    value_list.append(value)
        return value_list[0]

    def get_SQLtable_vul_name_child_id(self,tbname, vul_name):
        '''
        读取数据表指定行vul_name的top_level_item_id-id数据
        :param tbname: 数据表名称
        :param column: 行名称
        :return 返回查询到的值列表
        '''
        # SELECT * FROM 表名 WHERE ID = 行号;
        name_list = self.get_SQLtable_column_name(tbname)
        num = len(name_list)
        q = QSqlQuery()
        command = "SELECT child_id FROM {} WHERE vul_name='{}';".format(tbname, str(vul_name))
        value_list = []
        # print(command)
        if q.exec_(command):
            while q.next():
                for i in range(0, num):
                    value = q.value(i)
                    value_list.append(value)
        return value_list[0]

    def get_SQLtable_vul_name_hash(self,tbname, vul_name):
        '''
        读取数据表指定行vul_name的vul_hash数据
        :param tbname: 数据表名称
        :param column: 行名称
        :return 返回查询到的值列表
        '''
        # SELECT * FROM 表名 WHERE ID = 行号;
        name_list = self.get_SQLtable_column_name(tbname)
        num = len(name_list)
        q = QSqlQuery()
        command = "SELECT * FROM {} WHERE vul_name='{}';".format(tbname, str(vul_name))
        value_list = []
        if q.exec_(command):
            while q.next():
                for i in range(0, num):
                    value = q.value(i)
                    value_list.append(value)
        return value_list[3]

    def get_SQLtable_vul_number(self,tbname,vul_hash):
        '''
        读取数据表指定行vul_hash的vul_vul_number数据
        :param tbname: 数据表名称
        :param column: 行名称
        :return 返回查询到的值列表
        '''
        # SELECT * FROM 表名 WHERE ID = 行号;
        name_list = self.get_SQLtable_column_name(tbname)
        num = len(name_list)
        q = QSqlQuery()
        command = "SELECT vul_number FROM {} WHERE vul_hash='{}';".format(tbname, str(vul_hash))
        value_list = []
        if q.exec_(command):
            while q.next():
                for i in range(0, num):
                    value = q.value(i)
                    if value is not None:
                        value_list.append(value)
                    else:
                        pass
        return value_list

    def get_SQLtable_vul_hash(self,tbname,vul_number):
        """
        读取数据表获取指定vul_number 获取 vul_hash
        :param tbname:
        :param vul_number:
        :return:
        """
        # SELECT * FROM 表名 WHERE ID = 行号;
        name_list = self.get_SQLtable_column_name(tbname)
        num = len(name_list)
        q = QSqlQuery()
        command = "SELECT vul_hash FROM {} WHERE vul_number='{}';".format(tbname, str(vul_number))
        value_list = []
        if q.exec_(command):
            while q.next():
                for i in range(0, num):
                    value = q.value(i)
                    if value is not None:
                        value_list.append(value)
                    else:
                        pass
        return value_list




    def get_SQLtable_vul_name_linkage(self,tbname, vul_name):
        """
        读取数据表 linkage 的内容
        :param tbname:
        :param vul_name:
        :return:
        """
        # SELECT * FROM 表名 WHERE ID = 行号;
        name_list = self.get_SQLtable_column_name(tbname)
        num = len(name_list) - 1
        q = QSqlQuery()
        command = "SELECT * FROM {} WHERE vul_name='{}';".format(tbname, str(vul_name))
        value_list = []
        if q.exec_(command):
            while q.next():
                for i in range(2, 3):
                    value = q.value(i)
                    value_list.append(value)
        return value_list

    def delete_SQLtable_value(tbname):
        '''
        清空指定数据表
        :param tbname: 表名
        '''
        # DELETE FROM table_name WHERE[condition];
        q = QSqlQuery()
        command = "DELETE FROM " + tbname + ";"
        q.exec_(command)

