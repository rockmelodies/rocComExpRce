#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/9/3 10:35 上午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : db_config.py
# @Software: PyCharm


import sys
from PyQt5.QtSql import QSqlDatabase, QSqlQuery
from PyQt5.QtCore import *


class db_config(object):
    def __init__(self):
        self.name = "linkage"
        self.db = QSqlDatabase.addDatabase("QSQLITE")
        self.db.setDatabaseName("./db/database.db")
        self.creatDB = creatDB(self)
        self.connectDB = connectDb(self)


def connectDb(self):
    if not self.db.open():
        print("无法建立与数据库的连接")
        return False

def creatDB(self):

    if not self.db.open():
        print("无法建立与数据库的连接")
        return False
    query = QSqlQuery()
    query.exec(
        'create table roc_nav_exploit (id INTEGER PRIMARY KEY,vul_name varchar(50),linkage varchar(50),vul_hash varchar(50),parent_id varchar (10))')
    # query.exec('insert into roc_nav_exploit values("big","0","kjsdkfjskdjfk123")')

    query.exec(
        'create table roc_top_level_item (id INTEGER PRIMARY KEY,title varchar(50),linkage varchar(50),vul_hash varchar(50),parent_id varchar (10))')
    # query.exec('insert into roc_nav_exploit values("big","0","kjsdkfjskdjfk123")')

    query.exec(
        'create table roc_submodule (id INTEGER PRIMARY KEY,vul_number varchar(50),vul_name varchar(50),vul_hash varchar(50),author varchar (20))')
    # query.exec('insert into roc_submodule values("CVE-201923-123123","big","kjsdkfjskdjfk123")')

    query.exec(
        'create table roc_check_req (id INTEGER PRIMARY KEY,vul_number varchar(50),vul_name varchar(50),vul_hash varchar(50),req_uri varchar(25),req_timeout varchar(10),verify varchar(10),req_check varchar(251),method varchar(10),jump varchar(10),req_header varchar(251),req_data varchar(251),resp_variable varchar(251),req_queue varchar(50))')
    # qurey.exec('insert into roc_check_req values(1,"CVE-201923-123123","big","kjsdkfjskdjfk123","jdfskldjf","1")')
    # qurey.exec('create table roc_check_req (id int primary key,vul_number varchar(50),vul_name varchar(50),vul_hash varchar(50),queue varchar(50),queue varchar(50))')
    # qurey.exec('insert into roc_check_req values(1,"CVE-201923-123123","big","kjsdkfjskdjfk123","1","dsfsdfdsf")')
    self.db.close()
    return True

if __name__ == "__main__":
    dbConfig = db_config()
    dbConfig.creatDB
    # db_config.connectDB
