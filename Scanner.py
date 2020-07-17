#!/usr/bin/python

#Author: maxime.chardon, Stage EPITA SPE

# --------------------------------------------------------------------------------------------------------------------- #

import subprocess, json, time, os

# Process to test import or install and import
def install_and_import(package):
    import importlib
    try:
        importlib.import_module(package)
        print(package + ' is already installed')
    except ImportError:
        import pip
        install(package)
        print(package + ' is install')
    finally:
        globals()[package] = importlib.import_module(package)

def install(name):
    if name == 'nmap' or name == 'whois':
        subprocess.call(['pip', 'install', '--trusted-host', 'files.pythonhosted.org', '--trusted-host', 'pypi.org', '--trusted-host', 'pypi.python.org', 'python-' + name ,'-vvv'])
    elif name == 'dns.resolver':
        subprocess.call(['pip', 'install', '--trusted-host', 'files.pythonhosted.org', '--trusted-host', 'pypi.org', '--trusted-host', 'pypi.python.org', 'dnspython3' ,'-vvv'])
    else:
        subprocess.call(['pip', 'install', '--trusted-host', 'files.pythonhosted.org', '--trusted-host', 'pypi.org', '--trusted-host', 'pypi.python.org', name, '-vvv'])

# Modules to install
install_and_import('nmap') # for scan IP
install_and_import('csv') # Exel part (save)
install_and_import('whois') # for localisation of server
install_and_import('dns.resolver')

if not os.path.exists('./Output'):
    os.mkdir('./Output')
    print("Directory Output Created ")
if not os.path.exists('./Logs'):
    os.mkdir('./Logs')
    print("Directory Logs Created ")

# --------------------------------------------------------------------------------------------------------------------- #

#import my Scripts
import ScannerIP
import ScannerSubDomain
import ScannerServer
import ScannerWhois

# --------------------------------------------------------------------------------------------------------------------- #

time_tmp = time.localtime(time.time())
year = str(time_tmp[0])
month = str(time_tmp[1])
day = str(time_tmp[2])
hour = str(time_tmp[3])
minute = str(time_tmp[4])
seconde = str(time_tmp[5])
OutputName = year + '-' + month + '-' + day + '-' + hour + '-' + minute + '-' + seconde

logs = open("./Logs/logs" + OutputName + '.txt', "w")

ports = '1-6535'
domain = 'megacorpone.com'

# --------------------------------------------------------------------------------------------------------------------- #

SubList = ScannerSubDomain.ScanSubDom(domain, OutputName, logs)
'''
path = ScannerSubDomain.SaveSubDom(SubList, OutputName, logs)
ScannerServer.SaveQuery(domain, OutputName,logs)
List_IP_SubDomain = ScannerIP.IP_sort(path, logs)
List_IP_SubDomain_Scan = ScannerIP.Scanner(List_IP_SubDomain, ports, logs)
ScannerIP.SaveData(List_IP_SubDomain_Scan, OutputName, logs)
'''
WhoisList = ScannerWhois.WhoisScan(SubList, logs)
ScannerWhois.ParseJson(WhoisList, OutputName, logs)
# --------------------------------------------------------------------------------------------------------------------- #

logs.close()
