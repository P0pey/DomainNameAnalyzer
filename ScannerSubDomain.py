#!/usr/bin/python

#Author: maxime.chardon, Stage EPITA SPE

# --------------------------------------------------------------------------------------------------------------------- #

import nmap, time, subprocess, csv

# --------------------------------------------------------------------------------------------------------------------- #

def ScanSubDom(domain, name, logs):
    logs.write('\n#----------------------------------------Subdomains search------------------------------------------#\n\n')
    logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : Starting search subdomains\n')
    path = './Output/SubDomain' + name + '.xml'
    subprocess.check_output(['nmap', '--script', 'dns-brute', '--script-args', 'dns-brute.domain='+ domain + ',dns-brute.threads=6', '-oX', path])
    SubDomainList = []
    file = open(path, "r")
    L = file.readlines()
    if len(L) <= 17:
        raise Exception("Domain not found")
    i = 10
    while i < len(L):
        line = L[i]
        if line[21] == '<':
            break
        if line[11] == 'a':
            ipline = line
            subline = L[i + 1]
        else:
            ipline = L[i + 1]
            subline = line
        x = 20
        y = 21
        tmp = ''
        while ipline[x] != '<':
            tmp += ipline[x]
            x += 1
        ip = tmp
        tmp = ''
        while subline[y] != '<':
            tmp += subline[y]
            y += 1
        SubDomainList.append((ip, tmp))
        i += 4
    return SubDomainList

def SaveSubDom(SubDomList, name, logs):
    path = './Output/SubDomain' + name + '.csv'
    with open(path, 'w', newline='') as csvfile:
        fields = ['IP', 'SubDomain', 'IPtype']
        writer = csv.DictWriter(csvfile, fieldnames=fields, delimiter=';')
        writer.writeheader()
        rows = []
        for ip, sub in SubDomList:
            if ':' in ip:
                rows.append({'IP': ip, 'SubDomain': sub, 'IPtype': 'IPv6'})
            else:
                rows.append({'IP': ip, 'SubDomain': sub, 'IPtype': 'IPv4'})

            logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : subdomain: ' + sub + 'at ip ' + ip + 'is saved\n')
        writer.writerows(rows)
        csvfile.close()
    logs.write('\n#--------------------------------------END Subdomains search----------------------------------------#\n\n')
    return path
