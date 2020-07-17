#!/usr/bin/python

#Author: Popey

# --------------------------------------------------------------------------------------------------------------------- #

import dns.resolver, time, csv

# --------------------------------------------------------------------------------------------------------------------- #

def nsQuery(domain, logs):
    nsList = []
    for line in dns.resolver.query(domain, 'NS'):
        nsList.append(line.to_text())
        logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : ' + line.to_text() + ' found\n')
    return nsList

def mxQuery(domain, logs):
    mxList = []
    for line in dns.resolver.query(domain, 'MX'):
        mxList.append(line.to_text())
        logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : ' + line.to_text() + ' found\n')
    return mxList

def SaveQuery(domain, name, logs):
    logs.write('\n#----------------------------------------Server NS and MX search------------------------------------------#\n\n')
    mxList = mxQuery(domain, logs)
    nsList = nsQuery(domain, logs)

    with open('./Output/ServerScan' + name + '.csv', 'w', newline='') as csvfile:
        fields = ['Domain', 'Type', 'MX_int', 'link']
        writer = csv.DictWriter(csvfile, fieldnames=fields, delimiter=';')
        writer.writeheader()
        rows = []
        for line in mxList:
            tmp = ''
            x = ''
            for c in line:
                if c == ' ':
                    x = tmp
                    tmp = ''
                else:
                    tmp += c
            rows.append({'Domain': domain, 'Type': 'MX', 'MX_int': x, 'link': tmp})

        for line in nsList:
            rows.append({'Domain': domain, 'Type': 'MX', 'MX_int': '', 'link': line})
        writer.writerows(rows)
        csvfile.close()
    logs.write('\n#--------------------------------------END Server NS and MX search----------------------------------------#\n\n')
