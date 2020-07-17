#!/usr/bin/python

#Author: Popey

# --------------------------------------------------------------------------------------------------------------------- #

import time, nmap, csv

# --------------------------------------------------------------------------------------------------------------------- #

# Bring back IP in a list
def IP_sort(path, logs):
    IP_file = open(path, "r")

    lines = IP_file.readlines()
    IP_file.close()

    logs.write('\n#-------------------------------------NMAP Scan on subdomain-------------------------------------#\n\n')
    lines.pop(0)
    IPs = []
    for line in lines:
        tmp, x = '', 0
        IP = ''
        SubDomain = ''
        type = ''
        for c in line:
            if c == ';':
                if x == 0:
                    IP = tmp
                    tmp = ''
                else:
                    SubDomain = tmp
                    tmp = ''
                x += 1
            elif c == '\n' or c == '\r':
                type = tmp
            else:
                tmp += c
        if type == '':
            type = tmp
        IPs.append((IP, SubDomain, type))
    print("The program extract some IPs: ")
    print(IPs)
    logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : ' + "IPs out of csv file:\n  " + str(IPs) + '\n')
    return IPs

# Run nmap for each IPs and return a list of dictionnaries
def Scanner(list, ports, logs):
    JSONres = []
    logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : ' + "starting the NMAP\n")
    for ip, subdomain, type in list:
        Scan = nmap.PortScanner()
        if '4' in type:
            res = Scan.scan(ip, ports, '-T4 -A -v -Pn')
        else:
            res = res = Scan.scan(ip, ports, '-6 -sV -Pn')
        JSONres.append((ip, subdomain, res))
        print('Scan of ' + ip + ' is finished')
        logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : ' + 'Scan of ' + ip + ' is finished\n')
    logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : ' + 'All scan finished\n')
    return JSONres

# Process each JSON and return in a CSV file
def SaveData(JSONlist, Name, logs):
    with open('./Output/IPScan' + Name + '.csv', 'w', newline='') as csvfile:
        fields = ['SubDomain', 'IP', 'Port', 'State', 'Port Name', 'Software', 'Version']
        writer = csv.DictWriter(csvfile, fieldnames=fields, delimiter=';')
        writer.writeheader()
        rows = []
        for ip, sub, scan in JSONlist:
            if len(list(scan["scan"][ip].keys())) <= 6:
                print('begin to save ', ip, '/', sub)
                logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : ' + 'Begin to save the scan of ' + ip + '/' + sub + '\n')
                rows.append({'SubDomain': sub, 'IP': ip, 'Port': 'N/A', 'State': 'N/A', 'Port Name': 'N/A', 'Software': 'N/A', 'Version': 'N/A'})
                continue
            new_scan = scan["scan"][ip]["tcp"]
            open_ports = list(new_scan.keys())
            for port in open_ports:
                state = new_scan[port]["state"]
                if state == "closed":
                    soft = 'N/A'
                    version = 'N/A'
                else:
                    soft = new_scan[port]["product"]
                    version = new_scan[port]["version"]
                name = new_scan[port]["name"]
                rows.append({'SubDomain': sub, 'IP': ip, 'Port': port, 'State': state, 'Port Name': name, 'Software': soft, 'Version': version})
            print(ip + ' is saved')
            logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : ' + ip + '/' + sub +' is saved\n')
        writer.writerows(rows)
        csvfile.close()
    logs.write('\n#-----------------------------------END NMAP Scan on subdomain-----------------------------------#\n\n')
