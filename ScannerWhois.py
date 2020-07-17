#!/usr/bin/python

#Author: maxime.chardon, Stage EPITA SPE

# --------------------------------------------------------------------------------------------------------------------- #

import json, whois, time, csv

# --------------------------------------------------------------------------------------------------------------------- #

def WhoisScan(DomainList, logs):
    logs.write('\n#-------------------------------------WhoIs Scan on subdomain-------------------------------------#\n\n')
    list = []
    for ip, sub in DomainList:
        logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : ' + "starting the whois on: " + ip + "\n")
        list.append((ip, sub, whois.whois(ip)))
    return list

def LoadJson(path, List):
    Json = []
    for ip, sub, path in pathList:
        with open(path) as f:
            Json.append((ip, sub, json.load(f)))
    return Json

def ParseJson(JsonList, name, logs):
    with open('./Output/WhoisScan' + name + '.csv', "w", newline='') as csvfile:
        fields = ['SubDomain', 'IP', 'creation Date', 'Updated Date', 'Expiration Date', 'Name', 'Organisation', 'Registrar', 'Address', 'Country', 'State', 'ZipCode', 'Servers', 'Emails', 'WhoisServer']
        writer = csv.DictWriter(csvfile, fieldnames=fields, delimiter=';')
        writer.writeheader()
        rows = []

        for i in range(len(JsonList)):
            json = JsonList[i][2]
            ip = JsonList[i][0]
            sub = JsonList[i][1]
            creation = json["creation_date"][0]
            update = json["updated_date"][0]
            expir = json["expiration_date"][0]
            name = 'N/A'
            if json["name"]:
                name = json["name"]
            org = 'N/A'
            if json["org"]:
                org = json["org"]
            registrar = 'N/A'
            if json["registrar"]:
                registrar = json["registrar"]
            address = 'N/A'
            if json["address"]:
                address = json["address"]
            country = 'N/A'
            if json["country"]:
                country = json["country"]
            state = 'N/A'
            if json["state"]:
                state = json["state"]
            zip = 'N/A'
            if json["zipcode"]:
                zip = json["zipcode"]
            servers = ''
            if json["name_servers"]:
                for j in range(len(json["name_servers"])):
                    servers += json["name_servers"][j]
                    if j + 1 < len(json["name_servers"]):
                        servers += ', '
            else:
                servers = 'N/A'
            mail = ''
            if json["emails"]:
                for j in range(len(json["emails"])):
                    mail += json["emails"][j]
                    if j + 1 < len(json["emails"]):
                        mail += ', '
            else:
                mail = 'N/A'
            whoiserv = 'N/A'
            if json["whois_server"]:
                whoiserv = json["whois_server"]
            logs.write('[ ' + time.asctime(time.localtime(time.time())) + ' ] : ' + "saved: " + ip + "\n")
    logs.write('\n#-----------------------------------END WhoIs Scan on subdomain-----------------------------------#\n\n')
