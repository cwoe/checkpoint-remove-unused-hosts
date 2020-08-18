from netmiko import ConnectHandler
import ipaddress
import json

import mysecrets

username = mysecrets.username
password = mysecrets.password


#IP and API port of your Checkpoint MDS
ip = "10.0.0.1"
api_port = "4430"

def login(net_connect, domain, user, passwd):
            sid = net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -d "+domain+" -u "+user+" -p "+passwd+" login --format json")
            sid_clean = json.loads(sid)
            return sid_clean["sid"]

def getHostsInNetwork(net_connect, domain, sid, network):
            addresses = ipaddress.ip_network(network)
            hosts_raw = net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -d "+domain+" --session-id "+sid+" show hosts limit 1 --format json")
            hosts_clean = json.loads(hosts_raw)
            hostlist = []
            curr = 0
            total = hosts_clean["total"]
            print("Getting Hosts...")
            while curr < total:
                        hosts_raw = net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -d "+domain+" --session-id "+sid+" show hosts limit 500 offset "+str(curr)+" --format json")
                        hosts_clean = json.loads(hosts_raw)
                        for host in hosts_clean["objects"]:
                                    if ipaddress.ip_address(host["ipv4-address"]) in addresses:
                                                hostlist.append(host["uid"])
                        curr = hosts_clean["to"]
                        print(domain+": "+str(curr)+"/"+str(total))
            return hostlist

def checkIfInRules(net_connect, domain, sid, hostlist):
            print("Getting Rules...")
            layers_raw = net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -d "+domain+" --session-id "+sid+" show access-layers --format json")
            layers_clean = json.loads(layers_raw)
            for layer in layers_clean["access-layers"]:
                        rules_raw = net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -d "+domain+" --session-id "+sid+" show access-rulebase uid "+layer["uid"]+" limit 1 --format json")
                        rules_clean = json.loads(rules_raw)
                        curr = 0
                        total = rules_clean["total"]
                        while curr < total:
                                    rules_raw = net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -d "+domain+" --session-id "+sid+" show access-rulebase uid "+layer["uid"]+" limit 500 offset "+str(curr)+" --format json")
                                    rules_clean = json.loads(rules_raw)
                                    for rule in rules_clean["rulebase"]:
                                                if rule["type"] == "access-section":
                                                            for secrule in rule["rulebase"]:
                                                                        for dest in secrule["destination"]:
                                                                                    if dest in hostlist:
                                                                                                hostlist.remove(dest)
                                                                        for src in secrule["source"]:
                                                                                    if src in hostlist:
                                                                                                hostlist.remove(src)
                                                else:
                                                            for dest in rule["destination"]:
                                                                        if dest in hostlist:
                                                                                    hostlist.remove(dest)
                                                            for src in rule["source"]:
                                                                        if src in hostlist:
                                                                                    hostlist.remove(src)
                                    curr = rules_clean["to"]
                                    print(domain+" "+layer["name"]+": "+str(curr)+"/"+str(total))
            return hostlist

def checkIfInGroup(net_connect, domain, sid, host):
            host_data_raw = net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -d "+domain+" --session-id "+sid+" show host uid "+host+" --format json")
            host_data = json.loads(host_data_raw)
            return len(host_data["groups"])

def deleteHost(net_connect, domain, sid, host):
            print("Removing unused Host "+host+" on "+domain)
            print(net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -d "+domain+" --session-id "+sid+" delete host uid "+host))

def publish(net_connect, domain, sid):
            net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -d "+domain+" --session-id "+sid+" publish")
def logout(net_connect, domain, sid):
            net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -d "+domain+" --session-id "+sid+" logout")

def searchAndDestroy(network):
            connection = {
                                    'device_type': "checkpoint_gaia",
                                    'host': ip,
                                    'username': username,
                                    'password': password,
            }
            net_connect = ConnectHandler(**connection)
            print("Getting Domains...")
            domains_raw = net_connect.send_command("mgmt_cli --port "+api_port+" -m 127.0.0.1 -u "+username+" -p "+password+" show domains --format json")
            domains = json.loads(domains_raw)
            for obj in domains["objects"]:
                        sid = login(net_connect, obj["name"], username, password)
                        hostlist_raw = getHostsInNetwork(net_connect, obj["name"], sid, network)
                        hostlist_clean = checkIfInRules(net_connect, obj["name"], sid, hostlist_raw)
                        for host in hostlist_clean:
                                    if checkIfInGroup(net_connect, obj["name"], sid, host) == 0:
                                                deleteHost(net_connect, obj["name"], sid, host)
                        publish(net_connect, obj["name"], sid)
                        logout(net_connect, obj["name"], sid)

searchAndDestroy(input("Enter subnet (Format: \"10.10.10.0/24\"):"))
