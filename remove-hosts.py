import ipaddress
import json
import requests
import urllib3

import secrets

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

username = secrets.username
password = secrets.password

ip = "127.0.0.1"
api_port = "443"

def login(domain, user, passwd):
	headers = {'Content-Type' : 'application/json'}
	payload = {'user' : user, 'password' : passwd, 'domain' : domain}
	sid = requests.post('https://'+ip+':'+api_port+'/web_api/login',data=json.dumps(payload), headers=headers, verify=False)
	sid_clean = sid.json()
	return sid_clean['sid']

def getHostsInNetwork(sid, network):
	addresses = ipaddress.ip_network(network)
	headers = {'Content-Type' : 'application/json', 'X-chkp-sid': sid}
	payload = {'limit' : 1, 'offset' : 0}
	hosts_raw = requests.post('https://'+ip+':'+api_port+'/web_api/show-hosts',data=json.dumps(payload), headers=headers, verify=False)
	hosts_clean = hosts_raw.json()
	hostlist = []
	curr = 0
	total = hosts_clean["total"]
	print("Getting Hosts...")
	while curr < total:
		payload = {'limit' : 500, 'offset' : curr}
		hosts_raw = requests.post('https://'+ip+':'+api_port+'/web_api/show-hosts',data=json.dumps(payload), headers=headers, verify=False)
		hosts_clean = hosts_raw.json()
		for host in hosts_clean["objects"]:
			if ipaddress.ip_address(host["ipv4-address"]) in addresses:
				hostlist.append(host["uid"])
		curr = hosts_clean["to"]
		print("Hosts: "+str(curr)+"/"+str(total))
	return hostlist

def checkIfInRules(sid, hostlist):
	print("Getting Rules...")
	headers = {'Content-Type' : 'application/json', 'X-chkp-sid': sid}
	payload = {}
	layers_raw = requests.post('https://'+ip+':'+api_port+'/web_api/show-access-layers',data=json.dumps(payload), headers=headers, verify=False)
	layers_clean = layers_raw.json()
	for layer in layers_clean["access-layers"]:
		payload = {'uid': layer['uid'], 'limit': 1}
		rules_raw = requests.post('https://'+ip+':'+api_port+'/web_api/show-access-rulebase',data=json.dumps(payload), headers=headers, verify=False)
		rules_clean = rules_raw.json()
		curr = 0
		total = rules_clean["total"]
		while curr < total:
			payload = {'uid': layer['uid'], 'limit': 500, 'offset': curr}
			rules_raw = requests.post('https://'+ip+':'+api_port+'/web_api/show-access-rulebase',data=json.dumps(payload), headers=headers, verify=False)
			rules_clean = rules_raw.json()
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
			curr = rules_clean['to']
			print(layer["name"]+": "+str(curr)+"/"+str(total))
	return hostlist

def checkIfInGroup(sid, host):
	headers = {'Content-Type' : 'application/json', 'X-chkp-sid': sid}
	payload = {'uid': host}
	host_data_raw = requests.post('https://'+ip+':'+api_port+'/web_api/show-host',data=json.dumps(payload), headers=headers, verify=False)
	host_data = host_data_raw.json()
	return len(host_data["groups"])

def deleteHost(sid, host):
	headers = {'Content-Type' : 'application/json', 'X-chkp-sid': sid}
	payload = {'uid': host}
	host_data_raw = requests.post('https://'+ip+':'+api_port+'/web_api/delete-host',data=json.dumps(payload), headers=headers, verify=False)
	host_data = host_data_raw.json()
	print(host_data["message"])

def publish(sid):
	headers = {'Content-Type' : 'application/json', 'X-chkp-sid': sid}
	payload = {}
	r = requests.post('https://'+ip+':'+api_port+'/web_api/publish', headers=headers, data=json.dumps(payload), verify=False)

def logout(sid):
	headers = {'Content-Type' : 'application/json', 'X-chkp-sid': sid}
	payload = {}
	r = requests.post('https://'+ip+':'+api_port+'/web_api/logout', headers=headers, data=json.dumps(payload), verify=False)	

def searchAndDestroy(network):
	print("Getting Domains...")
	headers = {'Content-Type' : 'application/json'}
	payload = {'user' : username, 'password' : password}
	sid = requests.post('https://'+ip+':'+api_port+'/web_api/login',data=json.dumps(payload), headers=headers, verify=False)
	sid_clean = sid.json()
	headers = {'Content-Type' : 'application/json', 'X-chkp-sid': sid_clean['sid']}
	payload = {}
	domains_raw = requests.post('https://'+ip+':'+api_port+'/web_api/show-domains',data=json.dumps(payload), headers=headers, verify=False)
	domains = domains_raw.json()
	logout(sid_clean['sid'])
	for obj in domains["objects"]:
		sid = login(obj["name"], username, password)
		hostlist_raw = getHostsInNetwork(sid, network)
		hostlist_clean = checkIfInRules(sid, hostlist_raw)
		for host in hostlist_clean:
			if checkIfInGroup(sid, host) == 0:
				print("Removing unused Host "+host+" on "+obj['name'])
				deleteHost(sid, host)
		publish(sid)
		logout(sid)

searchAndDestroy(input("Enter subnet (Format: \"201.1.11.0/30\"):"))
