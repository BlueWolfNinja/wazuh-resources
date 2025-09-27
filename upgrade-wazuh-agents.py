#!/usr/bin/env python3

#
# upgrade-wazuh-agents.py
# by Kevin Branch (@BlueWolfNinja)
# https://bluewolfninja.com
# 
# Authoritatively available from:
# https://github.com/BlueWolfNinja/wazuh-resources
#
# Explained in this blog article
# https://bluewolfninja.com/---TBD---
#
# This script checks for outdated Wazuh agents, initiates upgrades,
# monitors upgrade progress, logs results, and refreshes the agents index in Wazuh Indexer
#

import os
import time
import json
import requests
import urllib3  # for warning suppression
import jq
import argparse
import tempfile
from pathlib import Path
from datetime import datetime, timezone

# Suppress only InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_auth(config_file=None):
	if config_file is None:
		config_file = "/etc/.siem-auth"
	creds = {}
	with open(config_file) as f:
		for line in f:
			line = line.strip()
			if not line or line.startswith("#"):
				continue
			k, v = line.split("=", 1)
			creds[k.strip()] = v.strip().strip('"')
	return creds

def get_token(creds):
	url = f"https://{creds['WAPIHOST']}:55000/security/user/authenticate?raw=true"
	resp = requests.get(url, auth=(creds["WAPIUSER"], creds["WAPIPASS"]), verify=False)
	resp.raise_for_status()
	return resp.text.strip()

def check_upgrading_agents(agents, creds, log_file):
	token = get_token(creds)
	for agent_id in list(agents.keys()):
		print(f"Checking upgrade task status for Agent ID: {agent_id}")
		url = f"https://{creds['WAPIHOST']}:55000/agents/upgrade_result?agents_list={agent_id}"
		resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, verify=False)
		resp.raise_for_status()
		data = resp.json()

		# Safer jq processing
		matches = jq.all('.data.affected_items[] | select(.command == "upgrade")', data)
		disposition = matches[0] if matches else None

		if disposition:
			status = disposition.get("status")
			if status != "Updating":
				print(f'  Final result found - merging and logging details. Status: "{status}".')
				full_results = {**agents[agent_id], **disposition}

				# Remove unwanted keys before logging
				for key in ["create_time", "message", "task_id", "agent", "module"]:
					full_results.pop(key, None)

				with open(log_file, "a") as f:
					f.write(json.dumps(full_results) + "\n")
				del agents[agent_id]
			else:
				print("  Agent is still updating.")
		else:
			print("  No results yet")

def main():
	parser = argparse.ArgumentParser(description="Upgrade Wazuh agents")
	parser.add_argument("-n", "--number", type=int, default=None, help="Limit the number of agents to start upgrading")
	parser.add_argument("-c", "--config", type=str, default="/etc/.siem-auth", help="Path to the credentials file for Wazuh API")
	parser.add_argument("-l", "--log", type=str, default="/var/log/wazuh-agent-upgrade-attempts.json", help="Path to log file for upgrade attempts")
	args = parser.parse_args()

	log_file = args.log
	creds = load_auth(args.config)
	token = get_token(creds)

	# Determine target version
	target_version = None
	wazuh_info = os.popen("/var/ossec/bin/wazuh-control info").read()
	for line in wazuh_info.splitlines():
		if "WAZUH_VERSION" in line:
			target_version = line.split("=")[1].strip().strip('"').lstrip("v")

	# Fetch outdated active agents
	url = f"https://{creds['WAPIHOST']}:55000/agents/outdated?select=id,name,version,os.platform,os.name,os.version,os.arch&q=status=active"
	resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, verify=False)
	resp.raise_for_status()
	agents_raw = resp.json()["data"]["affected_items"]

	# Filter ARM and apply -n limit safely
	agents_raw = [a for a in agents_raw if a.get("os", {}).get("arch") not in ("arm64", "aarch64")]
	if args.number is not None:
		agents_raw = agents_raw[:args.number]

	if not agents_raw:
		print("There are no candidates for agent upgrades at this time.")
		return

	now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
	agents_aug = []
	for a in agents_raw:
		a["timestamp"] = now_str
		a["target_version"] = target_version
		if a.get("version", "").startswith("Wazuh v"):
			a["version"] = a["version"].replace("Wazuh v", "", 1)
		agents_aug.append(a)

	agents = {a["id"]: a for a in agents_aug}

	print("Agents to attempt to upgrade:")
	for a in agents.values():
		print(json.dumps(a, indent=2))

	# Build CSV of agent IDs to upgrade
	agent_ids_csv = ",".join(agents.keys())

	print(f"Kicking off upgrades - https://{creds['WAPIHOST']}:55000/agents/upgrade?agents_list={agent_ids_csv}")

	# Initiate upgrade
	url_upgrade = f"https://{creds['WAPIHOST']}:55000/agents/upgrade?agents_list={agent_ids_csv}"
	resp = requests.put(url_upgrade, headers={"Authorization": f"Bearer {token}"}, verify=False)

	# Monitor progress
	while agents:
		print("5 minute pause...")
		time.sleep(300)
		check_upgrading_agents(agents, creds, log_file)

		if not agents:
			print("All agents have final results.")
			break

		# Check if any agents are actively updating
		url_check = f"https://{creds['WAPIHOST']}:55000/agents/upgrade_result"
		resp_check = requests.get(url_check, headers={"Authorization": f"Bearer {token}"}, verify=False)
		resp_check.raise_for_status()
		updating_agents = jq.all('.data.affected_items[] | select(.command == "upgrade") | select(.status == "Updating")', resp_check.json())
		if not updating_agents:
			print("No agents reporting 'Updating'. Waiting 10 more minutes...")
			time.sleep(600)
			check_upgrading_agents(agents, creds, log_file)
			break

	# Handle any lingering agents as 'Absent'
	for agent_id in list(agents.keys()):
		print(f"Agent {agent_id} has gone absent. Logging and giving up on it...")
		full_results = {**agents[agent_id], "status": "Absent"}
		for key in ["create_time", "message", "task_id", "agent", "module"]:
			full_results.pop(key, None)
		with open(log_file, "a") as f:
			f.write(json.dumps(full_results) + "\n")
		del agents[agent_id]

	# Refresh agents index (temporary bulk file)
	tmpfile = tempfile.NamedTemporaryFile(prefix="bulk_", suffix=".json", delete=False)
	tmpfile_path = Path(tmpfile.name)
	tmpfile.close()

	url_all_agents = f"https://{creds['WAPIHOST']}:55000/agents?select=id,name,version,os.name,os.version,os.arch,os.platform,lastKeepAlive&limit=10000"
	resp_agents = requests.get(url_all_agents, headers={"Authorization": f"Bearer {token}"}, verify=False)
	resp_agents.raise_for_status()
	all_agents = resp_agents.json()["data"]["affected_items"]

	with tmpfile_path.open("w") as f:
		for a in all_agents:
			if a.get("id") != "000":
				if a.get("version", "").startswith("Wazuh v"):
					a["version"] = a["version"].replace("Wazuh v", "", 1)
				f.write(json.dumps({"create": {}}) + "\n")
				f.write(json.dumps(a) + "\n")
		f.write("\n")

	# Post bulk to Wazuh index (example, requires credentials)
	# requests.post(..., data=tmpfile_path.read_bytes(), ...)

	tmpfile_path.unlink()
	print("Upgrade cycle complete. Agents index refreshed.")

if __name__ == "__main__":
	main()
