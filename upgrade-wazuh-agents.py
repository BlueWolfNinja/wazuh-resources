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
# This script checks for outdated Wazuh agents, initiates upgrades, monitors upgrade progress,
# logs results, refreshes the bwn-states-agents index, recalculates agent version stats, and
# refreshes them in the bwn-states-agent-version-stats index.
#

import os
import sys
import time
import json
import requests
import urllib3
import warnings
import jq
import argparse
from datetime import datetime, timezone, timedelta
from dateutil import parser  # pip install python-dateutil

from opensearchpy import OpenSearch, helpers

# Suppress InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Suppress opensearchpy SSL warnings
warnings.filterwarnings(
	"ignore",
	message="Connecting to .* using SSL with verify_certs=False is insecure",
	category=UserWarning
)

# How long to pause before each check on the progress of the upgrade tasks
sleep1 = 30
# How long to pause after a progress check reports no agents in the "Upgrading" state before checking for the last time
sleep2 = 60


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

	# Required variables validation
	required_vars = ["WAPIHOST", "WAPIUSER", "WAPIPASS", "WIHOST", "WIUSER", "WIPASS"]
	missing_vars = [v for v in required_vars if v not in creds]
	if missing_vars:
		raise ValueError(f"Missing required variables in config file '{config_file}': {', '.join(missing_vars)}")

	return creds


def get_token(creds):
	url = f"https://{creds['WAPIHOST']}:55000/security/user/authenticate?raw=true"
	try:
		resp = requests.get(url, auth=(creds["WAPIUSER"], creds["WAPIPASS"]), verify=False)
		resp.raise_for_status()
	except requests.RequestException as e:
		print(f"Error fetching Wazuh API token: {e}")
		raise
	return resp.text.strip()


def check_upgrading_agents(agents, creds, log_file):
	token = get_token(creds)
	for agent_id in list(agents.keys()):
		print(f"Checking upgrade task status for Agent ID: {agent_id}")
		url = f"https://{creds['WAPIHOST']}:55000/agents/upgrade_result?agents_list={agent_id}"
		try:
			resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, verify=False)
			resp.raise_for_status()
		except requests.RequestException as e:
			print(f"Warning: Could not fetch upgrade status for agent {agent_id}: {e}")
			continue

		data = resp.json()
		matches = jq.all('.data.affected_items[] | select(.command == "upgrade")', data)
		disposition = matches[0] if matches else None

		if disposition:
			status = disposition.get("status")
			if status != "Updating":
				print(f'  Final result found - merging and logging details. Status: "{status}".')
				full_results = {**agents[agent_id], **disposition}
				for key in ["create_time", "message", "task_id", "agent", "module"]:
					full_results.pop(key, None)
				with open(log_file, "a") as f:
					f.write(json.dumps(full_results) + "\n")
				del agents[agent_id]
			else:
				print("  Agent is still updating.")
		else:
			print("  No results yet")


def refresh_agents_index(os_client, creds):
	token = get_token(creds)
	
	# Delete the bwn-states-agents index if it exists
	print("Deleting index bwn-states-agents if present...")	
	os_client.indices.delete(index="bwn-states-agents", ignore=[404])
	
	# Define the legacy template with smart dynamic mapping
	template_body = {
		"index_patterns": ["bwn-states-agents"],
		"mappings": {
			"dynamic_templates": [
				{
					"all_strings_as_keyword": {
						"match_mapping_type": "string",
						"mapping": {
							"type": "keyword",
							"ignore_above": 256
				} } },
				{
					"numbers_booleans_as_keyword": {
						"match_mapping_type": "long",
						"mapping": {"type": "keyword"}
				} },
				{
					"numbers_booleans_as_keyword_float": {
						"match_mapping_type": "double",
						"mapping": {"type": "keyword"}
				} },
				{
					"numbers_booleans_as_keyword_bool": {
						"match_mapping_type": "boolean",
						"mapping": {"type": "keyword"}
				} }
			],
			"properties": {
				"lastKeepAlive": {
					"type": "date"
	} } } }

	# Push the template for the bwn-states-agents index
	response = os_client.indices.put_template(
		name="bwn-states-agents-template",
		body=template_body
	)
	print("Template creation response:", response)

	# Create the bwn-states-agents index with the benefit of the template
	response = os_client.indices.create(index="bwn-states-agents")
	print("Created index bwn-states-agents", response)

	# Fetch all agents from Wazuh API with only desired fields
	url_all_agents = f"https://{creds['WAPIHOST']}:55000/agents?select=id,name,version,os.name,os.version,os.arch,os.platform,lastKeepAlive&limit=10000"
	try:
		resp_agents = requests.get(url_all_agents, headers={"Authorization": f"Bearer {token}"}, verify=False)
		resp_agents.raise_for_status()
	except requests.RequestException as e:
		print(f"Error fetching all agents: {e}")
		return
	all_agents = resp_agents.json()["data"]["affected_items"]

	# Build records to write to new bwn-states-agents index, dropping agent 000 (manager) and normalizing the version field value.
	actions = []
	for a in all_agents:
		if a.get("id") != "000":
			if a.get("version", "").startswith("Wazuh v"):
				a["version"] = a["version"].replace("Wazuh v", "", 1)
			actions.append({"_index": "bwn-states-agents", "_source": a})
	
	# Bulk push the documents to OpenSearch directly
	if actions:
		helpers.bulk(os_client, actions)

	print("Refresh of bwn-states-agents index and template complete.")


def upgrade_agents(agents, creds, token, log_file):
	if not agents:
		print("No candidates for agent upgrades.")
		sys.exit(0)

	print("Agents to attempt to upgrade:")
	for a in agents.values():
		print(json.dumps(a, indent=2))

	# Initiate upgrade
	agent_ids_csv = ",".join(agents.keys())
	url_upgrade = f"https://{creds['WAPIHOST']}:55000/agents/upgrade?agents_list={agent_ids_csv}"
	print(f"Initiating upgrade tasks for agents: {url_upgrade}")
	try:
		resp = requests.put(url_upgrade, headers={"Authorization": f"Bearer {token}"}, verify=False)
		resp.raise_for_status()
	except requests.RequestException as e:
		print(f"Error initiating agent upgrades: {e}")
		return

	# Monitor upgrades
	while agents:
		print(f"Pausing for {sleep1} seconds before checking on agent upgrade progress...")
		time.sleep(sleep1)
		check_upgrading_agents(agents, creds, log_file)
		if not agents:
			break
		url_check = f"https://{creds['WAPIHOST']}:55000/agents/upgrade_result"
		try:
			resp_check = requests.get(url_check, headers={"Authorization": f"Bearer {token}"}, verify=False)
			resp_check.raise_for_status()
		except requests.RequestException as e:
			print(f"Warning: Could not fetch upgrade results: {e}")
			time.sleep(sleep2)
			continue
		updating_agents = jq.all('.data.affected_items[] | select(.command == "upgrade") | select(.status == "Updating")', resp_check.json())
		if not updating_agents:
			print(f"No agents are reporting they are updating, though one or more final agents may be restarting. Waiting for {sleep2} more seconds...")
			time.sleep(sleep2)
			check_upgrading_agents(agents, creds, log_file)
			break

	# Classify lingering agents as 'Absent' and log about them as well, leaving no remaining agents in the array.
	for agent_id in list(agents.keys()):
		print(f"Agent {agent_id} absent. Logging.")
		full_results = {**agents[agent_id], "status": "Absent"}
		for key in ["create_time", "message", "task_id", "agent", "module"]:
			full_results.pop(key, None)
		with open(log_file, "a") as f:
			f.write(json.dumps(full_results) + "\n")
		del agents[agent_id]

	print("Agent upgrade attempts complete")

def refresh_agents_stats_index(os_client, target_version):
	print("Refreshing bwn-states-agent-version-stats...")

	# Delete the index if it exists
	os_client.indices.delete(index="bwn-states-agent-version-stats", ignore=[404])

	# Define the template with explicit fields
	template_body = {
		"index_patterns": ["bwn-states-agent-version-stats"],
		"mappings": {
			"properties": {
				"target_version": {"type": "keyword"},
				"day_count": {"type": "integer"},
				"day_compliant": {"type": "integer"},
				"day_percent": {"type": "integer"},
				"week_count": {"type": "integer"},
				"week_compliant": {"type": "integer"},
				"week_percent": {"type": "integer"},
				"month_count": {"type": "integer"},
				"month_compliant": {"type": "integer"},
				"month_percent": {"type": "integer"},
				"year_count": {"type": "integer"},
				"year_compliant": {"type": "integer"},
				"year_percent": {"type": "integer"},
				"all_count": {"type": "integer"},
				"all_compliant": {"type": "integer"},
				"all_percent": {"type": "integer"}
			}
		}
	}

	os_client.indices.put_template(
		name="bwn-states-agent-version-stats-template",
		body=template_body
	)

	os_client.indices.create(index="bwn-states-agent-version-stats")

	# This index was recreated milliseconds ago.  Make sure to refresh it or it will appear empty.
	os_client.indices.refresh(index="bwn-states-agents")

	# Fetch all agents with only lastKeepAlive and version fields
	resp = os_client.search(
		index="bwn-states-agents",
		body={
			"_source": ["lastKeepAlive", "version"],
			"query": {"match_all": {}},
			"size": 10000
		}
	)
	all_agents = [hit["_source"] for hit in resp["hits"]["hits"]]

	now = datetime.now(timezone.utc)
	day_ago = now - timedelta(days=1)
	week_ago = now - timedelta(weeks=1)
	month_ago = now - timedelta(days=30)
	year_ago = now - timedelta(days=365)

	def count_window(agents, cutoff, version_filter=None):
		count = 0
		for a in agents:
			last_keepalive_str = a.get("lastKeepAlive")
			if not last_keepalive_str:
				continue
			try:
				last_keepalive = parser.isoparse(last_keepalive_str)
			except Exception:
				continue
			if last_keepalive >= cutoff:
				if version_filter is None or a.get("version") == version_filter:
					count += 1
		return count

	all_count = len(all_agents)
	all_compliant = sum(1 for a in all_agents if a.get("version") == target_version)

	day_count = count_window(all_agents, day_ago)
	day_compliant = count_window(all_agents, day_ago, version_filter=target_version)

	week_count = count_window(all_agents, week_ago)
	week_compliant = count_window(all_agents, week_ago, version_filter=target_version)

	month_count = count_window(all_agents, month_ago)
	month_compliant = count_window(all_agents, month_ago, version_filter=target_version)

	year_count = count_window(all_agents, year_ago)
	year_compliant = count_window(all_agents, year_ago, version_filter=target_version)

	# Percentages relative to the count of that specific time window
	def pct(part, total):
		return int(part / total * 100) if total else 0

	doc = {
		"target_version": target_version,
		"day_count": day_count,
		"day_compliant": day_compliant,
		"day_percent": pct(day_compliant, day_count),
		"week_count": week_count,
		"week_compliant": week_compliant,
		"week_percent": pct(week_compliant, week_count),
		"month_count": month_count,
		"month_compliant": month_compliant,
		"month_percent": pct(month_compliant, month_count),
		"year_count": year_count,
		"year_compliant": year_compliant,
		"year_percent": pct(year_compliant, year_count),
		"all_count": all_count,
		"all_compliant": all_compliant,
		"all_percent": pct(all_compliant, all_count)
	}

	os_client.index(index="bwn-states-agent-version-stats", body=doc)
	print("Inserted global statistics into bwn-states-agent-version-stats.")


def main():
	parser = argparse.ArgumentParser(description="Upgrade Wazuh agents")
	parser.add_argument("-n", "--number", type=int, default=None)
	parser.add_argument("-c", "--config", type=str, default="/etc/.siem-auth")
	parser.add_argument("-l", "--log", type=str, default="/var/log/wazuh-agent-upgrade-manager.json")
	parser.add_argument('-r', '--refresh', action='store_true', help='Only refresh the stateful indexes.  Initiate no upgrading of agents.')
	args = parser.parse_args()

	log_file = args.log
	creds = load_auth(args.config)
	token = get_token(creds)

	# Find target Wazuh version
	target_version = None
	wazuh_info = os.popen("/var/ossec/bin/wazuh-control info").read()
	for line in wazuh_info.splitlines():
		if "WAZUH_VERSION" in line:
			target_version = line.split("=")[1].strip().strip('"').lstrip("v")

	# Fetch outdated agents via Wazuh API
	url = f"https://{creds['WAPIHOST']}:55000/agents/outdated?select=id,name,version,os.platform,os.name,os.version,os.arch&q=status=active"
	try:
		resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, verify=False)
		resp.raise_for_status()
	except requests.RequestException as e:
		print(f"Error fetching outdated agents: {e}")
		return
	agents_raw = resp.json()["data"]["affected_items"]

	# Filter ARM and apply -n limit to # of agents to initiate upgrades on
	agents_raw = [a for a in agents_raw if a.get("os", {}).get("arch") not in ("arm64", "aarch64")]
	if args.number is not None:
		agents_raw = agents_raw[:args.number]

	# Form agents array of objects, merging original outdated agent query findings with additional keys
	agents_aug = []
	for a in agents_raw:
		a["timestamp"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
		a["target_version"] = target_version
		if a.get("version", "").startswith("Wazuh v"):
			a["version"] = a["version"].replace("Wazuh v", "", 1)
		agents_aug.append(a)
	agents = {a["id"]: a for a in agents_aug}

	# Proceed to initiate and track agent upgrades unless -r/--refresh was specified
	if not args.refresh: 
		upgrade_agents(agents, creds, token, log_file)
	else:
		print("Refreshing stateful indexes without any upgrading of agents...")
		
	# Connect to Wazuh Indexer for stateful index and template refresh purposes
	os_client = OpenSearch(
		hosts=[{"host": creds["WIHOST"], "port": int(creds["WIPORT"])}],
		http_auth=(creds["WIUSER"], creds["WIPASS"]),
		scheme="https",
		verify_certs=False
	)

	# Regenerate the bwn-states-agents index with a fresh query of the Wazuh API and refreshing the template.
	refresh_agents_index(os_client, creds)

	# Regenerate the bwn-states-agent-version-stats index with a fresh data from bwn-states-agents and refreshing the template.
	refresh_agents_stats_index(os_client, target_version)

if __name__ == "__main__":
	main()
