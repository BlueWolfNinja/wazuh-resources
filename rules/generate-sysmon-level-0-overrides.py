#!/usr/bin/env python3

import sys
import glob
import re
from pathlib import Path

BASE_DIR = Path("/var/ossec/ruleset/rules")

STATIC_FILES = [
	"0595-win-sysmon_rules.xml",
	"*-sysmon_id_*.xml",
]

IF_TAG_RE = re.compile(r"<if_.*>")

HEADER_COMMENT = """<!--
This is Wazuh's full set of built-in Windows EventChannel Sysmon level 0 rules, overridden to have a severity level of 3.  
These are pulled from the 0595-win-sysmon_rules.xml and *-sysmon_id_*.xml rule files.
All <if_*> lines are commented out as they cannot be redefined with an overwrite.
Add this as something like /var/ossec/etc/rules/sysmon_level_0_overrides.xml to your standalone/master Wazuh server.
Use it to make Wazuh capture and index full Sysmon event telemetry.
This will substantially increase the Wazuh indexing volume of Sysmon alerts, so adjust your Sysmon configuration to exclude noise as needed.
-->"""


def find_rule_blocks(text: str):
	i = 0
	n = len(text)

	while True:
		start = text.find("<rule", i)
		if start == -1:
			return

		j = start + 5
		in_quote = None

		while j < n:
			c = text[j]
			if in_quote:
				if c == in_quote:
					in_quote = None
			else:
				if c in ('"', "'"):
					in_quote = c
				elif c == ">":
					break
			j += 1

		if j >= n:
			return

		start_tag_end = j
		close = text.find("</rule>", start_tag_end + 1)
		if close == -1:
			return

		end = close + len("</rule>")
		yield text[start:end]
		i = end


def transform_rule_start_tag(block: str):
	n = len(block)
	j = 0
	in_quote = None

	while j < n:
		c = block[j]
		if in_quote:
			if c == in_quote:
				in_quote = None
		else:
			if c in ('"', "'"):
				in_quote = c
			elif c == ">":
				break
		j += 1

	if j >= n:
		return None

	start_tag = block[:j+1]
	rest = block[j+1:]

	needle = 'level="0"'
	pos = start_tag.find(needle)
	if pos == -1:
		return None

	new_start_tag = (
		start_tag[:pos]
		+ 'level="3" overwrite="yes"'
		+ start_tag[pos + len(needle):]
	)

	return new_start_tag + rest


def indent_block(block: str, indent: str = "  "):
	out = []

	for line in block.splitlines(True):
		line_body = line.rstrip("\r\n")
		line_ending = line[len(line_body):]

		match = IF_TAG_RE.search(line_body)
		if match:
			start, end = match.span()
			line_body = (
				line_body[:start]
				+ "<!--"
				+ line_body[start:end]
				+ "-->"
				+ line_body[end:]
			)

		modified = line_body + line_ending

		if modified.startswith("  </rule>"):
			out.append(modified)
		else:
			out.append(indent + modified)

	return "".join(out)


def get_target_files():
	seen = set()

	for pattern in STATIC_FILES:
		full_pattern = str(BASE_DIR / pattern)
		for match in glob.glob(full_pattern):
			path = Path(match)
			if path.is_file() and path not in seen:
				seen.add(path)
				yield path


def main():
	if not BASE_DIR.exists():
		print(f"[ERROR] Directory not found: {BASE_DIR}", file=sys.stderr)
		sys.exit(1)

	# Header comment + blank line
	sys.stdout.write(HEADER_COMMENT + "\n\n")

	# Group wrapper + blank line
	sys.stdout.write('<group name="windows,sysmon,">\n\n')

	for path in sorted(get_target_files()):
		try:
			text = path.read_text(encoding="utf-8", errors="strict")
		except UnicodeDecodeError:
			text = path.read_text(encoding="utf-8", errors="replace")

		for block in find_rule_blocks(text):
			new_block = transform_rule_start_tag(block)
			if new_block is None:
				continue

			sys.stdout.write(indent_block(new_block, "  "))

			if not new_block.endswith("\n"):
				sys.stdout.write("\n")
			sys.stdout.write("\n")

	sys.stdout.write("</group>\n")


if __name__ == "__main__":
	main()
