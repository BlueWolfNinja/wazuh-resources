# Establishing a shared Python 3 virtual environment for use with Blue Wolf Ninja scripts.
Most Python scripts shared in this repository assume the presence of Python 3 and a virtual environment installed under `/venv/bwn/`.  Such scripts will be documented at the top of the file with their dependencies.  Blue Wolf Ninja seeks to maintain a set of non-conflicting dependencies across all shared Python scripts that require a virtual environment.  You are of course completely free to use whatever Python 3 interpreter you like with BWN-shared scripts, with or without a virtual environment, as long as you work out the dependency details.  This is just an effort to provide as simple and non-conflicting of an experience as possible.  If you see any way I could make the following more Linux distro-agnsotic in a simple way, please share your ideas!

### 1. Ensure Python 3 with virtual environment support is in place.

``` bash
if command -v apt >/dev/null 2>&1; then
	sudo apt -y install python3; sudo apt -y install python3-venv
elif command -v dnf >/dev/null 2>&1; then
	sudo dnf -y install --skip-unavailable python3 python3-venv
elif command -v yum >/dev/null 2>&1; then
	sudo yum -y install --skip-unavailable python3 python3-venv
fi
```

### 2. Put the virtual environment in place.

``` bash 
sudo mkdir /venv
sudo python3 -m venv /venv/bwn
sudo touch /venv/bwn/requirements.txt
```

### 3. If step 2 fails...

Research how to add Python 3 virtual environment support for your specific Linux distro and version.  Do what is necessary to add it, and then repeat step 2.

### 4. When installing a new BWN Python script, ensure its dependencies are met and up-to-date.
#### Search in the top of the script for a list of dependencies under "# This script requires at least the following lines to be present in /venv/bwn/requirements.txt:", and add/replace lines in that file as needed.  For example, you might need to add:
``` bash
jq>=1.0,<2.0
opensearch-py>=2.0.0,<3.0.0
python-dateutil>=2.0.0,<3.0.0
```
#### If you make any additions or changes above, then apply them with:
```
sudo /venv/bwn/bin/pip install -r /venv/bwn/requirements.txt
```
You may wish to keep this virtual environment up-to-date by adding the above command to your standard Linux update procedure.
