# A common Python 3 virtual environment for Blue Wolf Ninja scripts.
All Python scripts shared in this repository assume the presence of a baseline Python 3 virtual environment installed under /venv/bwn/.  Assuming you are using a modern Ubuntu, Debian, or Redhat variant, the following guide should work for you with little to no customization.

## Goal

Create a Python 3 virtual environment at:

    /venv/bwn/

## 1. Install Prerequisites

Install Python 3, pip, and the venv module using the system package
manager.

### Ubuntu / Debian

``` bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip
```

### Redhat-type distos

Use whichever package manager exists on the host.

Using `dnf`:

``` bash
sudo dnf install -y python3 python3-pip
```

Using `yum`:

``` bash
sudo yum install -y python3 python3-pip
```

If this command fails:

``` bash
python3 -m venv /venv/bwn
```

Install the appropriate venv-related package provided by your
distribution. Possible package names include:

-   `python3-venv`
-   `python3-virtualenv`
-   `python3.x-venv` (version-specific)

------------------------------------------------------------------------

## 2. Create the Parent Directory

``` bash
sudo mkdir -p /venv
sudo chmod 0755 /venv
```

------------------------------------------------------------------------

## 3. Create the Virtual Environment

``` bash
sudo python3 -m venv /venv/bwn
```

------------------------------------------------------------------------

## 4. Activate the Virtual Environment and Upgrade Packaging Tools

Activate:

``` bash
source /venv/bwn/bin/activate
```

Upgrade packaging tools:

``` bash
python -m pip install --upgrade pip setuptools wheel
```

Verify:

``` bash
which python
python --version
python -m pip --version
```

Deactivate when finished:

``` bash
deactivate
```

------------------------------------------------------------------------

## 5. Non-Interactive Usage (systemd, cron, automation)

Avoid activation in automation contexts. Instead, call the virtual
environment's binaries directly.

Install dependencies:

``` bash
/venv/bwn/bin/python -m pip install -r /path/to/requirements.txt
```

Run an application:

``` bash
/venv/bwn/bin/python /path/to/app.py
```

------------------------------------------------------------------------

## Additional Notes

-   Ensure the virtual environment directory is writable by the intended
    managing user.
-   On SELinux-enforcing RHEL-family systems, file contexts may require
    adjustment depending on the service domain.
-   If multiple Python 3 versions are installed, explicitly target the
    required version:

``` bash
python3.11 -m venv /venv/bwn
```
