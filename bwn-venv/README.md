# Distro-Agnostic Python 3 Virtual Environment Setup

## Goal

Create a Python 3 virtual environment at:

    /venv/bwn/

These steps apply to modern:

-   Ubuntu
-   Debian
-   RHEL-family (RHEL, Rocky, AlmaLinux, CentOS Stream, Fedora)

------------------------------------------------------------------------

## 1. Install Prerequisites

Install Python 3, pip, and the venv module using the system package
manager.

### Ubuntu / Debian

``` bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip
```

### RHEL-family (RHEL, Rocky, AlmaLinux, CentOS Stream, Fedora)

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

Package naming varies by distribution and release.

------------------------------------------------------------------------

## 2. Create the Parent Directory

Choose an ownership model based on how the virtual environment will be
managed.

### Option A --- Service-Owned Virtual Environment (Recommended)

``` bash
sudo mkdir -p /venv
sudo chown bwn:bwn /venv
sudo chmod 0755 /venv
```

### Option B --- Root-Owned Virtual Environment

``` bash
sudo mkdir -p /venv
sudo chmod 0755 /venv
```

------------------------------------------------------------------------

## 3. Create the Virtual Environment

### If the venv should be owned by user `bwn`

``` bash
sudo -u bwn python3 -m venv /venv/bwn
```

### If root will manage the venv

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
