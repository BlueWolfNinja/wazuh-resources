#
# check-sysmon-lite.ps1 (Blue Wolf Ninja lightweight Sysmon Checker)
# by Kevin Branch (@BlueWolfNinja)
# https://bluewolfninja.com
#
# Authoritatively available from:
# https://github.com/BlueWolfNinja/wazuh-resources
#
# Presented in Ninja Nugget #10:
# path here...
#
# This script checks for the presence and version of Sysmon, and initiates a config reload if the running Sysmon configuration does
# not match the centrally shared configuration.  It then reports all findings and results as a single JSON output record.
#

# The Sysmon executable location and Wazuh's application directory differ for 32 vs 64 bit Windows.  Detect what is present.
$SysmonPath = ("C:\Windows\sysmon64.exe", "C:\Windows\sysmon.exe" | Where-Object { Test-Path $_ } | Select-Object -First 1)
$WazuhDir  = ("C:\Program Files (x86)\ossec-agent", "C:\Program Files\ossec-agent" | Where-Object { Test-Path $_ } | Select-Object -First 1)

$Version = 0
$StartConfigHash = ""
$LiveConfigHash = ""
$SharedConfigHash = ""
$ReloadAttempted = $false
$ReloadSucceeded = $false

# Confirm what version--if any--of Sysmon is present.  A version of zero means Sysmon is absent.
if ($SysmonPath) {
	try {
		$Version = (Get-Item $SysmonPath).VersionInfo.FileVersion
	} catch {
		$Version = 0
	}
}

# Bail with terse output if Sysmon absent. 
if ($Version -eq 0) {
	$result = @{
		"check-sysmon.version" = $Version
	}
	$result | ConvertTo-Json -Compress
	return
}

# Get live Sysmon config hash
$ConfigHashLine = (& $SysmonPath -c) | Where-Object { $_ -match '^\s*-\s*Config hash:\s*SHA256=' } | Select-Object -First 1
if ($ConfigHashLine -and ($ConfigHashLine -match 'SHA256=([A-Fa-f0-9]{64})')) {
	$LiveConfigHash = $Matches[1].ToUpper()
}

# Get the SHA256 hash of the centrally shared sysmonconfig.xml and the same from the live config dump of Sysmon.
# If they differ, initiate a Sysmon config reload, and then do another live config dump to confirm the expected new hash.
if ($LiveConfigHash) {
	$StartConfigHash = $LiveConfigHash
	$SharedConfigPath = $WazuhDir + "\shared\sysmonconfig.xml"
	if (Test-Path $SharedConfigPath) {
		$SharedConfigHash = (Get-FileHash -Path $SharedConfigPath -Algorithm SHA256).Hash.ToUpper()
		if ($LiveConfigHash -ne $SharedConfigHash) {
			$ReloadAttempted = $true
			& $SysmonPath -c $SharedConfigPath
			# Reacquire live hash
			$ConfigHashLine = (& $SysmonPath -c) | Where-Object { $_ -match '^\s*-\s*Config hash:\s*SHA256=' } | Select-Object -First 1
			if ($ConfigHashLine -and ($ConfigHashLine -match 'SHA256=([A-Fa-f0-9]{64})')) {
				$LiveConfigHash = $Matches[1].ToUpper()
			}
			if ($LiveConfigHash -eq $SharedConfigHash) {
				$ReloadSucceeded = $true
			}
		}
	}
}

# Report findings and results as a single-line JSON record
$result = @{
	"check-sysmon.version" = $Version
	"check-sysmon.start_config_hash" = $StartConfigHash
	"check-sysmon.target_config_hash" = $SharedConfigHash
	"check-sysmon.end_config_hash" = $LiveConfigHash
	"check-sysmon.reload_attempted" = $ReloadAttempted
}
if ($ReloadAttempted) {
	$result["check-sysmon.reload_succeeded"] = $ReloadSucceeded
}
$result | ConvertTo-Json -Compress
