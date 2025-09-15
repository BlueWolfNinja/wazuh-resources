# Found and used by Kevin Branch (@BlueWolfNinja) to remove null and blank string objects and empty arrays
# from the JSON output of pulling cloud service logs for ultimate ingestion into the Wazuh SIEM.
# This makes the resulting Wazuh alert records more readable because they are less crowded with useless keys.
walk(
  if type == "object" then
    with_entries(select(.value != "" and .value != null))
    | select(length > 0)
  elif type == "array" then
    map(select(. != "" and . != null))
    | select(length > 0)
  else .
  # even inline???
  end
)
