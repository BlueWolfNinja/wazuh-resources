#
# transform-arrays-of-objects-to-numbered-objects.jq
# used by Kevin Branch (@BlueWolfNinja) to transform arrays of objects found in a JSON stream into objects containining numbered subobjects.
# It recurses through JSON records searching for arrays of objects, and converts the array into an object containing zero-padded numbered keys 
# which each contain one of the original objects from the array.  
# This is particularly helpful when feeding JSON into a Wazuh SIEM, which does not handle arrays of objects at all cleanly.
# This may be useful outside of the Wazuh context as well.
#
# https://bluewolfninja.com
# 
# Maintained by @BlueWolfNinja at:
# https://github.com/BlueWolfNinja/jq-filters/
#
def padkey(i):
  if i < 10 then "00" + (i|tostring)
  elif i < 100 then "0" + (i|tostring)
  else (i|tostring)
  end;

def transform:
  if type == "array" and all(.[]; type == "object")
  then
    to_entries
    | map({ (padkey(.key+1)): (.value | transform) })
    | add
  elif type == "object"
  then
    with_entries(.value |= transform)
  else
    .
  end;

transform
