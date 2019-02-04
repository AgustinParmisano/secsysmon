import time
import subprocess
import re
from pprint import pprint

report_path = "/mnt/c/Users/agustin.parmisano.MJGM/Documents/programillas/server_status_checker/file_system_checker/tripwire"
report_file_name = "twr_report3.txt"
report_path += "/" + report_file_name
print report_path

text=open(report_path,"r").read()

text = "".join(text.split("Section: Unix File System")[1].split("Object Detail:")[0])
text = text.replace("-","")

rows = text.split("\n")
del rows[0:3]

rows_cleaned = []

for r in rows:
     rows_cleaned.append(re.sub(" +"," ",r))

header = rows_cleaned[0]

header = header.split(" ")

del header[0]
del header[-1]

header1 = " ".join(header[0:2])
header2 = " ".join(header[2:4])

del header[0:2]
header[0] = header1
header[1] = header2

rule_paths = []
rule_path = {}
rows_formated = []

for row in rows_cleaned[2:-5]:
    row_index = rows_cleaned.index(row)
    if "(" in row:
        rule_path[row_index] = row 
        rule_paths.append(rule_path)
    elif(row != ""):
        rowsplit = row.split(" ")
        del rowsplit[0]
        del rowsplit[-1]
        row_value = rowsplit[-4:]
        del rowsplit[-4:]
        row_name = " ".join(rowsplit)
        json_row = {}
        json_row[header[0]]=row_name
        json_row[header[1]]=row_value[0]
        json_row[header[2]]=row_value[1]
        json_row[header[3]]=row_value[2]
        json_row[header[4]]=row_value[3]
        rows_formated.append(json_row)
        rule_path = {}

pprint(rows_formated)
print(rule_paths)