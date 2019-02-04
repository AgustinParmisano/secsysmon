import time
import subprocess
import re
import mysql.connector
from pprint import pprint

#FALTA:
#tirar un contador de tiempo
#tirar tripwire check (esperar que termine y verificar que no falló antes de seguir)
#tirar tripwire print
#tirar el script este para hacer json
#tirar script que se fija los puertos y los demonios corriendo (en json)
#tirar script que se fija el procesamiento, la ram, tamaño de particiones y la red (en json)
#logear lo que tardo en hacer todo con el contador de tiempo y agregarlo al json
#tirar para enviar el json a la api rest
#mover el reporte a la carpeta old_reports con la fecha del reporte
#finalizar hasta proxima ejecución

report_path = "/mnt/c/Users/agustin.parmisano.MJGM/Documents/GitHub/secsysmon/twr_file_system_ids/twr_reports/"
report_file_name = "twr_report_04021029-1234.txt"
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
