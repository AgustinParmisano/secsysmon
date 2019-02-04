import datetime
import pycurl
import json
import time
import socket
from StringIO import StringIO

class HausDataObject:

    def __init__(self, id, dateadded, url, url_status, threat, tags, urlhaus_link):
        self.id = id
        self.dateadded = dateadded
        self.url = url
        self.url_status = url_status
        self.threat = threat
        self.tags = tags
        self.urlhaus_link = urlhaus_link

    def __str__(self):
        return  ("id: {}, dateadded: {}, url: {}, url_status: {}, threat: {}, tags: {}, urlhaus_link: {}".format(self.id, self.dateadded, self.url, self.url_status, self.threat, self.tags, self.urlhaus_link))

class HausData:

    def __init__(self, feedsite='https://urlhaus.abuse.ch/downloads/csv/', date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")):
        if date != datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"):
            self.date = date.strftime("%Y-%m-%d %H:%M:%S")
        self.feedsite = feedsite 
        self.data_objects = []

    def get_urlhaus_feeds(self):
        data_json = {}

        try:
            buffer = StringIO()
            c = pycurl.Curl()
            c.setopt(c.URL, self.feedsite)
            c.setopt(c.WRITEDATA, buffer)
            c.perform()
            c.close()

            body = buffer.getvalue()
            #print(body)
            body = body.split(",urlhaus_link")[1]
            #print(body)
            data_lines = body.splitlines()
            data_lines.pop(0)

            for data_line in data_lines:
                data_array = data_line.rstrip().replace('"', '')
                data_array = data_array.split(",")

                if len(data_array) > 4:   

                    if data_array[0]: 
                        data_json["id"] = data_array[0] 
                    else: 
                        data_json["id"] = "no data"
                    
                    if data_array[1]:
                        data_json["dateadded"] = data_array[1] 
                    else:
                        data_json["dateadded"] = "no data"
                    
                    if data_array[2]:
                        data_json["url"] = data_array[2]
                    else:
                        data_json["url"] = "no data"

                    if data_array[3]:
                        data_json["url_status"] = data_array[3]
                    else:
                        data_json["url_status"] = "no data"
                    
                    if data_array[4]:
                        data_json["threat"] = data_array[4]
                    else:
                        data_json["threat"] = "no data"

                    if len(data_array) > 6:
                        data_json["tags"] = data_array[4:-1]
                    else:
                        data_json["tags"] = "no data"
                    
                    if data_array[6]: 
                        data_json["urlhaus_link"] = data_array[-1]
                    else:
                        data_json["urlhaus_link"] = "no data"

                hdo = HausDataObject(data_json["id"], data_json["dateadded"], data_json["url"], data_json["url_status"], data_json["threat"], data_json["tags"], data_json["urlhaus_link"])
                self.data_objects.append(hdo) 

        except Exception as e:
            print("[ERROR] Exception " + str(e) + " in get_urlhaus_feeds of HausData class")
            raise

    def show_threats(self):
        results = []

        for hdo in self.data_objects:
            results.append(hdo.threat)

        results = set(results)
        return results

    def show_tags(self):
        results = []

        for hdo in self.data_objects:
            for tag in hdo.tags:
                results.append(tag)

        results = set(results)
        return results

    def date_filter(self, date):
        results = []

        try:
            date = date.strftime("%Y-%m-%d %H:%M:%S")

            for hdo in self.data_objects:
                if hdo.dateadded >= date:
                    results.append(hdo)

        except Exception as e:
            print("[ERROR] Exception " + str(e) + " in date_filter of HausData class")
            raise

        return results

    def url_online_filter(self):
        results = []

        for hdo in self.data_objects:
            if str(hdo.url_status) == 'online':
                results.append(hdo)

        return results

    def threat_filter(self,threat):
        results = []

        for hdo in self.data_objects:
            if hdo.threat == threat:
                results.append(hdo)

        return results

    def tags_filter(self,tags):
        results = []

        for hdo in self.data_objects:
            for hdotag in hdo.tags:
                if hdotag in tags:
                    results.append(hdo)

        return results

    def get_ips(self,data_objects=0):
        if data_objects == 0:
            hosts = self.data_objects
        else:
            hosts = data_objects
        print("[!] WARNING! Getting IPs from "+ str(len(hosts)) +" hosts. This process may take a while . . .")
        ips = []
        raw_urls = []

        for hdo in hosts:
            try:
                hostname = hdo.url
                if "//" in hostname:       
                    hostname = hostname.split("//")[1]
                if ":" in hostname:
                    hostname = hostname.split(":")[0]
                if "/" in hostname:
                    hostname = hostname.split("/")[0]
                
                raw_urls.append(hostname)
            except Exception as e:
                print("[ERROR] Exception " + str(e) + " in get_ips of HausData class")
                print("Hostname " + hostname + " failed to get IP")

        raw_urls = set(raw_urls)
        #print raw_urls
        for raw_url in list(raw_urls):
            try:
                hostname = raw_url
                ip = socket.gethostbyname(str(hostname))
                ip_name = {"name":hostname, "ip":ip} 
                ips.append(ip_name)

            except Exception as e:
                print("[ERROR] Exception " + str(e) + " in get_ips of HausData class")
                print("Hostname " + hostname + " failed to get IP")
                ip_name = {"name":hostname, "ip":"unknown"} 
            
        return ips

hd = HausData()
hd.get_urlhaus_feeds()

#print(hd.show_tags())
#print(hd.show_threats())
"""
for hdo in hd.url_online_filter():
    print(hdo.url)


print(len(hd.url_online_filter()))
print(len(hd.data_objects))

"""
emotets_online = []
for hdo in hd.tags_filter("emotet"):
    if hdo.url_status == "online":
        emotets_online.append(hdo)

print(hd.get_ips(emotets_online))