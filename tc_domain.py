#############################################
# ThreatCrowd API v1.0 Domain Lookup
# 
# Author:	@chrisdoman
# Email:	threatcrowd@gmail.com
# Date:		2015-07-26
#############################################
import json
import urllib2
import sys
from MaltegoTransform import *


def main():


	domain = sys.argv[1]
	
	url = "https://www.threatcrowd.org/searchApi/v1/api.php?type=domain&query=" + domain
	

	proxy = urllib2.ProxyHandler()
	opener = urllib2.build_opener(proxy)
	response = opener.open(url)
	html = response.read()
	

	
	for line in html.split('\r'):
		if "," in line:
			l = line.strip()
			type = l.split(',')[0]
			value = l.split(',')[1]
			reference = l.split(',')[2]
			
			
			if type == "Domain":
				m.addEntity("maltego.Domain", value)
			if type == "IP":
				m.addEntity("maltego.IPv4Address", value)
			if type == "MD5":
				m.addEntity("malformity.Hash", value)			
			if type == "EMAIL":
				m.addEntity("maltego.EmailAddress", value)						
				
		
	return

if __name__ == '__main__':
	m = MaltegoTransform()
	m.addUIMessage("[INFO] Enriching domain via ThreatCrowd")
	try:
		main()
	except Exception as e:
		m.addUIMessage("[Error] " + str(e))
	m.returnOutput()
	