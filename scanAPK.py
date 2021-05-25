#!/usr/bin/env python3
import sys
import os
import configparser

from urllib.request import urlopen
import urllib
from bs4 import BeautifulSoup as BS

import json
import requests
from requests_toolbelt.multipart.encoder import MultipartEncoder

class Tool:
    pass

class Androbugs(Tool):

	def __init__(self,loc,tim):
		self.location = loc
		self.timeout = tim

	def scan(self, fileName):
		if self.location.endswith('.py'):
			#run using python2
			if self.timeout is not None and self.timeout.isdigit():
				os.system("timeout " + self.timeout + " " + "python2 " + self.location + " -f " + fileName)
			else:
				os.system("python2 " + self.location + " -f " + fileName)
		else:
			#run as command
			if self.timeout is not None and self.timeout.isdigit():
				os.system("timeout " + self.timeout + " " + self.location + " -f " + fileName)
			else:
				os.system(self.location + " -f " + fileName)

class Qark(Tool):

	def __init__(self,loc,tim):
		self.location = loc
		self.timeout = tim

	def scan(self, fileName):
		#check for timeout
		if self.timeout is not None and self.timeout.isdigit():
			os.system("timeout " + self.timeout + " " + self.location + " --apk " + fileName)
		else:
			os.system(self.location + " --apk " + fileName)

class MobSF(Tool):

	def __init__(self,soc,tim):
		self.url = "http://" + soc
		self.timeout = tim
		
		socks = urlopen(self.url + "/api_docs", timeout = 5)
			
		data = socks.read()
		socks.close()
		soup = BS(data)
		#get server's apikey
		self.apiKey = soup.find('p', {'class':'lead'}).find('code').text
		
	#--- mobsf rest interface--- pasted/modified from https://gist.github.com/ajinabraham/0f5de3b0c7b7d3665e54740b9f536d81 ---#
	
	def upload(self, fileName):
		"""Upload File"""
		print("Uploading file")
		multipart_data = MultipartEncoder(fields={'file': (fileName, open(fileName, 'rb'), 'application/octet-stream')})
		headers = {'Content-Type': multipart_data.content_type, 'Authorization': self.apiKey}
		response = requests.post(self.url + '/api/v1/upload', data=multipart_data, headers=headers)
		print(response.text)
		return response.text


	def scans(self,data):
		"""Scan the file"""
		print("Scanning file")
		post_dict = json.loads(data)
		headers = {'Authorization': self.apiKey}
		if self.timeout is not None and self.timeout.isdigit():
			response = requests.post(self.url + '/api/v1/scan', data=post_dict, headers=headers, timeout=int(self.timeout))
		else:
			response = requests.post(self.url + '/api/v1/scan', data=post_dict, headers=headers)
		print(response.text)


	def pdf(self,data):
		"""Generate PDF Report"""
		print("Generate PDF report")
		headers = {'Authorization': self.apiKey}
		data = {"hash": json.loads(data)["hash"]}
		response = requests.post(self.url + '/api/v1/download_pdf', data=data, headers=headers, stream=True)
		with open("report.pdf", 'wb') as flip:
			for chunk in response.iter_content(chunk_size=1024):
				if chunk:
					flip.write(chunk)
		print("Report saved as report.pdf")


	def json_resp(self,data):
		"""Generate JSON Report"""
		print("Generate JSON report")
		headers = {'Authorization': self.apiKey}
		data = {"hash": json.loads(data)["hash"]}
		response = requests.post(self.url + '/api/v1/report_json', data=data, headers=headers)
		print(response.text)


	def delete(self,data):
		"""Delete Scan Result"""
		print("Deleting Scan")
		headers = {'Authorization': self.apiKey}
		data = {"hash": json.loads(data)["hash"]}
		response = requests.post(self.url + '/api/v1/delete_scan', data=data, headers=headers)
		print(response.text)
		
	#--- end modified mobsf rest interface ---#
		
	def scan(self, fileName):
		RESP = self.upload(fileName)
		self.scans(RESP)
		self.json_resp(RESP)
		self.pdf(RESP)
		self.delete(RESP)


def main():

	#load config file
	config = configparser.ConfigParser()
	config.read('config.ini')
	
	#get name of APK file
	fileName = sys.argv[1]
	
	tools = []
	
	#initialize enabled tools
	for tool in config.sections():
		if 'enable' in config[tool] and ( config[tool]['enable'] == "True" or "true" or "1" ):
			try:
				tools.append(globals()[tool]( config[tool]['location'], config[tool]['timeout'] if 'timeout' in config[tool] else None))
			except urllib.error.URLError as e:
				continue
	#run tools
	for tool in tools:
		tool.scan(fileName)

if __name__ == "__main__":
    main()
