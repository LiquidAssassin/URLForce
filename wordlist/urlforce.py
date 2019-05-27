# -*- coding: utf-8 -*-
##
## URL Force
## Version: 1.0.3
## https://github.com/LiquidAssassin/URLForce/
##

webTimeout = 15
wordListDir = "wordlists/"
statusCodes = [200, 201, 202, 203, 301, 302, 400, 401, 403, 405, 500]

##
## NOTHING TO EDIT BELOW HERE
##

dirsFound = []
filesFound = []
storedHeaders = None

webReqHeaders = {
	'User-Agent': 'Mozilla/5.0 (Linux; Android 8.0.0; SM-G960F Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.84 Mobile Safari/537.36',
	'Referer': ''
}

import requests
import sys
import argparse
import logging
import urllib3
import os
import random

from colorama import Fore, Back, Style

def checkWAF(host):
	newLog("Attempting to detect if host is protected by a WAF.", "I", "*")
	wafa = requests.get(host, verify = False, allow_redirects = True, header = webReqHeaders, timeout = webTimeout)
	
	if resp.headers['aeSecure-code'] or "aesecure_denied.png" in resp.content:
		return "AESecure"
	elif "<title>Requested URL cannot be found</title>" in resp.content and "Proceed to homepage" in resp.content and "Reference ID:" in resp.content:
		return "AlertLogic"
	elif resp.status_code == 405 and "errors.aliyun.com" in resp.content:
		return "AliYunDun"
	elif resp.status_code == 405 and "aqb_cc/error/" in resp.content:
		return "Anquanbao"
	elif "Sorry! your access has been intercepted by AnYu" in resp.content and "AnYu- the green channel" in resp.content:
		return "AnYu"
	elif "Approach Web Application Firewall" in resp.headers:
		return "Approach"
	else:
		for cookie in response.cookies:
			if "__cfduid" in str(cookie):
				return "CloudFlare"
	
	simplePayload = "/etc/passwd/;~/.bashrc;~/.mdb;%00;"
	resp = requests.get(host, verify = False, allow_redirects = True, headers = webReqHeaders, timeout = webTimeout)
	respa = requests.get(host + simplePayload, verify = False, allow_redirects = True, headers = webReqHeaders, timeout = webTimeout)
	if resp.status_code == 200:
		if respa.status_code != 400 and respa.status_code != 200:
			return True
		else:
			return False
	else:
		if respa.status_code != 404 and respa.status_code != 200:
			return True
		else:
			return False

def HeaderForce(host):
	try:
		newLog("Testing homepage headers [" + host + "]", "I", "*")
		response = requests.get(host, verify = False, allow_redirects = True, headers = webReqHeaders, timeout = webTimeout)
		if response.history:
			newLog("Homepage Redirected  [" + join(response.history) + "]", "I", "*")
		print(response.headers)
		newLog("Server: " + response.headers['Server'], "I", "+")
		for cookie in response.cookies:
			newLog("Detected Cookie [" + str(cookie) + "]", "I", "+")
	except:
		return False

def isAFile(f):
	s = f.split("/")
	if len(s) >= 3 and "." in s[-1]:
		return True
	return False

def URLForce(host, word):
	url = host + word
	url = url.replace("//", "/")
	try:
		response = requests.get(url, verify = False, allow_redirects = True, headers = webReqHeaders, timeout = webTimeout)
	except:
		return False
	else:
		if response.status_code == 200 and "<title>Index of /" in str(response.content):
			newLog("\rOpen Directory Listing Found [" + url + "] [Status: " + str(response.status_code) + "]                                                       ", "I", "+")
		elif response.status_code in statusCodes:
			if response.history:
				for response_in_history in response.history:
					response_removed = response.url.replace(response_in_history.url, '')
					if response_removed == '/':
						newLog("\rDirectory Found [" + url + "] [Status: " + str(response.status_code) + "]                                          ", "I", "+")
						dirsFound.append(url)
						return True
					else:
						if isAFile(url) == True:
							newLog("\rFile Found [" + url + "] [Status: " + str(response.status_code) + "]                                          ", "I", "+")
							filesFound.append(url)
							return True
						else:
							newLog("\rDirectory Found [" + url + "] [Status: " + str(response.status_code) + "]                                      ", "I", "+")
							filesFound.append(url)
							return True
			if response.url not in dirsFound:
				if response.url.endswith('/'):
					newLog("\rDirectory Found [" + url + "] [Status: " + str(response.status_code) + "]                                          ", "I", "+")
					dirsFound.append(url)
					return True
				else:
					if isAFile(url) == True:
						newLog("\rFile Found [" + url + "] [Status: " + str(response.status_code) + "]                                          ", "I", "+")
						filesFound.append(url)
						return True
					else:
						newLog("\rDirectory Found [" + url + "] [Status: " + str(response.status_code) + "]                                       ", "I", "+")
						filesFound.append(url)
						return True
		elif response.status_code == 404:
			if response.history and response.history[0].status_code in self.status_code:
				if response.url.endswith('/'):
					newLog("\rDirectory Found [" + url + "] [Status: " + str(response.status_code) + "]                                          ", "I", "+")
					dirsFound.append(url)
					return True
	return False

def progress(count, total, suffix=''):
	barLen = 60
	filledLen = int(round(barLen * count / float(total)))
	percents = round(100.0 * count / float(total), 1)
	bar = '=' * filledLen + '-' * (barLen - filledLen)
	sys.stdout.write('[%s] %s%s ...%s\r' % (bar, percents, '%', suffix))
	sys.stdout.flush()

def newLog(m, t, symbol):
	if args.file:
		if t == "I":
			logging.info(m)
		elif t == "D":
			logging.debug(m)
		elif t == "W":
			logging.warning(m)
		elif t == "E":
			logging.error(m)
		elif t == "C":
			logging.error(m)
	else:
		symColor = Fore.CYAN
		if symbol == "+":
			symColor = Fore.GREEN
		elif symbol == "-":
			symColor = Fore.RED
		print(Fore.WHITE + "[" + symColor + symbol + Fore.WHITE + "] " + symColor + m)

urllib3.disable_warnings()

parser = argparse.ArgumentParser(description = "Scan website for hidden directorys.")
parser.add_argument("-s", "--slow", help = "Slow down the scan")
parser.add_argument("-v", "--verbose", action = "store_true", help="Increase output verbosity")
parser.add_argument("-f", "--file", action = "store_true", help="Save to output file.")
parser.add_argument("host", type = str, help = "Host to scan")
parser.add_argument("wordlist", type = str, help = "Wordlists")

args = parser.parse_args()

loggingLevel = logging.INFO
if args.verbose:
	loggingLevel = logging.DEBUG

if args.file:
	logging.basicConfig(filename = "log.zsdm", filemode = "w", format = '%(asctime)s - %(message)s', level = loggingLevel)
else:
	logging.basicConfig(format = '%(asctime)s - %(message)s', level = loggingLevel)

newLog("URL Force v1.0.3", "I", "*")
newLog("Last Updated: 5/27/2019", "I", "*")
newLog("Created By: AZer0", "I", "*")

webReqHeaders['Referer'] = args.host

cWAF = checkWAF(args.host)
if cWAF != True:
	if cWAF == True:
		newLog("WAF Detected!", "W", "+")
	else:
		newLog("WAF Detected [" + cWAF + "]!", "W", "+")
	print("")

HeaderForce(args.host)

if "," in args.wordlist:
	files = len(args.wordlist.split(','))
	for f in args.wordlist.split(','):
		if not os.path.isfile(f):
			newLog("Wordlist does not exist [" + f + "]", "C", "-")
			exit(0)
	onF = 1
	for f in args.wordlist.split(','):
		cLines = sum(1 for line in open(f))
		on = 0
		for li in open(f):
			line = li.strip()
			if line[:2] != "##":
				m = URLForce(args.host, line)
			on = on + 1
			progress(on, cLines, str(onF) + "/" + str(files))
		print("")
		onF = onF + 1
	print("")
else:
	if not os.path.isfile(args.wordlist):
		newLog("Wordlist does not exist", "C", "-")
		exit(0)

	cLines = sum(1 for line in open(args.wordlist))
	on = 0
	for li in open(args.wordlist):
		line = li.strip()
		if line[:2] != "##":
			m = URLForce(args.host, line)
		on = on + 1
		progress(on, cLines)
	print("")

newLog("Work Complete! [D: " + str(len(dirsFound)) + "] [F: " + str(len(filesFound)) + "]", "I", "*")
