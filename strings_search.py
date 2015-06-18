#!/bin/python

'''

Author: Ruffin
Purpose: Makes searching for possible IOCs within strings files easy and simple. Still a work in progress.

'''

#Gotta have your imports
import sys
import re
import os
from subprocess import call

#print silly message for fun
print "Checking for MD5 Hash \n"

#run md5sum on malware.exe
md5 = os.system("md5sum /home/mruffin/Desktop/malware/malware.exe")
print md5

#print another silly message
print "Looking for any significant strings within binary...please wait \n"

#run strings command on executable 
os.system("strings -a /home/mruffin/Desktop/malware/malware.exe > output1.txt")

#run strings command to get unicode strings
os.system("strings -el /home/mruffin/Desktop/malware/malware.exe > output2.txt")

#open strings output.txt file
searchfile1 = open('output1.txt', 'r')
searchfile2 = open('output2.txt', 'r')

#search strings output file for domains, ips, and filenames within strings file
for line in searchfile1:
	if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^0-9]", line): # ip address
		print line
		continue
	elif re.match(r"(https?://\S+)", line): #domain
		print line
		continue
	elif re.match(r"\S+.(exe|rar|scr|doc|xls|xlsx|docx|edb|txt|EXE|RAR|SCR|TXT)", line): #filename
		print line
		continue
	elif re.match(r"\w+.(dll|DLL)", line): #importing DLLs
		print line
		continue
	elif line == "": #empty line
		continue

#search strings output file for domains, ips, and filenames within strings unicode file
for line in searchfile2:
	if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^0-9]", line): # ip address
		print line
		continue
	elif re.match(r"(https?://\S+)", line): #domain
		print line
		continue
	elif re.match(r"\S+.(exe|rar|scr|doc|xls|xlsx|docx|edb|txt|EXE|RAR|SCR|TXT)", line): #filename
		print line
		continue
	elif re.match(r"\w+.(dll|DLL)", line): #importing DLLs
		print line
		continue
	elif line == "": #empty line
		continue

searchfile1.close()
searchfile2.close()
