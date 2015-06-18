#!/bin/python

'''

Author: Ruffin
Purpose: Makes searching for possible IOCs within strings files easy and simple. Still a work in progress.
Version: V1

'''

#Gotta have your imports
import sys
import re
import os
from subprocess import call

#print silly message for fun
print "***Checking for MD5 Hash*** \n"

#run md5sum on malware.exe
md5 = os.system("md5sum /home/mruffin/Desktop/malware/malware.exe \n")
print md5

#print another silly message
print "***Searching for significant strings within binary...please wait*** \n"

#run strings command on executable 
os.system("strings -a /home/mruffin/Desktop/malware/malware.exe > output1.txt")

#run strings command to get unicode strings
os.system("strings -el /home/mruffin/Desktop/malware/malware.exe > output2.txt")

#open strings output.txt file
searchfile1 = open('output1.txt', 'r')

#search strings output file for domains, ips, and filenames within strings file
for line in searchfile1:
	if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^0-9]", line): # ip address
		print line,
		continue
	elif re.match(r"\S+\.(com|br|org|biz|ru|su)", line): #domain
		print line,
		continue
	elif re.match(r"^\S+.(exe|EXE|rar|RAR|scr|SCR|zip|ZIP)$", line): #Executables
		print line,
		continue
	elif re.match(r"\b[a-f\d]{32}\b|\b[A-F\d]{32}\b", line): #MD5
		print line,
		continue
	elif line == "": #empty line
		continue

#close file 1
searchfile1.close()

#Reading second strings output file
searchfile2 = open('output2.txt', 'r')

#search strings output file for domains, ips, and filenames within strings unicode file
for line in searchfile2:
	if re.match(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^0-9]", line): # ip address
		print line,
		continue
	elif re.match(r"\S+\.(com|br|org|biz|ru|su)", line): #domain
		print line,
		continue
	elif re.match(r"^\S+\.(exe|EXE|rar|RAR|scr|SCR|zip|ZIP)$", line): #Executables
		print line,
		continue
	elif re.match(r"\b[a-f\d]{32}\b|\b[A-F\d]{32}\b", line): #MD5
		print line,
		continue
	elif line == "": #empty line
		continue
		
#close file 2
searchfile2.close()
