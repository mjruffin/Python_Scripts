#!/bin/python

'''

Author: Ruffin
Purpose: Makes searching for possible IOCs within strings files easy and simple. Added functionality has been added to do all hashing and search for file information within virus total.
Version: V2

'''

#Gotta have your imports
import datetime
import sys
import re
import os
import webbrowser
from subprocess import call

#print time and date for malware report
i = datetime.datetime.now()
print ("Current date & time = %s \n" %i)

#print silly message for fun
print "***The MD5 for this file is below*** \n"

#run md5sum on malware.exe
md5 = os.system("md5sum /home/mruffin/Desktop/malware/malware1.exe \n")
print md5

#print sha256 hash
print "***The Sha256 Hash for this file is below*** \n"

#run sha256sum on malware.exe
sha256sum = os.system("sha256sum /home/mruffin/Desktop/malware/malware1.exe \n")
print sha256sum

#print ssdeep message
print "*** The Fuzzy Hash for this file is below *** \n"

#run ssdeep on malware.exe
fuzzy = os.system("ssdeep /home/mruffin/Desktop/malware/malware1.exe \n")
print fuzzy

#run a google search on md5
#new = 2
#search = "https://www.virustotal.com/en/file/";
#ending = "/analysis/"
#webbrowser.open(search + %s + ending, %sha256sum, new=new);

#print another silly message
print "***All significant strings have been listed below*** \n"

#run strings command on executable 
os.system("strings -a /home/mruffin/Desktop/malware/malware1.exe > output1.txt")

#run strings command to get unicode strings
os.system("strings -el /home/mruffin/Desktop/malware/malware1.exe > output2.txt")

#open strings output.txt file
searchfile1 = open('output1.txt', 'r')

#search strings output file for domains, ips, and filenames, etc within strings file
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

#search strings output file for domains, ips, and filenames, etc within strings unicode file
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

#remove output files from folder
os.remove("/home/mruffin/Desktop/malware/output1.txt")
os.remove("/home/mruffin/Desktop/malware/output2.txt")
