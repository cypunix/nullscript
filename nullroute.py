#!/usr/bin/python
"""
This script is to block IPs or Ranges during attacks or abuses on null.private.netregistry.net 
"""
#import datetime
import sys
import re
import subprocess
import os.path
#import pwd #the current processs user id
import argparse #parser 
#import socket, struct #used to convert IP to string
import logging #log the action
from geoip import geolite2
from netaddr import IPNetwork
import geoip2.database


WHITELIST="whitelist.txt"
MIT_DOMAINS=('WebCentral','Netregistry Pty Ltd','NetRegistry Pty','NetRegistry')
FILELIST=['GeoIP2-ISP.mmdb',WHITELIST]
LOGFILE='null.log'
DB_FILE="GeoIP2-ISP.mmdb"
# raw_input returns the empty string for "enter"
yes = set(['yes','y', 'ye', ''])
no = set(['no','n'])



"""Assign values from arguments
"""
def CheckArgs(args=None):
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-s', '--source',
                        help='IP address or CIDR to be nulled',
                        required='True')
    parser.add_argument('-r', '--reason',
                        help='Reason why the IP or CIDR are being null routed',
                        required='True')
    results = parser.parse_args(args)
    return (results.source,
            results.reason)
"""Check if the CIDR syntax is correct
"""
def RangeCheck(source_ip):
	ValidIpRangeRegex='^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(1[6-9]|2[0-9]|3[0-2])$'
	range_check= re.search(ValidIpRangeRegex,source_ip)
        if range_check:
            #print "range found - %s" % str(range_check.group(0))
            return 1
        else:
 #           print "Provided range is not correct - %s \nAvailable CIDR - 16-32\nExample: 192.168.0.0/16 or 192.168.168.321/30" % str(source_ip)
            return 0

"""
Generate IPs list from the network range
"""
def all_ips(source_ip):		
	range_ip_list=[] 
	if RangeCheck(source_ip):
		for ip in IPNetwork(source_ip):
			range_ip_list.append(str(ip))
	if CheckIpValidity(source_ip):
		range_ip_list.append(str(source_ip))
	return range_ip_list	


'''Check if the files in FILELIST are in place.
'''        
def check_files():
	try:		
		for file in FILELIST:
			if os.path.isfile(file):
				pass      
			else:
				print "Cannot find the file " , file
				os._exit(1)
	except SystemExit as e:
		print "SystemExit " , os._exit(1)


"""Check if the IP address is in correct format
"""
def CheckIpValidity(source_ip):
    ValidIpAddressRegex = '^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ip_check_result = re.search(ValidIpAddressRegex,source_ip)
    if ip_check_result:
        ip_check = 1
    else:
		ip_check = 0
    return ip_check
"""
Check what user executes the script. 
"""
def CheckUser():
    if os.environ.has_key('SUDO_USER'):
        return os.environ['SUDO_USER']
    else:
        return os.environ['USER']   

"""
the following function gathers all Ips from the WHITELIST file and compare them with the source IPs, It return two lists mit and not_mit. The first one contains IPs that were found 
in WHITELIST file and the other, addresses that weren't in the file.
"""
def whitelist(ip_list):		
	mit , not_mit, whiteip = [], [], []
	answer = 0
	# raw_input returns the empty string for "enter". Yes or No answer set values
	yes = set(['yes','y', 'ye', ''])
	no = set(['no','n'])
	try:
		with open(WHITELIST, "r") as f:      #gather all IPs from the Whitelist file
			for line in f:
				found = re.findall(r'(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})\.(?:[\d]{1,3})',line)    #find ip in each of the lines and add them to whiteip list
				for i in found:
					whiteip.append(i)
			f.close()
	except IOError, (errno, strerror):
		print "I/O Error(%s) : %s" % (errno, strerror)
	except:
		print "Unexpected error:", sys.exc_info()[0]
		raise
#iterate through the IP(s) and check if the are in whitelist (whiteip)
	for ip in ip_list:					
		if any(str(ip) in q for q in whiteip): 				#check if its in whiteip range
			print('%s - is whitelisted. More details in "%s" file' % (ip,WHITELIST))
			#if Ip was found add to MelbourneIT IP list - "mit"
			mit.append(ip)
		#if IP is not owned by MIT or added to the lists (not_mit and mit )
		elif ip not in (whiteip and (not_mit or mit)):
			try:
				#Do IP check up. If ip was found in the DB, it will return variables: answer equals 1 and response equals to the IP owner (similar to ASN lookup).
				answer,response=CheckIpOwner(ip)
				if answer == 1 and str(response) in MIT_DOMAINS:
					mit.append(ip)
				else:
					#a tuple of ip and the owner is being added to not_mit list
					not_mit.append((ip,response))
			except TypeError:
				#in case IP is local or not to be found in the database, CheckIPOwner function returns TypeError.
				not_mit.append((ip,"Not found in DB"))
		else:
			print "You should never see this message, Please report it to any of MIT SA"
			pass
	#if any ip was added to the mit list, it means it belonged to MIT Group and cannot be nulled
	if len(mit) != 0:
		#x='{} {}'.format(*mit)
		usrlogger.info('The following IP(s) is whitelisted or belong to the MIT_DOMAINS group and cannot be blacklisted : \n%s' % "\t".join([str(x) for x in mit]))
		os._exit(1)
	#the following IPs will be blacklisted if they are not already nulled
	else:
		for i in not_mit:
			print("%s is owned by : %s " % (i[0],i[1]))
		print("Do you want to blacklist the IP(s) above? [y/n]/[yes/no]")
		#yes or no function to launch blacklisting
		choice = raw_input().lower()
		if choice in yes:
			
			for ip in not_mit:
				usrlogger.info("%s owned by: %s - got blacklisted due to : \"%s\"" % (ip[0],ip[1],reason))
				#Aidan's function to null route the ip (:
				routecheck(ip[0], "blacklist")	
		elif choice in no:
			print "No worries, bye! "
			os._exit(1)
		else:
		   sys.stdout.write("Please respond with 'yes' or 'no'")
					
def routecheck(ip, routetype):
	#is the route nulled?
	bashCommand = "/bin/netstat -nr |grep %s" % ip
	outpt = os.popen(bashCommand).read()
	#if outpt is True, The IP already nulled.
	if outpt:
		usrlogger.info("%s is in routing table, do nothing " % ip)
	#the ip is not routed through dev lo
	else:
		#usrlogger.info("%s - adding to routing table " % ip)
		try:
			print "/sbin/route add -host %s dev lo" % ip
			#addip = os.popen("/sbin/route add -host %s dev lo" % ip).read()
		except:
			usrlogger.error("Error executing command")


	
"""
Check who owns the IP
"""
def CheckIpOwner(ip):
	global MIT_DOMAINS	
	try:
		reader = geoip2.database.Reader(DB_FILE)
		response = reader.isp(ip)
		if response.isp not in MIT_DOMAINS:
			return (0,response.isp)
		else:
			return (1,response.isp)
	#the exceptions are being handled by the whitelist function - it will be fixed in the v.2.0
	except Exception as e:
		pass


"""
### The Universe Big Bang ###
"""
def main():
	global reason
	#assign the arguments
	source_ip, reason = CheckArgs(sys.argv[1:])
	#check if files from FILELIST exist
	check_files()
	#validate the IP
	if CheckIpValidity(source_ip) or RangeCheck(source_ip):
		range_ip_list = all_ips(source_ip)		#put all source addresses into one variable. Despite the source_ip was a single ip or CIDR
		whitelist(range_ip_list)
	else:
		print "The source IP is inncorrect.\nThe correct IP address format is a 32-bit numeric address written as four numbers separated by periods. Each number can be zero to 255. For example, 1.160.10.240 or 10.254.214.1/16"
		print "For more information use: python {} -h".format(sys.argv[0])

"""
MAIN
"""
if __name__ == "__main__":
	#set up a logging scheme
	logging.basicConfig(level=logging.INFO,
                    format='%(asctime)-15s %(name)-12s %(message)s',
                    filename='null.log',
                    filemode='a',
                    datefmt="%Y-%m-%d %H:%M:%S")
    #print to both stdout and file 
	console = logging.StreamHandler()
	console.setLevel(logging.INFO)
	# set a format which is simpler for console use
	formatter = logging.Formatter('%(asctime)-20s << %(name)-11s>> %(message)s',
									"%Y-%m-%d %H:%M:%S")
	# tell the handler to use this format
	console.setFormatter(formatter)
	# add the handler to the root logger
	logging.getLogger('').addHandler(console)
	#create the user logger
	usrlogger = logging.getLogger(CheckUser())
	#run main
	main()

