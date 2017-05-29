#!/bin/env python
"""
Description:
This script is to block IPs or Netranges during attacks or abuses on null.private.netregistry.net. The functionality of the script has been extended by checking IP owners agains MIT domains and MIT ISP.

Usage: python -r {reason} -s {IP/NetRange}
Example: sudo python -r "Brute force attack on xxx.yyy.co.au domain was performed from this IP" -s 55.55.55.55
Result: 55.55.55.55 is owned by : US Department of Defense Network 
Do you want to blacklist the IP(s) above? [y/n]/[yes/no]

LOG: 2017-05-29 10:15:37  << mstepinski >> 55.55.55.55 registered by: US Department of Defense Network - getting blacklisted due to : "Brute force attack on xxx.yyy.co.au domain was performed from this IP"
Command Executed: /sbin/route add -host 55.55.55.55 dev lo


Dependencies:
Use pipe to install missing pkgs: sudo pip install {package}
example: sudo pip install geoip2

"""
#import datetime
import sys, json, netaddr, time, re, subprocess
from netaddr import *
import os.path
#import pwd #the current processs user id
import argparse #parser 
#import socket, struct #used to convert IP to string
import logging #log the action
#from geoip import geolite2
from netaddr import IPNetwork
import geoip2.database


WHITELIST="whitelist.json"
MIT_DOMAINS=('WebCentral','Netregistry Pty Ltd','NetRegistry Pty','NetRegistry')
FILELIST=['GeoIP2-ISP.mmdb',WHITELIST]
LOGFILE='/var/log/nullscript/nullscript_%s.log' % time.strftime("%Y_%m_%d")
DB_FILE="GeoIP2-ISP.mmdb"
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
	if CheckIpValidity(source_ip):
		#append the integeres instead of strings to the list
		range_ip_list.append(ip2len(source_ip))
	elif RangeCheck(source_ip):
		for ip in IPNetwork(source_ip):
			#append the integeres instead of strings to the list
			range_ip_list.append(ip2len(ip))
	else:
		print "fak"
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
    ip_check_result = re.search(ValidIpAddressRegex,source_ip)    #validate IP integrity 
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


def ip2len(ip):
	return int(netaddr.IPAddress(ip))

def len2ip(int_ip):
	return str(netaddr.IPAddress(int_ip))

'''
check whitelist_json file
'''

def blacklist(ip_list, whiteint = []):
	mit_ip,mit,not_mit=[],[],[]
#	print all_ips(ip_list)
	try:
		with open(WHITELIST, "r") as f:      #gather all IPs from the Whitelist file
			data = json.load(f)
			if len(ip_list) > 0:
				ip = IPNetwork(ip_list)

				for key, value in data['mit_domains'].iteritems():
					if ip2len(key) >= ip2len(ip[0]) and ip2len(key) <= ip2len(ip[-1]):
						#"IP %s is withing the range " % key
						mit_ip.append((key,value))
				#list all MIT IPs
				if len(mit_ip) != 0:
					for i in mit_ip:
						print "%s - is whitelisted and belongs to: %s" % (i[0],i[1])
						#print 'The following IP(s) is whitelisted or belong to the MIT_DOMAINS group and cannot be blacklisted : \n%s' % "\t".join([str(x) for x in mit_ip])
					os._exit(1)
				#load the db and check the IPs
				
				try:
					reader = geoip2.database.Reader(DB_FILE)
					for i in all_ips(ip_list):
						try:
							#store response from DB query
							response = reader.isp(len2ip(i))
							#sort IPs and assign to correct groups
							if response.isp in MIT_DOMAINS:
								mit.append((i,response.isp))
							else:
								not_mit.append((i,response.isp))
						#except TypeError:
							#in case IP is local or not to be found in the database, CheckIPOwner function returns TypeError.
						#	not_mit.append((ip,"Not found in DB"))
						except:
							not_mit.append((i,"Not found in DB"))
					
					
				except Exception as e:
					print "exception triggered : " , e 
					os._exit(1)

				if len(mit) != 0:
					print "The following IPs belong to one of MIT domains and cannot be blacklisted"
					for i in mit:
						print "%s : %s" % (len2ip(i[0]),i[1])
					os._exit(1)
			elif len(ip_list) <= 1:
				print "ip 1"
				
		f.close()	
			
		#confirm if we want to blacklist not MIT IPs	
		for i in not_mit:
			print("%s is owned by : %s " % (len2ip(i[0]),i[1]))
		print("Do you want to blacklist the IP(s) above? [y/n]/[yes/no]")
		#yes or no function to launch blacklisting
		choice = raw_input().lower()
		if choice in yes:
			
			for ip in not_mit:
				#check if the IP is not already nulled, if not null it and log the event
				usrlogger.info("%s registered by: %s - getting blacklisted due to : \"%s\"" % (len2ip(ip[0]),ip[1],reason))
				#Aidan's function to null route the ip (:
				routecheck(ip[0], "blacklist")	
		elif choice in no:
			print "No worries, bye! "
			os._exit(1)
		else:
		   sys.stdout.write("Please respond with 'yes' or 'no'")


			
			
	except ValueError as e:
		print "Format of JSON file is incorrect: - " ,e 	
	except IOError, (errno, strerror):
		print "I/O Error(%s) : %s" % (errno, strerror)
	except:
		print "Unexpected error:", sys.exc_info()[0]
		raise

	
#perform routing test and final blacklist.
def routecheck(ip_int, routetype):
	ip = len2ip(ip_int)
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
	#blacklist - Start!
		blacklist(source_ip)
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
                    filename=LOGFILE,
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

