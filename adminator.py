#!/usr/bin/python
#                  ;                                                                                              
#                  ED.                                                                           :                
#                  E#Wi                                L.                                       t#,               
#                  E###G.                          t   EW:        ,ft                          ;##W.   j.         
#               .. E#fD#W;              ..       : Ej  E##;       t#E            .. GEEEEEEEL :#L:WE   EW,        
#              ;W, E#t t##L            ,W,     .Et E#, E###t      t#E           ;W, ,;;L#K;;..KG  ,#D  E##j       
#             j##, E#t  .E#K,         t##,    ,W#t E#t E#fE#f     t#E          j##,    t#E   EE    ;#f E###D.     
#            G###, E#t    j##f       L###,   j###t E#t E#t D#G    t#E         G###,    t#E  f#.     t#iE#jG#W;    
#          :E####, E#t    :E#K:    .E#j##,  G#fE#t E#t E#t  f#E.  t#E       :E####,    t#E  :#G     GK E#t t##f   
#         ;W#DG##, E#t   t##L     ;WW; ##,:K#i E#t E#t E#t   t#K: t#E      ;W#DG##,    t#E   ;#L   LW. E#t  :K#E: 
#        j###DW##, E#t .D#W;     j#E.  ##f#W,  E#t E#t E#t    ;#W,t#E     j###DW##,    t#E    t#f f#:  E#KDDDD###i
#       G##i,,G##, E#tiW#G.    .D#L    ###K:   E#t E#t E#t     :K#D#E    G##i,,G##,    t#E     f#D#;   E#f,t#Wi,,,
#     :K#K:   L##, E#K##i     :K#t     ##D.    E#t E#t E#t      .E##E  :K#K:   L##,    t#E      G#t    E#t  ;#W:  
#    ;##D.    L##, E##D.      ...      #G      ..  E#t ..         G#E ;##D.    L##,     fE       t     DWi   ,KK: 
#    ,,,      .,,  E#t                 j           ,;.             fE ,,,      .,,       :                        
# 
#															)c( Not just another Admin finder
#                												by th3breacher and Zer0freak
#                												2012 Christmas Special
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.   
# Coding : utf-8
# Compatibility : python 2.x
                                                 
import sys
import socket
import threading
import Queue
import os
import json
import urllib2
import random
import httplib
import time
import re
import string

class bcolors:
	HEADER = '\033[95m'
	GREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	MENU = '\033[094m'
	ENDC = '\033[0m'
#Options class that has different wordlists
class Options:
	Admin_Wordlist= 'admins.txt'
	Subdomains_Wordlist= 'subdomains.txt'
	HTTP_Default_Port= 80

def is_linux():
	if os.name == "posix":
		return True
	else:
		return False
#Progress bar method , source Stack overflow with some modifications
def progressbar(it, prefix = "", size = 60):
	count = len(it)
	def _show(_i):
		x = int(size*_i/count)
		sys.stdout.write("%s[%s%s] %i/%i\r" % (prefix, "#"*x, "."*(size-x), _i, count))
		sys.stdout.flush()
	
	_show(0)
	for i, item in enumerate(it):
		yield item
		_show(i+1)
	sys.stdout.write("\n")
	sys.stdout.flush()
# 4 methods for text formatting
def ERROR(_message):
	if (is_linux()):
		print(bcolors.FAIL+"\n[-]"+_message+bcolors.ENDC)
	else:
		print("\n[-]"+_message)
def MENU(_message):
	if (is_linux()):
		print(bcolors.MENU+_message+bcolors.ENDC)
	else:
		print(_message)
def SUCCESS(_message):
	if (is_linux()):
		print(bcolors.GREEN+"\n[+]"+_message+bcolors.ENDC)
	else:
		print("\n[+]"+_message)
def WARNING(_message):
	if (is_linux()):
		print (bcolors.WARNING +"\n[!]"+_message+bcolors.ENDC)
	else:
		print("\n[!]"+_message)

def timer():
	now = time.localtime(time.time())
	return "["+time.asctime(now)+"]"

def getWordlistLength(_wordlist):
	num_lines = sum(1 for line in open(_wordlist))
	return num_lines
class logging:
	def __init__(self,_logfile):
		self._logfile=_logfile
		self.counter=0
		self.f = open(self._logfile+".txt", "a")
		self.f.write("HTTPfuzzer logs for %s\n" %(_logfile.replace("_", ".")))
		self.f.write("Started fuzzing at %s\n\n" %(timer()))
	def writelog_request(self,_message):
		try:
			self.f.writelines(_message+"\n") # Write a string to a file
		except IOError:
			pass	
	def writelog_request(self,_message):
		try:
			self.counter=self.counter + 1
			self.f.write("Request:---------------%s-------------------\n"%(str(self.counter)))
			self.f.writelines(_message.replace("\n", "")+"\n") # Write a string to a file
		except IOError:
			pass
	def writelog_response(self,_message):
		try:
			self.f.write("Response:--------------------------------------\n")
			self.f.writelines(_message.replace("\n", "")+"\n\n") # Write a string to a file
		except IOError:
			pass		
	def close(self):
		self.f.close()

class HTTPfuzzer(object):
	"""HTTPfuzzer Class
	Fuzzing HTTP Servers like a boss
	Multithreaded and has multiple vectors
	Powered by a Logger
	"""
	def __init__(self,domain,port):
		self.domain=domain.replace("http://","") if '://' in domain else domain
		self.ip = self.getIP()
		self.port = port
		self.fuzznumber=0
		self.targetfile = ["index.html","index.php","robots.txt"]
		self.httpmethods=["GET","POST","TRACE","PUT","OPTION","HEAD"]
		self.httpver = ([" HTTP/0.9"," HTTP/1.0"," HTTP/1.1"," HTTP/2.0"])
		self.useragents=['Mozilla/4.0 (compatible; MSIE 5.0; SunOS 5.10 sun4u; X11)',
		  'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.2.2pre) Gecko/20100207 Ubuntu/9.04 (jaunty) Namoroka/3.6.2pre',
		  'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; Avant Browser;',
		  'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)',
		  'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1)',
		  'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.0.6)',
		  'Microsoft Internet Explorer/4.0b1 (Windows 95)',
		  'Opera/8.00 (Windows NT 5.1; U; en)',
		  'amaya/9.51 libwww/5.4.0',
		  'Mozilla/4.0 (compatible; MSIE 5.0; AOL 4.0; Windows 95; c_athome)',
		  'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
		  'Mozilla/5.0 (compatible; Konqueror/3.5; Linux) KHTML/3.5.5 (like Gecko) (Kubuntu)',
		  'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; ZoomSpider.net bot; .NET CLR 1.1.4322)',
		  'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; QihooBot 1.0 qihoobot@qihoo.net)',
		  'Mozilla/5.0 (compatible; MSIE 5.0; Windows ME) Opera 5.11 [en]']
		self.logging=logging(self.domain.replace(".","_"))
	def randomIP(self):
		not_valid = [10,127,169,172,192]
		first = random.randrange(1,256)
		while first in not_valid:
			first = random.randrange(1,256)
		ip = ".".join([str(first),str(random.randrange(1,256)),str(random.randrange(1,256)),str(random.randrange(1,256))])
		return ip
	def randomJibberJabber(self,rnd_length):
		return "".join([random.choice(string.letters+string.digits) for x in range(1, rnd_length)])
	def randomUseragent(self):
		return self.useragents[random.randrange(1,len(self.useragents))]
	def randomHttpver(self):
		return self.httpver[random.randrange(1,len(self.httpver))]
	def randomFile(self):
		return self.targetfile[random.randrange(1,len(self.targetfile))]
	def randomHttpmethod(self):
		return self.httpmethods[random.randrange(1,len(self.httpmethods))]
	def randomReferer(self):
		return "http://www."+self.randomJibberJabber(random.randrange(1,100))+".com"
	def setFile(self,targetfile):
		self.targetfile=targetfile
	def getIP(self):
		return socket.gethostbyname(self.domain)
	def httpFuzz(self,httpmethod,targetfile,httpver,domain,useragent,ip,referer):	
		request = '%s /%s %s\r\n' %(httpmethod,targetfile,httpver)
		request += 'Host: %s\r\n' % (domain)
		request += 'User-Agent: %s\r\n' %(useragent)
		request += 'X-Forwarded-For: %s\r\n' %(ip)
		request += 'Referer: %s\r\n' %(referer)
		if httpmethod=="POST":
			jibberjabber=self.randomJibberJabber(random.randrange(1,1000))
			request += 'Content-Type: application/x-www-form-urlencoded\r\n'
			request += 'Content-length: %s\r\n\r\n' % (len(jibberjabber))
			request += '%s\r\n' % (jibberjabber)
		request += '\r\n\r\n'
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			s.connect((self.ip, self.port))
			s.send(request)
			response=s.recv(4094)
			#time.sleep(2)
			s.close()
		except socket.error:
			WARNING("We Got Something interesting over here")
		self.logging.writelog_request(request)
		self.logging.writelog_response(response)
		return request,response
	def run(self):
		WARNING("Starting HTTP Fuzzer on %s"%(self.domain))
		self.fuzznumber=raw_input(bcolors.MENU +" How many requests ? (example : 1000) :"+bcolors.ENDC)
		try:
			for i in progressbar(range(int(self.fuzznumber)), "Fuzzing: ", 40):
				request , response = self.httpFuzz(self.randomHttpmethod(),self.randomFile(),self.randomHttpver(),self.domain,self.randomUseragent(),self.randomIP(),self.randomReferer())
			SUCCESS("Fuzzing completed , Logfile saved in "+self.domain.replace(".","_")+".txt ...")
			self.logging.close()
		except Exception,e:
			raise e
		except KeyboardInterrupt:
			sys.exit(0)		
class Subdomaincrawler(object):
	"""Subdomaincrawler Class handles subdomains bruteforcing"""
	def __init__(self,dic,domain,threads):
		self.dictfile=dic
		self.dictcontent=self.readfile()
		self.domain=domain
		self.threads=threads
		self.lock=threading.Lock()
		self.rejected = ["404","300","301","302","303","307"]
		self.reject_regex=["404","error","ERROR"]
		self.foundsubs=[]
		self.q = Queue.Queue()
		self.fillqueue()

	def readfile(self):
		try:
			lines = [line.strip() for line in open(self.dictfile)]
			return lines
		except  IOError:
			print "Could not open dic file: %s" % self.dictfile
			sys.exit(0)

	def fillqueue(self):
		for element in self.dictcontent:
			self.q.put(element)

	def getrandomitem(self):
		randomitem_nber=random.randrange(1,len(self.dictcontent))
		self.dictcontent.pop(randomitem_nber)
		return self.dictcontent[randomitem_nber]

	def subbrute(self):
		while True:
			
			#print ("trying : "+sub)
			try:
				sub=self.q.get()
				conn = httplib.HTTPConnection( '%s.%s' % (sub, self.domain), timeout = 5 )
				conn.request('HEAD','/')
				res = conn.getresponse()
				if ((res.status not in self.rejected )):
					self.lock.acquire()
					self.foundsubs.append('%s.%s' % (sub, self.domain))
					WARNING("Found Sub-domain :"+sub+"."+self.domain)
					self.lock.release()
					conn.close()
			except Exception, e:
				pass
			except self.q.Empty:
				pass
			finally:
				self.q.task_done()

	def runThreads(self):
		SUCCESS(timer()+" Running Sub-domain bruteforce on : "+self.domain)
		for i in range(self.threads):
			t = threading.Thread(target=self.subbrute,)
			t.setDaemon(True)
			t.start()
		self.q.join()
		

	def print_findings(self):
		SUCCESS(timer()+" Found "+str(len(self.foundsubs))+" sub-domains")
		for found in self.foundsubs:
			print ("\t\t\t"+found+" IP : "+socket.gethostbyname(found))
		pass

class AdminFinder(object):
	"""Subdomaincrawler Class handles admin paths bruteforcing"""
	def __init__(self,dic,domain,threads):
		self.dictfile=dic
		self.dictcontent=self.readfile()
		self.domain=domain.replace("http://","") if '://' in domain else domain
		self.threads=threads
		self.lock=threading.Lock()
		self.rejected = ["404","300","301","302","303","307"]
		self.reject_regex="404"
		self.foundadmins=[]
		self.q = Queue.Queue()
		self.fillqueue()
		self.dic_counter=0
	def readfile(self):
		try:
			lines = [line.strip() for line in open(self.dictfile)]
			return lines
		except  IOError:
			print "Could not open dic file: %s" % self.dictfile
			sys.exit(0)

	def fillqueue(self):
		for element in self.dictcontent:
			self.q.put(element)

	def getrandomitem(self):
		randomitem_nber=random.randrange(1,len(self.dictcontent))
		self.dictcontent.pop(randomitem_nber)
		return self.dictcontent[randomitem_nber]

	def adminbrute(self):
		while True:
			try:
				admin=self.q.get()
				conn = httplib.HTTPConnection( '%s' % (self.domain), timeout = 5 )
				conn.request('GET',"/%s"% (admin))
				res = conn.getresponse()
				if ((res.status not in self.rejected ) and (self.reject_regex not in res.read())):
					self.lock.acquire()
					self.foundadmins.append('%s/%s' % (self.domain,admin))
					WARNING("Found Admin Panel : "+self.domain+"/"+admin)
					self.lock.release()
					conn.close()
					self.dic_counter=self.dic_counter+1
			except Exception, e:
				pass
			except self.q.Empty:
				pass
			finally:
				self.q.task_done()

	def runThreads(self):
		SUCCESS(timer()+" Running Admin bruteforce on : "+self.domain+" against "+str(getWordlistLength(self.dictfile)) +" admin paths")
		for i in range(self.threads):
			t = threading.Thread(target=self.adminbrute,)
			t.setDaemon(True)
			t.start()
		self.q.join()
		

	def print_findings(self):
		SUCCESS(timer()+" Found "+str(len(self.foundadmins))+" Admin paths")
		for found in self.foundadmins:
			print (bcolors.MENU+"\t\t\t"+found+bcolors.ENDC)
		pass

	def run(self):
		WARNING("Starting Admin Finder on %s"%(self.domain))
		try:
			self.runThreads()
			self.print_findings()
		except Exception,e:
			pass
		except KeyboardInterrupt:
			sys.exit(0)

class Httpintelligence(object):
	"""Simple Class that return HEAD data
	   and fetches Server,X-Powered-By,Last-Modified data
	   Author : th3breacher
	"""
	def __init__(self, domain):
		self.domain = domain
		self.cloudflare_string="cloudflare"

	def getHeader(self):
		response=[]
		if self.domain.startswith('http://'):
			self.domain = self.domain[7:]
		try:
			conn = httplib.HTTPConnection(self.domain)
			conn.request("HEAD", "/index.html")
			res = conn.getresponse()
			response.append(res.getheader("server"))
			response.append(res.getheader("X-Powered-By"))
			response.append(res.getheader("Last-Modified"))
		except Exception, e:
			ERROR("Error Establishing connection")	
		return response

	def printHeader(self):
		header_response=self.getHeader()
		SUCCESS("Running Server recognition on : "+self.domain)
		print("HTTP Server : "+str(header_response[0]))
		print("Powered By : "+str(header_response[1]))
		print("Last Modified : "+str(header_response[2]))

class Portscanner(object):
	"""Just a portscanner Class 
	   Author : th3breacher
	"""
	def __init__(self,domain):
		self.domain=domain
		self.ipadress=self.resolveIP()
		self.portlist=[21,22,23,25,53,80,81,110,139,220,443,1194,2083,2087,3306,6667]

	def resolveIP(self):
		if self.domain.startswith('http://'):
			self.domain = self.domain[7:]
		try:
			return socket.gethostbyname(self.domain)
		except Exception, e:
			raise e

	def portscan_range(self):
		openports=[]
		for i in range(20, 1000):
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ping_ACK = s.connect_ex((self.ipadress, i))
			if(ping_ACK == 0) :
			   openports.append(i)
			s.close()
		return openports

	def portscan_major(self):
		openports=[]
		for i in self.portlist:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			ping_ACK = s.connect_ex((self.ipadress, i))
			if(ping_ACK == 0) :
			   openports.append(i)
			s.close()
		return openports
	def print_openports(self,mode):
		SUCCESS("Running Port scanner on : "+self.ipadress)
		openports=[]
		try:
			if mode==1:
				openports=self.portscan_major()
			else:
				openports=self.portscan_range()
		except Exception, e:
			raise e
		else:
			WARNING("Open Ports :")
			print '[%s]' % ', '.join(map(str, openports))


class Whois_query(object):
	"""Provides a wrapper for whois queries , thanks to Adam Kahtava web service
	   Author : th3breacher
	"""
	def __init__(self, domain):
		self.domain=domain
		self.ip_adress=self.resolveIP()
		self.webservice_url="http://adam.kahtava.com/services/whois.json?query="
		self.domain_webservice_url="http://whomsy.com/api/example.com?output=json"
		self.whois_catalog=["Domain IP","AbuseContact | Email","AbuseContact | Name","AbuseContact | Phone","AdministrativeContact | Email",
		"AdministrativeContact | Name","AdministrativeContact | Phone","Registrant | Address","Registrant | City","Registrant | Country","Registrant | Name"]
	def resolveIP(self):
		if self.domain.startswith('http://'):
			self.domain = self.domain[7:]
		try:
			return socket.gethostbyname(self.domain)
		except Exception, e:
			raise e
	def get_Whois(self):
		important_data=[]
		try:
			req = urllib2.Request(self.webservice_url+self.ip_adress)
			f = urllib2.urlopen(req)
			response = f.read()
			f.close()
		except Exception, e:
			raise e
		else:
			jsondata=json.loads(response)
			important_data.append(jsondata["DomainName"]) 
			important_data.append(jsondata["RegistryData"]["AbuseContact"]["Email"])
			important_data.append(jsondata["RegistryData"]["AbuseContact"]["Name"])
			important_data.append(jsondata["RegistryData"]["AbuseContact"]["Phone"])
			important_data.append(jsondata["RegistryData"]["AdministrativeContact"]["Email"])
			important_data.append(jsondata["RegistryData"]["AdministrativeContact"]["Name"])
			important_data.append(jsondata["RegistryData"]["AdministrativeContact"]["Phone"])
			important_data.append(jsondata["RegistryData"]["Registrant"]["Address"])
			important_data.append(jsondata["RegistryData"]["Registrant"]["City"])
			important_data.append(jsondata["RegistryData"]["Registrant"]["Country"])
			important_data.append(jsondata["RegistryData"]["Registrant"]["Name"])
		
		return important_data
	def get_Domain_Whois(self):
		message=""
		try:
			req = urllib2.Request(self.domain_webservice_url.replace("example.com", self.domain))
			f = urllib2.urlopen(req)
			response = f.read()
			f.close()
		except Exception, e:
			raise e
		else:
			jsondata=json.loads(response)
			message=jsondata["message"] 
			
		return message
	def print_Whois_info(self):
		SUCCESS("Running IP Whois query on : "+self.ip_adress)
		queryoutput=self.get_Whois()
		for i in range(len(queryoutput)):
			print (self.whois_catalog[i]+" : "+queryoutput[i])

	def print_Domain_Whois_info(self):
		SUCCESS("Running Domain Whois query on : "+self.domain)
		queryoutput=self.get_Domain_Whois()
		print (queryoutput)

def banner():
	print bcolors.FAIL+"""

		 .d888888        dP            oo                     dP                     
		d8'    88        88                                   88                     
		88aaaaa88a .d888b88 88d8b.d8b. dP 88d888b. .d8888b. d8888P .d8888b. 88d888b. 
		88     88  88'  `88 88'`88'`88 88 88'  `88 88'  `88   88   88'  `88 88'  `88 
		88     88  88.  .88 88  88  88 88 88    88 88.  .88   88   88.  .88 88       
		88     88  `88888P8 dP  dP  dP dP dP    dP `88888P8   dP   `88888P' dP

									Not just another Admin finder
									)c( by th3breacher and Zer0freak
									2012 Christmas Special
	"""+bcolors.ENDC

def usage():
	print bcolors.WARNING+"""

Adminat0r , Not just another Admin finder
-----------------------------
For a complete list of commands type :usage
Available Commands :
	:whoisip => Finding Whois information about the IP hosting the website 
	:whoisdomain => Fetching Domain Whois information
	:portscanner => Finding Important open ports
	:intelligence => Getting Intelligence data from a website(HTTP server,Software,Last update)
	:subdomain => Multithreaded Subdomain Finder using a wordlist
	:admin => Multithreaded Admin Finder using a wordlist
	:fuzzer => HTTP Fuzzer to Fuzz HTTP servers
	:usage => prints this help section
	:quit =>
	"""
		
def execute(_command):
	WARNING("EXEC :"+_command)
	os.system(_command)

def menu_Subdomain():
	MENU("Running Subdomain Crawler")
	domain=raw_input(bcolors.FAIL +"Target Domain (example : www.google.com) :  "+bcolors.ENDC)
	threads=raw_input(bcolors.FAIL +"Number of Threads (example : 10) :  "+bcolors.ENDC)
	t=Subdomaincrawler(Options.Subdomains_Wordlist,domain,int(threads))
	t.runThreads()
	t.print_findings()
	pass
def menu_WhoisIP():
	MENU("Running IP Whois Info")
	domain=raw_input(bcolors.FAIL +"Target Domain (example : www.google.com) :  "+bcolors.ENDC)
	t=Whois_query(domain)
	t.print_Whois_info()
	pass
def menu_WhoisDomain():
	MENU("Running Domain Whois Info")
	domain=raw_input(bcolors.FAIL +"Target Domain (example : www.google.com) :  "+bcolors.ENDC)
	t=Whois_query(domain)
	t.print_Domain_Whois_info()
	pass
def menu_PortScanner():
	MENU("Running TCP Port scanner on major ports")
	domain=raw_input(bcolors.FAIL +"Target Domain (example : www.google.com) :  "+bcolors.ENDC)
	t=Portscanner(domain)
	t.print_openports(1)
	pass
def menu_Intelligence():
	MENU("Running HTTP Intelligence Crawler")
	domain=raw_input(bcolors.FAIL +"Target Domain (example : www.google.com) :  "+bcolors.ENDC)
	t=Httpintelligence(domain)
	t.printHeader()
	pass
def menu_HTTPFuzzer():
	MENU("Running HTTP Fuzzer")
	domain=raw_input(bcolors.FAIL +"Target Domain (example : www.google.com) :  "+bcolors.ENDC)
	httpport=raw_input(bcolors.FAIL +"Target port (example : 80) :  "+bcolors.ENDC)
	t=HTTPfuzzer(domain,int(httpport))
	t.run()
	pass
def menu_AdminFinder():
	MENU("Running Admin Finder")
	domain=raw_input(bcolors.FAIL +"Target Domain (example : www.google.com) :  "+bcolors.ENDC)
	threads=raw_input(bcolors.FAIL +"Number of Threads (example : 10) :  "+bcolors.ENDC)
	t=AdminFinder(Options.Admin_Wordlist,domain,int(threads))
	t.runThreads()
	t.print_findings()
	pass	
def main():
	cmd=""
	while cmd != ":quit":
		cmd=raw_input(bcolors.FAIL +"\nAdminator > "+bcolors.ENDC)
		if cmd.lower() == ":whoisip":
			menu_WhoisIP()
		elif cmd.lower()==":whoisdomain":
			menu_WhoisDomain()
		elif cmd.lower()==":portscanner":
			menu_PortScanner()
		elif cmd.lower()==":intelligence":
			menu_Intelligence()
		elif cmd.lower()==":subdomain":
			menu_Subdomain()
		elif cmd.lower()==":admin":
			menu_AdminFinder()
		elif cmd.lower()==":fuzzer":
			menu_HTTPFuzzer()
		elif cmd.lower()==":usage":
			usage()
		elif cmd.lower()==":quit":
			sys.exit(1)
		else:
			execute(cmd)   
	
if __name__=="__main__":
	if is_linux():
		os.system("clear")
	else:
		os.system("cls")
	banner()
	main()
