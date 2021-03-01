import socket
import nmap
import nmap3
import datetime
import json
import dns.resolver
hostname = socket.gethostname()
ip = socket.gethostbyname(hostname)
nm = nmap.PortScanner()
nm3Host = nmap3.NmapHostDiscovery()
nm3 = nmap3.Nmap()
DT = datetime.datetime.now()
dns = dns.resolver.Resolver()
def rangeScan(ip):
    for ip in nm.all_hosts():
         deviceName = ("Host : %s (%s)" % (ip, nm[ip].hostname()))
         state = ("State : %s" % nm[ip].state())
         fOpen = open("Port-Range-Scan(%s)-Created(%s).txt" % (portRange, DT),"a")
         fOpen.write("%s\n%s" % (deviceName, state))
         fOpen.close()
         for protocol in nm[ip].all_protocols():
             lb = ("\n----------")
             proto = ("Protocol : %s" % protocol)
             fOpen = open("Port-Range-Scan(%s)-Created(%s).txt" % (portRange, DT),"a")
             fOpen.write("%s\n%s" % (lb, proto))
             fOpen.close()
             portList = nm[ip][protocol].keys()
             for port in portList:
               results = ("port : %s : %s" % (port, nm[ip][protocol][port]['state']))
               fOpen = open("Port-Range-Scan(%s)-Created(%s).txt" % (portRange, DT),"a")
               fOpen.write("\n%s" % results)
               fOpen.close()
             print("The scan is finished and file has been created")
def commonScan(ip):
    topScan = nm3.scan_top_ports(ip)
    fOpen = open("Top-Ports-Scan-Created(%s).txt" % (DT),"a")
    json.dump(topScan,fOpen)
    fOpen.close()
    print("The scan is finished and file has been created")

def DNSinfo():
    dnsScan = dns.nameservers[0]
    if scanType == "r" or scanType == "R":
        lb = ("\n----------\n")
        fOpen = open("Port-Range-Scan(%s)-Created(%s).txt" % (portRange, DT),"a")
        fOpen.write("%sThe DNS address is: %s\n" % (lb,dnsScan))
        fOpen.close()
    else:
        lb = ("\n----------\n")
        fOpen = open("Top-Ports-Scan-Created(%s).txt" % (DT),"a")
        fOpen.write("\nThe DNS address is: %s\n" % dnsScan)
        fOpen.close()

def osDetect():
    os = nm3.nmap_os_detection(ip)
    if scanType == "r" or scanType == "R":
        lb = ("\n----------\n")
        fOpen = open("Port-Range-Scan(%s)-Created(%s).txt" % (portRange, DT),"a")
        fOpen.write("%sOS Detection Script Output\n" % lb)
        json.dump(os,fOpen)
        fOpen.close()
    else:
        lb = ("\n----------\n")
        fOpen = open("Top-Ports-Scan-Created(%s).txt" % DT,"a")
        fOpen.write("%sOS Detection Script Output\n" % lb)
        json.dump(os,fOpen)
        fOpen.close()

autoORuser = input("Would you like the ip address to be inputed automatically (a) or mannually (m):")
if autoORuser == "a" or autoORuser == "A":
    print("The target IP to be scanned is: %s" % ip)
    checkIP = input("Please in a Y to continue or a N to cancel:")
    if checkIP == "y" or checkIP == "Y":
        scanType = input("Please input if you would like a top ports scan (T) or a range port scan(R):")
        if scanType == "r" or scanType == "R":
            portRange = input("Please input the port or port range with a (-) to be scanned:")
            portScan = nm.scan(ip,portRange)
            rangeScan(ip)
            DNSinfo()
        else:
            commonScan(ip)
            DNSinfo()
    else:
        print("The Program Is Now Exiting")
        exit()
else:
    ip = input("Please input in the IP to be scanned:")
    print("The target IP to be scanned is: %s" % ip)
    checkIP = input("Please in a Y to continue or a N to cancel:")
    if checkIP == "y" or checkIP == "Y":
        scanType = input("Please input if you would like a top ports scan (T) or a port/range port scan(R):")
        if scanType == "r" or scanType == "R":
            portRange = input("Please input the port or port range with a (-) to be scanned:")
            portScan = nm.scan(ip,portRange)
            rangeScan(ip)
            DNSinfo()
            osDetect()
        else:
            commonScan(ip)
            DNSinfo()
            osDetect()
    else:
        print("The Program Is Now Exiting")
        exit()
