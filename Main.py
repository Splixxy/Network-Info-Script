import socket
import nmap
import nmap3
import datetime
import json
import dns.resolver
#Imports the required packages
hostname = socket.gethostname() #sets the varaiable hostname to the socket command
ip = socket.gethostbyname(hostname) #sets the ip varaible and gets the ip of the machine
nm = nmap.PortScanner() #sets the nm varaible to call the nmap PortScanner
nm3Host = nmap3.NmapHostDiscovery() #sets the nm3Host to the nmap host discover
nm3 = nmap3.Nmap() #sets the nm3 varaible to the nmap command
DT = datetime.datetime.now() #sets DT to the date and time
dns = dns.resolver.Resolver() #sets dns to the dns command
def rangeScan(ip): #creates the range scan function with the input of the ip
    for ip in nm.all_hosts(): #creates a for loop for the ip in the scanned hosts
         deviceName = ("Host : %s (%s)" % (ip, nm[ip].hostname()))
         state = ("State : %s" % nm[ip].state())
         fOpen = open("Port-Range-Scan(%s)-Created(%s).txt" % (portRange, DT),"a")
         fOpen.write("%s\n%s" % (deviceName, state))
         fOpen.close()
         #writes to the file
         for protocol in nm[ip].all_protocols(): #creates a for loop for protocol in all of the protocols that were scanned
             lb = ("\n----------")
             proto = ("Protocol : %s" % protocol)
             fOpen = open("Port-Range-Scan(%s)-Created(%s).txt" % (portRange, DT),"a")
             fOpen.write("%s\n%s" % (lb, proto))
             fOpen.close()
             #writes to the file
             portList = nm[ip][protocol].keys() #creates a varaible for the ports
             for port in portList: #creates a for loop for ports in the dictionary
               results = ("port : %s : %s" % (port, nm[ip][protocol][port]['state']))
               fOpen = open("Port-Range-Scan(%s)-Created(%s).txt" % (portRange, DT),"a")
               fOpen.write("\n%s" % results)
               fOpen.close()
               #writes to the file
def commonScan(ip): #creates the commonScan function with the IP input
    topScan = nm3.scan_top_ports(ip) #sets topScan varaible to the topscan function of the nmap3 package
    fOpen = open("Top-Ports-Scan-Created(%s).txt" % (DT),"a")
    json.dump(topScan,fOpen)
    fOpen.close()
    #writes to the file
    print("The scan is finished and file has been created")

def DNSinfo(): #creates the DNS info function
    dnsScan = dns.nameservers[0] #sets the dnsScan varaible to the dns server finder command
    if scanType == "r" or scanType == "R": #checks if the scan type entered was r or R
        lb = ("\n----------\n")
        fOpen = open("Port-Range-Scan(%s)-Created(%s).txt" % (portRange, DT),"a")
        fOpen.write("%sThe DNS address is: %s\n" % (lb,dnsScan))
        fOpen.close()
        #writes to file
    else:
        lb = ("\n----------\n")
        fOpen = open("Top-Ports-Scan-Created(%s).txt" % (DT),"a")
        fOpen.write("\nThe DNS address is: %s\n" % dnsScan)
        fOpen.close()
        #writes to file
def osDetect(): #creates the os detect function
    os = nm3.nmap_os_detection(ip) #sets the os varaible to the nmap 3 os detection command
    if scanType == "r" or scanType == "R": #checks if the scan type was r or R
        lb = ("\n----------\n")
        fOpen = open("Port-Range-Scan(%s)-Created(%s).txt" % (portRange, DT),"a")
        fOpen.write("%sOS Detection Script Output\n" % lb)
        json.dump(os,fOpen)
        fOpen.close()
        #writes to file
        print("The scan is finished and file has been created")
    else:
        lb = ("\n----------\n")
        fOpen = open("Top-Ports-Scan-Created(%s).txt" % DT,"a")
        fOpen.write("%sOS Detection Script Output\n" % lb)
        json.dump(os,fOpen)
        fOpen.close()
        #writes to file
        print("The scan is finished and file has been created")

#asks if you would like the ip to be automatically aquired or mannually entered
autoORuser = input("Would you like the ip address to be inputed automatically (a) or mannually (m):")
if autoORuser == "a" or autoORuser == "A": #sees if autoORuser is a or A
    print("The target IP to be scanned is: %s" % ip)
    checkIP = input("Please in a Y to continue or a N to cancel:") #asks you to confirm the IP
    if checkIP == "y" or checkIP == "Y": #checks to see if you awnsered yes with y or Y
        scanType = input("Please input if you would like a top ports scan (T) or a range port scan(R):") #asks to input what scan type you would like
        if scanType == "r" or scanType == "R": #if the scanType is r or R
            portRange = input("Please input the port or port range with a (-) to be scanned:") #asks you to put in the port range to be scanned
            portScan = nm.scan(ip,portRange) #runs the port scan on the ip and range
            rangeScan(ip) #calls the rangeScan function
            DNSinfo() #calls the DNSinfo function
            osDetect() #calls the osDetect function
        else:
            commonScan(ip) #calls the commonScan function
            DNSinfo() #calls the DNSinfo function
            osDetect() #calls the osDetect function
    else:
        print("The Program Is Now Exiting") # if you awnsered no to the ip program exits
        exit()
else:
    ip = input("Please input in the IP to be scanned:") #asks user to input ip to be used
    print("The target IP to be scanned is: %s" % ip)
    checkIP = input("Please input a y to continue or a n to cancel:") #asks you to confirm ip address
    if checkIP == "y" or checkIP == "Y": #checks if you awnsered yes with y or Y
        scanType = input("Please input if you would like a top ports scan (T) or a port/range port scan(R):") #asks what scan type you would like
        if scanType == "r" or scanType == "R": #checks if scanType is r or R
            portRange = input("Please input the port or port range with a (-) to be scanned:") #asks for the portrange or port
            portScan = nm.scan(ip,portRange) #runs the scan on the ip with the port or port range
            rangeScan(ip) #calls the range scan function
            DNSinfo() #calls the Dnsinfo function
            osDetect() #calls the osDetect function
        else:
            commonScan(ip) #calls the commonScan function
            DNSinfo() #calls the DNSinfo function
            osDetect() #calls the osDetect function
    else:
        print("The Program Is Now Exiting") #if you awnsered no to the ip program exits
        exit()
