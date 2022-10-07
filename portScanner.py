import sys
import socket
import pyfiglet
from datetime import datetime
from colorama import Fore
import re

ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")  
banner = pyfiglet.figlet_format("BUG   BREAKERS")
print(Fore.GREEN + banner)
print('-' * 69)
if len(sys.argv) == 2:
    # translate hostname to IPv4
    target = socket.gethostbyname(sys.argv[1])
elif len(sys.argv) == 4:
    target = socket.gethostbyname(sys.argv[1])
    start = sys.argv[2];
    end = sys.argv[3];
else:
    while True:
        target = input(Fore.LIGHTBLACK_EX + "Please enter the ip address that you want to scan: ")
        if ip_add_pattern.search(target):
            print(f"{target} is a valid ip address")
            break
        else:
            print(Fore.LIGHTBLACK_EX + "invalid ip address, try again: ")
    #target = input(Fore.LIGHTBLACK_EX + "Enter The Host to be scanned : ")
    start = input(Fore.LIGHTBLACK_EX + "Enter The start of the port range you wish to scan : ")
    end = input(Fore.LIGHTBLACK_EX + "Enter The end of the port range you wish to scan : ")
 
print(Fore.GREEN + '-' * 69)
print(Fore.RESET + "Scanning Target: " + target)
print(Fore.RESET + "Scanning started time: " + str(datetime.now()))

try: 
    for port in range(int(start),int(end)):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(1)
        result = s.connect_ex((target,port))
        if result ==0:
            print("Port {} is open".format(port))
        s.close()
         
except KeyboardInterrupt:
        print("\nProgram Exited")
        sys.exit()
except socket.gaierror:
        print("\nThe Host you entered was invalid")
        sys.exit()
except socket.error:
        print("\nServer Error")
        sys.exit()

print(Fore.RESET + "Scanning end time: " + str(datetime.now()))