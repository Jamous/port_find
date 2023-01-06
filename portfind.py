# Portfind.py by Jamous Bitrick - Version x
# https://github.com/Jamous/port-find/

'''
TODO:
* Match partial addresses
* set hosts.txt as default for public release
'''
#Imports
import argparse
from multiprocessing.pool import ThreadPool
from netmiko import ConnectHandler
import getpass
import re

#Global variables
session_values = None
mac_address = {}

#Regex search expressions
cisco_format = "[0-9A-Fa-f]{4}[.][0-9A-Fa-f]{4}[.][0-9A-Fa-f]{4}" #Ex. 4ced.fb8f.6a74
standard_format = "[0-9A-Fa-f]{2}[:][0-9A-Fa-f]{2}[:][0-9A-Fa-f]{2}[:][0-9A-Fa-f]{2}[:][0-9A-Fa-f]{2}[:][0-9A-Fa-f]{2}" #Ex. 4C:ED:FB:8F:6A:74 or 4c:ed:fb:8f:6a:74
ip_format = "\d?\d?\d[.]\d?\d?\d[.]\d?\d?\d[.]\d?\d?\d"
ip_octect = "\d?\d?\d"

#Command dictionary
command_dictionary = {
    'ubiquiti_edgerouter': {'arp_table' : 'show arp | match ', 'regex_mac_key': 'standard_format'},
    'ubiquiti_edgeswitch': { 'mac_type': 'mac_large','host': 'show running-config | include host', 'mac_table': 'show mac-addr-table ', 'show_interfaces': 'show mac-addr-table interface ', 'regex_key': '0/..', 'regex_find_key': 'mac_address', 'regex_mac_key': 'standard_format'},
    'cisco_ios': { 'arp_table' : 'show ip arp | i ', 'mac_type': 'mac_cisco', 'host': 'show running-config | include host', 'mac_table': 'show mac address-table | i ', 'show_interfaces': 'show mac address-table interface ', 'regex_key': '[FGT][ie]\d[/\d]+', 'regex_find_key': 'port', 'regex_mac_key': 'cisco_format'},
}

def main():
    #Readin all IP adresses and router (optional)
    all_ip_addresses, router = setup_connections()
    
    #If input is an IP address find the MAC
    if session_values['is_ip']:
        find_mac_from_router(router)

    #Generate all mac_addresses
    mac_parser()
    
    #Iniate SSH connections
    initiate_connections(all_ip_addresses)

def input_parser():
    global session_values

    #Default log positions
    output_file = 'log/output.txt'
    exception_file = 'log/exceptions.txt'

    #Default hostfile locations
    host_file = 'etc/hosts.txt'

    #Parse inputs and save as input_values
    parser = argparse.ArgumentParser(description='Portfind finds what port an IP or MAC address are in a campus lan.')
    #default parameters
    parser.set_defaults(location='default', is_ip=False, exception_file=False, output_file=False, number=10, verbose=False, thread_count=None) #Set default values
    #Location parameters
    location_group = parser.add_mutually_exclusive_group() #Define mutally exclusive groups. You can add multiple groups here.
    location_group.add_argument('-l', '--location', dest='location', action='store_const', const='default', help='Search smiths landing for this IP or MAC address. (Default)') #Parse Smiths Landing
    #Mac address
    parser.add_argument('address', nargs='?', help='MAC or IP address to search for') #Search for the MAC
    #Logging and output parameters 
    verbose_group = parser.add_argument_group('Logging and output parameters')
    verbose_group.add_argument('-v', '--verbose', dest='verbose', action='store_const', const=True, help='Enables cli output and logging. Disables some error handeling.' )
    verbose_group.add_argument('-e', '--exceptions', nargs='?', dest='exception_file', help='Name of exceptions file. Default is log/exceptions.txt. Used in conjunction with -v.')
    verbose_group.add_argument('-o', '--output', nargs='?', dest='output_file', help='Name of output/log file Ex. output.txt. Used in conjunction with -v.')
    #Optional parameters
    optional_group = parser.add_argument_group('Optional parameters')
    optional_group.add_argument('-n','--number', nargs='?', type=int, help='If a MAC address is found on an interface, how many other MAC addresses will you accept? A higher number will also include trunk ports. Default is 10.')
    optional_group.add_argument('-t', '--thread_count', nargs='?', type=int, help='Changes thread count. The default is to try and create a thread for every address. Set to 1 to disable multithreading (very slow)')

    #Convert to dictionary for easy access
    session_values = vars(parser.parse_args())
    
    #Raise an error if address has not ben input.
    if not session_values['address']:
        parser.print_help()
        print("\n[-] Please specify a MAC or IP address to search for.\nEx. portfind 4C:ED:FB:8F:6A:74")
        exit()
     
    #Check if valid IP address has been input. If it has set is_ip to true
    elif regex_search(ip_format,session_values['address']):
        #Check if IP address is valid
        ip_1, ip_2, ip_3, ip_4 = regex_findall(ip_octect,session_values['address'])
        if int(ip_1) < 256 and int(ip_2) < 256 and int(ip_3) < 256 and int(ip_4) < 256:
            session_values.update({'is_ip': True})
        else:
            parser.print_help()
            print("\n[-] Invalid IP address " + str(session_values['address']) + " \nPlease specify a MAC or IP address to search for.\nEx. portfind 4C:ED:FB:8F:6A:74")
            exit()

    #Check if valid MAC address has been input
    else:
        if re.match(standard_format,session_values['address']):
            pass
        elif re.match(cisco_format,session_values['address']):
            pass
        else:
            parser.print_help()
            print("\n[-] Invalid MAC address " + str(session_values['address']) + " \nPlease specify a MAC address to search for.\nEx. portfind 4C:ED:FB:8F:6A:74")
            exit()

    #Update host list, device type and mac address. You can add more here later
    if session_values['location'] == 'default':
        session_values.update({'host_file': host_file})

    #Settup logging values
    session_values.update({'log_output': False})
    session_values.update({'log_exception': False})

    #Enable everything if verbose mode is active
    if session_values['verbose']:
        if session_values['output_file'] == False or session_values['output_file'] == None:
            session_values['output_file'] = output_file
        if session_values['exception_file'] == False or session_values['exception_file'] == None:
                session_values['exception_file'] = exception_file
        session_values.update({'log_output': True})
        session_values.update({'log_exception': True})   
        
    #Enable only options selected if verbose mode is active
    else:
        #Check if output file has been enabled, but no filename was given    
        if session_values['output_file'] == None:
            session_values['output_file'] = output_file
            session_values.update({'log_output': True})
        #Check if outputfile was enabeled and a filename was given
        elif session_values['output_file'] != False:
            session_values.update({'log_output': True})
        
        #Check if exceptions file has been enabled, but no filename was given 
        if session_values['exception_file'] == None:
            session_values['exception_file'] = exception_file
            session_values.update({'log_exception': True})
        #Check if outputfile was enabeled and a filename was given
        elif session_values['exception_file'] != False:
            session_values.update({'log_exception': True})       

def setup_connections():
    global session_values
    all_ip_addresses = []
    device_type = router = None
    password_group = None

    #Get username and password
    username, password = get_credentials()

    #Open list of clients and read into all_ip_addresses. Lines beginning with ~ denote network device types. Ignore empty lines and lines with #
    host_list = open (session_values['host_file'])

    for line in host_list:
        try: 
            ip_address = line.strip()
            
            #Strip out username/password changes
            if ip_address != "" and ip_address[0] == "*":
                password_group = ip_address[1:]
                print("Device group "  + str(password_group))
                username, password = get_credentials()
            
            #Strip out device_type
            elif ip_address != "" and ip_address[0] == "~":
                device_type = ip_address[1:]
            
            #Strip out router_address
            elif ip_address != "" and ip_address[0] == "!":
                router = ([ip_address[1:], device_type, username, password, password_group])
            
            #Accept new addresses
            elif ip_address != "" and ip_address[0] != "#":
                all_ip_addresses.append([ip_address, device_type, username, password, password_group])
        
        except Exception as exc:
            if session_values['verbose']:
                print("Could not read from file " + host_list + "\n" + str(exc) + "\nWriting error to " + str(session_values['exception_file']))
                exception_file = open(session_values['exception_file'], 'a')
                exception_file.write("Could not read from file " + host_list + "\n" + str(exc) + "\n\n")
    
    #Return all_ip_addresses and router
    return all_ip_addresses, router

def get_credentials():
    #Get username and password
    username = input("Username: ")
    password = getpass.getpass()

    return username, password

def find_mac_from_router(node_details):
    #Node details: [ip address,device type,username,password,password group]
    try:
        ssh_dictionary = {
            'device_type': node_details[1],
            'host':   node_details[0],
            'username': node_details[2],
            'password': node_details[3],
        }

        net_connect = ConnectHandler(**ssh_dictionary)
        
        #Log connection. Print if verbose is enabeled
        logg_output = "Successful connection! IP address: " + str(node_details[0]) + " Device type: " + str(node_details[1]) + " Password group: " + str(node_details[4]) + " Username: " + str(node_details[2]) + "\n"
        
        #Get arp address from router
        command_out = net_connect.send_command(command_dictionary[node_details[1]]['arp_table'] + session_values['address'])
        logg_output += command_out

        #Check if a mac address was returned
        if command_out == "":
            if session_values['verbose']:
                print("\n\nIP address " + str(session_values['address']) + " is not present on router " + str(node_details[0]) + ". Exiting")
            if session_values['log_exception']:
                print("Writing host ip address to " + str(session_values['exception_file']))
                exception_file = open(session_values['exception_file'], 'a')
                exception_file.write("\n\nIP address " + str(session_values['address']) + " is not present on router " + str(node_details[0]) + ". Exiting")
            exit()

        #strip out arp address based on mac type
        if command_dictionary[node_details[1]]['regex_mac_key'] == 'standard_format':
            mac_address = regex_search(standard_format,command_out)
        elif command_dictionary[node_details[1]]['regex_mac_key'] == 'cisco_format':
            mac_address = regex_search(cisco_format,command_out)
        
        #Update session valuse
        session_values.update({'ip': session_values['address']})
        session_values['address'] = mac_address

        #Handle logging
        if session_values['log_output']:
            outfile = open(session_values['output_file'], 'a')
            outfile.write(logg_output)   
            if session_values['verbose']:
                print(logg_output)   

    #Hanle errors
    except Exception as exc:
        if session_values['verbose']:
            print("There was an exception on host " + node_details[0] + "\n" + str(exc) +  "\nCould not connect to router, could not preform ARP lookup, could not resolve MAC address. Exiting")
        if session_values['log_exception']:
            print("Writing host ip address to " + str(session_values['exception_file']))
            exception_file = open(session_values['exception_file'], 'a')
            exception_file.write("There was an exception on host " + node_details[0] + "\n" + str(exc) + "\nCould not connect to router, could not preform ARP lookup, could not resolve MAC address. Exiting\n\n")
        exit()

def mac_parser():
    global mac_address

    #Convert mac address to Uppercase standard
    if re.match(cisco_format,session_values['address']):
        mac_address.update({'mac_large': (session_values['address'][0:2] + ":" + session_values['address'][2:4] + ":" + session_values['address'][5:7] + ":" + session_values['address'][7:9] + ":" + session_values['address'][10:12] + ":" + session_values['address'][12:14]).upper()})
    else:
        mac_address.update({'mac_large': session_values['address'].upper()})

    #Convert mac address to Lowercase standard
    if re.match(cisco_format,session_values['address']):
        mac_address.update({'mac_small': (session_values['address'][0:2] + ":" + session_values['address'][2:4] + ":" + session_values['address'][5:7] + ":" + session_values['address'][7:9] + ":" + session_values['address'][10:12] + ":" + session_values['address'][12:14]).upper()})
    else:
        mac_address.update({'mac_small': session_values['address'].lower()})
    
    #Convert mac to Cisco standard
    if re.match(standard_format,session_values['address']):
        mac_address.update({'mac_cisco': (session_values['address'][0:2] + session_values['address'][3:5] + "." + session_values['address'][6:8] + session_values['address'][9:11] + "." + session_values['address'][12:14]  + session_values['address'][15:17]).lower()})
    else:
        mac_address.update({'mac_cisco': session_values['address'].lower()})

def initiate_connections(all_ip_addresses):
    #Create multiple threads and try to connect. Threads can be limited
    if session_values['thread_count'] == None:
        thread = ThreadPool(len(all_ip_addresses))
    else:
        thread = ThreadPool(session_values['thread_count'])
    thread.map(ssh_connect, all_ip_addresses)
    thread.close()
    thread.join()

def ssh_connect(node_details):
    #Node details: [ip address,device type,username,password,password group]
    try:
        ssh_dictionary = {
            'device_type': node_details[1],
            'host':   node_details[0],
            'username': node_details[2],
            'password': node_details[3],
        }

        net_connect = ConnectHandler(**ssh_dictionary)
        
        #Handle logging
        if session_values['log_output']:
            printable_output = "Successful connection! IP address: " + str(node_details[0]) + " Device type: " + str(node_details[1]) + " Password group: " + str(node_details[4]) + " Username: " + str(node_details[2])
            outfile = open(session_values['output_file'], 'a')
            outfile.write(printable_output)   
            if session_values['verbose']:
                print(printable_output)     

        #Send to SSH commands. 
        find_mac(net_connect,node_details[1])

    except Exception as exc:
        if session_values['verbose']:
            print("There was an exception on host " + node_details[0] + "\n" + str(exc))
        if session_values['log_exception']:
            exception_file = open(session_values['exception_file'], 'a')
            exception_file.write("There was an exception on host " + node_details[0] + "\n" + str(exc) + "\n\n")

def find_mac(net_connect,device_type):
    #Read response from device
    command_out = net_connect.send_command(command_dictionary[device_type]['mac_table'] + mac_address[command_dictionary[device_type]['mac_type']])
    logg_output = command_out

    #If found 
    port = regex_search(command_dictionary[device_type]['regex_key'],command_out)

    #Count number of MAC addresses on the interface. Cisco and ubiquity devices will need to searc for diffrent values. See below.
    port_output = net_connect.send_command(command_dictionary[device_type]['show_interfaces'] + port)

    #If elif statements to preform the correct type of search to count number of times this appears on a port
    if command_dictionary[device_type]['regex_find_key'] == 'port':
        if command_dictionary[device_type]['regex_mac_key'] == 'standard_format':
            num_on_interface = len(regex_findall(standard_format,port_output))
        elif command_dictionary[device_type]['regex_mac_key'] == 'cisco_format':
            num_on_interface = len(regex_findall(cisco_format,port_output))
    
    elif command_dictionary[device_type]['regex_find_key'] == 'mac_address':
        if command_dictionary[device_type]['regex_mac_key'] == 'standard_format':
            num_on_interface = len(regex_findall(standard_format,port_output))
        elif command_dictionary[device_type]['regex_mac_key'] == 'cisco_format':
            num_on_interface = len(regex_findall(cisco_format,port_output))

    logg_output += "MAC address found on port " + str(port) + "\nNumber of MAC addresses on port " + str(port) + ": " + str(num_on_interface)
    
    if 0 < num_on_interface < session_values['number']:
        if not session_values['verbose']:
            if 'ip' in session_values:
                standard_output = "\n\nIP address " + str(session_values['ip']) + " MAC address " + str(mac_address[command_dictionary[device_type]['mac_type']]) + " has been found at this location:\n"
            else:
                standard_output = "\n\nMAC address " + str(mac_address[command_dictionary[device_type]['mac_type']]) + " has been found at this location:\n"
            standard_output = net_connect.send_command(command_dictionary[device_type]['host'])
            standard_output += net_connect.send_command(command_dictionary[device_type]['mac_table'] + mac_address[command_dictionary[device_type]['mac_type']])
            print(standard_output)
        else:
            if 'ip' in session_values:
                logg_output += "\n\nIP address " + str(session_values['ip']) + " MAC address " + str(mac_address[command_dictionary[device_type]['mac_type']]) + " has been found at this location:\n"
            else:
                logg_output += "\n\nMAC address " + str(mac_address[command_dictionary[device_type]['mac_type']]) + " has been found at this location:\n"
            print("Sending command: " + str(command_dictionary[device_type]['host']))
            logg_output += net_connect.send_command(command_dictionary[device_type]['host'])
            print("Sending command: " + str(net_connect.send_command(command_dictionary[device_type]['mac_table'] + mac_address[command_dictionary[device_type]['mac_type']])))
            logg_output += net_connect.send_command(command_dictionary[device_type]['mac_table'] + mac_address[command_dictionary[device_type]['mac_type']])

    #Handle logging
    if session_values['log_output']:
            outfile = open(session_values['output_file'], 'a')
            outfile.write(logg_output) 
    if session_values['verbose']:
        print(logg_output) 

def regex_search(expression,str_in):
    try:
        search_results = re.search(expression,str_in)
        return search_results.group()
    except:
        if session_values['verbose']:
            print("Not found in regex_search: expression: " + str(expression) + "\nstr_in: " + str(str_in))
        return None

def regex_findall(expression,str_in):
    try:
        search_results = re.findall(expression,str_in)
        return search_results
    except:
        if session_values['verbose']:
            print("Not found in regex_findall: expression: " + str(expression) + "\nstr_in: " + str(str_in))
        return None

if __name__=='__main__':
    #Parses input
    input_parser()
    
    #Launch main if verbose is disabled
    if not session_values['verbose']:
        try:
            main()
        except Exception as exc:
            print("\nAn exceptoin was raised.\n" + str(exc))

    #Launch main. Disabels error handling
    else:
        main()