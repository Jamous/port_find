# Portfind.py by Jamous Bitrick - Version 1.0
# https://github.com/Jamous/port-find/

'''
TODO:
* Match partial addresses
'''
#Imports
import argparse
import getpass
from multiprocessing.pool import ThreadPool
from netmiko import ConnectHandler
import os
import re

#Import device modules. must be in the same folder as this script.
import ubiquiti_nodes
import cisco_nodes

def main():
    global regex, session_values

    #Create regex object
    regex = regex_class()

    #Create setup object and run setup. Reads commandline inputs and config files. Returns a list of switches, routers, and updates session_values
    setup = session_setup_class()
    switches, routers, session_values, device_types = setup.run()
   
    #Check if ip address
    if session_values['is_ip']:
        ssh.initiate_threads(routers,'find_arp')
    
    #Generate all mac addresses
    mac_parser()

    #Update session_values in device_types
    setup.update_node_objects(session_values,device_types)

    #From here we call initiate_threads in the ssh_class. This is three parts, part 1 initiate_threads will create threads. class_selectror will sellect the appropiate class and method to send the dails too. Then it will be processed in its appropiate file.
    ssh.initiate_threads(switches,'find_mac')

def mac_parser():
    global session_values

    #Convert mac address to Uppercase standard
    if regex.regex_fullmatch('cisco_format',session_values['address']):
        session_values.update({'mac_large': (session_values['address'][0:2] + ":" + session_values['address'][2:4] + ":" + session_values['address'][5:7] + ":" + session_values['address'][7:9] + ":" + session_values['address'][10:12] + ":" + session_values['address'][12:14]).upper()})
    else:
        session_values.update({'mac_large': session_values['address'].upper()})

    #Convert mac address to Lowercase standard
    if regex.regex_fullmatch('cisco_format',session_values['address']):
        session_values.update({'mac_small': (session_values['address'][0:2] + ":" + session_values['address'][2:4] + ":" + session_values['address'][5:7] + ":" + session_values['address'][7:9] + ":" + session_values['address'][10:12] + ":" + session_values['address'][12:14]).upper()})
    else:
        session_values.update({'mac_small': session_values['address'].lower()})
    
    #Convert mac to Cisco standard
    if regex.regex_fullmatch('standard_format',session_values['address']):
        session_values.update({'mac_cisco': (session_values['address'][0:2] + session_values['address'][3:5] + "." + session_values['address'][6:8] + session_values['address'][9:11] + "." + session_values['address'][12:14]  + session_values['address'][15:17]).lower()})
    else:
        session_values.update({'mac_cisco': session_values['address'].lower()})

def class_selectror(node_details):
    #Determins which class to send the connection too. This method is multithreaded by the time you get to it. Select node type and node_details,ssh object and the regex object

    #Select method for find_mac
    if node_details['method_descriptor'] == "find_mac":
        if node_details['device_type'] == 'ubiquiti_edgeswitch':
            #Remove unused node_details and launch the method
            node_details.pop('method_descriptor')
            edgeswitch.find_mac_on_switch(node_details,ssh,regex)
        elif node_details['device_type'] == 'cisco_ios':
            #Remove unused node_details and launch the method
            node_details.pop('method_descriptor')
            cisco.find_mac_on_switch(node_details,ssh,regex)      
    
    #Select method for find_arp
    elif node_details['method_descriptor'] == "find_arp":
        if node_details['device_type'] == 'ubiquiti_edgerouter':
            #Remove unused node_details, launch the method, and update session_values
            node_details.pop('method_descriptor')
            update_dict = edgerouter.find_arp_on_router(node_details,ssh,regex)
            update_session_values(update_dict)
        
        if node_details['device_type'] == 'cisco_ios':
            #Remove unused node_details, launch the method, and update session_values
            node_details.pop('method_descriptor')
            update_dict = cisco.find_arp_on_router(node_details,ssh,regex)
            update_session_values(update_dict)

def update_session_values(update_dict):
    global session_values

    #If didct is not a non type update session_values
    if update_dict:
        session_values.update(update_dict)

class session_setup_class:
    def __init__(self):
        pass

    def run(self):
        #Read input from parser
        self.input_parser()

        #Setup logging and config files
        self.setup_logging_and_config()

        #Readin all switches, routers, and device catagories
        switches, routers, device_types = self.readin_node_configs()

        #Setup objects for individual devices
        self.setup_node_objects(device_types)

        #Return valuse
        return switches, routers, self.session_values, device_types

    def input_parser(self):
        #Parse inputs and save as input_values
        parser = argparse.ArgumentParser(description='Portfind finds what port an IP or MAC address are in a campus lan. This program is located at ' + r'\\biznet\dfs\user\BiznetAdmin\Scripts\portfind' + '. Smiths landing is the default commandline variable.')
        #default parameters
        parser.set_defaults(location='default', is_ip=False, exception_file=False, output_file=False, number=10, verbose=False, thread_count=None) #Set default values
        #Location parameters
        location_group = parser.add_mutually_exclusive_group() #Define mutally exclusive groups. You can add multiple groups here.
        location_group.add_argument('-h', '--host', dest='location', action='store_const', const='default', help='Search default config file for this IP or MAC address. (Default)') #Parse Smiths Landing
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
        self.session_values = vars(parser.parse_args())
        
        #Raise an error if address has not ben input.
        if not self.session_values['address']:
            parser.print_help()
            print("\n[-] Please specify a MAC or IP address to search for.\nEx. portfind 4C:ED:FB:8F:6A:74")
            exit()
        
        #Check if valid IP address has been input. If it has set is_ip to true
        elif regex.regex_search('ip_format',self.session_values['address']):
            #Check if IP address is valid
            ip_1, ip_2, ip_3, ip_4 = regex.regex_findall('ip_octect',self.session_values['address'])
            if int(ip_1) < 256 and int(ip_2) < 256 and int(ip_3) < 256 and int(ip_4) < 256:
                self.session_values.update({'is_ip': True})
            else:
                parser.print_help()
                print("\n[-] Invalid IP address " + str(self.session_values['address']) + " \nPlease specify a MAC or IP address to search for.\nEx. portfind 4C:ED:FB:8F:6A:74")
                exit()

        #Check if valid MAC address has been input
        else:
            if regex.regex_fullmatch('standard_format',self.session_values['address']):
                pass
            elif regex.regex_fullmatch('cisco_format',self.session_values['address']):
                pass
            else:
                parser.print_help()
                print("\n[-] Invalid MAC address " + str(self.session_values['address']) + " \nPlease specify a MAC address to search for.\nEx. portfind 4C:ED:FB:8F:6A:74")
                exit()
    
    def setup_logging_and_config(self):  
        #Set filepaths to alwasy querry the script directory
        script_directory = os.path.dirname(__file__)

        #Default log positions
        output_file =  os.path.join(script_directory, 'log/output.txt')
        exception_file =  os.path.join(script_directory, 'log/exceptions.txt')

        #Default hostfile locations
        default_host = os.path.join(script_directory, 'etc/host.txt')

        #Update host list, device type and mac address. You can add more here later
        if self.session_values['location'] == 'default':
            self.session_values.update({'host_file': default_host})

        #Settup logging values
        self.session_values.update({'log_output': False})
        self.session_values.update({'log_exception': False})

        #Enable everything if verbose mode is active
        if self.session_values['verbose']:
            if self.session_values['output_file'] == False or self.session_values['output_file'] == None:
                self.session_values['output_file'] = output_file
            if self.session_values['exception_file'] == False or self.session_values['exception_file'] == None:
                    self.session_values['exception_file'] = exception_file
            self.session_values.update({'log_output': True})
            self.session_values.update({'log_exception': True})   
            
        #Enable only options selected if verbose mode is active
        else:
            #Check if output file has been enabled, but no filename was given    
            if self.session_values['output_file'] == None:
                self.session_values['output_file'] = output_file
                self.session_values.update({'log_output': True})
            #Check if outputfile was enabeled and a filename was given
            elif self.session_values['output_file'] != False:
                self.session_values.update({'log_output': True})
            
            #Check if exceptions file has been enabled, but no filename was given 
            if self.session_values['exception_file'] == None:
                self.session_values['exception_file'] = exception_file
                self.session_values.update({'log_exception': True})
            #Check if outputfile was enabeled and a filename was given
            elif self.session_values['exception_file'] != False:
                self.session_values.update({'log_exception': True})     

    def readin_node_configs(self):
        switches = [] #List of switches. Defined with config command !
        routers = [] #List of routers. Defined with config command !
        device_type =  None #Used by Netmiko for connections
        device_types = [] #List of device types used by Netmiko. Used to create objects for the respecitve devices. 
        device_catagory = None #Used to define a device as a router or switch (you can add more here). Currently accepts switch and router

        #Get username and password
        username, password = self.get_credentials()

        #Open list of clients and read. 
        # '#' denotes a comment
        # '!' denotes a device catagory - Used by this script. Accepts switch and router
        # '~' denotes a device type - Used by nemiko
        # '*' denotes a new password. A name can be given after this password also   
        host_list = open (self.session_values['host_file'])

        for line in host_list:
            try: 
                config_line = line.strip()

                #Ignore comments and empty lines
                if config_line == "" or config_line[0] == "#":
                    pass

                #Define device_catagory
                elif config_line[0] == "!":
                    device_catagory = config_line[1:]
                
                #Define device_type
                elif config_line[0] == "~":
                    device_type = config_line[1:]
                    device_types.append(config_line[1:])
                
                #Define new password
                elif config_line[0] == "*":
                    print("\nNew username and password for " + str(config_line[1:]))
                    username, password = self.get_credentials()
                
                #Add new address to its respective group. (These values are used by netmiko), replaces ssh_dictionary
                elif config_line != "":
                    #Assign to appropiate lists
                    if device_catagory == "switch":
                        switches.append({'device_type': device_type, 'host': config_line,  'username': username, 'password': password})
                    elif device_catagory == "router":
                        routers.append({'device_type': device_type, 'host': config_line,  'username': username, 'password': password})

            except Exception as exc:
                if self.session_values['verbose']:
                    print("Could not read from file " + host_list + "\n" + str(exc) + "\nWriting error to " + str(self.session_values['exception_file']))
                    exception_file = open(self.session_values['exception_file'], 'a')
                    exception_file.write("Could not read from file " + host_list + "\n" + str(exc) + "\n\n")
        
        #Return switches and routers lists and device_types lists
        return switches, routers, device_types

    def get_credentials(self):
        #Get username and password
        username = input("Username: ")
        password = getpass.getpass()

        return username, password

    def setup_node_objects(self,device_types):
        global ssh, edgeswitch, edgerouter, cisco

        #Create ssh object
        ssh = ssh_class()

        #Device_types are used by netmiko. Use this method to create an object for each device type.
        if 'ubiquiti_edgeswitch' in device_types:
            #Create object for ubiquity edge switch, pass session_values, ssh, and regex
            edgeswitch = ubiquiti_nodes.ubiquiti_edgeswitch_class(self.session_values)
        
        if 'ubiquiti_edgerouter' in device_types:
            #Create object for ubiquity edge router, pass session_values, ssh, and regex
            edgerouter = ubiquiti_nodes.ubiquiti_edgerouter_class(self.session_values)
        
        if 'cisco_ios' in device_types:
            #Create object for Cisco switch, pass session_values, ssh, and regex
            cisco = cisco_nodes.cisco_ios_class(self.session_values)

    def update_node_objects(self,session_values,device_types):
        #Update node objects
        
        if 'ubiquiti_edgeswitch' in device_types:
            #Create object for ubiquity edge switch, pass session_values, ssh, and regex
            edgeswitch.update_session_values(session_values)
        
        if 'ubiquiti_edgerouter' in device_types:
            #Create object for ubiquity edge router, pass session_values, ssh, and regex
            edgerouter.update_session_values(session_values)
        
        if 'cisco_ios' in device_types:
            #Create object for Cisco switch, pass session_values, ssh, and regex
            cisco.update_session_values(session_values)

class regex_class:
    def __init__(self):
        #Regex search expressions. Contains cisco_format, standard_format, ip_format, ip_octect
        self.regex_dictionary = {
            'cisco_format': '[0-9A-Fa-f]{4}[.][0-9A-Fa-f]{4}[.][0-9A-Fa-f]{4}', #Ex. 4ced.fb8f.6a74
            'standard_format': '[0-9A-Fa-f]{2}[:][0-9A-Fa-f]{2}[:][0-9A-Fa-f]{2}[:][0-9A-Fa-f]{2}[:][0-9A-Fa-f]{2}[:][0-9A-Fa-f]{2}', #Ex. 4C:ED:FB:8F:6A:74 or 4c:ed:fb:8f:6a:74
            'ip_format': '\d?\d?\d[.]\d?\d?\d[.]\d?\d?\d[.]\d?\d?\d',
            'ip_octect': '\d?\d?\d',
        }

    #Regex_search finds the first match to a string and returns it. If no matche is found it returns None.
    def regex_search(self,expression,str_in):
        try:
            if expression in self.regex_dictionary:
                search_results = re.search(self.regex_dictionary[expression],str_in)
            else:
                search_results = re.search(expression,str_in)

            if search_results:
                return search_results.group()
            else:
                return None
        except:
            if session_values['verbose']:
                print("Not found in regex_search: expression: " + str(self.regex_dictionary[expression]) + "\nstr_in: " + str(str_in))
            return None

    #Regex_findall finds all matches to a string and returns them. If no matches are found it returns None.
    def regex_findall(self,expression,str_in):
        try:
            if expression in self.regex_dictionary:
                search_results = re.findall(self.regex_dictionary[expression],str_in)
            else:
                search_results = re.findall(expression,str_in)
            return search_results
        except:
            if session_values['verbose']:
                print("Not found in regex_findall: expression: " + str(self.regex_dictionary[expression]) + "\nstr_in: " + str(str_in))
            return None

    #Regex_fullmatch Matches patters in the string. It only matches against the entire string. If the string does not match it returns None.
    def regex_fullmatch(self,expression,str_in):
        try:
            if expression in self.regex_dictionary:
                search_results = re.fullmatch(self.regex_dictionary[expression],str_in)
            else:
                search_results = re.fullmatch(expression,str_in)
            return search_results
        except:
            if session_values['verbose']:
                print("Not found in regex_fullmatch: expression: " + str(self.regex_dictionary[expression]) + "\nstr_in: " + str(str_in))
            return None

class ssh_class:
    def __init__(self):
        pass
    
    def initiate_threads(self,node_details,method_descriptor):
        for node in node_details:
            node.update({'method_descriptor': method_descriptor})

        #Create multiple threads and try to connect. Threads can be limited
        if session_values['thread_count'] == None:
            thread = ThreadPool(len(node_details))
        else:
            thread = ThreadPool(session_values['thread_count'])
        thread.map(class_selectror,node_details)
        thread.close()
        thread.join()

    def start_ssh_connection(self,node_details):
        #Node details: [device_type,host,username,password]
        try:
            net_connect = ConnectHandler(**node_details)
            
            #Handle logging
            if session_values['log_output']:
                printable_output = "Successful connection! IP address: " + str(node_details['host']) + " Device type: " + str(node_details['device_type']) + " Username: " + str(node_details['username'])
                outfile = open(session_values['output_file'], 'a')
                outfile.write(printable_output)   
                if session_values['verbose']:
                    print(printable_output)    

            #Send to net_connect to SSH commands.             
            return net_connect
        
        except Exception as exc:
            if session_values['verbose']:
                print("There was an exception on host " + node_details['host'] + "\n" + str(exc))
            if session_values['log_exception']:
                exception_file = open(session_values['exception_file'], 'a')
                exception_file.write("There was an exception on host " + node_details['host'] + "\n" + str(exc) + "\n\n")

if __name__=='__main__':
    try:
        main()
    except Exception as exc:
        print("\nAn exceptoin was raised.\n" + str(exc))