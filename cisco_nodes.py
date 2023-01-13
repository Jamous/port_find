class cisco_ios_class:
    #Initalize and take in session_values
    def __init__(self,session_values):
        self.session_values = session_values

    #Update session_values
    def update_session_values(self,session_values):
        self.session_values = session_values

    def find_mac_on_switch(self,node_details,ssh,regex):
        #Usses session_values['mac_cisco'] for mac address
        #Connect to node
        net_connect = ssh.start_ssh_connection(node_details)

        #Actual commands happen here. This checks if net_connect failed
        if net_connect:
            #Send command and read response. Find which port the mac address is on
            command_out = net_connect.send_command("show mac address-table | i  " + self.session_values['mac_cisco'])
            logg_output = command_out

            #Check output and grab the corosponding port number. There should only be one port, this only finds one.
            port = regex.regex_search('[FGT][ie]\d[/\d]+',command_out)
            
            try:
                #Count number of MAC addresses on the interface.
                port_output = net_connect.send_command("show mac address-table int " + port)
                num_on_interface = len(regex.regex_findall('cisco_format',port_output))
            except:
                num_on_interface = 0
                
            if 0 < num_on_interface < self.session_values['number']:
                if not self.session_values['verbose']:
                    if 'ip' in self.session_values:
                        standard_output = "\n\nIP address " + str(self.session_values['ip']) + " MAC address " + str(self.session_values['mac_cisco']) + " has been found at this location:\n"
                    else:
                        standard_output = "\n\nMAC address " + str(self.session_values['mac_cisco']) + " has been found at this location:\n"
                    standard_output = net_connect.send_command("show running-config | include host")
                    standard_output += net_connect.send_command("show mac address-table | i  " + self.session_values['mac_cisco'])
                    print(standard_output)
                else:
                    if 'ip' in self.session_values:
                        logg_output += "\n\nIP address " + str(self.session_values['ip']) + " MAC address " + str(self.session_values['mac_large']) + " has been found at this location:\n"
                    else:
                        logg_output += "\n\nMAC address " + str(self.session_values['mac_large']) + " has been found at this location:\n"
                    print("Sending command: show running-config | include host")
                    logg_output += net_connect.send_command("show running-config | include host")
                    print("Sending command: show mac-addr-table " + str(self.session_values['mac_large']))
                    logg_output += net_connect.send_command("sshow mac address-table | i  " + self.session_values['mac_cisco'])

            else:
                    logg_output = "net_connect failed. node_details: " + str(node_details)

        #Handle logging
        if self.session_values['log_output']:
                outfile = open(self.session_values['output_file'], 'a')
                outfile.write(logg_output) 
        if self.session_values['verbose']:
            print(logg_output) 

    def find_arp_on_router(self,node_details,ssh,regex):
        #Usses session_values['mac_cisco'] for mac address
        net_connect = ssh.start_ssh_connection(node_details)
        
        #Actual commands happen here. This checks if net_connect failed
        if net_connect:
            #Get arp address from router
            command_out = net_connect.send_command("show ip arp | i " + self.session_values['address'])
            logg_output = command_out

            #Check if a mac address was returned
            if command_out == "":
                if self.session_values['verbose']:
                    print("\n\nIP address " + str(self.session_values['address']) + " is not present on router " + str(node_details['host']) + ". Exiting")
                if self.session_values['log_exception']:
                    print("Writing host ip address to " + str(self.session_values['exception_file']))
                    exception_file = open(self.session_values['exception_file'], 'a')
                    exception_file.write("\n\nIP address " + str(self.session_values['address']) + " is not present on router " + str(node_details['host']) + ". Exiting")
                exit()

            #strip out arp address
            mac_address = regex.regex_search('cisco_format',command_out)
            
            #Update IP address and mac address
            update_dict = {'address': mac_address, 'ip': self.session_values['address']}

        else:
            logg_output = "net_connect failed. node_details: " + str(node_details)
            update_dict = None

        #Handle logging
        if self.session_values['log_output']:
            outfile = open(self.session_values['output_file'], 'a')
            outfile.write(logg_output)   
            if self.session_values['verbose']:
                print(logg_output)   

        return update_dict
