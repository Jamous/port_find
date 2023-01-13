Port-find
----------
Version 1.0
Port-find is a multithreaded python program that will search a lan network for a specific MAC or IP address. The goal of this project is to simplify finding what port a MAC or IP address is connected to in a large campus lan network.

Dependincies
------------
* Netmiko

Features
--------
* Can run simultaneously on multiple devices from different vendors.
* Uses multithreading by default. To disable multithreading set thread_count to using --thread_count 1
* Will accept MAC addresses or IP adresses in any of these four common formants:
    * 123.123.123.123 
    * A1:B2:C3:D4:E5:F6
    * a1:b2:c3:d4:e5:f6
    * a1b2.c3d4.e5f6 (Cisco standard)
* Can work with partial MAC or IP addresses. 
* Supports password groups: If you have multiple devices with diffrent credentials in your hosts file you can now elect to use password groups. The default is None, however devices in diffrent password groups can use diffrent usernames and passwords.

Usage
-----
By default Port-find search will use etc/hosts.txt as its config file. the default usage can be seen below. 
```
python.exe ./portfind.py a1:b2:c3:d4:e5:f6 
```
For more advanced usage please see the help file.
```
python.exe ./portfind.py --help
```

Host config files
-----------------
Config files are stored in etc/.
Each config file contains a list of switch addresses (IP or FQDN) that should be queried by Port-find. Order is not required. There can be multiple config files for multiple sites. Config files are user definable, however the default is etc/hosts.txt

‘#’ at the beginning of a line denotes a comment in the config file. This is the address the program will try to initate an SSH connection from.

‘~’ at the beginning of a line denotes a device type in the config file. Every address below this statement will be assumed to be of the device type listed in the config file. You can change device types at any time during the script.

‘!’ at the beginning of a line denotes node type. The script currently supports switches 'switch' and routers 'router'

‘*’ denotes a diffrent password will be used. You can add a name here '*My second password'. This will be displayed when you are prompted for the new password

Standard config file example:
```
#hosts.txt config file
!router
~ubiquiti_edgerouter
10.0.0.1

!switch
~ubiquiti_edgeswitch
10.0.0.10
10.0.0.11
```

Config file example using every option:
```
#hosts.txt config file
#These devices are treated as Ubiquity edge switches
!switch
~ubiquiti_edgeswitch
10.0.0.10
10.0.0.11

#These devices are treated as Cisco routers
~cisco_ios
!router
10.0.0.1

#This device is treated as a cisco switch with a diffrent set of login credentials
!switch
~cisco_ios
10.0.0.2
```

Verbose mode and logging
------------------------
* Verbose mode is enabled with -v. This will give information about every device connected too and every match found. Verbose mode enables output logging and exception logging.
* Logging: Logging can either be enabled by turning on verbose mode, or by activating the log below. There are two logs:
    * Output log: Enabled with --output this option will log all onscreen messages. If no logfile is specified it will use the default of log/output.txt.
    * Exception log: Enabled with --exceptions this option will log all exception messages (usually only seen in verbose mode). If no exceptions file is specified it will use the default of log/exceptions.txt.


Currently supported vendors
---------------------------
This project uses Netmiko to create SSH connections. Currently only end devices supported by Netmiko are supported. The currently implemented supported devices are:
* Cisco IOS switches and routers (cisco_ios)
* Ubiquity Edge Routers (ubiquiti_edgerouter)
* Ubiquity Edge Max switches (ubiquiti_edgeswitch)

