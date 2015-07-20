nmapthrottle
============

Description
-----------
This Python script scans multiple IP addresses with nmap.  Throttling of scans is done, 3 max processes, one IP address per process, as the default.  This default setting can be changed via command line argument.  The output is meant for import into a spreadsheet for easy pivot table and report creation.   The format is a comma-separated record with

IP Address, Status (OPEN, OPEN|FILTERED), Protocol (TCP/UDP), Port number.

There are other options.  Type the following to see all options.

sudo python nmapthrottle.py -h 

The nmap command is called with the following scan types and flag settings:
-T3 : normal speed
-P0 : skip host discover
-sS : Syn scan, to find TCP ports
-sU : UDP scan

*** Warning:  Use caution when running this program with a large number of IP addresses.  This program starts nmap scans of all IP addresses in parallel.  Too many processes may cause system performance issues including possibly a system crash. ***

Possible changes to be made:
--------
* Addition of optional argument and functionality for host discovery.
* Addition of optional output file name argument.
* Addition of optional speed argument.

Features
--------
* nmap processes run in parallel, saving a large amount of time.  Care must be taken when running in a production environment. If the number of IPs to scan gets into the hundreds and thousands, that may bog down the system considerably or have other adverse ffects.

Instructions
-----
1. Create a directory.
2. Download nmapthrottle.py to the directory.
3. Create a text file called target_addresses.txt containing the IP addresses to be scanned, one IP per line. It should be in the same directory as nmapthrottle.py.  A different filename could be used.  Simply set the -i command line option to set it.
4. Ensure the current directory is this newly created directory by typing pwd.
5. Run the following command: sudo python nmapthrottle.py . It is necessary to run as superuser since a SYN scan flag requires it. As the program runs, it will display the number of nmap scans still running and update it as processes complete. Since a UDP scan is time-consuming, these processes will take more than just a few seconds to complete. I could take half an hour.
6. The resultant file is final.txt .

### Usage
$ python nmapthrottle.py -h
usage: nmapthrottle.py [-h] [-i FILE] [-s [SLEEP]] [-c [CONCURRENT]] [-d]

optional arguments:
  -h, --help                                  show this help message and exit
  -i FILE, --inputfile FILE                   Input file with IP addresses, one per line. Default name is target_addresses.txt
  -s [SLEEP], --sleep [SLEEP]                 Amount of time in seconds to sleep between status checks
  -c [CONCURRENT], --concurrent [CONCURRENT]  Maximum number of concurrent processes allowed
  -d, --debug                                 Show debug messages


Requirements
------------
Linux OS / Python / nmap

Versions tested:

Python: 2.73 (major=2, minor=7, micro=3, releaselevel='final', serial=0)

nmap: 6.46

Linux: 3.14-kali1-686-pae


Copyright and license
---------------------
nmapthrottle is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nmapthrottle is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  

See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nmapthrottle. 
If not, see http://www.gnu.org/licenses/.

Contact
-------
* Andy Marks < ajmarcs at yahoo d0t com >
