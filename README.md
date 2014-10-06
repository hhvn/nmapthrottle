nmapformat
============

Description
-----------
This Python script scans multiple IP addresses with nmap and pretty's up the output.

Based on a list of IP addresses the user populates in a text file, this program performs Nmap udp and syn scansby pretty formatting of results which can more easily be integrated into a penetration test report.   The nmap scans run in parallel. The number of processes still running displays on the screen.  If a process or two is not completing, get the pid and kill it with:

sudo ps -A|grep nmap

kill -9 *pid*

Warning:  Use caution when running this program with a large number of IP addresses.  This program starts nmap scans of all IP addresses in parallel.  Too many processes may cause system performance issues including possibly a system crash.

Changes to be made:
Addition of a separate UDP port category called 'open|filtered', to more accurately represent UDP port states.  At this time  'open|filtered' and 'open' UDP ports are grouped together.
Modularization of code by addition of functions, and review/implementation of Python best practices

Considered changes for future:  
Host discovery may be integrated into this script using tools such as fing.  It'll basically automate the generation of the target IP address file.
Addition of options:  The ability to skip the scans and go straight to the formatting of results from a previous scan; a maximum scan time parameter, to allow for an abort after a set time period.  I have seen at least one case where a scan never finished and I had to kill its process.

Features
--------
* nmap processes run in parallel, saving a large amount of time.  Care must be taken when running in a production environment.  If the number of IPs to scan gets into the hundreds and thousands, that may bog down the system considerably or have other adverse ffects.

Usage
-----
1. Create a directory.
2. Download format.py to the directory.
3. Within the new directory, create a text file called, target_addresses.txt, containing the IP addresses to be scanned.
4. Ensure the current directory is this newly created directory.
5. Run the following command:  sudo python nmapformat.py
7. The resultant file is nmapformat.txt .

### Options
None

Requirements
------------
Linux OS / Python / nmap

Versions tested:

Python: 2.73 (major=2, minor=7, micro=3, releaselevel='final', serial=0)

nmap: 6.46

Linux: 3.14-kali1-686-pae


Copyright and license
---------------------
nmapformat is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

nmapformat is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  

See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with nmapformat. 
If not, see http://www.gnu.org/licenses/.

Contact
-------
* Andy Marks < ajmarcs at yahoo d0t com >
