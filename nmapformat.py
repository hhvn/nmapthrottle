import subprocess
import os
import time
import errno
import array
#
# *** Incomplete program ***
#
# Author: x1x
# 
# Date: 10/04/14
#
# Description:  Typically, a penetration test report will 
# contain a list of active hosts and ports.   In this instance, 
# ports of types TCP and UDP will be listed.
#
# Requirements: Linux OS / Python / nmap
#
# Versions tested: 
#  Python: 2.73 (major=2, minor=7, micro=3, releaselevel='final', serial=0)
#  nmap:   6.46
#  Linux:  3.14-kali1-686-pae (debian-kernel@lists.debian.org) 
#                            (gcc version 4.7.2 (Debian 4.7.2-5) ) #1 SMP Debian 3.14.4-1kali1 (2014-05-14)
#  
# Instructions:
#
# 1. Create a directory.
# 2. Download format.py to the directory.
# 3. Create a text file called target_addresses.txt containing 
#    the IP addresses to be scanned.
# 4. Run the following command: sudo python nmapformat.py
#    It is necessary to run as superuser since a SYN scan flag
#    requires it.
#
#    The program will display the number of nmap scans still 
#    running and update it as processes complete.  Since a UDP
#    scan is time-consuming, these processes will take more 
#    than just a few seconds to complete.  
#    
# 6. The resultant file is nmapformat.txt . *** INCOMPLETE AS OF 10/5/14 ***
#
# Details:  This program will start nmap for each IP in the 
# target_addresses.txt file.  The flags for nmap are:
#
# -P0 : Host discovery is disabled to save time.
# -sS : Syn scan is optimal for determination of open TCP ports
# -sU : This lengthens the duration of the scan but is necessary
#       for a complete penetration test report.
# -oG : This flag specifies an output file format which is
#       easier to reformat to more easily integrate with the 
#       penetration test report.                                                                                                                                                                                  

def process_exists(tst):
    """Check whether pid exists in the current process table."""
    retcode = tst.poll()
    if retcode is None:
       return True
    else:
       return False

running_processes = 0
# All processes are stored in process_array just after they are started.
# This allows for checking if it is still running.
process_array = []
file = open('target_addresses.txt', 'r')

for line in file:
   filename='nmap'+str(line.strip())+'.txt'
   p = subprocess.Popen(["nmap", "-P0", "-sS", "-sU", "-oG",filename, str(line)],
   #p = subprocess.Popen(["nmap", "-P0", "-sS", "-sU", "-oG","nmap"+str(line)+".txt", str(line)],
   stdout=subprocess.PIPE)
   process_array.append(p);
   running_processes += 1
   sv_running_processes = 0
   sv_running_processes == running_processes

while running_processes > 0:
  # Sleep for awhile so as not to waste too much system resources rechecking.
    time.sleep(5)
  # Computer the number of processes by looking at all the processes stored in the process_array
  # structure.  The format of that object is defined in the subprocess module.
    running_processes = 0
    for s in process_array:    
        if process_exists(s):
           running_processes = running_processes + 1

    if sv_running_processes != running_processes:
    # If the number of running processes has changed, display the value on the screen.
       print 'Number of running Processes: '+str(running_processes)
       sv_running_processes = running_processes

#
# All nmap processes are now complete and the results are stored as individual files for
# each IP.  To ease the reformatting process, they will now be recombined.
#
filenames = os.listdir('.')
content = ''                                                                                                                                                                                                      
for f in filenames:
    if f.startswith("nmap") and f.endswith(".txt"):
       content = content + '\n' + open(f).read()
       open('joined_file.txt','wb').write(content)
#
# The parsing of the resultant file is not complete.  Work continues on this.
#

# Incomplete:  See the file called joined_file.txt for the partial results.
