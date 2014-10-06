import subprocess
import os
import time
import errno
import array
import re
#
# Author: x1x
# 
# Date: 10/04/14
#
# Description:  Typically, a penetration test report will 
# contain a list of active hosts and ports.   In this instance, 
# ports of types
# TCP and UDP will be listed.
#
# Requirements: Linux OS / Python / nmap
# Versions tested: *&*&
#
#
# Instructions:
#
# 1. Create a directory.
# 2. Download format.py to the directory.
# 3. Create a text file called target_addresses.txt containing 
#    the IP addresses to be scanned.
# 4. Ensure the current directory is this newly created directory
#    by typing pwd.
# 5. Run the following command: sudo python nmapformat.py
#    It is necessary to run as superuser since a SYN scan flag
#    requires it.
#
#    The program will display the number of nmap scans still 
#    running and update it as processes complete.  Since a UDP
#    scan is time-consuming, these processes will take more 
#    than just a few seconds to complete.  
#    
# 6. The resultant file is final.txt .
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
# The resultant file is called final_file.txt . The parsing and file writes
# are below.   Exception handling and modular programming was secondary while
# coding this section but it will be improved.
#
lines = [line.strip() for line in open('joined_file.txt')]

myfile = open('final.txt', 'w')
for s in lines:
   print 'Line: '+s
   tcp_ports = []
   udp_ports = []
   port_fields = []
   line = s
   end_of_ip_address = re.search(r"[^a-zA-Z](\(\))[^a-zA-Z]", line).start()
   ip_addr = line[7:end_of_ip_address]

   port_pos = re.search(r"[^a-zA-Z](Ports: )[^a-zA-Z]", line).start()
   line_stripped_left = line[port_pos+8:]

   print 'LSL: '+line_stripped_left

   if re.search(r"[^a-zA-Z](Ignored)[^a-zA-Z]",line_stripped_left) is not None:
      right_end_pos = re.search(r"[^a-zA-Z](Ignored)[^a-zA-Z]", line_stripped_left).start()
      line_stripped_lr = line_stripped_left[:right_end_pos-1]
   else:
      line_stripped_lr = line_stripped_left
   print 'LSLR: '+line_stripped_lr
   ports = line_stripped_lr.split(" ")
   print ports
   for s in ports:
       port_fields_work = s
       port_fields = port_fields_work.split("/")
       print port_fields
       if port_fields[2]=="udp":
          udp_ports.append(port_fields[0])
       if port_fields[2]=="tcp":
          tcp_ports.append(port_fields[0])

   output_line = ip_addr
   firsttcp = 'yes'                                                                                                                                                                                               
   for t in tcp_ports:
      if firsttcp == 'yes':
         output_line = output_line+' TCP:'                                                                                                                                                                        
         firsttcp = 'no'
      else:
         output_line = output_line+', '
      output_line = output_line+" "+t.strip()

   firstudp = 'yes'
   for u in udp_ports:
      if firstudp == 'yes':
         output_line = output_line+' UDP: '
         firstudp = 'no'
      else:
         output_line = output_line+', '
      output_line = output_line+u.strip()+" "

   #var1, var2 = output_line.split(",")
   myfile.write("%s\n" % output_line)

myfile.close()
