import os.path
import argparse
import subprocess
import sys
import os
import time
import errno
import array
import re
#
# Author: Andy Marks
#
# Date: 07/19/15
#
# Function:  Reformat nmap output as one row per combination of
# IP address / Protocol Type (TDP/UDP) / Port Status / Port Number.
# Importing this format into a spreadsheet, pivot tables can 
# be used to quickly create a wide variety of report formats.
#
def is_valid_file(parser, arg):
    if not os.path.exists(arg):
        parser.error("The file %s does not exist!" % arg)
    else:
        return open(arg, 'r')  # return an open file handle
#
def process_exists(tst):
    """Check whether pid exists in the current process table."""
    retcode = tst.poll()
    if retcode is None:
       return True
    else:
       return False

#
###############################################################
#
# Begin ---->>> get_running_processes <<<-----
#
def get_running_processes():
#
    running_processes = 0
    for s in process_array:
        if process_exists(s):
           running_processes = running_processes + 1
    return running_processes
#
# End End End ---->>> get_running_processes <<<-----
#
###############################################################
#
# Begin ---->>> Main program <<<-----
#
# The debugf flag essentially displays trace messages to aid in
# troubleshooting.  It must be 'yes' to show the messages.
#
parser = argparse.ArgumentParser()
parser.add_argument("-i", "--inputfile", dest="filename", # required=True,
                    help="Input file with IP addresses, one per line. Default name is target_addresses.txt",
                    metavar="FILE",
                    type=lambda x: is_valid_file(parser, x), default='target_addresses.txt')
parser.add_argument("-s", "--sleep", help="Amount of time in seconds to sleep between status checks",
                    nargs='?', const=10, type=int, default=10)
parser.add_argument("-c", "--concurrent", help="Maximum number of concurrent processes allowed",
                    nargs='?', const=3, type=int, default=3)
parser.add_argument("-d", "--debug", help="Show debug messages",action="store_true")
args = parser.parse_args()

max_concurrent_scans = args.concurrent
sleep_seconds = args.sleep
file = args.filename
if args.debug:
   debugf = 'yes'
else:
   debugf = 'no'
if debugf == 'yes':
   print 'File: '+str(args.filename)
   print 'Print debug messages: '+debugf
   print 'Sleep '+str(sleep_seconds)+' seconds between status checks.'
   print 'Maximum concurrent scans: '+str(max_concurrent_scans)

# All processes are stored in process_array just after they are started.
# This allows for checking if it is still running. We count the number
# of processes in the following variable.                                      
#
file = open('target_addresses.txt', 'r')

ip_array = []
for line in file:
   ip_array.append([str(line).rstrip()])

if debugf == 'yes':
   print ip_array

#####################################################################
#
# Beginning of process execution and throttling loop.
#
process_array = []
running_scans = 0
if max_concurrent_scans > len(ip_array):
   max_concurrent_scans = len(ip_array)

while running_scans > 0 or len(ip_array) > 0:
   if running_scans < max_concurrent_scans:
      number_to_kickoff = max_concurrent_scans - running_scans
      if debugf == 'yes':
         print number_to_kickoff
      if len(ip_array) > 0:
         for startloop in range(0,number_to_kickoff):
            if debugf == 'yes':
               print ip_array[0]
            ip_address = ip_array[0]
            filename='nmap'+(ip_address)[0]+'.txt'
          # p = subprocess.Popen(["nmap", "-T2", "-P0", "-sS", "-sU", "-oG",filename, (ip_address)[0]],
            p = subprocess.Popen(["nmap", "-T3", "-P0", "-sS", "-sU", "-oG",filename, (ip_address)[0]],
            stdout=subprocess.PIPE)
            process_array.append(p);
            del ip_array[0]

   running_scans = get_running_processes()
   print 'Running scans: '+str(running_scans)
  # Sleep for awhile so as not to waste too much system resources rechecking.
   time.sleep(sleep_seconds)
#
# End of process execution and throttling loop.
#
#####################################################################
#
# Beginning the nmap output file consolidation.
#

filenames = os.listdir('.')
content = ''
for f in filenames:
    if f.startswith("nmap") and f.endswith(".txt"):
       content = content + '\n' + open(f).read()
       open('joined_file.txt','wb').write(content)
line_work = [line.strip() for line in open('joined_file.txt')]                 
lines=[]
for r in line_work:
    if re.match("(.*)Port(.*)", r):
       lines.append(r)
       if debugf == 'yes':
          print r

#
# End the nmap output file consolidation.
#
##############################################################
#
# Beginning of main print loop.
#
#   Open the report output file:
#
myfile = open('final.txt', 'w')
#
# One line at a time, we read the lines array and use string functions
# to build the record for final.txt .
#
for s in lines:                                                                
   line = s
   if debugf == 'yes':
      print s

# Working lists for parsing port information.
   port_fields = []
   tcp_ports = []
   openfiltered_udp_ports = []
   open_udp_ports = []

#
# The IP address is parse and stored for later inclusion in the output
# file at the beginning of the line.  The key part of the search method
# is \(\).  The search string is actually looking for (), but the back-
# slash is necessary as an escape character.  Essentially, we are looking
# for (), which occurs on every line in the line array.  The rest of the 
# line, before and after (\(\)) means there can be a string of characters
# before or after the one for which we are searching.
#
   end_of_ip_address = re.search(r"[^a-zA-Z](\(\))[^a-zA-Z]", line).start()
   ip_addr = line[6:end_of_ip_address]
#
# The following code group strips off extraneous information from the
# left and right of the line, leaving only port information.
#
#
   port_pos = re.search(r"[^a-zA-Z](Ports: )[^a-zA-Z]", line).start()
   line_stripped_left = line[port_pos+8:]

   if re.search(r"[^a-zA-Z](Ignored)[^a-zA-Z]",line_stripped_left) is not None:
      right_end_pos = re.search(r"[^a-zA-Z](Ignored)[^a-zA-Z]", line_stripped_left).start()
      line_stripped_lr = line_stripped_left[:right_end_pos-1]                  
   else:
      line_stripped_lr = line_stripped_left
#
# The line has been stripped of extraneous information and only port information remains.
# Those fields are separated by a space, and can be easily stored in an array.
#

   ports = line_stripped_lr.split(" ")
   if debugf == 'yes':
      print ports

#
# The port array populated above is now evaluated, one port at a time, and the UDP and
# TCP port arrays are populated along the way.
#

   for s in ports:
       port_fields_work = s                                                    
       port_fields = port_fields_work.split("/")
       if debugf == 'yes':
          print port_fields
       if port_fields[2]=="tcp":
          tcp_ports.append(port_fields[0])
       if port_fields[2]=="udp" :
          if port_fields[1]=='open|filtered':
             openfiltered_udp_ports.append(port_fields[0])
          else:
             open_udp_ports.append(port_fields[0])
           
   for t in tcp_ports:
      output_line = ip_addr+","+"OPEN"+",TCP,"+str(t.strip())
      myfile.write("%s\n" % output_line)

   for u in open_udp_ports:
      output_line = ip_addr+","+"OPEN"+",UDP,"+str(u.strip())
      myfile.write("%s\n" % output_line)

   for u in openfiltered_udp_ports:
      output_line = ip_addr+","+"OPEN|FILTERED"+",UDP,"+str(u.strip())
      myfile.write("%s\n" % output_line)
#
# End of main print loop.
#
##############################################################
