import csv, os, sys, socket, re, string, traceback, argparse
from _winreg import *
# from Tkinter import *
from datetime import *
import time
# import tkFileDialog, tkMessageBox
import win32evtlog
import win32evtlogutil
import win32security
import win32con
import winerror

 
parser = argparse.ArgumentParser(description='Options to run.')
parser.add_argument('-V', dest='vlevel', action='store', default = 0, help = "Level of verbosity: 0 - None, 1 - Minimum, 2 - Maximum")
parser.add_argument('-d', dest='history', action='store', default = 7, help = "On each suspected machine, how far in the past do you want to search? (# days)")
parser.add_argument('-sb', dest='bbs', action='store', default = "y", help = "If a permitted device is found, skip analysis AND do not log : y - Skip/Do NOT log if found, n - Do NOT skip/Log if found")
 
args = parser.parse_args()
 
print "Program written by Craig L. Bowser"
print "USB analysis from HBSS report on 1157 alerts, version 10"
print "\n"
print "You have chosen the following options: "
print "Verbosity Level: ", args.vlevel
print "Days in the past to search: ", args.history
print "Skip permitted devices: ", args.bbs
print "\n"
print "For help and other executable options type usbcheck1.py -h"
print "\n"
 
# root = Tk()
# root.withdraw() #hiding tkinter window
 
def date2sec(evt_date):
    '''
    This function converts dates with format
    '12/23/99 15:54:09' to seconds since 1970.
    '''
    regexp=re.compile('(.*)\\s(.*)') #store result in site
    reg_result=regexp.search(evt_date)
    date=reg_result.group(1)
    the_time=reg_result.group(2)
    (mon,day,yr)=map(lambda x: string.atoi(x),string.split(date,'/'))
    (hr,min,sec)=map(lambda x: string.atoi(x),string.split(the_time,':'))
    tup=[yr,mon,day,hr,min,sec,0,0,0]
 
    sec=time.mktime(tup)
 
    return sec
 
#get date
 
getdate = time.strftime("%d%b%Y%H%M%S", time.localtime())
nameit1 = 'NO_ACCESS_' + getdate
nameit2 = 'USB_ALERT_' + getdate
nameit3 = 'TIME_OUT_' + getdate
 
#print nameit1, nameit2
 
 
socket.setdefaulttimeout(15)
 
 
# create list of devices to skip if found
skipcheck = ['BlackBerry', 'Blackberry', 'CP1518', 'HDT72252']
answers = ['1', '2', '3']
 
print ('do you want to input a single machine or multiple machines from a HBSS csv report?')
print ''
print '1     Single Remote Machine'
print '2     HBSS csv report'
print '3     Local Machine'
print '\nNOTE:  It is imperitive that if you import a csv file, the machine names and/or IP addresses are in the THIRD column!!\n'
choice5 = raw_input ('?    ')
 
 
while choice5 not in answers:
    choice5 = raw_input('Please choose 1, 2 or 3 (ctrl-c or ctrl-break to exit):  ')
 
if choice5 == '1' or choice5=='3':
 
    if choice5=='1':
        machinename1 = raw_input('what is the machine name? ')
        print '\n\n'
        print "Now checking ", machinename1
        machine = "\\\\" + machinename1
        if args.vlevel > 1: print machine
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn = (machinename1, 139)
            if args.vlevel > 1: print conn
            s.connect(conn)
            print 'connect'
        except socket.error, e:
            #output3.write("Timeout when connecting to,, " + machine + "\n")
            print "Timeout when attempting to connect to ", machine
            sys.exit()
        print 'now checking the registry of ', machinename1
        try:
            areg = ConnectRegistry(machine, HKEY_LOCAL_MACHINE)
        except WindowsError:
            #output1.write("No registry accesss to " + machine + "\n")
            print "No registry access to", machine
            sys.exit()

    if choice5=='3':
        machinename1 = "LocalHost"
        print 'now checking the registry of ', machinename1
        try:
            areg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        except WindowsError:
            #output1.write("No registry accesss to " + machine + "\n")
            print "No registry access to", machine
            sys.exit()
    
    try:
        bKey = OpenKey(areg, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
    except WindowsError as (winerror, strerror):
        if winerror == 2: print "The USBSTOR key does not exist on ", machine
        if winerror <> 2: print "No access to HKLM hive on", machine
        sys.exit()
 
    aKey = OpenKey(areg, r"SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")  
    bKey = OpenKey(areg, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
    _FILETIME_null_date = datetime(1601, 1, 1, 0, 0, 0)
 
    xx = 0
 
    try:
        while 1:
            usbname = EnumKey(bKey, xx)
            seek1 = 0
            seek2 = 0
            print "this is the usbname:   " + usbname
            if args.bbs == "y" or args.bbs == "Y" :
                for skips in skipcheck:
                    seek1 = usbname.find(skips)
                    seek2 = seek2 + seek1
            #print seek2
            if seek2 > 0:
                print "found one on list of devices to skip"
                break # skip if device is in the list
            subkey1 = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\" + usbname
            cKey = OpenKey(areg, subkey1)
            yy = 0
            try:
                while 1:
                    usbsubname = EnumKey(cKey, yy)
                    time.sleep(3)
                    zz = 0
                    try:
                        while 1:
                            device = EnumKey(aKey, zz)
                            if usbsubname in device:
                                # clear variables     
                                newtime = None
                                checktime = None                                                                         
                                Subkey2 =  "SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\\" + device
                                dKey = OpenKey(areg, Subkey2)
                                newtime = _FILETIME_null_date + timedelta(microseconds = QueryInfoKey(dKey)[2]/10)
                                print "A device: ", usbname ," was inserted at ", newtime ," into " , machinename1
                                checktime = datetime.today() - timedelta(days=int(args.history))
                                if args.vlevel > 1: print "checktime", usbname ," ", checktime , " " , machinename1
                                if newtime > checktime:
 
                                    #initialize variables
                                    flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
 
                                    #This dict converts the event type into a human readable form
                                    evt_dict={win32con.EVENTLOG_AUDIT_FAILURE:'EVENTLOG_AUDIT_FAILURE',
                                                      win32con.EVENTLOG_AUDIT_SUCCESS:'EVENTLOG_AUDIT_SUCCESS',
                                                      win32con.EVENTLOG_INFORMATION_TYPE:'EVENTLOG_INFORMATION_TYPE',
                                                      win32con.EVENTLOG_WARNING_TYPE:'EVENTLOG_WARNING_TYPE',
                                                      win32con.EVENTLOG_ERROR_TYPE:'EVENTLOG_ERROR_TYPE'
                                              }
                                                       
                                    # print "Now searching security log"
                                    logtype='Security'
                                    begin_sec=time.time()
                                    begin_time=time.strftime('%H:%M:%S  ',time.localtime(begin_sec))
                                    target_low = str(newtime - timedelta(seconds = 5)).split('.')
                                    target_high = str(newtime + timedelta(seconds = 5)).split('.')
 
                                    # try:
                                        # hand=win32evtlog.OpenEventLog(machinename1,logtype)
 
                                        # try:
                                          # events=1
                                          # while events:
                                            # events=win32evtlog.ReadEventLog(hand,flags,0)
                                            # for ev_obj in events:
                                                # #check if the event is between target times
                                                # the_time=ev_obj.TimeGenerated.Format()
                                                # seconds=date2sec(the_time)
                                                # time_tuple_high = time.strptime(target_high[0], "%Y-%m-%d %H:%M:%S")
                                                # timeagain_high = time.mktime(time_tuple_high)
                                                # time_tuple_low = time.strptime(target_low[0], "%Y-%m-%d %H:%M:%S")
                                                # timeagain_low = time.mktime(time_tuple_low)
                                                # if seconds > timeagain_low and seconds < timeagain_high:
                                                # #if seconds < begin_sec-100: sys.exit()
                                                    # usr=(ev_obj.Sid)
                                                    # username, domain, type = win32security.LookupAccountSid(None, usr)
                                                    # if username == 'SYSTEM' or username == 'sluser2' or username == 'NETWORK SERVICE' or username == 'LOCAL SERVICE' or username == 'ANONYMOUS LOGON':
                                                        # continue
                                                    # else:
                                                        # #print username
                                                        # output1 = open("temp.txt", "wb")
                                                        # getusername = 'dsquery.exe * -s DOMAIN-CONTROLLER -filter "(samAccountName='+username+')"'
                                                        # username = subprocess.check_output(getusername)
                                                        # print "This is the username:  ", username
                                                        # fixedusername = username.rstrip('\n')
                                                        # print "This is the fixed username:  ", fixedusername
                                                        # pt1_command = 'dsget user '
                                                        # pt3_command = ' -display -office'
                                                        # output1.write(pt1_command)
                                                        # output1.write(fixedusername[:-1])
                                                        # output1.write(pt3_command)
                                                        # output1.close()
                                                        # print "This is Part 1 of the command:  ", pt1_command
                                                        # print "This is Part 3 of the command:  ", pt3_command
                                                        # output2 = open('temp.txt')
                                                        # full_command = output2.readline()  
                                                        # print 'try this command?  ' + full_command
                                                        # nameandoffice = subprocess.call(full_command)
                                                    # finaltime = str(newtime - timedelta(seconds=time.timezone))
                                                    # if args.vlevel > 1: print 'timeagain high' , timeagain_high
                                                    # print "\n" + usbname, "(", usbsubname, ") was last inserted into or connected to ", machine
                                                    # print "by" , nameandoffice, "on" , newtime - timedelta(seconds=time.timezone)
                                                    # if args.vlevel > 1: print 'timeagain low', timeagain_low
                                                # if seconds < timeagain_high: break #get out of while loop as well
                                          # win32evtlog.CloseEventLog(hand)
                                        # except:
                                          # if args.vlevel > 1: print traceback.print_exc(sys.exc_info())
                                        # #also try and clear out newtime and checktime variables to prevent errors.
                                        # #check to see if already closed
                                        # try:
                                            # win32evtlog.CloseEventLog(hand)
                                        # except:
                                            # time.sleep(0)
                                    # except:
                                        # print "No permissions to " + machine
                                        # time.sleep(10)
                            zz += 1
                    except WindowsError:
                        time.sleep(0)
                    yy += 1
            except WindowsError:
                time.sleep(0)
            xx += 1
    except WindowsError:
        time.sleep(0)
    print "Finished with", machinename1
    #print "now close socket"
    if choice5 == '1': s.close()
    # output1.close()
    # output2.close()
    # output3.close()
    # output4.close()
 
if choice5 == '2':
 
    # Create output files
    output1 = open(nameit1 + ".txt", "w")
    output2 = open(nameit2 + ".txt", "w")
    output3 = open(nameit3 + ".csv", "wb")
    output4 = open("USB_Found_Tracker-" + getdate + ".csv", 'wb')
    totalcnt = 0
    # ask for HBSS CSV report file name
    file_input_names = tkFileDialog.askopenfilenames(title='Open file', filetypes=[('csv files', '*.csv')])
 
    InputfilesList =  root.tk.splitlist(file_input_names)
 
 
    #print "got input file names"
    print InputfilesList
 
    # create list for machine names so we can weed out duplicates
 
    listofpcs = []
 
    for name in InputfilesList:
        print name
        file = open(name)
        reader = csv.reader(file)
        line = 0
        # skip header row
        for rows in reader:
            if line == 0:
                line = line + 1
                continue
            print rows[2]
            print "Now checking", rows[2]
            if rows[2] in listofpcs: continue
            listofpcs.append(rows[2])
            machine = "\\\\" + rows[2]
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                conn = (rows[2], 139)
                if args.vlevel > 1: print conn
                if args.vlevel > 1: output2.write(str(conn))
                if args.vlevel > 1: output2.write(' ' + rows[2] + '\n')
                s.connect(conn)
                if args.vlevel > 1: print 'connect'
                if args.vlevel > 1: output2.write('connected to ' + rows[2] + '\n')
            except socket.error, e:
                output3.write("Timeout when connecting to,, " + rows[2] + "\n")
                if args.vlevel > 1: print "Timeout when attempting to connect to ", rows[2]
                if args.vlevel > 1: output2.write( "Timeout when attempting to connect to " + rows[2] + "\n")
                #print e
                #s.close()
                #time.sleep(10)
                continue
            if args.vlevel > 0: print 'now checking the registry of ', rows[2]
            if args.vlevel > 0: output2.write('now checking the registry of ' + rows[2] + "\n")
            try:
                areg = ConnectRegistry(machine, HKEY_LOCAL_MACHINE)
            except WindowsError:
                output1.write("No registry accesss to " + machine + "\n")
                if args.vlevel > 1: print "No registry access to", machine
                if args.vlevel > 1: output2.write ("No registry access to", machine, "\n")
                continue
            
            try:
                bKey = OpenKey(areg, r"SYSTEM\CurrentControlSet\Enum\USB")
            except WindowsErroras (winerror, strerror):
                if winerror == 2:  
                    if args.vlevel > 1: print "The USBSTOR key does not exist on ", machine
                    if args.vlevel > 1: output2.write("The USBSTOR key does not exist on " + machine + "\n")
                if winerror <> 2:  
                    output1.write("No access to HKLM hive on " + machine + "\n")
                    if args.vlevel > 1: print "No access to HKLM hive on", machine
                    if args.vlevel > 1: output2.write("No access to HKLM hive on" + machine + "\n")
                continue
 
            aKey = OpenKey(areg, r"SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}")  
            try:
                bKey = OpenKey(areg, r"SYSTEM\CurrentControlSet\Enum\USBSTOR")
            except  WindowsError as (winerror, strerror):
                if winerror == 2:  
                    if args.vlevel > 1: print "The USBSTOR key does not exist on ", machine
                    if args.vlevel > 1: output2.write( "The USBSTOR key does not exist on " + machine + "\n")
                if winerror <> 2:  
                    output1.write("No access to HKLM hive on " + machine + "\n")
                    if args.vlevel > 1: print "No access to HKLM hive on", machine
                    if args.vlevel > 1: output2.write( "No access to HKLM hive on" + machine + "\n")
                continue
            _FILETIME_null_date = datetime(1601, 1, 1, 0, 0, 0)
 
            xx = 0
 
            try:
                while 1:
                    usbname = EnumKey(bKey, xx)
                    seek1 = 0
                    seek2 = 0
                    if args.vlevel > 1: print "this is the usbname:   " + usbname
                    if args.vlevel > 1: output2.write("this is the usbname:   " + usbname + "\n")
                    if args.bbs == "y" or args.bbs == "Y" :
                        for skips in skipcheck:
                            seek1 = usbname.find(skips)
                            seek2 = seek2 + seek1
                    #print seek2
                    if seek2 > 0:
                        if args.vlevel > 1:  
                            print "found one on list of devices to skip"
                            output2.write("found one on list of devices to skip\n")
                        break # skip if device is in the list
                    subkey1 = "SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\" + usbname
                    cKey = OpenKey(areg, subkey1)
                    yy = 0
                    try:
                        while 1:
                            usbsubname = EnumKey(cKey, yy)
                            time.sleep(3)
                            zz = 0
                            try:
                                while 1:
                                    device = EnumKey(aKey, zz)
                                    if usbsubname in device:
                                        # clear variables     
                                        newtime = None
                                        checktime = None                                                                         
                                        Subkey2 =  "SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\\" + device
                                        dKey = OpenKey(areg, Subkey2)
                                        newtime = _FILETIME_null_date + timedelta(microseconds = QueryInfoKey(dKey)[2]/10)
                                        print "A device: ", usbname ," was inserted at ", newtime ," into " , rows[2]
                                        if "DGM" == rows[2][0:3]:  # check the name to see if the device is located Down South
                                            output2.write("A device: " +  usbname + " was inserted at " + str(newtime)  + " into " + rows[2] + " but since the device is probably located in the BAY, a connection to the security log will not be attempted.\n")
                                            print "A device: " +  usbname + " was inserted at " + str(newtime)  + " into " + rows[2] + " but since the device is probably located in the BAY, a connection to the security log will not be attempted.\n"
                                            totalcnt += 1
                                            break #get out of while loop as well
                                        checktime = datetime.today() - timedelta(days=int(args.history))
                                        if args.vlevel > 1: print "checktime", usbname ," ", checktime , " " , rows[2]
                                        if args.vlevel > 1: output2.write( "checktime" + usbname  +" " + str(checktime) + " " + rows[2] + "\n")
                                        if newtime > checktime:
 
                                            #initialize variables
                                            flags = win32evtlog.EVENTLOG_BACKWARDS_READ|win32evtlog.EVENTLOG_SEQUENTIAL_READ
 
                                            #This dict converts the event type into a human readable form
                                            evt_dict={win32con.EVENTLOG_AUDIT_FAILURE:'EVENTLOG_AUDIT_FAILURE',
                                                              win32con.EVENTLOG_AUDIT_SUCCESS:'EVENTLOG_AUDIT_SUCCESS',
                                                              win32con.EVENTLOG_INFORMATION_TYPE:'EVENTLOG_INFORMATION_TYPE',
                                                              win32con.EVENTLOG_WARNING_TYPE:'EVENTLOG_WARNING_TYPE',
                                                              win32con.EVENTLOG_ERROR_TYPE:'EVENTLOG_ERROR_TYPE'
                                                      }
                                                               
                                            if args.vlevel > 0: print "Now searching security log"
                                            if args.vlevel > 0: output2.write( "Now searching security log\n")
                                            logtype='Security'
                                            begin_sec=time.time()
                                            begin_time=time.strftime('%H:%M:%S  ',time.localtime(begin_sec))
                                            target_low = str(newtime - timedelta(seconds = 5)).split('.')
                                            target_high = str(newtime + timedelta(seconds = 5)).split('.')
 
                                            try:
                                                hand=win32evtlog.OpenEventLog(rows[2],logtype)
 
                                                try:
                                                  events=1
                                                  while events:
                                                    events=win32evtlog.ReadEventLog(hand,flags,0)
                                                    for ev_obj in events:
                                                        #check if the event is between target times
                                                        the_time=ev_obj.TimeGenerated.Format()
                                                        seconds=date2sec(the_time)
                                                        time_tuple_high = time.strptime(target_high[0], "%Y-%m-%d %H:%M:%S")
                                                        timeagain_high = time.mktime(time_tuple_high)
                                                        time_tuple_low = time.strptime(target_low[0], "%Y-%m-%d %H:%M:%S")
                                                        timeagain_low = time.mktime(time_tuple_low)
                                                        if seconds > timeagain_low and seconds < timeagain_high:
                                                        #if seconds < begin_sec-100: sys.exit()
                                                            usr=(ev_obj.Sid)
                                                            username, domain, type = win32security.LookupAccountSid(None, usr)
                                                            if username == 'SYSTEM' or username == 'sluser2' or username == 'NETWORK SERVICE' or username == 'LOCAL SERVICE' or username == 'ANONYMOUS LOGON':
                                                                continue
                                                            else:
                                                                #print username
                                                                output1 = open("temp.txt", "wb")
                                                                getusername = 'dsquery.exe * -s DOMAINCONTROLLER -filter "(samAccountName='+username+')"'
                                                                username = subprocess.check_output(getusername)
                                                                print "This is the username:  ", username
                                                                fixedusername = username.rstrip('\n')
                                                                print "This is the fixed username:  ", fixedusername
                                                                pt1_command = 'dsget user '
                                                                pt3_command = ' -display -office'
                                                                output1.write(pt1_command)
                                                                output1.write(fixedusername[:-1])
                                                                output1.write(pt3_command)
                                                                output1.close()
                                                                print "This is Part 1 of the command:  ", pt1_command
                                                                print "This is Part 3 of the command:  ", pt3_command
                                                                output2 = open('temp.txt')
                                                                full_command = output2.readline()  
                                                                print 'try this command?  ' + full_command
                                                                nameandoffice = subprocess.call(full_command)#print username, the_time
                                                            finaltime = str(newtime - timedelta(seconds=time.timezone))
                                                            output2.write("On " + finaltime + " I received an alert that an unauthorized USB flash device was connected to ")
                                                            output2.write(machine + ".  This device appears to be a " + usbname + ".  The event itself was associated with user " + nameandoffice + "\n")
                                                            # output2.write(usbname + "(" + usbsubname + ") was last inserted into or connected to " + machine)
                                                            # output2.write(" by " + username + " on " + finaltime + "\n")
                                                            output4.write("," + finaltime + ",,,," + usbname + ",," + nameandoffice + "," + machine + "\n")
                                                            totalcnt += 1
                                                            if args.vlevel > 1: print 'timeagain high' , timeagain_high
                                                            if args.vlevel > 1: output2.write( 'timeagain high' + str(timeagain_high) + '\n')
                                                            print "\n" + usbname, "(", usbsubname, ") was last inserted into or connected to ", machine
                                                            print "by" , nameandoffice, "on" , newtime - timedelta(seconds=time.timezone)
                                                            if args.vlevel > 1: print 'timeagain low', timeagain_low
                                                            if args.vlevel > 1: output2.write( 'timeagain low' + str(timeagain_low) + '\n')
                                                        if seconds < timeagain_high:
                                                            raw_input("check point 0: " + events)
                                                            output2.write("A device: " +  usbname + " was inserted at " + str(newtime)  + " into " + rows[2] + " but the username could not be determined.")
                                                            print "A device: " +  usbname + " was inserted at " + str(newtime)  + " into " + rows[2] + " but the username could not be determined."
                                                            totalcnt += 1
                                                            raw_input("check point 1")
                                                            break #get out of while loop as well
                                                            raw_input("check point 2")
                                                            events = 0
                                                  win32evtlog.CloseEventLog(hand)
                                                except:
                                                  if args.vlevel > 1: print traceback.print_exc(sys.exc_info())
                                                  if args.vlevel > 1: output2.write( str(traceback.print_exc(sys.exc_info())) + '\n')
                                                #also try and clear out newtime and checktime variables to prevent errors.
                                                #check to see if already closed
                                                try:
                                                    win32evtlog.CloseEventLog(hand)
                                                except:
                                                    time.sleep(0)
                                            except:
                                                output2.write("A device: " +  usbname + " was inserted at " + newtime  + " into " + rows[2] + " but the username could not be determined.")
                                                if args.vlevel > 0: print "No permissions to " + machine
                                                if args.vlevel > 0: output2.write( "No permissions to " + machine + "\n")
                                                time.sleep(10)
                                    zz += 1
                            except WindowsError:
                                time.sleep(0)
                            yy += 1
                    except WindowsError:
                        time.sleep(0)
                    xx += 1
            except WindowsError:
                time.sleep(0)
            print "Finished with", rows[2]
        #print "now close socket"
        s.close()
        file.close()
        output1.close()
        output2.close()
        output3.close()
        output4.close()
        print "\nTotal number of machines found with USBs in the last " + str(args.history) + " days: ", str(totalcnt)