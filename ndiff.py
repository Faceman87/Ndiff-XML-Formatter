#openIP is an IP/port scanner for Synovus Information Security
#Copyright 2013 Synovus
#Created by: Christopher Gaines / Info Security Analyst I
#Modified on: Aug-27-2013

#This program is a regular expression formatter for openIP
#Used to create an easy to read format of the ndiff results from openIP.sh

import sys
sysCheck = sys.version
if (sysCheck[:3] < 2.5):
        sys.exit("Upgrade Python to 2.5 or higher, this version does not have SQlite")
import sqlite3, os, re, time, logging, datetime, fileinput, subprocess, functools, itertools
from subprocess import Popen, call
import subprocess as sp
#ConfigParser is all lower case in Python versions 3.2 +
from datetime import timedelta, date
from itertools import chain

#Today's date
today = datetime.datetime.now()

#Today in YYYYMMDD format for reading (ndiffYYYYMMDD.txt) files
todayYMD = today.strftime("%Y%m%d")
yesterdayYMD = today - datetime.timedelta(days=1)
yesterdayYMD = yesterdayYMD.strftime("%Y%m%d")
#todayYMD = "20140322"
#yesterdayYMD = "20140321"

#create file name for Today's ndiff File to be Formatted
ndiff_File = 'ndiff' + todayYMD + '.xml'

ndiff_File_Location = "/home/stikman1/openip/Scans/" + ndiff_File
database = "/home/stikman1/openip/Results/openIPdb.db"
ndiffResultsFile = "/home/stikman1/openip/Results/" + "ndiffResults-" + todayYMD + ".txt"
logFile = "/home/stikman1/openip/logs/log-" + todayYMD + ".txt"
ipFile = "/home/stikman1/openip/openIP.list"

#open all files for read or appending
printResults = open(ndiffResultsFile, 'a+')
log = open(logFile, 'a+')
listIPs = open(ipFile, 'r')

#List all IPs scanned
print("IP's Scanned:\n")
printResults.write("IP's Scanned:\n")
for p in listIPs:
        printer = p
        print(printer)
        printResults.write(printer)
printResults.write("\n")

#=========================================================================================================================================================================================================
#                    SETUP DATABASE FILE
#=========================================================================================================================================================================================================      
#Creates database if it doesn't exist

if not os.path.isfile(database):
        logReportDB = "Database doesnt exist... Creating it... '\n'"
        print (logReportDB)
        log.write(logReportDB)


        #isolation_level = NONE turns off auto commit, so we don't slow down the indexing
        dbconn = sqlite3.connect(database, isolation_level = None)
        dbconn.execute('PRAGMA foreign_keys = on')
        dbconn.execute('PRAGMA auto_vacuum = 1')
        dbconn.execute('PRAGMA synchronous = OFF')
        crsr = dbconn.cursor()
        dbconn.execute('PRAGMA auto_vacuum = 1')
        dbconn.execute('PRAGMA synchronous = OFF')
        crsr = dbconn.cursor()

        crsr.execute('''CREATE TABLE IP (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_Num BLOB, status BLOB, UNIQUE (ip_Num))''')
        crsr.execute('''CREATE TABLE PORT (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_Num_Id INTERGER, port INTEGER, status BLOB, FOREIGN KEY(ip_Num_Id) REFERENCES IP(id))''')

        print ("OpenIP database was created '\n'")
        log.write("OpenIP database was created '\n'")
else:

        dbconn = sqlite3.connect(database, isolation_level = None)
        dbconn.execute('PRAGMA foreign_keys = on')
        dbconn.execute('PRAGMA synchronous = OFF')
        crsr = dbconn.cursor()
 
        crsr.execute("DROP TABLE PORT")
        crsr.execute("DROP TABLE IP")
        crsr.execute('''CREATE TABLE IP (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_Num BLOB, status BLOB, UNIQUE (ip_Num))''')
        crsr.execute('''CREATE TABLE PORT (id INTEGER PRIMARY KEY AUTOINCREMENT, ip_Num_Id INTERGER, port INTEGER, status BLOB, FOREIGN KEY(ip_Num_Id) REFERENCES IP(id))''')
        log.write("OpenIP database already exists, dropping old data from DB'\n'")
#ENDIF

#BEGIN EXECUTIONS ON DB, SURROUND ALL SQLITE STATEMENTS IN ONE BEGIN-END STATEMENT FOR SPEED
#Waits for all transaction from Begin to End, before commit()
#INSERT statements are very quick but the commit writes to memory before adding them to database, which is slow.
#=========================================================================================================================================================================================================
#                    BUILD DATABSE WITH PORTS AND IPS
#=========================================================================================================================================================================================================

crsr.execute('BEGIN')
log.write("Start Database Connection...'\n'")

#number of IP's found
all_IP = []
ip_Id = 0
previousLine = " "
portStatus = " "
ipStatus = " "
portChanged = False
if os.path.isfile(ndiff_File_Location):

        log.write("Opening ndiff file to read from'\n'")
        for line in open(ndiff_File_Location, 'r'):

                #========================================================================
                #Search New Host
                #========================================================================
                if re.search("<b>",line) and re.search("<hostdiff>",previousLine):
                        ipStatus = "new"

                if re.search ("<a>",line) and re.search("<hostdiff>",previousLine):
                        ipStatus = "removed"

                if re.search("<host>",line) and re.search("<hostdiff>", previousLine):
                        ipStatus = "changed"
                #endif

                #========================================================================
                #Search Changed Port
                #========================================================================
                if re.search("<b>",line):
                        portChanged = True
                if re.search("</b>",line):
                        portChanged = False
                #endif

                #========================================================================
                #GET UNIQUE IP ADDRESS AND IT'S Database id
                #========================================================================
                if (re.search("<address ", line)):

                        addressLine = line.split()
                        IP = addressLine[1].strip("addr=")
                        IP = IP.strip('"')
                        crsr.execute("INSERT INTO IP(ip_Num, status) VALUES(?,?)", (str(IP), str(ipStatus),))
                        crsr.execute("SELECT id FROM IP WHERE ip_Num=? LIMIT 1", (str(IP),))
                        ip_Num_Id = crsr.fetchone()[0]
                        all_IP.append(IP)

                        writelog = "Found <address writing " + IP + " to database...'\n'"
                        log.write(writelog)

                #ENDIF

                #========================================================================
                #New Host Ports
                #========================================================================
                if (ipStatus == "new" and re.search("<state ",line) and re.search("<port ",previousLine)):

                        portLine = previousLine.split()
                        PORT = portLine[1].strip("portid=")
                        PORT = PORT.strip('"')

                        crsr.execute("INSERT INTO PORT(ip_Num_Id, port, status) VALUES(?,?,?)", (int(ip_Num_Id), int(PORT), str(STATUS),))

                        writelog = "Found Added port, writing " + PORT + " to 'ADD' database...'\n'"
                        log.write(writelog)
                #ENDIF

                #========================================================================
                #Removed Host Ports
                #========================================================================
                if (ipStatus == "removed" and re.search("<state ",line) and re.search("<port ",previousLine)):

                        portLine = previousLine.split()
                        PORT = portLine[1].strip("portid=")
                        PORT = PORT.strip('"')

                        statusLine = line.split('"')
                        STATUS = statusLine[1]
                        STATUS = STATUS.strip('"')

                        crsr.execute("INSERT INTO PORT(ip_Num_Id, port, status) VALUES(?,?,?)", (int(ip_Num_Id), int(PORT), str(STATUS),))

                        writelog = "Found Added port, writing " + PORT + " to 'ADD' database...'\n'"
                        log.write(writelog)
                #ENDIF
                #========================================================================
                #Changed Host Ports
                #========================================================================
                if (ipStatus == "changed" and re.search("<state ",line) and re.search("<port ",previousLine) and portChanged == True):

                        portLine = previousLine.split()
                        PORT = portLine[1].strip("portid=")
                        PORT = PORT.strip('"')

                        statusLine = line.split('"')
                        STATUS = statusLine[1]
                        STATUS = STATUS.strip('"')

                        crsr.execute("INSERT INTO PORT(ip_Num_Id, port, status) VALUES(?,?,?)", (int(ip_Num_Id), int(PORT), str(STATUS),))

                        writelog = "Found Added port, writing " + PORT + " to 'ADD' database...'\n'"
                        log.write(writelog)
                #ENDIF

                previousLine = line

        #ENDFOR
else:
        print ("No Scans From Yesterday, So Ndiff File Was Not Created For Today, THERE WILL BE NO RESULTS FOR TODAY")
        print ("Try to uncomment $Yesterday variable in .SH file and add previous date you want to run against")
        log.write("ERROR: No Scans From Yesterday, So Ndiff File Was Not Created For Today, THERE WILL BE NO RESULTS FOR TODAY'\n'")
        log.write("ERROR: Try to uncomment $Yesterday variable in .SH file and add previous date you want to run against'\n'")
#=========================================================================================================================================================================================================
#                    PRINT NEW HOSTS PORTS: OPEN, CLOSED, FILTERED
#=========================================================================================================================================================================================================      

print ("New Hosts:")
printResults.write("New Hosts:\n")
log.write("Searching through DB for New Hosts...'\n'")
#Determines if there are any results for NEW HOSTS
results = False

for ip in all_IP:
        ipPrint = False
        #================================================================
        #New Hosts Port Status OPEN
        #================================================================
        all_PortsString = " "
        crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='new' AND PORT.status='open'", (str(ip),))
        if (crsr.fetchone()):
                crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='new' AND PORT.status='open'", (str(ip),))
                all_Ports = crsr.fetchall()

                for i in range(0,len(all_Ports)):
                        tempPort = str(all_Ports[i][0])
                        if i == (len(all_Ports) - 1):
                                all_PortsString += tempPort
                        else:
                                all_PortsString += tempPort + ', '
                        #ENDIF
                #ENDFOR
                if (ipPrint == False):
                        printaddPort = "\n   " + ip + ":"
                        printaddPortLog = "\n   " + ip + ":\n"
                        print(printaddPort)
                        printResults.write(printaddPortLog)
                        ipPrint = True

                printaddPortLog = "      " + "\033[95m" + "\033[1m" + " OPEN: " + "\033[0m" + all_PortsString + '\n'
                addPortLog = "      " + " OPEN: " + all_PortsString + '\n'
                print(printaddPortLog)
                printResults.write(addPortLog)
                results = True
        #ENDIF
        log.write("Writing New Host, Open Port Results...'\n'")
        #================================================================
        #New Hosts Port Status CLOSED
        #================================================================
        all_PortsString = " "
        crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='new' AND PORT.status='closed'", (str(ip),))
        if (crsr.fetchone()):
                crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='new' AND PORT.status='closed'", (str(ip),))
                all_Ports = crsr.fetchall()

                for i in range(0,len(all_Ports)):
                        tempPort = str(all_Ports[i][0])
                        if i == (len(all_Ports) - 1):
                                all_PortsString += tempPort
                        else:
                                all_PortsString += tempPort + ', '
                        #ENDIF
                #ENDFOR
                if (ipPrint == False):
                        printaddPort = "\n   " + ip + ":"
                        printaddPortLog = "\n   " + ip + ":\n"
                        print(printaddPort)
                        printResults.write(printaddPortLog)
                        ipPrint = True

                printaddPortLog = "      " + "\033[95m" + "\033[1m" + " Closed: " + "\033[0m" + all_PortsString + '\n'
                addPortLog = "      " + " Closed: " + all_PortsString + '\n'
                print(printaddPortLog)
                printResults.write(addPortLog)
                results = True
        #ENDIF
        log.write("Writing New Host, Open Port Results...'\n'")
        #================================================================
        #New Hosts Port Status FILTERED
        #================================================================
        all_PortsString = " "
        crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='new' AND PORT.status='filtered'", (str(ip),))
        if (crsr.fetchone()):
                crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='new' AND PORT.status='filtered'", (str(ip),))
                all_Ports = crsr.fetchall()

                for i in range(0,len(all_Ports)):
                        tempPort = str(all_Ports[i][0])
                        if i == (len(all_Ports) - 1):
                                all_PortsString += tempPort
                        else:
                                all_PortsString += tempPort + ', '
                        #ENDIF
                #ENDFOR
                if (ipPrint == False):
                        printaddPort = "\n   " + ip + ":"
                        printaddPortLog = "\n   " + ip + ":\n"
                        print(printaddPort)
                        printResults.write(printaddPortLog)
                        ipPrint = True

                printaddPortLog = "      " + "\033[95m" + "\033[1m" + " Filtered: " + "\033[0m" + all_PortsString + '\n'
                addPortLog = "      " + " Filtered: " + all_PortsString + '\n'
                print(printaddPortLog)
                printResults.write(addPortLog)
                results = True
        #ENDIF
        log.write("Writing New Host, Open Port Results...'\n'")

if results == False:
        printaddPort = "   (NO RESULTS)"
        printaddPortLog = "   (NO RESULTS)\n"
        print(printaddPort)
        printResults.write(printaddPortLog)
#ENDFOR

#=========================================================================================================================================================================================================
#                    PRINT REMOVED HOSTS PORTS: OPEN, CLOSED, FILTERED
#=========================================================================================================================================================================================================      

print ("Removed Hosts:")
printResults.write("Removed Hosts: \n")
log.write("Searching through DB for Removed Hosts...'\n'")
#Determines if there are any results for REMOVED HOSTS
results = False
for ip in all_IP:
        ipPrint = False
        #================================================================
        #Removed Hosts Port Status OPEN
        #================================================================
        all_PortsString = " "
        crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='removed' AND PORT.status='open'", (str(ip),))
        if (crsr.fetchone()):
                crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='removed' AND PORT.status='open'", (str(ip),))
                all_Ports = crsr.fetchall()

                for i in range(0,len(all_Ports)):
                        tempPort = str(all_Ports[i][0])
                        if i == (len(all_Ports) - 1):
                                all_PortsString += tempPort
                        else:
                                all_PortsString += tempPort + ', '
                        #ENDIF
                #ENDFOR
                if (ipPrint == False):
                        printaddPort = "\n   " + ip + ":"
                        printaddPortLog = "\n   " + ip + ":\n"
                        print(printaddPort)
                        printResults.write(printaddPortLog)
                        ipPrint = True

                printaddPortLog = "      " + "\033[95m" + "\033[1m" + " OPEN: " + "\033[0m" + all_PortsString + '\n'
                addPortLog = "      " + " OPEN: " + all_PortsString + '\n'
                print(printaddPortLog)
                printResults.write(addPortLog)
                results = True
        #ENDIF
        log.write("Writing New Host, Open Port Results...'\n'")

        #================================================================
        #Removed Hosts Port Status CLOSED
        #================================================================
        all_PortsString = " "
        crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='removed' AND PORT.status='closed'", (str(ip),))
        if (crsr.fetchone()):
                crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='removed' AND PORT.status='closed'", (str(ip),))
                all_Ports = crsr.fetchall()

                for i in range(0,len(all_Ports)):
                        tempPort = str(all_Ports[i][0])
                        if i == (len(all_Ports) - 1):
                                all_PortsString += tempPort
                        else:
                                all_PortsString += tempPort + ', '
                        #ENDIF
                #ENDFOR

               if (ipPrint == False):
                        printaddPort = "\n   " + ip + ":"
                        printaddPortLog = "\n   " + ip + ":\n"
                        print(printaddPort)
                        printResults.write(printaddPortLog)
                        ipPrint = True

                printaddPortLog = "      " + "\033[95m" + "\033[1m" + " Closed: " + "\033[0m" + all_PortsString + '\n'
                addPortLog = "      " + " Closed: " + all_PortsString + '\n'
                print(printaddPortLog)
                printResults.write(addPortLog)
                results = True
        #ENDIF
        log.write("Writing New Host, Open Port Results...'\n'")

        #================================================================
        #Removed Hosts Port Status FILTERED
        #================================================================
        all_PortsString = " "
        crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='removed' AND PORT.status='filtered'", (str(ip),))
        if (crsr.fetchone()):
                crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='removed' AND PORT.status='filtered'", (str(ip),))
                all_Ports = crsr.fetchall()

                for i in range(0,len(all_Ports)):
                        tempPort = str(all_Ports[i][0])
                        if i == (len(all_Ports) - 1):
                                all_PortsString += tempPort
                        else:
                                all_PortsString += tempPort + ', '
                        #ENDIF
                #ENDFOR
                if (ipPrint == False):
                        printaddPort = "\n   " + ip + ":"
                        printaddPortLog = "\n   " + ip + ":\n"
                        print(printaddPort)
                        printResults.write(printaddPortLog)
                        ipPrint = True

                printaddPortLog = "      " + "\033[95m" + "\033[1m" + " Filtered: " + "\033[0m" + all_PortsString + '\n'
                addPortLog = "      " + " Filtered: " + all_PortsString + '\n'
                print(printaddPortLog)
                printResults.write(addPortLog)
                results = True
        #ENDIF
        log.write("Writing New Host, Open Port Results...'\n'")

if results == False:
        printaddPort = "   (NO RESULTS)"
        printaddPortLog = "   (NO RESULTS)\n"
        print(printaddPort)
        printResults.write(printaddPortLog)

#ENDFOR
#=========================================================================================================================================================================================================
#                    PRINT CHANGED HOSTS PORTS:
#=========================================================================================================================================================================================================      

print ("Changed Hosts:")
printResults.write("Changed Hosts:\n")
log.write("Searching through DB for Changed Hosts...'\n'")
#Determines if there are any results for CHANGED HOSTS
results = False
for ip in all_IP:
        ipPrint = False
        #================================================================
        #Changed Hosts Port Status OPEN
        #================================================================
        all_PortsString = " "
        crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='changed' AND PORT.status='open'", (str(ip),))
        if (crsr.fetchone()):
                crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='changed' AND PORT.status='open'", (str(ip),))
                all_Ports = crsr.fetchall()

                #Print IP if it hasnt already been printed
                if (ipPrint == False):
                        printaddPort = "\n   " + ip + ":"
                        printaddPortLog = "\n   " + ip + ":\n"
                        print(printaddPort)
                        printResults.write(printaddPortLog)
                        ipPrint = True
                        #ENDIF
                #Print ports changed to open
                for i in range(0,len(all_Ports)):
                        tempPort = str(all_Ports[i][0])
                        printaddPortLog = "      " + "\033[95m" + "\033[1m" + tempPort + "\033[0m" + ": changed to OPEN"
                        print(printaddPortLog)
                        portLog = "      " + tempPort + ": changed to OPEN\n"
                        printResults.write(portLog)
                        results = True
                        #ENDIF

        #================================================================
        #Changed Hosts Port Status CLOSED
        #================================================================
        all_PortsString = " "
        crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='changed' AND PORT.status='closed'", (str(ip),))
        if (crsr.fetchone()):
                crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='changed' AND PORT.status='closed'", (str(ip),))
                all_Ports = crsr.fetchall()

                #Print IP if it hasnt already been printed
                if (ipPrint == False):
                        printaddPort = "\n   " + ip + ":"
                        printaddPortLog = "\n   " + ip + ":\n"
                        print(printaddPort)
                        printResults.write(printaddPortLog)
                        ipPrint = True
                        #ENDIF
                #Print ports changed to closed
                for i in range(0,len(all_Ports)):
                        tempPort = str(all_Ports[i][0])
                        printaddPortLog = "      " + "\033[95m" + "\033[1m" + tempPort + "\033[0m" + ": changed to Closed"
                        print(printaddPortLog)
                        portLog = "      " + tempPort + ": changed to Closed\n"
                        printResults.write(portLog)
                        results = True
                        #ENDIF

        #================================================================
        #Changed Hosts Port Status FILTERED
        #================================================================
        all_PortsString = " "
        crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='changed' AND PORT.status='filtered'", (str(ip),))
        if (crsr.fetchone()):
                crsr.execute("SELECT port FROM PORT INNER JOIN IP ON IP.id=PORT.ip_Num_Id WHERE IP.ip_Num=? AND IP.status='changed' AND PORT.status='filtered'", (str(ip),))
                all_Ports = crsr.fetchall()

                #Print IP if it hasnt already been printed
                if (ipPrint == False):
                        printaddPort = "\n   " + ip + ":"
                        printaddPortLog = "\n   " + ip + ":\n"
                        print(printaddPort)
                        printResults.write(printaddPortLog)
                        ipPrint = True
                        #ENDIF
                #Print ports changed to open
                for i in range(0,len(all_Ports)):
                        tempPort = str(all_Ports[i][0])
                        printaddPortLog = "      " + "\033[95m" + "\033[1m" + tempPort + "\033[0m" +  ": changed to Filtered"
                        print(printaddPortLog)
                        portLog = "      " + tempPort + ": changed to Filtered\n"
                        printResults.write(portLog)
                        results = True
                        #ENDIF
                #ENDFOR
        #ENDIF
        log.write("Writing New Host, Open Port Results...'\n'")

if results == False:
        printaddPort = "   (NO RESULTS)"
        printaddPortLog = "   (NO RESULTS)\n"
        print(printaddPort)
        printResults.write(printaddPortLog)
#ENDFOR

crsr.execute('END')
dbconn.commit()
dbconn.close()
log.write("END Commit Database and End connection ...'\n'")
log.close()
