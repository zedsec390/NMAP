# Nmap Mainframe Scripts

The repository is used to host the Nmap tn3270 library and various mainframe hacking/profiling scripts. 

## tn3270.lua

```
h4ckr > nmap -n -sV -Pn xxx.xxx.com -p 23 --script tn3270-screen

Starting Nmap 7.25SVN ( https://nmap.org ) at 2016-09-16 15:32 PDT
Nmap scan report for xxx.xxx.com (1.1.1.1)
Host is up (0.088s latency).
PORT   STATE SERVICE VERSION
23/tcp open  tn3270  IBM Telnet TN3270 (TN3270E)
| tn3270-screen: 
|  Mainframe Operating System                              z/OS V1.6              
|          FFFFF  AAA  N   N      DDDD  EEEEE      ZZZZZ H   H  III               
|          F     A   A NN  N      D   D E             Z  H   H   I                
|          FFFF  AAAAA N N N      D   D EEEE         Z   HHHHH   I                
|          F     A   A N  NN      D   D E           Z    H   H   I                
|          F     A   A N   N      DDDD  EEEEE      ZZZZZ H   H  III               
|                                                                                 
|                         ZZZZZ      / OOOOO  SSSS                                
|                            Z      /  O   O S                                    
|                           Z      /   O   O  SSS                                 
|                          Z      /    O   O     S                                
|                         ZZZZZ  /     OOOOO SSSS                                 
|                                                                                 
|                   Welcome to Fan DeZhi Mainframe System!                        
|                                                                                 
|                       Support: http://xxx.xxx.com                           
|          TSO      - Logon to TSO/ISPF        NETVIEW  - Netview System          
|          CICS     - CICS System              NVAS     - Netview Access          
|          IMS      - IMS System               AOF      - Netview Automation      
|                                                                                 
| Enter your choice==>                                                            
| Hi! Enter one of above commands in red.                                         
|                                                                                 
|_Your IP(12.34.56.789   :50666), SNA LU(        )       09/16/16 17:32:51        

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2.10 seconds

```

`tn3270.lua` is a Nmap Script Engine (NSE) library which implements a virtual tn3270 terminal. Tn3270 is what you might refer to a 'green screen' on a mainframe. This library allows you to interact with green screen applications such at VTAM, CICS, TSO through Nmap. 

This library supports multiple levels of verbosity and debug. Enabling the highest level of debug will show the library decoding the tn3270 stream.
```
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Current Item: f3
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Inserting 0xf3 (3) at the following location:
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Row: 25
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Col: 69
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Buffer Address: 1909
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Current Position: 1620 of 1622
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Current Item: 7a
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Inserting 0x7a (:) at the following location:
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Row: 25
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Col: 70
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Buffer Address: 1910
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Current Position: 1621 of 1622
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Current Item: f3
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Inserting 0xf3 (3) at the following location:
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Row: 25
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Col: 71
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Buffer Address: 1911
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Current Position: 1622 of 1622
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Current Item: f4
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Inserting 0xf4 (4) at the following location:
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Row: 25
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Col: 72
NSE: [tn3270-screen M:19d1be8 1.1.1.1:23] Buffer Address: 1912

```

**Note**: Requires a recent version (>= 6.49) of Nmap which include the correct probes to identify tn3270 servers.

### tn3270

Two scripts exist for just viewing tn3270 screens:

**tn3270-screen.nse**: Connects to a mainframe and prints out the first screen you see when connecting to a mainframe. Oftentimes the first screen will have lots of information available such as the OS version etc, this allows you to collect that information within Nmap. Takes the optional argument `tn3270.commands` which allows sending commands to the mainframe before taking the screenshot.

**tn3270-hidden.nse**: Displays 'hidden' portions of the tn3270 screen (either overwritten before display or explicitly hidden by the server):

```
23/tcp open  tn3270  syn-ack Telnet TN3270
| tn3270-hidden:
|   Hidden Field # 1: Type the number of your terminal:
|     Column: 1
|     Row   : 9
|   Hidden Field # 2: SKRIV SYSTEMNAVN ==>
|     Column: 40
|_    Row   : 9
```

### VTAM

VTAM is (sometimes) the first screen you get sent upon connecting to a mainframe. Currently only one VTAM testing script exists:

**vtam-enum.nse**: This script operates in two modes. The first (and default) mode is to attempt to enumerate valid application IDs through the VTAM application command `LOGON APPLID(<appID>)`. By default it attempts `tso`, `CICS`, `IMS`, and `NETVIEW`, the script argument `idlist=` allows you to specify a file of application IDs you want to test. The second mode attempts to enumerate *macros*. Though they aren't technically macros they allow you to have short form commands for `LOGON APPLID(X)`. For example the macro `TSO` may actually execute `LOGON APPLID(MVSTSO01)`. 

### TSO

TSO is what could be refered to as a 'shell' on the mainframe. It allows for command execution, JCL submission and general operations. Two TSO scripts exists:

**tso-enum.nse**: The logon procedure for TSO allows you to enumerate user IDs. This script currently supports RACF and TopSecret. By default it attempts to issue the command `TSO` and then tries a user ID. By default it uses the *macro* `TSO`, you can change this using the script arg `tso-enum.commands`. For example: `tso-enum.commands="logon applid(tso)"`. Since this script uses the `brute` and `unpwdb` libraries you can limit the max connections with `brute.threads` and specify your own user list over the default provided by Nmap (recommended) using the script argument `userdb`. All together a typical Nmap command would look like:

```
nmap -sV -p 2023 <ip> --script tso-enum --script-args userdb=users.txt,brute.threads=200,brute.useraspass=false,tso-enum.commands="logon applid(TSO331)"
```

This script is defeated in RACF by enabling `PASSWORDPREPROMPT`.

**tso-brute.nse**: Similar in principle to `tso-enum.nse` but goes one step further and attempts to brute force the users password. Supports RACF and TopSecret. On the first the script pass will check to see if a user ID is valid or not using the same logic as `tso-enum.nse`. TSO only allows a user to log in once per session. If a user is logged in you can't log on to test if a password is valid. You can force logging in (which kicks the actual user off) with the argument `tso-brute.always_logon=true`.

### CICS

CICS is similar to websites. A 'screen' is what a website with input fields and data would be, and a transaction ID, in this example, is the same as a URI. 

**cics-enum.nse**: Connecting to CICS (either directly or through VTAM) allows you to input CICS transaction IDs. These IDs can be any combination of 4  bytes. They are, normally, composed of `0-9` and `A-z`. This script first attempts to connect to CICS and once it's successful starts enumerating CICS transaction IDs. The default *macro* it tries is `CICS`, which can be changed with the script argument `cics-enum.commands`. By default it tries the CICS transaction IDs outlined in [IBM Knowledge Center DFHA726](https://www-01.ibm.com/support/knowledgecenter/SSGMCP_5.2.0/com.ibm.cics.ts.systemprogramming.doc/topics/dfha726.html). This can be added to by supplying the script argument `idlist`. This script uses the `brute` library to facilitate testing.

**cics-user-enum.nse**: Both ACF2 and TopSecret (but not RACF) allow you to enumerate valid CICS users. This script acts similarly to `tso-enum.nse` in that it relies on the `brute` and `unpwdb` libraries. It uses the *macro* `CICS` by default, use the script argument `cics-user-enum.commands` to change this default. Currently the default transaction ID of `CESL` is used, to change this use the `cics-user-enum.transaction` argument. For example:

```
nmap -sV -p 23 <ip> --script cics-user-enum --script-args userdb=users.txt,cics-user-enum.transaction=CESN,cics-user-enum.commands='logon applid(PRODCICS)',brute.threads=250 -v 
``` 

## Network Job Entry

Network Job Entry (NJE) is a protocol developed by IBM to allow mainframes to send jobs and control records between each other. A fairly detailed writeup about NJE can be found in [PoC||GTFO 12:6](https://www.alchemistowl.org/pocorgtfo/pocorgtfo12.pdf) page 32.

**nje-node-brute.nse**: This script allows for the brute forcing of NJE node names (OHOST and RHOST). By default it will try the LPAR host names then use the defaults supplied by `nselib/data/vhosts-default.lst`. To overide this default you can use the script argument `nje-node-brute.hostlist`. By default this script attempts to brute force the OHOST only. To brute force the RHOST just supply the known OHOST to the script with the argument `nje-node-brute.ohost`. As above this script relies the `brute` and `unpwdb` libraries and all their arguments can be used.

**nje-pass-brute.nse**: As outlined in *PoC||GTFO \#12* sometimes a system may implement a password requirement for NJE. This script, given a valid RHOST and OHOST will attempt to brute force the password required to connect. The arguments required to use this script are `nje-node-brute.rhost` and `nje-node-brute.ohost`. As above this script relies the `brute` and `unpwdb` libraries and all their arguments can be used.