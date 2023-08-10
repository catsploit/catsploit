# CATSploit
CATSploit is an automated penetration testing tool using Cyber Attack Techniques Scoring (CATS) method that can be used without pentester.
Currently, pentesters implicitly made the selection of suitable attack techniques for target systems to be attacked.
CATSploit uses system configuration information such as OS, open ports, software version collected by scanner and calculates a score value for capture eVc and detectability eVd of each attack techniques for target system.
By selecting the highest score values, it is possible to select the most appropriate attack technique for the target system without hack knack(professional pentester’s skill) .

CATSploit automatically performs penetration tests in the following sequence:

1. **Information gathering and prior information input**
First, gathering information of target systems. CATSploit supports nmap and OpenVAS to gather information of target systems.
CATSploit also supports prior information of target systems if you have.

2. **Calculating score value of attack techniques**
Using information obtained in the previous phase and attack techniques database, evaluation values of capture (eVc) and detectability (eVd) of each attack techniques are calculated.
For each target computer, the values of each attack technique are calculated.

3. **Selection of attack techniques by using scores and make attack scenario**
Select attack techniques and create attack scenarios according to pre-defined policies.
For example, for a policy that prioritized hard-to-detect, the attack techniques with the lowest eVd(Detectable Score) will be selected.

4. **Execution of attack scenario**
CATSploit executes the attack techniques according to attack scenario constructed in the previous phase.
CATSploit uses Metasploit as a framework and Metasploit API to execute actual attacks.


## Table of Contents
* [Prerequisities](#Prerequisities)
* [Installation](#Installation)
* [Usage](#usage)
* [Examples](#examples)
* [Disclaimer](#disclaimer)
* [License](#license)
* [Contact](#contact)

## Prerequisities
CATSploit has the following prerequisites:

* Kali Linux 2023.2a

## Installation
For Metasploit, Nmap and OpenVAS, it is assumed to be installed with the [Kali Distribution](https://www.kali.org/).

#### Installing CATSploit
To install the latest version of CATSploit, please use the following commands:

##### Cloneing and setup
```
$ git clone https://github.com/catsploit/catsploit.git
$ cd catsploit
$ git clone https://github.com/catsploit/cats-helper.git
$ sudo ./setup.sh
```

#### Editing configuration file
CATSploit is a server-client configuration, and the server reads the configuration JSON file at startup.
In ```config.json```, the following fields should be modified for your environment.
* DBMS
  * dbname: database name created for CATSploit
  * user: username of PostgreSQL
  * password: password of PostgrSQL
  * host: If you are using a database on a remote host, specify the IP address of the host
* SCENARIO
  * generator.maxscenarios: Maximum number of scenarios to calculate (*)
* ATTACKPF
  * msfpassword: password of MSFRPCD
  * openvas.user: username of PostgreSQL
  * openvas.password: password of PostgreSQL
  * openvas.maxhosts: Maximum number of hosts to be test at the same time (*)
  * openvas.maxchecks: Maximum number of test items to be test at the same time (*)
* ATTACKDB
  * attack_db_dir: Path to the folder where AtackSteps are stored

(\*) Adjust the number according to the specs of your machine.

## Usage <a name="usage"/></a>
To start the server, execute the following command:
```
$ python cats_server.py -c [CONFIG_FILE]
```
Next, prepare another console, start the client program, and initiate a connection to the server.
```
$ python catsploit.py -s [SOCKET_PATH]
```
After successfully connecting to the server and initializing it, the session will start.
```
   _________  ___________       __      _ __
  / ____/   |/_  __/ ___/____  / /___  (_) /_
 / /   / /| | / /  \__ \/ __ \/ / __ \/ / __/
/ /___/ ___ |/ /  ___/ / /_/ / / /_/ / / /_
\____/_/  |_/_/  /____/ .___/_/\____/_/\__/
                     /_/

[*] Connecting to cats-server
[*] Done.
[*] Initializing server
[*] Done.
catsploit>
```
The client can execute a variety of commands. Each command can be executed with `-h` option to display the format of its arguments.
```
usage: [-h] {host,scenario,scan,plan,attack,post,reset,help,exit} ...

positional arguments:
  {host,scenario,scan,plan,attack,post,reset,help,exit}

options:
  -h, --help       show this help message and exit 
```
I've posted the commands and options below as well for reference.
```
host list:
 show information about the hosts
 usage:  host list [-h] 
 options:
  -h, --help       show this help message and exit

host detail:
 show more information about one host
 usage:  host detail [-h] host_id 
 positional arguments:
  host_id          ID of the host for which you want to show information
 options:
  -h, --help       show this help message and exit

scenario list:
 show information about the scenarios
 usage:  scenario list [-h]
 options:
  -h, --help       show this help message and exit

scenario detail:
 show more information about one scenario
 usage:  scenario detail [-h] scenario_id
 positional arguments:
  scenario_id      ID of the scenario for which you want to show information
 options:
  -h, --help       show this help message and exit

scan:
 run network-scan and security-scan
 usage:  scan [-h] [--port PORT] target_host [target_host ...]
 positional arguments:
  target_host      IP address to be scanned
 options:
  -h, --help       show this help message and exit
  --port PORT      ports to be scanned

plan:
 planning attack scenarios
 usage:  plan [-h] src_host_id dst_host_id
 positional arguments:
  src_host_id      originating host
  dst_host_id      target host
 options:
  -h, --help       show this help message and exit

attack:
 execute attack scenario
 usage:  attack [-h] scenario_id
 positional arguments:
  scenario_id      ID of the scenario you want to execute

 options:
  -h, --help       show this help message and exit

post find-secret:
 find confidential information files that can be performed on the pwned host
 usage:  post find-secret [-h] host_id
 positional arguments:
  host_id          ID of the host for which you want to find confidential information
 options:
  -h, --help       show this help message and exit

reset:
 reset data on the server
 usage:  reset [-h] {system} ...
 positional arguments:
  {system}         reset system
options:
  -h, --help  show this help message and exit

exit:
  exit CATSploit
  usage:  exit [-h]
  options:
   -h, --help  show this help message and exit
```
## Examples <a name="examples"/></a>
In this example, we use CATSploit to scan network, plan the attack scenario, and execute the attack.
```
catsploit> scan 192.168.0.0/24
Network Scanning ... 100%
[*] Total 2 hosts were discovered.
Vulnerability Scanning ... 100%
[*] Total 14 vulnerabilities were discovered.
catsploit> host list
┏━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ hostID   ┃ IP             ┃ Hostname ┃ Platform                         ┃ Pwned ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ attacker │ 0.0.0.0        │ kali     │ kali 2022.4                      │ True  │
│ h_exbiy6 │ 192.168.0.10   │          │ Linux 3.10 - 4.11                │ False │
│ h_nhqyfq │ 192.168.0.20   │          │ Microsoft Windows 7 SP1          │ False │
└──────────┴────────────────┴──────────┴──────────────────────────────────┴───────┘


catsploit> host detail h_exbiy6
┏━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━┓
┃ hostID   ┃ IP           ┃ Hostname ┃ Platform     ┃ Pwned ┃
┡━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━┩
│ h_exbiy6 │ 192.168.0.10 │ ubuntu   │ ubuntu 14.04 │ False │
└──────────┴──────────────┴──────────┴──────────────┴───────┘

[IP address]
┏━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━┓
┃ ipv4         ┃ ipv4mask ┃ ipv6 ┃ ipv6prefix ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━┩
│ 192.168.0.10 │          │      │            │
└──────────────┴──────────┴──────┴────────────┘

[Open ports]
┏━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ ip           ┃ proto ┃ port ┃ service     ┃ product      ┃ version                    ┃
┡━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 192.168.0.10 │ tcp   │ 21   │ ftp         │ ProFTPD      │ 1.3.5                      │
│ 192.168.0.10 │ tcp   │ 22   │ ssh         │ OpenSSH      │ 6.6.1p1 Ubuntu 2ubuntu2.10 │
│ 192.168.0.10 │ tcp   │ 80   │ http        │ Apache httpd │ 2.4.7                      │
│ 192.168.0.10 │ tcp   │ 445  │ netbios-ssn │ Samba smbd   │ 3.X - 4.X                  │
│ 192.168.0.10 │ tcp   │ 631  │ ipp         │ CUPS         │ 1.7                        │
└──────────────┴───────┴──────┴─────────────┴──────────────┴────────────────────────────┘

[Vulnerabilities]
┏━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ ip           ┃ proto ┃ port ┃ vuln_name                                                           ┃ cve            ┃
┡━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ 192.168.0.10 │ tcp   │ 0    │ TCP Timestamps Information Disclosure                               │ N/A            │
│ 192.168.0.10 │ tcp   │ 21   │ FTP Unencrypted Cleartext Login                                     │ N/A            │
│ 192.168.0.10 │ tcp   │ 22   │ Weak MAC Algorithm(s) Supported (SSH)                               │ N/A            │
│ 192.168.0.10 │ tcp   │ 22   │ Weak Encryption Algorithm(s) Supported (SSH)                        │ N/A            │
│ 192.168.0.10 │ tcp   │ 22   │ Weak Host Key Algorithm(s) (SSH)                                    │ N/A            │
│ 192.168.0.10 │ tcp   │ 22   │ Weak Key Exchange (KEX) Algorithm(s) Supported (SSH)                │ N/A            │
│ 192.168.0.10 │ tcp   │ 80   │ Test HTTP dangerous methods                                         │ N/A            │
│ 192.168.0.10 │ tcp   │ 80   │ Drupal Core SQLi Vulnerability (SA-CORE-2014-005) - Active Check    │ CVE-2014-3704  │
│ 192.168.0.10 │ tcp   │ 80   │ Drupal Coder RCE Vulnerability (SA-CONTRIB-2016-039) - Active Check │ N/A            │
│ 192.168.0.10 │ tcp   │ 80   │ Sensitive File Disclosure (HTTP)                                    │ N/A            │
│ 192.168.0.10 │ tcp   │ 80   │ Unprotected Web App / Device Installers (HTTP)                      │ N/A            │
│ 192.168.0.10 │ tcp   │ 80   │ Cleartext Transmission of Sensitive Information via HTTP            │ N/A            │
│ 192.168.0.10 │ tcp   │ 80   │ jQuery < 1.9.0 XSS Vulnerability                                    │ CVE-2012-6708  │
│ 192.168.0.10 │ tcp   │ 80   │ jQuery < 1.6.3 XSS Vulnerability                                    │ CVE-2011-4969  │
│ 192.168.0.10 │ tcp   │ 80   │ Drupal 7.0 Information Disclosure Vulnerability - Active Check      │ CVE-2011-3730  │
│ 192.168.0.10 │ tcp   │ 631  │ SSL/TLS: Report Vulnerable Cipher Suites for HTTPS                  │ CVE-2016-2183  │
│ 192.168.0.10 │ tcp   │ 631  │ SSL/TLS: Report Vulnerable Cipher Suites for HTTPS                  │ CVE-2016-6329  │
│ 192.168.0.10 │ tcp   │ 631  │ SSL/TLS: Report Vulnerable Cipher Suites for HTTPS                  │ CVE-2020-12872 │
│ 192.168.0.10 │ tcp   │ 631  │ SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection          │ CVE-2011-3389  │
│ 192.168.0.10 │ tcp   │ 631  │ SSL/TLS: Deprecated TLSv1.0 and TLSv1.1 Protocol Detection          │ CVE-2015-0204  │
└──────────────┴───────┴──────┴─────────────────────────────────────────────────────────────────────┴────────────────┘

[Users]
┏━━━━━━━━━━━┳━━━━━━━┓
┃ user name ┃ group ┃
┡━━━━━━━━━━━╇━━━━━━━┩
└───────────┴───────┘


catsploit> plan attacker h_exbiy6
Planning attack scenario...100%
[*] Done. 15 scenarios was planned.
[*] To check each scenario, try 'scenario list' and/or 'scenario detail'.
catsploit> scenario list
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ scenario id ┃ src host ip ┃ target host ip ┃ eVc   ┃ eVd   ┃ steps ┃ first attack step             ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 3d3ivc      │ 0.0.0.0     │ 192.168.0.10   │ 1.0   │ 32.0  │ 1     │ exploit/multi/http/jenkins_s… │
│ 5gnsvh      │ 0.0.0.0     │ 192.168.0.10   │ 1.0   │ 53.76 │ 2     │ exploit/multi/http/jenkins_s… │
│ 6nlxyc      │ 0.0.0.0     │ 192.168.0.10   │ 0.0   │ 48.32 │ 2     │ exploit/multi/http/jenkins_s… │
│ 8jos4z      │ 0.0.0.0     │ 192.168.0.10   │ 0.7   │ 72.8  │ 2     │ exploit/multi/http/jenkins_s… │
│ 8kmmts      │ 0.0.0.0     │ 192.168.0.10   │ 0.0   │ 32.0  │ 1     │ exploit/multi/elasticsearch/… │
│ agjmma      │ 0.0.0.0     │ 192.168.0.10   │ 0.0   │ 24.0  │ 1     │ exploit/windows/http/managee… │
│ joglhf      │ 0.0.0.0     │ 192.168.0.10   │ 70.0  │ 60.0  │ 1     │ auxiliary/scanner/ssh/ssh_lo… │
│ rmgrof      │ 0.0.0.0     │ 192.168.0.10   │ 100.0 │ 32.0  │ 1     │ exploit/multi/http/drupal_dr… │
│ xuowzk      │ 0.0.0.0     │ 192.168.0.10   │ 0.0   │ 24.0  │ 1     │ exploit/multi/http/struts_dm… │
│ yttv51      │ 0.0.0.0     │ 192.168.0.10   │ 0.01  │ 53.76 │ 2     │ exploit/multi/http/jenkins_s… │
│ znv76x      │ 0.0.0.0     │ 192.168.0.10   │ 0.01  │ 53.76 │ 2     │ exploit/multi/http/jenkins_s… │
└─────────────┴─────────────┴────────────────┴───────┴───────┴───────┴───────────────────────────────┘

catsploit> scenario detail rmgrof
┏━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┳━━━━━━━┳━━━━━━┓
┃ src host ip ┃ target host ip ┃ eVc   ┃ eVd  ┃
┡━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━╇━━━━━━━╇━━━━━━┩
│ 0.0.0.0     │ 192.168.0.10   │ 100.0 │ 32.0 │
└─────────────┴────────────────┴───────┴──────┘

[Steps]
┏━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ # ┃ step                                  ┃ params                ┃
┡━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ 1 │ exploit/multi/http/drupal_drupageddon │ RHOSTS: 192.168.0.10  │
│   │                                       │ LHOST: 192.168.10.100 │
└───┴───────────────────────────────────────┴───────────────────────┘


catsploit> attack rmgrof
> ~
> ~
> Metasploit Console Log
> ~
> ~
[+] Attack scenario succeeded!


catsploit> exit
Bye.
```

## Disclaimer
All informations and codes are provided solely for educational purposes and/or testing your own systems.

## License
```
Copyright (C) 2023　Mitsubishi Electric Corporation.

The License details can be found at following URL:

https://github.com/catsploit/catsploit/LICENSE
```
## Contact
For any inquiry, please contact the email address as follows:

catsploit@nk.MitsubishiElectric.co.jp