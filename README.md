## Scenario 01 - [HASSH] SSH Client Software Connection to Bastion
<details>
  <summary>Expand to see details</summary>
Summary: Examine HASSH results when different SSH client software is used to connect to bastion

Connect from User PC to Bastion with username bob

  - User PC - 192.168.91.132 (Windows 10)
  - Bastion - 192.168.91.129 (Debian12)

PCAP Filter:
```bash
tcpdump -ni ens33 'tcp and port 22' -w scenario01.pcap
```


<details>
  <summary>PuTTY Client Connection</summary>
  
  Extract HASSH for `PuTTY` with tshark

  ```bash
  $ tshark -nr scenario01_putty_short.pcap -Y 'ssh.message_code == 20' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info -e ssh.kex.hassh
7	192.168.91.132	192.168.91.129	Client: Key Exchange Init	1dd4d89cd6b7a1f7b06acf808260c130
8	192.168.91.129	192.168.91.132	Server: Key Exchange Init	
  ```  
  
</details>


<details>
  <summary>MS Terminal SSH Client</summary>
  
  Extract HASSH for `MS Terminal ssh` with tshark
  ```bash
  $ tshark -nr scenario01_ms_terminal_short.pcap -Y 'ssh.message_code == 20' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info -e ssh.kex.hassh
7	192.168.91.132	192.168.91.129	Client: Key Exchange Init	ec7378c1a92f5a8dde7e8b7a1ddf33d1
8	192.168.91.129	192.168.91.132	Server: Key Exchange Init	
  ```
</details>

### Conclusion

Using different client software on UserPC produces different HASSH values. There is a difference between PuTTY and MS Terminal ssh.

| HASSH Value    | SSH Client Software       |
|----------------|----------------|
| 1dd4d89cd6b7a1f7b06acf808260c130  | PuTTY  |
| ec7378c1a92f5a8dde7e8b7a1ddf33d1  | MS Terminal ssh  |

TODO: extract client algorithms each software used - maybe in Appendix for space saving?

</details>

## Scenario 02 - [HASSH] Server Response to Different Client Connections
<details>
  <summary>Expand to see details</summary>
Summary: Examine HASSHserver results when different SSH client software is used to connect to bastion. PCAPs are copied from Scenario01.

Extract HASSHserver with tshark
```bash
$ tshark -nr scenario02_putty_short.pcap -Y 'ssh.message_code == 20' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info -e ssh.kex.hasshserver
7	192.168.91.132	192.168.91.129	Client: Key Exchange Init	
8	192.168.91.129	192.168.91.132	Server: Key Exchange Init	a65c3b91f743d3f246e72172e77288f1
```

Extract HASSHserver with tshark
```bash
$ tshark -nr scenario02_ms_terminal_short.pcap -Y 'ssh.message_code == 20' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info -e ssh.kex.hasshserver
7	192.168.91.132	192.168.91.129	Client: Key Exchange Init	
8	192.168.91.129	192.168.91.132	Server: Key Exchange Init	a65c3b91f743d3f246e72172e77288f1
```
TODO: extract server algorithms each software used - maybe in Appendix for space saving?

### Conclusion

hasshServer remains constant regardless of client connection

| HASSHserver Value    | SSH Client Software       |
|----------------|----------------|
|  a65c3b91f743d3f246e72172e77288f1 | PuTTY  |
|  a65c3b91f743d3f246e72172e77288f1 | MS Terminal ssh  |

</details>

## Scenario 03 - [HASSH] Connect Bastion to Defended Server 
<details>
  <summary>Expand to see details</summary>
Summary: Use either PuTTY or MS Terminal ssh to establish connection from UserPC to Bastion. Establish connection from Bastion to Defended Server. Examine HASSH and HASSHserver for Bastion to Defended Server.

  - User PC - 192.168.91.132 (Windows 10)
  - Bastion - 192.168.91.129 (Debian12)
  - Defended Server - 192.168.91.133 (Debain12)

<details>
<summary>PCAP Filter</summary>

```bash
tcpdump -ni ens33 'tcp and port 22' -w scenario03.pcap
```
</details>

Extract HASSH and HASSHserver with tshark

```bash
$ tshark -nr scenario03.pcap -Y 'ssh.message_code == 20 and ip.addr == 192.168.91.133' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info -e ssh.kex.hassh -e ssh.kex.hasshserver
48	192.168.91.129	192.168.91.133	Client: Key Exchange Init	aae6b9604f6f3356543709a376d7f657	
49	192.168.91.133	192.168.91.129	Server: Key Exchange Init	a65c3b91f743d3f246e72172e77288f1
```

### Conclusion:

Client HASSH uses SSH software on Bastion installed by Debian12. This `aae6b9604f6f3356543709a376d7f657` is different from PuTTY HASSH `1dd4d89cd6b7a1f7b06acf808260c130` and MS Terminal ssh HASSH `ec7378c1a92f5a8dde7e8b7a1ddf33d1`

| HASSH Value    | SSH Client Software       |
|----------------|----------------|
| 1dd4d89cd6b7a1f7b06acf808260c130  | PuTTY  |
| ec7378c1a92f5a8dde7e8b7a1ddf33d1  | MS Terminal ssh  |
| aae6b9604f6f3356543709a376d7f657  | OpenSSH Client from Bastion host |

Server HASSHserver `a65c3b91f743d3f246e72172e77288f1` remains constant from Scenario02.

Note: sshd_config is the same on both Bastion and Defended Server, resulting in same HASSHserver

| HASSHserver Value    | SSH Client Software       |
|----------------|----------------|
|  a65c3b91f743d3f246e72172e77288f1 | Scenario02 Bastion HASSHserver  |
|  a65c3b91f743d3f246e72172e77288f1 | Scenario03 Defended Server HASSHserver  |

</details>

## Scenario 04 - [JA4+SSH] Normal Behavior - Forward Interactive Shell to Bastion
<details>
  <summary>Expand to see details</summary>
Summary: Connect from UserPC to Bastion using either UserPC SSH client software. Perform typical system administator commands such as checking system information.

Systems used:

  - User PC - 192.168.91.132 (Windows 10 using MS Terminal ssh)
  - Bastion - 192.168.91.129 (Debian12)

System commands executed on Bastion:
```bash
pwd
whoami
cat /etc/os-release
uptime
uname -a
who
exit
```

<details>
<summary>PCAP Filter</summary>

```bash
tcpdump -ni ens33 'tcp and port 22' -w scenario04.pcap
```
</details>

Modify JA4.py script to calculate JA4+SSH values based on 20 SSH Packets. JA4.py by default will monitor 200 packets before calculating fingerprint. Modification is required because of the limited number of commands entered on the host.

Modify line 406 in script:
https://github.com/FoxIO-LLC/ja4/blob/main/python/ja4.py#L406

Conclusion:

JA4+SSH prints JA4SSH.x values indicating expected forward interactive shell. Each keystroke is encrypted on the client and sent to the server. A TCP ACK is sent acknowledging the encrypted packet from the client. Thus, the JA4+SSH fingerprint - c36s36_xxxx_xxxx

```json
$ ja4 scenario04_nopatch.pcap -J
{
    "stream": 0,
    "src": "192.168.91.132",
    "dst": "192.168.91.129",
    "srcport": "49765",
    "dstport": "22",
    "client_ttl": "128",
    "server_ttl": "64",
    "JA4L-S": "8_64",
    "JA4L-C": "1225_128",
    "ssh_extras": {
        "hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1",
        "hassh_server": "a65c3b91f743d3f246e72172e77288f1",
        "ssh_protocol_client": "SSH-2.0-OpenSSH_for_Windows_8.1",
        "ssh_protocol_server": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "encryption_algorithm": "chacha20-poly1305@openssh.com"
    },
    "JA4SSH.1": "c33s44_c9s11_c4s3",
    "JA4SSH.2": "c36s36_c9s11_c10s0",
    "JA4SSH.3": "c36s36_c9s11_c10s0",
    "JA4SSH.4": "c36s36_c10s10_c10s0",
    "JA4SSH.5": "c36s36_c8s12_c10s0",
    "JA4SSH.6": "c36s36_c8s12_c10s0",
    "JA4SSH.7": "c36s36_c7s13_c8s0",
    "JA4SSH.8": "c36s36_c7s13_c10s0",
    "JA4SSH.9": "c36s36_c0s0_c0s1"
}
```

</details>

## Scenario 05 - [JA4+SSH] Unauthorized File Copy to Bastion - linpeas.sh
<details>
  <summary>Expand to see details</summary>

Summary: Simulate an unauthorized file copy using SCP from UserPC to Bastion. File copied in example is linpeas.sh without any obfuscation or armoring.

Systems used:

  - User PC - 192.168.91.132 (Windows 10 using MS Terminal ssh)
  - Bastion - 192.168.91.129 (Debian12)

File details for `linpeas.sh` on UserPC
```bash
PS C:\Users\Bob> ls -l linpeas.sh


    Directory: C:\Users\Bob


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/15/2024  12:05 PM         824745 linpeas.sh
```

Execute SCP command to simulate unauthorized file copy to Bastion

```bash
$ scp linpeas.sh bob@bastion:~/
```

<details>
<summary>PCAP Filter</summary>

```bash
tcpdump -ni ens33 'tcp and port 22' -w scenario05.pcap
```
</details>



Conclusion:

The file chosen is 824745 bytes. The MTU for this network is 1500 bytes. As the Secure Copy (SCP) process encrypts the file and sends over SSH, the JA4+SSH fingerprint value detects the SSH payload as 1460 bytes, allowing 20 bytes for the IP and TCP header values. Previously, the SSH payload was padded to 36 bytes based on the encryption algorithms used in the connection.

```json
$ ja4 scenario05.pcap -J
{
    "stream": 0,
    "src": "192.168.91.132",
    "dst": "192.168.91.129",
    "srcport": "49826",
    "dstport": "22",
    "client_ttl": "128",
    "server_ttl": "64",
    "JA4L-S": "9_64",
    "JA4L-C": "1327_128",
    "ssh_extras": {
        "hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1",
        "hassh_server": "a65c3b91f743d3f246e72172e77288f1",
        "ssh_protocol_client": "SSH-2.0-OpenSSH_for_Windows_8.1",
        "ssh_protocol_server": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "encryption_algorithm": "chacha20-poly1305@openssh.com"
    },
    "JA4SSH.1": "c1460s36_c185s15_c4s131",
    "JA4SSH.2": "c1460s36_c0s0_c0s1"
}
```

| JA4+SSH Value    | Simulated Activity       |
|----------------|----------------|
|  c36s36_c10s10_c10s0 | Forward Interactive Shell   |
|  c1460s36_c185s15_c4s131 | Unauthorized SCP to Bastion  |

</details>

## Scenario 06 - [JA4+SSH] Data Exfil from Bastion - loot.gz
<details>
  <summary>Expand to see details</summary>

Summary: Simulate data exfiltration from Bastion. Secure Copy (SCP) a file from Bastion to UserPC. A generated file on Bastion host is SCP to UserPC.

Systems used:

  - User PC - 192.168.91.132 (Windows 10 using MS Terminal ssh)
  - Bastion - 192.168.91.129 (Debian12)

<details>
<summary>Generate `loot.gz` file for data exfiltration simulation on Bastion</summary>

```bash
$ dd if=/dev/urandom of=loot bs=1M count=1
1+0 records in
1+0 records out
1048576 bytes (1.0 MB, 1.0 MiB) copied, 0.00341959 s, 307 MB/s
$ gzip loot
$ ls -l loot.gz
-rw-r--r-- 1 bob bob 10487383 Oct 19 16:23 loot.gz
```
</details>


Execute SCP command to simulate unauthorized file copy to Bastion

```bash
$ scp bob@bastion:~/loot.gz .
```

<details>
<summary>PCAP Filter</summary>

```bash
tcpdump -ni ens33 'tcp and port 22' -w scenario06.pcap
```
</details>

Conclusion:

Similar to Scenario05, the server (Bastion) is the one sending data via SSH with very few client interactions. The JA4+SSH fingerprint value accurately represents this scenario.

```json
$ ja4 scenario06.pcap -J
{
    "stream": 0,
    "src": "192.168.91.132",
    "dst": "192.168.91.129",
    "srcport": "49897",
    "dstport": "22",
    "client_ttl": "128",
    "server_ttl": "64",
    "JA4L-S": "9_64",
    "JA4L-C": "1391_128",
    "ssh_extras": {
        "hassh": "ec7378c1a92f5a8dde7e8b7a1ddf33d1",
        "hassh_server": "a65c3b91f743d3f246e72172e77288f1",
        "ssh_protocol_client": "SSH-2.0-OpenSSH_for_Windows_8.1",
        "ssh_protocol_server": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "encryption_algorithm": "chacha20-poly1305@openssh.com"
    },
    "JA4SSH.1": "c60s1460_c11s189_c13s3",
    "JA4SSH.2": "c60s1460_c0s200_c10s0",
    "JA4SSH.3": "c36s1460_c3s197_c10s0"
}
```

| JA4+SSH Value    | Simulated Activity       |
|----------------|----------------|
|  c36s36_c10s10_c10s0 | Forward Interactive Shell   |
|  c1460s36_c185s15_c4s131 | Unauthorized SCP to Bastion  |
|  c60s1460_c0s200_c10s0  | Data Exfiltration from Bastion      |

</details>

## Scenario 07 - [JA4+SSH] Reverse Shell
<details>
  <summary>Expand to see details</summary>

Summary: Simulate reverse shell on Bastion. 

Systems used:

  - User PC - 192.168.91.132 (Windows 10 using MS Terminal ssh)
  - Bastion - 192.168.91.129 (Debian12)
  - Defended - 192.168.91.133 (Debian12)

<details>
<summary>Setup SSH Reverse Shell</summary>

```bash
$ ssh -N -R 2222:localhost:22 root@192.168.91.129
```
On Bastion observe before and after netstat output
Before:

```bash
$ sudo netstat -antp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      795/sshd: /usr/sbin 
tcp6       0      0 :::22                   :::*                    LISTEN      795/sshd: /usr/sbin 
```

After reverse shell established:

```bash
$ sudo netstat -antp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      3708/sshd: root     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      795/sshd: /usr/sbin 
tcp        0      0 192.168.91.129:22       192.168.91.133:59190    ESTABLISHED 3708/sshd: root     
tcp6       0      0 :::2222                 :::*                    LISTEN      3708/sshd: root     
tcp6       0      0 :::22                   :::*                    LISTEN      795/sshd: /usr/sbin 
```

After connection from UserPC
```bash
$ sudo netstat -antp
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:2222            0.0.0.0:*               LISTEN      3708/sshd: root     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      795/sshd: /usr/sbin 
tcp        0      0 192.168.91.129:2222     192.168.91.132:51477    ESTABLISHED 3708/sshd: root     
tcp        0      0 192.168.91.129:22       192.168.91.133:59190    ESTABLISHED 3708/sshd: root     
tcp6       0      0 :::2222                 :::*                    LISTEN      3708/sshd: root     
tcp6       0      0 :::22                   :::*                    LISTEN      795/sshd: /usr/sbin 
```

</details>


Connect from UserPC to Bastion on port 2222

```bash
$ ssh -p 2222 bastion
```

<details>
<summary>PCAP Filter - updates!</summary>

```bash
tcpdump -ni ens33 'tcp and (port 22 or port 2222)' -w scenario07.pcap
```
</details>

Conclusion:

Similar to previous scenarios, chacha20-poly1305 is the chosen algorithm. Each keystroke is 36 bytes. However, since this is a reverse shell, we have SSH over SSH. Each keystroke on UserPC is echoed to a psuedo tty (shell) on the defended server. The PCAP will show each SSH Payload to be 76 bytes, because this is 'double' encrypted + HMAC. The JA4+SSH fingerprint value accurately represents this scenario.

```json
$ ja4 scenario07.pcap -J
{
    "stream": 0,
    "src": "192.168.91.133",  (Defended)
    "dst": "192.168.91.129",  (Bastion)
    "srcport": "59190",
    "dstport": "22",
    "client_ttl": "64",
    "server_ttl": "64",
    "JA4L-S": "9_64",
    "JA4L-C": "549_64",
    "ssh_extras": {
        "hassh": "aae6b9604f6f3356543709a376d7f657",
        "hassh_server": "a65c3b91f743d3f246e72172e77288f1",
        "ssh_protocol_client": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "ssh_protocol_server": "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "encryption_algorithm": "chacha20-poly1305@openssh.com"
    },
    "JA4SSH.1": "c44s40_c10s10_c9s5",
    "JA4SSH.2": "c84s52_c11s9_c7s5",
    "JA4SSH.3": "c76s76_c10s10_c0s10",
    "JA4SSH.4": "c76s76_c10s10_c0s10",
    "JA4SSH.5": "c76s76_c10s10_c0s10",
    "JA4SSH.6": "c76s76_c10s10_c0s10",
    "JA4SSH.7": "c76s76_c10s10_c0s10",
    "JA4SSH.8": "c76s76_c10s10_c0s10",
    "JA4SSH.9": "c76s76_c10s10_c0s10",
    "JA4SSH.10": "c76s76_c10s10_c0s10",
    "JA4SSH.11": "c76s76_c10s10_c0s10",
    "JA4SSH.12": "c76s76_c10s10_c0s10",
    "JA4SSH.13": "c76s76_c0s0_c0s1"
}
{
    "stream": 1,
    "src": "192.168.91.132",   (UserPC)
    "dst": "192.168.91.129",   (Bastion)
    "srcport": "51477",
    "dstport": "2222",
    "client_ttl": "128",
    "server_ttl": "64",
    "JA4L-S": "9_64",
    "JA4L-C": "2325_128"
}
```

| JA4+SSH Value    | Simulated Activity       |
|----------------|----------------|
|  c36s36_c10s10_c10s0 | Forward Interactive Shell   |
|  c1460s36_c185s15_c4s131 | Unauthorized SCP to Bastion  |
|  c60s1460_c0s200_c10s0  | Data Exfiltration from Bastion      |
|  c76s76_c10s10_c0s10    | Reverse Shell |

</details>