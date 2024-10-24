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
tcpdump -ni ens33 'tcp and port 22' -w scenario01.pcap
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