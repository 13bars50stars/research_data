## Scenario 01 - [HASSH] SSH Client Software Connection to Bastion

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

  ```bash
  $ tshark -nr scenario01_putty_short.pcap -Y 'ssh.message_code == 20' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info -e ssh.kex.hassh
7	192.168.91.132	192.168.91.129	Client: Key Exchange Init	1dd4d89cd6b7a1f7b06acf808260c130
8	192.168.91.129	192.168.91.132	Server: Key Exchange Init	
  ```  
  
</details>


<details>
  <summary>MS Terminal SSH Client</summary>
  
  ```bash
  $ tshark -nr scenario01_ms_terminal_short.pcap -Y 'ssh.message_code == 20' -T fields -e frame.number -e ip.src -e ip.dst -e _ws.col.Info -e ssh.kex.hassh
7	192.168.91.132	192.168.91.129	Client: Key Exchange Init	ec7378c1a92f5a8dde7e8b7a1ddf33d1
8	192.168.91.129	192.168.91.132	Server: Key Exchange Init	
  ```
</details>

Conclusion

| HASSH Value    | Software       |
|----------------|----------------|
| 1dd4d89cd6b7a1f7b06acf808260c130  | PuTTY  |
| ec7378c1a92f5a8dde7e8b7a1ddf33d1  | MS Terminal ssh  |

TODO: extract client algorithms each software used - maybe in Appendix for space saving?

## Scenario 02 - [HASSH] Server Response to Client Connection


