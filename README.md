## CyberSecurity Project 2

### Files
1. `attack.py` contains the code to do a buffer overflow on the server.
2. `sample_client.py` and `sample_server.py` contain the code to run a client and server. 
3. `aes.py` and `rsa.py` were files provided in the original project zip.
4. `key` and `key.pub` is the private and public key pair provided in the sample project. 
5. `serverPublicKey` is the public key for the server on the cs machines. 
6. `exported_bytes.bin` contains the packet data from a pcap file that I generated (`out.pcap`) which captured an AES encrypted message, and an RSA encrypted AES key from a client to the ser. 
7. `lab2_packet.bin` contains the packet data from the pcap that came in the original project folter.

### Run the Attack

#### Start the server
`python3 sample_server.py -p 10005 -kp key.pub -ks key`

#### Start the attack
`python3 attack.py exported_bytes.bin key.pub`
