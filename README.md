#projet files 
***To run the project,please download that full fales the link below.
1. DHMITM withRSA (1st scenario):https://drive.google.com/drive/folders/1eZAe_gAjOxAyhsk2JvtFwPTiTJx3jlmO?usp=sharing

Projct Overview 
This project demonstrates  how the Diffie-Hellman (DH) key exchange is vulnerable to Man-in-the-Middle (MITM) attack and how adding RSA digital signatuer prevents the attack.

We implemented two versions:
1. Insecure version:DH & AES (MITM success).
2. Secure version:DH & RSA & AES signature (MITM is blocked).

Motivation
DH alon doesnt authenticate the communiction,attackers can intercpet public keys and create 2 shared secret key,we implement real-word secure both version to understand the secuer communication.

Techonologies & Cryptography used
1. Diffie-Hellman (DH):Shared key generation.
2. AES signatures: Encrypting messages.
3. python3 and PyCryptodome libraries.
4. Soket programming for communication.
5. Wireshark for network traffic analysis.

System Components
1. Eddie client
2. Venom server
3. Mallory MITM attacker (proxy)


How the MITM attack works
1. Mallory intercept the DH public key from Eddie.
2. Mallory replaces it with her own key then send it to Venom.
3. she repeat tha same process in reverse.
4. Mallory create 2 shared key & can read or modify all message .

this work only when DH is not authentical.


Defense:RSA Digital Signatures 
1. Both Eddie & Venom sign their DH parameters using private keys.
2. Receiver verification signature using RSA public key.
3. If Mallory modifiiies any vlaue verification fails and attack is stopped.


**How to run the code

We have 2 scenario so both need to run Virtual environmet you have to open different window to do the order to run the code make every window you open activ virtual environment using PowerShell:
1. pyhon -m venv venv
2. venv\scripts\activate

If you went to close it :
1. deactivate

Make suer you have this libraries :
1. pip install pwntools 
2. pip install cyptograpy

**Each of scenario have different file:
1. DHMITM withRSA (1st scenario)
2. DiffieHellman-ManInTheMiddle-master without RSA(2sd scenario)
Eache of them work alone run separately.

**So to run 1st scenario which is seccess MITM:
1. python run.py 8000
2. python mitm.py 127.0.0.1 8000 9001  or python mitm.py localhost 8000 9001
3. python run.py 127.0.0.1  9001 or  python run.py localhost 9001


**So to run 2sd scenario which is MITM attecker failure:
1. python run.py 12345
2. python mitm.py 127.0.0.1 12345 8888
3. python run.py 127.0.0.1  8888



Testing scenarios
Scenarios 1 without RSA insecure :
1. Mallory successfully intercepts DH values.
2. 2 shared keys are created.
3. Massages appear in plaintext in attacker terminal.
4. Wireshark show read traffic.

Scenarios2 with RSA secure:
1. Eddie & venom sign DH.
2. Mallory fails to modify DH key.
3. Signature verification fail connection bloced.
4. Wireshark shows only encrypted ciphertext.

Results summary 
1. DH+AES(No RSA) MITM success =Insecure
2. DH+AES+RSA MITM fail =Secure


Referenes
[1]“GeeksforGeeks,” GeeksforGeeks, 2025. https://www.google.com/url?q=https://www.geeksforgeeks.org/&sa=U&sqi=2&ved=2ahUKEwjLjqqVgaSRAxUd_rsIHWuaHCAQFnoECCQQAQ&usg=AOvVaw3L-dQySvfQ6DeMIJSnFAkl (accessed Dec. 04, 2025).
‌	[2]W. Shen, Y. Cheng, B. Yin, K. Liu, and X. Cao, “Diffie-Hellman in the Air: A Link Layer Approach for In-Band Wireless Pairing,” arXiv.org, 2019. https://www.google.com/url?q=https://arxiv.org/abs/1901.09520&sa=U&sqi=2&ved=2ahUKEwjI7u_MgaSRAxVLOPsDHVhoOJYQFnoECCcQAQ&usg=AOvVaw2uPQYZ9RCWoRUB0FqwXHTa (accessed Dec. 04, 2025).
‌
[3]S. Devi and R. Makani, “Generation of N-party Man-In-Middle Attack for Diffie-Hellman Key Exchange Protocol: A Review.” Accessed: Dec. 04, 2025. [Online]. Available: https://www.ijcsit.com/~ijcsitco/docs/Volume%206/vol6issue05/ijcsit2015060526.pdf
‌

[4]“Securing Text Files: A Comprehensive Study on AES and Diffie-Hellman Encryption,” Ijraset.com, 2024. https://www.ijraset.com/research-paper/comprehensive-study-on-aes-and-diffie-hellman-encryption
‌
[5]Davidmenamm, “GitHub - Davidmenamm/Cyber_Security_Diffie_Hellman_Man_in_the_Middle_Attack: Diffie Hellman Algorithm implementation with man in the middle attack simulation.,” GitHub, 2025. https://github.com/Davidmenamm/Cyber_Security_Diffie_Hellman_Man_in_the_Middle_Attack (accessed Dec. 04, 2025).
‌[6]jaybosamiya, “GitHub - jaybosamiya/DiffieHellman-ManInTheMiddle: Demonstrating a practical attack on the Diffie Hellman Key Exchange protocol, through breaking a secure chat system,” GitHub, 2025. https://github.com/jaybosamiya/DiffieHellman-ManInTheMiddle (accessed Dec. 04, 2025).
‌
[7]“Home,” Openssl.org, 2024. https://openssl.org/
‌
[8]Cryptography, “Welcome to pyca/cryptography — Cryptography 3.0.dev1 documentation,” cryptography.io. https://cryptography.io/en/latest/
[9]H. Eijs, “pycryptodome: Cryptographic library for Python,” PyPI. https://pypi.org/project/pycryptodome/
