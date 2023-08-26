**Socket File Transfer**

A simple socket client/server for transferring files.

Features Integrity checking and SSL support. No External Dependencies required.

Usage: 
```
python3 file_transfer.py server (-p <port> --ssl --certfile <certfile> --keyfile <keyfile>)
python3 file_transfer.py client <filename> <target> (-p <port> --ssl --reverse)
```
If using SSL, server certificates can be generated using openssl:
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes
```