**Socket File Transfer**

A simple socket client/server for transferring files.

Features Integrity checking and SSL support. No External Dependencies required.

Usage: 
```
python3 server.py -p 80 (--ssl --certfile --keyfile)
python3 client.py -p 80 <filename> <target> (--ssl)