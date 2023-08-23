import socket
import hashlib
import argparse
import json
from os.path import exists
import random
import string
import ssl


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s", "--server", help="set address to listen on", default="0.0.0.0"
    )
    parser.add_argument(
        "-p", "--port", help="set port to listen on", type=int, default=9001
    )
    parser.add_argument("-o", "--outfile", help="set outfile name", default=None)
    parser.add_argument("--ssl", help="encrypt traffic", action="store_true")
    parser.add_argument("--certfile", help="cert if using ssl", default="cert.pem")
    parser.add_argument("--keyfile", help="private key if using ssl", default="key.pem")
    # Example command to generate cert and key:
    # openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes

    args = parser.parse_args()
    return args.server, args.port, args.outfile, args.ssl, args.certfile, args.keyfile


def md5_file(file_name, file_len):
    md5sum = hashlib.md5()
    remaining_len = file_len
    with open(file_name, "rb") as f:
        while remaining_len > 0:
            data = f.read(4096)
            remaining_len -= 4096
            md5sum.update(data)
    return md5sum.hexdigest()


def gen_ssl_context(certfile, keyfile):
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.check_hostname = False
    try:
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    except FileNotFoundError:
        print("Can't file cert file or key file for encryption!")
        exit()
    return ssl_context


def md5sum_check(outfile, file_len, md5sum):
    new_md5sum = md5_file(outfile, file_len)
    if md5sum == new_md5sum:
        print("Outfile integrity Confirmed!")

    else:
        print("Outfile integrity doesn't match!")


def accept_connection(sock, outfile):
    conn, addr = sock.accept()
    with conn:
        print(f"\nConnection from {addr[0]}")
        json_metadata = conn.recv(128).strip(b"\x00").decode()
        metadata = json.loads(json_metadata)
        file_len = metadata["file_len"]
        md5sum = metadata["md5sum"]
        if not outfile:
            outfile = metadata["filename"]
        if exists(outfile):
            outfile = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
            print(f"\nFile already Exists! Saving copy as {outfile}")

        received_data = 0
        with open(outfile, "wb") as f:
            while received_data < file_len:
                data = conn.recv(4096)
                f.write(data)
                received_data += len(data)
    md5sum_check(outfile, file_len, md5sum)


def main():
    server, port, outfile, encrypt, certfile, keyfile = parse_args()
    with socket.socket() as s:
        s.bind((server, port))
        s.listen()
        print(f"Listening on {server}")
        if encrypt:
            ssl_context = gen_ssl_context(certfile, keyfile)
            with ssl_context.wrap_socket(s, server_side=True) as ssock:
                accept_connection(ssock, outfile)
        else:
            accept_connection(s, outfile)
    print(f"\nReceived all data!")


if __name__ == "__main__":
    main()
