import socket
import os
import hashlib
import argparse
import json
import ssl


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="set file to send")
    parser.add_argument("target", help="set target address")
    parser.add_argument("-p", "--port", help="set target port", type=int, default=9001)
    parser.add_argument("--ssl", help="encrypt traffic", action="store_true")

    args = parser.parse_args()
    return args.target, args.port, args.filename, args.ssl


def md5_file(file_name, file_len):
    md5sum = hashlib.md5()
    remaining_len = file_len
    with open(file_name, "rb") as f:
        while remaining_len > 0:
            data = f.read(4096)
            remaining_len -= 4096
            md5sum.update(data)
    return md5sum.hexdigest()


def send_file(sock, target, port, filename):
    sock.connect((target, port))
    print("Connected!")
    file_len = os.stat(filename).st_size
    md5sum = md5_file(filename, file_len)
    metadata = {
        "file_len": file_len,
        "md5sum": md5sum,
        "filename": filename.split("/")[-1],
    }
    json_metadata = json.dumps(metadata)
    if len(json_metadata) <= 128:
        padded_json_metadata = json_metadata.encode().ljust(128, b"\x00")
    else:
        print("Metadata (probably file name) too long!")
        exit()

    sock.sendall(padded_json_metadata)
    print("Sent Metadata!")
    remaining_len = file_len
    with open(filename, "rb") as f:
        while remaining_len > 0:
            data = f.read(4096)
            remaining_len -= 4096
            sock.sendall(data)
    print("Sent file!")


def main():
    target, port, filename, encrypt = parse_args()
    with socket.socket() as s:
        if encrypt:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            with ssl_context.wrap_socket(s) as ssock:
                send_file(ssock, target, port, filename)
        else:
            send_file(s, target, port, filename)


if __name__ == "__main__":
    main()
