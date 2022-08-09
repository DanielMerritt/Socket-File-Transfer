import socket
import hashlib
import argparse
import json
from os.path import exists
import random
import string


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-s", "--server", help="set address to listen on", default="0.0.0.0"
    )
    parser.add_argument(
        "-p", "--port", help="set port to listen on", type=int, default=9001
    )
    parser.add_argument("-o", "--outfile", help="set outfile name", default=None)

    args = parser.parse_args()
    return args.server, args.port, args.outfile


def md5_file(file_name, file_len):
    md5sum = hashlib.md5()
    remaining_len = file_len
    with open(file_name, "rb") as f:
        while remaining_len > 0:
            data = f.read(4096)
            remaining_len -= 4096
            md5sum.update(data)
    return md5sum.hexdigest()


def main():
    server, port, outfile = parse_args()

    with socket.socket() as s:
        s.bind((server, port))
        s.listen()
        print(f"Listening on {server}")
        conn, addr = s.accept()
        with conn:
            print(f"\nConnection from {addr[0]}\n")
            json_metadata = conn.recv(128).strip(b"\x00").decode()
            print(json_metadata)
            metadata = json.loads(json_metadata)
            file_len = metadata["file_len"]
            md5sum = metadata["md5sum"]
            if not outfile:
                outfile = metadata["filename"]
            if exists(outfile):
                outfile = "".join(
                    random.choice(string.ascii_letters) for _ in range(10)
                )
                print(f"\nFile already Exists! Saving copy as {outfile}")

            received_data = 0
            with open(outfile, "wb") as f:
                while received_data < file_len:
                    data = conn.recv(4096)
                    f.write(data)
                    received_data += len(data)

    print(f"\nReceived all data!")

    new_md5sum = md5_file(outfile, file_len)
    if md5sum == new_md5sum:
        print("Outfile integrity Confirmed!")

    else:
        print("Outfile integrity doesn't match!")


if __name__ == "__main__":
    main()
