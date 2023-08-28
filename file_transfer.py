import socket
import hashlib
import argparse
import json
import random
import string
import ssl
import sys
import os
from os.path import exists
from typing import Tuple, Dict, Any, Optional, Union


def client_argparser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    client_parser = subparsers.add_parser("client", help="client mode")
    client_parser.add_argument("filename", help="set file to send/receive")
    client_parser.add_argument("target", help="set target address")
    client_parser.add_argument(
        "-p", "--port", help="set target port", type=int, default=9001
    )
    client_parser.add_argument("--ssl", help="encrypt traffic", action="store_true")
    client_parser.add_argument("--receive", help="receive mode", action="store_true")
    return client_parser


def server_argparser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    server_parser = subparsers.add_parser("server", help="server mode")

    server_parser.add_argument(
        "-s", "--server", help="set address to listen on", default="0.0.0.0"
    )
    server_parser.add_argument(
        "-p", "--port", help="set port to listen on", type=int, default=9001
    )
    server_parser.add_argument("-o", "--outfile", help="set outfile name", default=None)
    server_parser.add_argument("--ssl", help="encrypt traffic", action="store_true")
    server_parser.add_argument(
        "--certfile", help="cert if using ssl", default="cert.pem"
    )
    server_parser.add_argument(
        "--keyfile", help="private key if using ssl", default="key.pem"
    )
    return server_parser


def parse_arguments() -> Tuple[Any]:
    parser = argparse.ArgumentParser(
        description="Socket client/server for file transfer"
    )
    subparsers = parser.add_subparsers(dest="mode", help="available modes")
    client_argparser(subparsers)
    server_argparser(subparsers)
    args = parser.parse_args()
    if args.mode == "client":
        return (
            args.mode,
            args.target,
            args.port,
            args.filename,
            args.ssl,
            args.receive,
        )
    elif args.mode == "server":
        return (
            args.mode,
            args.server,
            args.port,
            args.outfile,
            args.ssl,
            args.certfile,
            args.keyfile,
        )
    else:
        parser.print_help()
        sys.exit()


def md5_file(file_name: str, file_len: int) -> str:
    md5sum = hashlib.md5()
    remaining_len = file_len
    with open(file_name, "rb") as f:
        while remaining_len > 0:
            data = f.read(4096)
            remaining_len -= 4096
            md5sum.update(data)
    return md5sum.hexdigest()


def md5sum_check(outfile: str, file_len: int, md5sum: str) -> None:
    new_md5sum = md5_file(outfile, file_len)
    if md5sum == new_md5sum:
        print("Outfile integrity Confirmed!")

    else:
        print("Outfile integrity doesn't match!")


def send_metadata(connection: socket.socket, metadata: Dict[str, Any]) -> None:
    json_metadata = json.dumps(metadata)
    if len(json_metadata) <= 128:
        padded_json_metadata = json_metadata.encode().ljust(128, b"\x00")
    else:
        print("Metadata (probably file name) too long!")
        sys.exit()
    connection.sendall(padded_json_metadata)
    print("Sent Metadata!")


def send_file(connection: socket.socket, filename: str, file_len: int) -> None:
    remaining_len = file_len
    with open(filename, "rb") as f:
        while remaining_len > 0:
            data = f.read(4096)
            remaining_len -= 4096
            connection.sendall(data)
    print("Sent file!")


def receive_metadata(connection: socket.socket) -> Dict[str, Any]:
    json_metadata = connection.recv(128).strip(b"\x00").decode()
    received_metadata = json.loads(json_metadata)
    print("Received Metadata!")
    return received_metadata


def receive_file(
    connection: socket.socket,
    received_metadata: Dict[str, Any],
    outfile: Optional[str] = None,
) -> None:
    file_len = received_metadata["file_len"]
    md5sum = received_metadata["md5sum"]
    if not outfile:
        outfile = received_metadata["filename"]
    if exists(outfile):
        outfile = "".join(random.choice(string.ascii_lowercase) for _ in range(10))
        print(f"\nFile already Exists! Saving copy as {outfile}")

    received_data = 0
    with open(outfile, "wb") as f:
        while received_data < file_len:
            data = connection.recv(4096)
            f.write(data)
            received_data += len(data)
    md5sum_check(outfile, file_len, md5sum)
    print(f"\nReceived all data!")


class Client:
    def __init__(
        self, target: str, port: int, filename: str, encrypt: bool, receive: bool
    ) -> None:
        self.filename = filename
        self.receive = receive
        self.encrypt = encrypt
        self.sock = self.initialise_socket()
        self.sock.connect((target, port))

    def initialise_socket(self) -> Union[socket.socket, ssl.SSLSocket]:
        sock = socket.socket()
        if self.encrypt:
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            ssock = ssl_context.wrap_socket(sock)
            sock.close()
            return ssock
        return sock

    def client_send_protocol(self) -> None:
        file_len = os.stat(self.filename).st_size
        md5sum = md5_file(self.filename, file_len)
        metadata = {
            "file_len": file_len,
            "md5sum": md5sum,
            "filename": os.path.basename(self.filename),
            "mode": "SEND",
        }
        send_metadata(self.sock, metadata)
        send_file(self.sock, self.filename, file_len)

    def client_receive_protocol(self) -> None:
        metadata = {
            "filename": self.filename,
            "mode": "RECEIVE",
        }
        send_metadata(self.sock, metadata)
        received_metadata = receive_metadata(self.sock)
        receive_file(self.sock, received_metadata, self.filename)

    def run(self) -> None:
        """
        If send mode, send metadata of the file followed by the file itself,
        otherwise if receive mode, send metadata for requested file,
        await metadata for the file to receive, and then receive the file.
        """
        print("Connected!")
        if self.receive:
            self.client_receive_protocol()
        else:
            self.client_send_protocol()

        self.close()

    def close(self) -> None:
        if self.sock:
            self.sock.close()


class Server:
    def __init__(
        self,
        server: str,
        port: int,
        outfile: Optional[str],
        encrypt: bool,
        certfile: str,
        keyfile: str,
    ) -> None:
        self.outfile = outfile
        self.encrypt = encrypt
        self.sock = None
        self.conn = None
        self.ssock = None
        self.conn = self.get_connection(server, port, certfile, keyfile)

    def get_connection(
        self, server: str, port: int, certfile: str, keyfile: str
    ) -> socket.socket:
        self.sock = socket.socket()
        self.sock.bind((server, port))
        self.sock.listen()
        print(f"Listening on {server}")
        if self.encrypt:
            ssl_context = self.gen_ssl_context(certfile, keyfile)
            self.ssock = ssl_context.wrap_socket(self.sock, server_side=True)
            self.sock.close()
            conn, addr = self.ssock.accept()
            print(f"\nSecure Connection from {addr[0]}")
            return conn
        conn, addr = self.sock.accept()
        print(f"\nConnection from {addr[0]}")
        return conn

    def gen_ssl_context(self, certfile: str, keyfile: str) -> ssl.SSLContext:
        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.check_hostname = False
        try:
            ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        except FileNotFoundError:
            print("Can't file cert file or key file for encryption!")
            sys.exit()
        return ssl_context

    def client_receive_protocol(self, received_metadata: Dict[str, Any]) -> None:
        filename = received_metadata["filename"]
        file_len = os.stat(filename).st_size
        md5sum = md5_file(filename, file_len)
        metadata = {
            "file_len": file_len,
            "md5sum": md5sum,
        }
        send_metadata(self.conn, metadata)
        send_file(self.conn, filename, file_len)

    def client_send_protocol(self, received_metadata: Dict[str, Any]) -> None:
        receive_file(self.conn, received_metadata, self.outfile)

    def run(self) -> None:
        """
        Receive Metadata, then if client specifies recieve mode,
        send metadata of requested file followed by the file, otherwise
        prepare to receive file specified within the metadata
        """
        received_metadata = receive_metadata(self.conn)
        if received_metadata["mode"] == "RECEIVE":
            self.client_receive_protocol(received_metadata)
        else:
            self.client_send_protocol(received_metadata)
        self.close()

    def close(self) -> None:
        if self.conn:
            self.conn.close()
        if self.encrypt:
            if self.ssock:
                self.ssock.close()
        elif self.sock:
            self.sock.close()


def main():
    parsed_args = parse_arguments()
    mode = parsed_args[0]
    if mode == "client":
        target, port, filename, encrypt, receive = parsed_args[1:]
        Client(target, port, filename, encrypt, receive).run()

    elif mode == "server":
        server, port, outfile, encrypt, certfile, keyfile = parsed_args[1:]
        Server(server, port, outfile, encrypt, certfile, keyfile).run()


if __name__ == "__main__":
    main()
