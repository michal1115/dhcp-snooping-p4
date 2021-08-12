import socket

if __name__ == "__main__":
    src_ip = "10.0.0.111"
    src_port = 10000

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((src_ip, src_port))

    while True:
        data, addr = sock.recvfrom(1024)
        print(addr[0])
        print(data)