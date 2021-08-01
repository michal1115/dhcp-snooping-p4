import socket

if __name__ == "__main__":
    message = b"Received from trusted host!"
    dst_ip = "10.0.0.111"
    dst_port = 10000

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message, (dst_ip, dst_port))