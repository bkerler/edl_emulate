import socket

class tcpclient():
    def __init__(self, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ("localhost", port)
        print("connecting to %s port %s" % server_address)
        self.sock.connect(server_address)

    def sendcommands(self,commands):
        try:
            data = b""
            for command in commands:
                self.sock.sendall(command)
                amount_received = 0
                while True:
                    tmp = self.sock.recv(4096)
                    if tmp == b"":
                        break
                    data+=tmp
                    amount_received += len(data)
                    # print("received %s" % data)
            return data
        finally:
            print("closing socket")
            self.sock.close()


