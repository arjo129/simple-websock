import time
import struct
import socket
import hashlib
import base64
import sys
from select import select
import re
import logging
from threading import Thread
import errors

class WebSocket(object):
    handshake = (
        "HTTP/1.1 101 Web Socket Protocol Handshake\r\n"
        "Upgrade: WebSocket\r\n"
        "Connection: Upgrade\r\n"
        "WebSocket-Origin: %(origin)s\r\n"
        "WebSocket-Location: ws://%(bind)s:%(port)s/\r\n"
        "Sec-Websocket-Origin: %(origin)s\r\n"
        "Sec-Websocket-Location: ws://%(bind)s:%(port)s/\r\n"
        "Sec-Websocket-Accept: %(key)s\r\n"
        "Sec-Websocket-Version: 13\r\n"
        "\r\n"
    )
    def __init__(self, client, server):
        self.client = client
        self.server = server
        self.handshaken = False
        self.header = ""
        self.data = b""

    def feed(self, data):
        if not self.handshaken:
            #print("shaking hand")
            self.header = data.decode("utf-8")
            if self.header.find('\r\n\r\n') != -1:
                parts = self.header.split('\r\n\r\n', 1)
                self.header = parts[0]
                if self.dohandshake(self.header, parts[1]):
                    #print("Handshake successful")
                    self.handshaken = True
            else:
                raise errors.BrokenClientHandShake(data)
        else:
            self.decodeFrame(data)

    def decodeFrame(self,data):
        if len(data) < 14:
            raise SocketFrameTooShort(data)
        opcode = data[0] & 0b00001111
        if (data[1] & 0b10000000) > 0 and (opcode == 0 or opcode == 1 or opcode == 2):
            #proceed With the connection
            datalength = data[1] & 0b01111111
            masking_key = data[2:6]
            data_start = 6
            if datalength == 126:
                print ("16bit message length")
                datalength = int(datalength[2])*256+int(datalength[3])
                masking_key = data[4:8]
                data_start = 8
            elif datalength > 126:
                datalength = struct.unpack("<L", datalength[2:10])[0]
                masking_key = data[10:14]
                data_start = 14
                print ("64bit message length")
            payload = data[data_start:]
            message = b""
            if datalength != len(payload):
                raise WrongHeaderLength(datalength,len(payload));
            for i in range(0,datalength):
                message += bytes([payload[i]^masking_key[i%4]])
        elif opcode == 0x9:
            self.pong()
        elif opcode == 0x8:
            self.close()
        else:
            if (data[1] & 0b10000000) == 0 and (opcode == 0 or opcode == 1 or opcode == 2):
                raise ClientMustMaskMessage(data)
            else:
                raise UnsupportedOpcode(opcode)
    def dohandshake(self, header, key=None):
        print("Begin handshake: %s" % header)
        digitRe = re.compile(r'[^0-9]')
        spacesRe = re.compile(r'\s')
        part_1 = part_2 = v13 = origin = None
        v13 = origin = None
        sec_web_accept = None
        for line in header.split('\r\n')[1:]:
            name, value = line.split(': ', 1)
            if name.lower() == "sec-websocket-key1":
                key_number_1 = int(digitRe.sub('', value))
                spaces_1 = len(spacesRe.findall(value))
                if spaces_1 == 0:
                    return False
                if key_number_1 % spaces_1 != 0:
                    return False
                part_1 = key_number_1 / spaces_1
            elif name.lower() == "sec-websocket-key2":
                key_number_2 = int(digitRe.sub('', value))
                spaces_2 = len(spacesRe.findall(value))
                if spaces_2 == 0:
                    return False
                if key_number_2 % spaces_2 != 0:
                    return False
                part_2 = key_number_2 / spaces_2
            elif name.lower() == "origin":
                origin = value
            elif name.lower() == "sec-websocket-key":
                #calculate Websocket Hash
                v13 = True
                cat = bytes(value+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11","utf-8")
                sec_web_accept = base64.b64encode(hashlib.sha1(cat).digest()).decode("utf-8")
        if v13:
            print ("using v13")
            handshake = WebSocket.handshake % {
                'origin': origin,
                'port': self.server.port,
                'bind': self.server.bind,
                'key': sec_web_accept
            }
        else:
            logging.warning("Not using challenge + response")
            handshake = WebSocket.handshake % {
                'origin': origin,
                'port': self.server.port,
                'bind': self.server.bind,
                'key': sec_web_accept
            }
        #print("Sending handshake %s" % handshake)
        self.client.send(bytes(handshake,"utf-8"))
        return True
    def pong(self):
        print("Ponging")
    def onmessage(self, data):
        print("Got message: %s" % data)

    def send(self, data):
        self.client.send("\x00%s\xff" % data)

    def close(self):
        self.client.close()

class WebSocketServer(object):
    def __init__(self, bind, port, cls):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((bind, port))
        self.bind = bind
        self.port = port
        self.cls = cls
        self.connections = {}
        self.listeners = [self.socket]

    def listen(self, backlog=5):
        self.socket.listen(backlog)
        logging.info("Listening on %s" % self.port)
        self.running = True
        while self.running:
            rList, wList, xList = select(self.listeners, [], self.listeners, 1)
            for ready in rList:
                if ready == self.socket:
                    #print("New client connection")
                    client, address = self.socket.accept()
                    fileno = client.fileno()
                    self.listeners.append(fileno)
                    self.connections[fileno] = self.cls(client, self)
                else:
                    #print("Client ready for reading %s" % ready)
                    client = self.connections[ready].client
                    data = client.recv(1024)
                    fileno = client.fileno()
                    #print(data)
                    if data:
                        self.connections[fileno].feed(data)
                    else:
                        #print("Closing client %s" % ready)
                        self.connections[fileno].close()
                        del self.connections[fileno]
                        self.listeners.remove(ready)
            for failed in xList:
                if failed == self.socket:
                    print("Socket broke")
                    for fileno, conn in self.connections:
                        conn.close()
                    self.running = False
