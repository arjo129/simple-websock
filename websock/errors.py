class BrokenClientHandShake(Exception):
    def __init__(self, handshake):
        self.value = "Client side handshake message broken: \n\t{}".format(handshake)
    def __str__(self):
        return self.value
class SocketFrameTooShort(Exception):
        def __init__(self, data):
            self.value = "Client sent too short a message: \n\t{}".format(data)
        def __str__(self):
            return self.value
class ClientMustMaskMessage(Exception):
        def __init__(self, data):
            self.value = "Client did not mask message but got header: \n\t{}".format(data[0:2])
        def __str__(self):
            return self.value
class UnsupportedOpcode(Exception):
        def __init__(self, data):
            self.value = "Client did not mask message but got header: {}".format(data)
        def __str__(self):
            return self.value
class WrongHeaderLength(Exception):
        def __init__(self, datalength, actuallength):
            self.value = "Client sent header length of {}, but got message length {}".format(datalength, actuallength)
        def __str__(self):
            return self.value
