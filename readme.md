# A Simple WebSocket API
Usage:
`````
import websock

class MyApp(websock.WebSocketDelegate):
  def onRecieve(self, data):
    print data
`````
