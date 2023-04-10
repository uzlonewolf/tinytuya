
#import SimpleWebSocketServer.SimpleWebSocketServer
from SimpleWebSocketServer import WebSocket

Websocket_CLOSE = 0x8

class ClientWebSocketHandler( WebSocket ):
    def __init__( self, sock, BigDataObj ):
        super( ClientWebSocketHandler, self ).__init__( BigDataObj.clients[sock], sock, BigDataObj.clients[sock].addr )
        self.BigDataObj = BigDataObj
        self.send_queue = []
        self.opened = False
        self.closed = False

    def handleMessage(self):
        self.BigDataObj.log.debug( 'Websocket got message: %r', self.data )
        self.BigDataObj.client_message( self.server, self.data )

    def handleConnected(self):
        self.opened = True
        try:
            self.BigDataObj.log.debug( 'Websocket connected, addr:%r, path:%r', self.address, self.request.path )
        except:
            self.BigDataObj.log.debug( 'Websocket connected, addr:%r, no path', self.address )

        if self.send_queue:
            for msg in self.send_queue:
                self.sendMessage( msg )
            self.send_queue = []

    def handleClose(self):
        self.BigDataObj.log.debug( 'ClientWebSocketHandler: Websocket closed, addr:%r', self.address, exc_info=True )
        self.server.closed = True

    def trySend(self):
        if self.closed:
            return

        if self.sendq:
            opcode, payload = self.sendq.popleft()
            try:
                remaining = self._sendBuffer( payload )
                if remaining is not None:
                    self.sendq.appendleft( (opcode, remaining) )
                elif opcode == Websocket_CLOSE:
                    self.handleClose()
            except:
                self.handleClose()
