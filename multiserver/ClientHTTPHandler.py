
from http.server import SimpleHTTPRequestHandler
from http import HTTPStatus
from urllib import parse
from io import BytesIO

class ClientHTTP(SimpleHTTPRequestHandler):
    server_version = "tinytuya-multiserver/1.0"
    index_pages = []

    def __init__( self, request, addr ):
        self.directory = ''
        self.rfile = BytesIO( request )
        self.wfile = BytesIO()
        self.wbody = None
        self.client_address = addr
        self.handle_one_request()

    def process_request( self, want_body=True ):
        self.send_header( 'Connection', 'close' )
        self.path_translated = self.translate_path( self.path )

        print( 'HTTP path:', self.path, 'translated:', self.path_translated )

        if self.path == '/':
            self.path_translated = self.path = '/testws.html'
            self.wbody = self.send_head()
        elif self.path == '/favicon.ico':
            self.send_error( HTTPStatus.NOT_FOUND )
        else:
            self.send_error( HTTPStatus.IM_A_TEAPOT )


        if self.wbody and not want_body:
            self.wbody.close()
            self.wbody = None

    def do_GET( self ):
        return self.process_request()

    def	do_HEAD( self ):
        return self.process_request( False )

    def send_response_only( self, *args, **kwargs ):
        if not hasattr(self, '_headers_buffer'):
            self._headers_buffer = []
        headers_buffer = self._headers_buffer
        self._headers_buffer = []
        super( ClientHTTP, self ).send_response_only( *args, **kwargs )
        for h in headers_buffer:
            self._headers_buffer.append( h )

class ClientHTTPHandler:
    def __init__( self, sock, BigDataObj ):
        self.sock = sock
        self.BigDataObj = BigDataObj
        self.sendq = b''
        self.send_fp = None
        self.recvq = b''
        self.close = False

    def recv( self, data ):
        self.recvq += data

        if b"\r\n\r\n" in self.recvq:
            req = ClientHTTP( self.recvq, self.BigDataObj.clients[self.sock].addr )
            self.recvq = b''
            self.close = req.close_connection
            self.sendq = req.wfile.getvalue()
            self.send_fp = req.wbody
            self.send()

    def send( self ):
        #self.BigDataObj.log.info( 'sendq:%d close:%r', len(self.sendq), self.close )
        sent = self.sock.send( self.sendq )
        self.sendq = self.sendq[sent:]
        if (not self.sendq) and self.send_fp:
            self.sendq = self.send_fp.read( 4096 )
            if not self.sendq:
                self.send_fp.close()
                self.send_fp = None
        self.BigDataObj.log.info( 'sent:%d sendq:%d close:%r', sent, len(self.sendq), self.close )
