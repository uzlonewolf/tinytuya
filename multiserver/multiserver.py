import logging

#logging.basicConfig( encoding='utf-8', level=logging.DEBUG )

import sys
import time
import json
import socket
import select
import ssl
from datetime import datetime
from hashlib import md5,sha256
from collections import namedtuple

import SimpleWebSocketServer.SimpleWebSocketServer

#logging.basicConfig( encoding='utf-8', level=logging.DEBUG )
logging.basicConfig( encoding='utf-8', level=logging.INFO )

import tinytuya
import tinytuya.scanner

#tinytuya.set_debug(False, True)

heartbeat_time = 10
refresh_counter = 6

bind_host = '::'
bind_port = 9997

ssl_cert = 'localhost.pem'
ssl_key = 'localhost.pem'
ssl_key_passwd = None

tuyadevs = {}
#tuyadevs['dev1'] = tinytuya.Device( 'eb...v', '172.20.10.', '...key...', version=3.4 )
#tuyadevs['dev2'] = tinytuya.Device( '83...a', '172.20.10.', '...key...', version=3.3 )

log = logging.getLogger( 'main' )
log.setLevel( logging.DEBUG )


searchdevs = {}
searchlist = None

try:
    with open('devicelist.json', 'r') as fp:
        searchlist = json.load( fp )
except:
    pass

if (not searchlist) and (not tuyadevs):
    try:
        with open('devices.json', 'r') as fp:
            searchlist = json.load( fp )
    except:
        pass

if (not searchlist) and (not tuyadevs):
    raise Exception( 'devicelist.json or devices.json must be present' )

if searchlist:
    for i in searchlist:
        k = i['id']
        searchdevs[k] = i
    del searchlist

try:
    with open('actions.json', 'r') as fp:
        actions = json.load( fp )
except:
    actions = {}

searchlist = list(searchdevs.keys())
notfound = {}

if searchdevs:
    log.warning( 'Searching for devices, please wait...' )
    found = tinytuya.scanner.devices( verbose=False, scantime=8, poll=False, byID=True, wantids=searchlist )
    for i in searchdevs.keys():
        if i not in found:
            notfound[i] = i if 'name' not in searchdevs[i] else searchdevs[i]['name']
            continue

        if 'dev_type' not in found[i]: found[i]['dev_type'] = 'default'
        if 'object' not in searchdevs[i]: searchdevs[i]['object'] = 'Device'

        name = i if 'name' not in searchdevs[i] else searchdevs[i]['name']
        tuyadevs[name] = getattr(tinytuya, searchdevs[i]['object'])( i, found[i]['ip'], searchdevs[i]['key'], version=found[i]['version'], dev_type=found[i]['dev_type'] )

if notfound:
    log.warning( 'Warning: the following devices were not found: %r', notfound )
else:
    log.info( 'All %d devices found', len(searchdevs) )



SetMessage = namedtuple( 'SetMessage', 'device dps value')

if ssl_cert and ssl_key:
    try:
        # python 3.6+ only
        ssl_ctx = ssl.SSLContext( ssl.PROTOCOL_TLS_SERVER )
    except:
        ssl_ctx = ssl.SSLContext()

    ssl_ctx.options |= ssl.OP_SINGLE_DH_USE
    ssl_ctx.options |= ssl.OP_SINGLE_ECDH_USE

    # minimum_version / maximum_version only available in python 3.7+
    try:
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    except:
        ssl_ctx.options |= ssl.OP_NO_SSLv2
        ssl_ctx.options |= ssl.OP_NO_SSLv3
        ssl_ctx.options |= ssl.OP_NO_TLSv1
        ssl_ctx.options |= ssl.OP_NO_TLSv1_1

    ssl_ctx.load_cert_chain(ssl_cert, keyfile=ssl_key, password=ssl_key_passwd)
    ##ssl_ctx.load_verify_locations(cafile='/etc/pki/tls/certs/.ca.crt') #, capath=None, cadata=None)
    #ss = ssl_ctx.wrap_socket(s, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True) #, server_hostname='aacs.zonehead.com')


srv = socket.socket( socket.AF_INET6, socket.SOCK_STREAM )
#srv.setblocking( False )
srv.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
srv.bind( (bind_host, bind_port) )
srv.listen()

CLIENT_PROTO_NONE      = 0
CLIENT_PROTO_TCP       = 1
CLIENT_PROTO_WEBSOCKET = 2
CLIENT_PROTO_UNKNOWN   = 3

Websocket_CLOSE = 0x8

class clientobj(object):
    def __init__( self, sock, addr ):
        self.sock = sock
        self.addr = addr
        self.closed = False
        self.buf = b''
        self.want_repeat = False
        self.is_ssl = False
        self.need_ssl_detect = True
        self.need_ssl_handshake = True
        self.proto = 0
        self.time_connected = time.time()

    def send_message( self, msg ):
        if self.closed:
            log.debug( 'Client already closed, not sending msg' )
        elif not self.proto:
            log.debug( 'No client proto, not sending msg' )
        elif self.proto == CLIENT_PROTO_TCP or self.proto == CLIENT_PROTO_UNKNOWN:
            # raw or JSON
            try:
                self.sock.sendall( msg + b"\n" )
            except:
                log.exception( 'Client send msg failed! addr:%r msg:%r', self.addr, msg )
        elif self.proto == CLIENT_PROTO_WEBSOCKET:
            try:
                if type(msg) == bytes:
                    msg = msg.decode()
            except:
                pass

            if self.websocket.closed:
                return
            elif self.websocket.opened:
                self.websocket.sendMessage( msg )
                self.websocket.trySend()
            else:
                self.websocket.send_queue.append( msg )
        else:
            log.debug( 'Unknown client proto %r, not sending msg', self.proto )

    def send_all_device_status( self, tuyadevs ):
        if self.closed:
            log.debug( 'Client already closed, not sending all' )
        elif not self.proto:
            log.debug( 'No client proto, not sending all' )
        else:
            for dname in tuyadevs:
                self.send_message( current_status( tuyadevs[dname] ) )

    def close( self ):
        self.closed = True
        if self.proto == CLIENT_PROTO_WEBSOCKET:
            self.websocket.close()
            return

        try:
            self.sock.close()
        except:
            pass

def ssl_peekable_recv( self, want_bytes, flags=0 ):
    print(self)
    print(want_bytes, flags)
    if flags == socket.MSG_PEEK:
        if want_bytes > len(self._ssl_peekable_recv_buf):
            self._ssl_peekable_recv_buf += self._orig_recv( (want_bytes - len(self._ssl_peekable_recv_buf)), 0 )
        return self._ssl_peekable_recv_buf
    elif flags:
        return self._orig_recv( want_bytes, flags )

    if want_bytes < len( self._ssl_peekable_recv_buf ):
        ret = self._ssl_peekable_recv_buf[:want_bytes]
        self._ssl_peekable_recv_buf = self._ssl_peekable_recv_buf[want_bytes:]
        return ret

    ret = self._ssl_peekable_recv_buf
    self._ssl_peekable_recv_buf = b''
    self.ssl_peekable_recv_finished	= True

    if want_bytes == len( self._ssl_peekable_recv_buf ):
        return ret

    return ret + self._orig_recv( (want_bytes - len(ret)), flags )

class ClientWebSocket( SimpleWebSocketServer.WebSocket ):
    def __init__( self, server, sock, address ):
        super( ClientWebSocket, self ).__init__( server, sock, address )
        self.messages = []
        self.send_queue = []
        self.opened = False
        self.closed = False

    def handleMessage(self):
        log.debug( 'Websocket got message: %r', self.data )
        self.messages.append( self.data )

    def handleConnected(self):
        self.opened = True
        try:
            log.debug( 'Websocket connected, addr:%r, path:%r', self.address, self.request.path )
        except:
            log.debug( 'Websocket connected, addr:%r, no path', self.address )

        if self.send_queue:
            for msg in self.send_queue:
                self.sendMessage( msg )
            self.send_queue = []

    def handleClose(self):
        log.debug( 'Websocket closed, addr:%r', self.address )
        self.closed = True
        try:
            if self.client:
                self.client.close()
        except:
            pass

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

def socket_opened( tdev ):
    #log.info('opened: %r', tdev.socket)
    if tdev.socket:
        #tdev.set_socketPersistent( True )
        tdev.socket.setblocking( False )
        tdev.readable = True
        tdev.errmsg = b''
        tdev.reconnect_delay = 0
    else:
        log.warning( 'socket_opened(): socket not open! device %r', tdev.name )
        tdev.readable = False
        tdev.errmsg = json.dumps( {'device':tdev.name, "error": "Connect to device failed"} ).encode( 'utf8' )
        tdev.reconnect_delay = 3
    tdev.writeable = False
    tdev.buf = b''
    tdev.need_status = True
    tdev.requested_status = False
    tdev.sending = False
    tdev.send_queue = []
    tdev.state = {}
    tdev.start_time = time.time()
    tdev.last_send_time = time.time()
    tdev.last_msg_time = time.time()

def current_status( tdev ):
    if tdev.socket and tdev.readable:
        return json.dumps( {'device':tdev.name, 'dps': tdev.state} ).encode( 'utf8' )
    else:
        if not tdev.errmsg:
            tdev.errmsg = json.dumps( {'device':tdev.name, "error": "No connection to device"} ).encode( 'utf8' )
        return tdev.errmsg

def request_status( tdev ):
    if tdev.socket and tdev.readable:
        tdev.need_status = False
        tdev.requested_status = True
        tdev._send_receive( tdev.generate_payload( tinytuya.DP_QUERY ), getresponse=False )
        tdev.last_send_time = time.time()
        return True
    return False

def request_status_from_all( tuyadevs, client=None ):
    for dname in tuyadevs:
        if tuyadevs[dname].socket and tuyadevs[dname].readable:
            tuyadevs[dname].need_status = True
        elif client:
            client.send_message( current_status( tuyadevs[dname] ) )

def dev_send( tdev ):
    if not tdev.send_queue:
        tdev.sending = False
        #log.info( 'No queued data for %r', tdev.name )
        return

    cmd = tdev.send_queue.pop(0)
    log.info( 'Sending %r cmd: %r', tdev.name, cmd )

    if cmd.dps == 'multi':
        changed = False
        for dp in cmd.value:
            if (dp not in tdev.state) or (tdev.state[dp] != cmd.value[dp]):
                changed = True
                break
        if not changed:
            log.info( 'Device state already set, not actually sending cmd.  %r %r', tdev.name, cmd )
        else:
            tdev.set_multiple_values( cmd.value,  nowait=True )
            tdev.sending = True
            dps_changed( tdev.name, cmd.value, sent=True )
            for dp in cmd.value:
                tdev.state[str(dp)] = cmd.value[dp]
    else:
        if cmd.dps in tdev.state and tdev.state[cmd.dps] == cmd.value:
            log.info( 'Device state already set, not actually sending cmd.  %r %r', tdev.name, cmd )
        else:
            tdev.set_value( cmd.dps, cmd.value,  nowait=True )
            tdev.sending = True
            tdev.last_send_time = time.time()
            dps_changed( tdev.name, {str(cmd.dps): cmd.value}, sent=True )
            tdev.state[str(cmd.dps)] = cmd.value

def dev_msg( msg ):
    global tuyadevs
    tdev = tuyadevs[msg.device]
    if not (tdev.socket and tdev.readable):
        log.info( 'Device not online, ignoring set! %r', msg.device )
        return False

    tdev.send_queue.append( msg )

    if not tdev.sending:
        dev_send( tdev )

# actions['name']['1']['on_
# actions['name']['1']['match'] = val to match
# actions['name']['1']['set'] = [ ( 'name', dps, value ) ]
def dps_changed( dname, dps, sent=False ):
    global tuyadevs
    global actions

    tdev = tuyadevs[dname]
    dev_actions = {} if dname not in actions else actions[dname]
    num_dps = len(dps)
    have_change = False

    for dp in dps:
        dp = str(dp)
        if dp not in tdev.state:
            added = True
            changed = False
            old_val = None
            have_change = True
        else:
            added = False
            changed = tdev.state[dp] != dps[dp]
            old_val = tdev.state[dp]
            have_change = have_change or changed

        tdev.state[dp] = dps[dp]

        if added or changed or sent:
            log.debug( '%r dps %r now %r, added:%r changed:%r sent:%r', dname, dp, dps[dp], added, changed, sent )

        #for dp_match in ('*', 'x', dp)
        if dp in dev_actions:
            dp_actions = dev_actions[dp]
        elif '?' in dev_actions:
            dp_actions = dev_actions['?']
        else:
            #log.debug( 'no action for dps %r, not triggering', dp )
            continue

        for dp_action in dp_actions:
            if 'on_change' in dp_action and dp_action['on_change'] != changed:
                log.debug( 'dps %r not changed, not triggering', dp )
                continue

            if 'on_add' in dp_action and dp_action['on_add'] != added:
                log.debug( 'dps %r not added, not triggering', dp )
                continue

            if 'match' in dp_action and dp_action['match'] != dps[dp]:
                #log.debug( 'dps %r not matched, not triggering', dp )
                continue

            if 'num_changed_dps_limit' in dp_action and num_dps > dp_action['num_changed_dps_limit']:
                #log.debug( 'too many dps set for %r, not triggering (max:%r have:%r)', dp, dp_action['num_changed_dps_limit'], num_dps )
                continue

            if 'trigger_on_sent' in dp_action and dp_action['trigger_on_sent'] != sent:
                log.debug( 'dps %r not to be triggered when sending, not triggering', dp )
                continue




            if 'set' in dp_action:
                log.info( 'Triggering action for %r dps %r = %r', dname, dp, dps[dp] )
                for s in dp_action['set']:
                    log.debug( '%r/%r %r', dname, dps, s )
                    dest_name = s[0]
                    if dest_name not in tuyadevs:
                        log.warning( 'Cannot trigger action for %r/%r: dest device does not exist! %r', dname, dps, s )
                        continue
                    dev_msg( SetMessage( *s ) )

    return have_change

def client_data( client, data, clients, tuyadevs ):
    pos = client.buf.find( b"\x04" )
    if pos >= 0:
        log.debug( 'client sent <ctrl>-d, pos: %r', pos )
        client.close()
        client.buf = client.buf[:pos] + b"\n"

    pos = client.buf.find( b"\n" )
    while pos >= 0:
        cmdstr = client.buf[:pos].strip()
        client.buf = client.buf[pos+1:]
        pos = client.buf.find( b"\n" )

        if not cmdstr:
            continue

        log.info( 'client sent cmd: %r', cmdstr )

        if cmdstr[0] in (ord('{'), '{'):
            try:
                cmd = json.loads( cmdstr )
            except:
                log.warning( 'client sent malformed cmd! %r', cmdstr )
                continue
        else:
            cmd = { 'cmd': cmdstr.decode() }

        client_json_command( client, cmd, clients, tuyadevs )


def client_json_command( client, cmd, clients, tuyadevs ):
    if 'cmd' in cmd:
        log.info( 'client sent json cmd: %r', cmd['cmd'] )
        if cmd['cmd'] == 'refresh':
            request_status_from_all( tuyadevs, client )
        elif cmd['cmd'] == 'norepeat':
            client.want_repeat = False
        elif cmd['cmd'] == 'repeat':
            client.want_repeat = True
        elif cmd['cmd'] == 'exit' or cmd['cmd'] == 'quit':
            client.close()
        elif cmd['cmd'] == 'DiE':
            running = False

        return

    if not (cmd and 'device' in cmd and cmd['device']):
        log.warning( 'client did not send device! %r', cmd )
        return

    dname = cmd['device']
    if dname not in tuyadevs:
        log.warning( 'client sent bad device id! %r', cmd )
        errstr = json.dumps( {'device':dname, "error": "Bad Device ID"} ).encode( 'utf8' )
        clients[sock].send_message( errstr )
        return

    if 'dps' not in cmd or not cmd['dps']:
        log.warning( 'client did not send dps! %r', cmd )
        errstr = json.dumps( {'device':dname, "error": "Missing dp"} ).encode( 'utf8' )
        clients[sock].send_message( errstr )
        return

    if 'value' not in cmd:
        log.warning( 'client did not send value! %r', cmd )
        errstr = json.dumps( {'device':dname, "error": "Missing value"} ).encode( 'utf8' )
        clients[sock].send_message( errstr )
        return

    if not (tuyadevs[dname].socket and tuyadevs[dname].readable):
        log.warning( 'device connection not open! %r', cmd )
        if not tuyadevs[dname].errmsg:
            tuyadevs[dname].errmsg = json.dumps( {'device':dname, "error": "No connection to device"} ).encode( 'utf8' )
        for csock in clients:
            clients[csock].send_message( tuyadevs[dname].errmsg )
        return

    dev_msg( SetMessage( dname, cmd['dps'], cmd['value'] ) )


# this is gonna block
# it can be written not to, I just don't have the time right now
for dname in tuyadevs:
    tuyadevs[dname].set_socketPersistent( True )
    tuyadevs[dname].socketRetryLimit = 1
    tuyadevs[dname].connection_timeout = 2
    tuyadevs[dname].errmsg = b''
    tuyadevs[dname].name = dname
    #if dname == 'lobby_relays':
    #    tuyadevs[dname].set_debug(True, True)
    #log.info( 'Device %r status: %r', dname, tuyadevs[dname].status() )
    tuyadevs[dname]._get_socket( True ) # this will block!
    socket_opened( tuyadevs[dname] )
    request_status( tuyadevs[dname] )


clients = {}
heartbeat_timer = time.time() + heartbeat_time
running = True

while running:
    try:
        if( heartbeat_timer < time.time() ):
            heartbeat_timer = time.time() + heartbeat_time
            refresh_counter -= 1
            log.debug( '                  HB                , poll in %r', refresh_counter )

            for sock in clients:
                if clients[sock].proto == CLIENT_PROTO_NONE:
                    if (clients[sock].time_connected + 6) < time.time():
                        log.info( 'No data from no-proto client in 6 seconds, assuming raw TCP' )
                        clients[sock].proto = CLIENT_PROTO_TCP #UNKNOWN
                        clients[sock].send_all_device_status( tuyadevs )

            if refresh_counter == 0:
                refresh_counter = 6
                for dname in tuyadevs:
                    tuyadevs[dname].need_status = True

            for dname in tuyadevs:
                #log.debug( 'looking at %r', dname )
                if tuyadevs[dname].socket and tuyadevs[dname].readable:
                    #log.debug( 'HB %r', dname )
                    tdiff = tuyadevs[dname].last_msg_time - tuyadevs[dname].last_send_time
                    if tdiff < -1:
                        log.warning( 'Device %r no response to last message!', dname )
                    if tuyadevs[dname].need_status:
                        request_status( tuyadevs[dname] )
                    else:
                        tuyadevs[dname].heartbeat(nowait=True)
                        tuyadevs[dname].last_send_time = time.time()
                elif tuyadevs[dname].reconnect_delay == 0:
                    log.info( 'Socket for %r not open!  Reopening...', dname )
                    if tuyadevs[dname].socket:
                        try:
                            tuyadevs[dname].socket.close()
                        except:
                            pass
                        tuyadevs[dname].socket = None
                    tuyadevs[dname]._get_socket( True ) # this will block!
                    socket_opened( tuyadevs[dname] )
                    if tuyadevs[dname].socket:
                        request_status( tuyadevs[dname] )
                    else:
                        for csock in clients:
                            if clients[csock].want_repeat:
                                clients[csock].send_message( tuyadevs[dname].errmsg )
                else:
                    log.info( 'Socket for %r not open, delaying reopen for %r', dname, tuyadevs[dname].reconnect_delay )
                    tuyadevs[dname].reconnect_delay -= 1
                    

        inputs = list( clients.keys() ) + [srv] + [tuyadevs[dname].socket for dname in tuyadevs if tuyadevs[dname].socket and tuyadevs[dname].readable]
        outputs = [tuyadevs[dname].socket for dname in tuyadevs if tuyadevs[dname].socket and tuyadevs[dname].writeable]
        outputs += [sock for sock in clients if clients[sock].proto == CLIENT_PROTO_WEBSOCKET and clients[sock].websocket.sendq]
        timeo = heartbeat_timer - time.time()

        if timeo <= 0:
            readable = []
            writable = []
        else:
            readable, writable, _ = select.select( inputs, outputs, [], timeo )

        for s in writable:
            log.info( 'FIXME: got a writable socket' )
            if sock in clients:
                if clients[sock].proto == CLIENT_PROTO_WEBSOCKET:
                    clients[sock].websocket.trySend()

                    if clients[sock].websocket.closed:
                        del clients[sock].websocket
                        del clients[sock]
                continue

            log.info( 'FIXME: got a writable socket' )
            for dname in tuyadevs:
                if tuyadevs[dname].socket == s:
                    tuyadevs[dname].writeable = False
                    tuyadevs[dname].readable = True


        #if readable:
        #    log.info( 'got a readable socket' )

        for sock in readable:
            if sock == srv:
                newsock, addr = sock.accept()
                log.info( 'new client connected: %r', addr )
                clients[newsock] = clientobj( newsock, addr )
                continue

            if sock in clients:
                if clients[sock].need_ssl_detect:
                    clients[sock].need_ssl_detect = False
                    try:
                        # read the 5-byte TLS header
                        peek = sock.recv( 5, socket.MSG_PEEK )
                        # 0 = record type
                        # 1-2 = version
                        # 3-4 = length
                        if peek[0] in (0x16, chr(0x16)) and peek[1] in (0x03, chr(0x03)):
                            ssl_sock = ssl_ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False, suppress_ragged_eofs=True)
                            clients[ssl_sock] = clients[sock]
                            del clients[sock]
                            sock = ssl_sock
                            clients[sock].sock = sock
                            clients[sock].is_ssl = True
                            clients[sock].need_ssl_handshake = True
                            sock.ssl_peekable_recv_finished = False
                            log.debug( 'Client is SSL: %r %r', vars(clients[sock]), vars(sock) )
                    except:
                        log.exception( 'Exception in client SSL detect' )

                if clients[sock].is_ssl:
                    if clients[sock].need_ssl_handshake:
                        try:
                            sock.do_handshake()
                            clients[sock].need_ssl_handshake = False
                            sock._ssl_peekable_recv_buf = b''
                            sock.ssl_peekable_recv_finished = False
                            sock._orig_recv = sock.recv
                            sock.recv = lambda want_bytes, flags=0: ssl_peekable_recv( sock, want_bytes, flags )
                            log.info( 'client SSL handshake complete!' )
                            # we probably don't have any data yet, so go back to select()
                            continue
                        except:
                            log.exception( 'Exception in client SSL handshake' )
                            continue
                    elif sock.ssl_peekable_recv_finished:
                        sock.ssl_peekable_recv_finished = False
                        # FIXME need lambda wrapper as well?
                        sock.recv = sock._orig_recv

                if not clients[sock].proto:
                    log.info( 'need client proto. %r', vars(clients[sock]) )
                    peek = sock.recv( 5, socket.MSG_PEEK )
                    if len(peek) < 5:
                        log.debug( 'Not enough client data to peek, assuming raw TCP' )
                        clients[sock].proto = CLIENT_PROTO_TCP
                        clients[sock].send_all_device_status( tuyadevs )
                    elif peek == b'GET /':
                        # websocket
                        log.debug( 'Client wants websocket' )
                        clients[sock].proto = CLIENT_PROTO_WEBSOCKET
                        clients[sock].websocket = ClientWebSocket( clients[sock], sock, clients[sock].addr )
                        clients[sock].send_all_device_status( tuyadevs )
                    elif clients[sock].buf[0] in (ord('{'), '{'):
                        log.debug( 'Client wants JSON' )
                        clients[sock].proto = CLIENT_PROTO_TCP
                        clients[sock].send_all_device_status( tuyadevs )
                    else:
                        log.debug( 'Unknown client wants, %r', peek )
                        clients[sock].proto = CLIENT_PROTO_UNKNOWN
                        clients[sock].send_all_device_status( tuyadevs )

                #if clients[sock].proto == CLIENT_PROTO_TCP:
                #    # raw or JSON
                #    pass
                if clients[sock].proto == CLIENT_PROTO_WEBSOCKET:
                    try:
                        clients[sock].websocket._handleData()
                    except: # Exception as e:
                        log.exception( 'Exception in websocket._handleData()' )
                        try:
                            clients[sock].proto = CLIENT_PROTO_NONE
                            sock.close()
                        except:
                            pass
                        clients[sock].websocket.closed = True

                    if clients[sock].websocket.messages:
                        for msg in clients[sock].websocket.messages:
                            log.debug( 'Websock client sent message: %r', msg )
                            try:
                                if type(msg) == str:
                                    msg = msg.encode( 'utf8' )
                                clients[sock].buf = msg + b"\n"
                                client_data( clients[sock], msg, clients, tuyadevs )
                            except:
                                log.exception( 'Exception handling websocket command!' )
                        clients[sock].websocket.messages = []

                    if clients[sock].websocket.closed:
                        del clients[sock].websocket
                        del clients[sock]
                    else:
                        clients[sock].websocket.trySend()
                        log.debug( '.websocket.trySend()' )

                    continue
                #else:
                #    data = sock.recv( 5000 )
                #    log.debug( 'Unknown client sent: %r', data )
                #    continue

                log.info('client: %r', vars(clients[sock]) )

                #for dname in tuyadevs:
                #    if tuyadevs[dname].socket and tuyadevs[dname].readable:
                #        newsock.sendall( json.dumps( {'device':dname, 'dps': tuyadevs[dname].state} ).encode( 'utf8' ) + b"\n" )
                #    else:
                #        if not tuyadevs[dname].errmsg:
                #            tuyadevs[dname].errmsg = json.dumps( {'device':dname, "error": "No connection to device"} ).encode( 'utf8' ) + b"\n"
                #        newsock.sendall( tuyadevs[dname].errmsg )

            try:
                data = sock.recv( 5000 )
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                # SSL socket not ready yet, try again later
                log.debug( 'SSL socket not ready yet, try again later' )
                continue
            except:
                data = None

            if sock in clients:
                if not data:
                    log.info( 'client socket closed' )
                    clients[sock].close()
                    del clients[sock]
                    continue

                clients[sock].buf += data
                log.info( "TCP rec'd: %r", clients[sock].buf)

                if not clients[sock].proto:
                    if clients[sock].buf[0] in (ord('{'), '{'):
                        clients[sock].proto = 1
                elif clients[sock].proto > 2:
                    pass

                client_data( clients[sock], data, clients, tuyadevs )

                if clients[sock].closed:
                    del clients[sock]

                continue

            tdname = None
            for	dname in tuyadevs:
                if tuyadevs[dname].socket == sock:
                    tdname = dname
                    break

            if tdname:
                dname = tdname
                #if dname == 'lobby_relays':
                #    log.warning( '%r got data: %r', dname, data )

                if not data:
                    log.warning( 'tuya %r socket closed! time open: %r, last send: %r, last recv: %r - %r %r', dname, (time.time() - tuyadevs[dname].start_time), (time.time() - tuyadevs[dname].last_send_time), (time.time() - tuyadevs[dname].last_msg_time), tuyadevs[dname].id, tuyadevs[dname].address )
                    sock.close()
                    tuyadevs[dname].socket = None
                    tuyadevs[dname].readable = False
                    tuyadevs[dname].buf = b''
                    errmsg = {'device':dname, "error": "Lost connection to device", 'ts': datetime.now().isoformat(), 'last_msg': round(time.time() - tuyadevs[dname].last_msg_time, 3) }
                    tuyadevs[dname].errmsg = json.dumps( errmsg ).encode( 'utf8' )
                    log.warning( tuyadevs[dname].errmsg )
                    for csock in clients:
                        clients[csock].send_message( tuyadevs[dname].errmsg )
                    continue

                data = tuyadevs[dname].buf + data

                while len(data):
                    try:
                        prefix_offset = data.find(tinytuya.PREFIX_BIN)
                        if prefix_offset > 0:
                            data = data[prefix_offset:]
                        elif prefix_offset < 0: # not found
                            data = b''
                            break
                        hmac_key = tuyadevs[dname].local_key if tuyadevs[dname].version == 3.4 else None
                        msg = tinytuya.unpack_message(data, hmac_key=hmac_key)
                    except:
                        break

                    #odata = data
                    # this will not strip everything, but it will be enough for data.find() to skip over it
                    data = data[len(msg.payload)+8:]

                    last_msg = round( time.time() - tuyadevs[dname].last_msg_time, 3 )
                    tuyadevs[dname].last_msg_time = time.time()

                    if not msg:
                        log.debug( 'Got non-message from tuya device %r in %r', dname, last_msg )
                        continue

                    if last_msg > 11.5:
                        log.info( 'Got message %r (len:%d) from tuya device %r in %r', msg.cmd, len(msg.payload), dname, last_msg )

                    # ignore NULL packets
                    if len(msg.payload) == 0:
                        continue

                    #log.info( 'Got message from tuya device %r: %r (time: %r)', dname, msg, last_msg )

	                # Unpack Message into TuyaMessage format
                    # and return payload decrypted
                    try:
                        # Data available: seqno cmd retcode payload crc
                        result = tuyadevs[dname]._decode_payload( msg.payload )

                        if result is None:
                            log.warning("_decode_payload() failed!")
                    except:
                        log.warning("error unpacking or decoding tuya JSON payload", exc_info=True)
                        #result = error_json(ERR_PAYLOAD)
                        continue

                    result = tuyadevs[dname]._process_response( result )

                    #log.info( 'Final result: %r', result )

                    tuyadevs[dname].sending = False
                    is_poll_response = tuyadevs[dname].requested_status
                    tuyadevs[dname].requested_status = False
                    dev_send( tuyadevs[dname] )

                    if not result:
                        log.info( 'NOT result: %r', result )
                        result = { }

                    if 'dps' not in result and 'data' in result and 'dps' in result['data']:
                        result['dps'] = result['data']['dps']

                    if 'dps' in result and result['dps']:
                        send = { 'device': dname, 'dps': result['dps'] }
                        if dps_changed( dname, result['dps'] ):
                            log.info( 'Final result: %r', result )
                            is_poll_response = False
                    else:
                        log.info( 'Final result: %r', result )
                        send = { 'device': dname, 'rawdata': result }
                        is_poll_response = False

                    if 'ts' not in send:
                        send['ts'] = datetime.now().isoformat()
                    if 'last_msg' not in send:
                        send['last_msg'] = last_msg

                    send = json.dumps( send ).encode( 'utf8' )

                    for csock in clients:
                        if (not is_poll_response) or clients[csock].want_repeat:
                            clients[csock].send_message( send )

                tuyadevs[dname].buf = data

    except KeyboardInterrupt:
        log.exception( 'Main Loop Keyboard Interrupt!' )
        break
    except:
        log.exception( 'Main Loop Exception!' )
        break

srv.close()

for dname in tuyadevs:
    if tuyadevs[dname].socket:
        tuyadevs[dname].socket.close()

for s in clients:
    clients[s].close()
