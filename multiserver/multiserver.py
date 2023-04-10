#!/usr/bin/env python
# -*- coding: utf-8 -*-
# PYTHON_ARGCOMPLETE_OK

import logging

#logging.basicConfig( encoding='utf-8', level=logging.DEBUG )

import sys
import time
import json
import socket
import select
import ssl
from os import dup
from datetime import datetime
from hashlib import md5,sha256
from collections import namedtuple
import argparse

try:
    import argcomplete
    HAVE_ARGCOMPLETE = True
except:
    HAVE_ARGCOMPLETE = False

#logging.basicConfig( encoding='utf-8', level=logging.DEBUG )
logging.basicConfig( encoding='utf-8', level=logging.INFO )

import tinytuya
import tinytuya.scanner

from ClientWebSocketHandler import ClientWebSocketHandler
from ClientHTTPHandler import ClientHTTPHandler

log = logging.getLogger( 'main' )
#tinytuya.set_debug(False, True)

default_tls_certs = (
    ('/etc/letsencrypt/live/this_site/fullchain.pem', '/etc/letsencrypt/live/this_site/privkey.pem', None),
    ('localhost.pem', None, None)
)

heartbeat_time = 10
refresh_counter = 6

disc = '' #Reads PCAP files created by tcpdump and prints the traffic to/from Tuya devices.  Local keys are loaded from devices.json.'
epi = 'If the --device-list file cannot be loaded, "devices.json" is then tried.  If neither can be loaded then devices need to be added via the API.'
arg_parser = argparse.ArgumentParser( description=disc, epilog=epi )
arg_parser.add_argument( '-d', '--device-list', help='List of devices to use, in JSON format [default: "devicelist.json" (fallback: "devices.json")]', default='devicelist.json' )
arg_parser.add_argument( '-a', '--actions-list', help='List of actions (scene triggers) to use, in JSON format [default: "actions.json"]', default='actions.json' )
arg_parser.add_argument( '--all-devices', help='List of all-devices to use, in JSON format [default: "devices.json"]', default='devices.json' )
arg_parser.add_argument( '-l', '--listen-host', help='IP address to listen on [default: "::"]', default='::' )
arg_parser.add_argument( '-p', '--listen-port', help='IP port to listen on [default: 9997]', type=int, default=9997 )
arg_parser.add_argument( '-c', '--tls-cert', help='File to read TLS Certificate chain from [default: "localhost.pem"]', metavar='certificate.pem' )
arg_parser.add_argument( '-k', '--tls-key', help='File to read TLS Key from (if not in Certificate file) [default: same file as Certificate]', metavar='keyfile.pem' )
arg_parser.add_argument( '--tls-key-password', help='Password for TLS Key [default: None]' )
arg_parser.add_argument( '--skip-initial-scan', help='', action='store_true' )


if HAVE_ARGCOMPLETE:
    argcomplete.autocomplete( arg_parser )

args = arg_parser.parse_args()

log.setLevel( logging.DEBUG )

#wantdevs = {}
#wantdevs['dev1'] = tinytuya.Device( 'eb...v', '172.20.10.', '...key...', version=3.4 )
#wantdevs['dev2'] = tinytuya.Device( '83...a', '172.20.10.', '...key...', version=3.3 )

class PeekableSocket:
    def __init__( self, cls, *args, **kwargs ):
        print('MyPeekableSocket')
        self._peekable_recv_buf = b''
        self.peekable_recv_started = False
        self.peekable_recv_finished = False
        self.parent_class = cls

    def _peekable_recv( self, want_bytes, flags=0 ):
        print( 'PeekableSocket recv', self)
        print( want_bytes, flags )
        if flags == socket.MSG_PEEK:
            if want_bytes > len(self._peekable_recv_buf):
                try:
                    self._peekable_recv_buf += self._orig_recv( self, (want_bytes - len(self._peekable_recv_buf)), 0 )
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    if not self._peekable_recv_buf:
                        raise
            return self._peekable_recv_buf
        elif flags:
            return self._orig_recv( self, want_bytes, flags )

        if want_bytes < len( self._peekable_recv_buf ):
            ret = self._peekable_recv_buf[:want_bytes]
            self._peekable_recv_buf = self._peekable_recv_buf[want_bytes:]
            return ret

        ret = self._peekable_recv_buf
        self._peekable_recv_buf = b''
        self.peekable_recv_finished = True
        self.recv = self._restore_recv

        if want_bytes == len( self._peekable_recv_buf ):
            return ret

        try:
            return ret + self._orig_recv( self, (want_bytes - len(ret)), flags )
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
            if ret:
                return ret
            raise

    def peekable_sock_start( self ):
        self.peekable_recv_started = True
        self.peekable_recv_finished = False
        self.recv = self._peekable_recv

class PlainPeekableSocket( socket.socket, PeekableSocket ):
    def __init__( self, *args, **kwargs ):
        print('My Plain PeekableSocket')
        #super( PlainPeekableSocket, self ).__init__(*args, **kwargs)
        socket.socket.__init__( self, *args, **kwargs )
        PeekableSocket.__init__( self, socket.socket, *args, **kwargs )
        self._orig_recv	= socket.socket.recv
        self._restore_recv = socket.socket.recv

    @classmethod
    def copy(cls, sock):
        fd = dup(sock.fileno())
        copy = cls(sock.family, sock.type, sock.proto, fileno=fd)
        copy.settimeout(sock.gettimeout())
        copy.peekable_sock_start()
        return copy

class TLSPeekableSocket( ssl.SSLSocket, PeekableSocket ):
    #def __init__( self, *args, **kwargs ):
    #    print('My TLS PeekableSocket')
    #    #super( TLSPeekableSocket, self ).__init__(*args, **kwargs)
    #    ssl.SSLSocket.__init__( self, *args, **kwargs )
    #    PeekableSocket.__init__( self, ssl.SSLSocket, *args, **kwargs )

    def peekable_sock_start( self ):
        #self._orig_recv = lambda want_bytes, flags=0: ssl.SSLSocket.recv( self, want_bytes, flags )
        self._orig_recv = ssl.SSLSocket.recv
        self._restore_recv = lambda want_bytes, flags=0: ssl.SSLSocket.recv( self, want_bytes, flags )
        self._peekable_recv_buf = b''
        return PeekableSocket.peekable_sock_start( self )

def load_tls_context( tls_cert, tls_key=None, tls_key_password=None, default_tls_certs=[], err_not_found=True ):
    warnings = []
    if tls_cert:
        ssl_ctx, err = _load_tls_context( tls_cert, tls_key, tls_key_password, err_not_found=err_not_found )
        warnings += err
    else:
        for tls_cert, tls_key, tls_key_password in default_tls_certs:
            try:
                ssl_ctx, err = _load_tls_context( tls_cert, tls_key, tls_key_password, err_not_found=False )
                warnings += err
            except:
                msg = 'Exception while loading TLS certs! Cert:%r Key:%r' % (tls_cert, tls_key)
                log.exception( msg )
                warnings += [ msg ]
                ssl_ctx = None
            if ssl_ctx:
                log.info( 'Loaded TLS Certificate files: Cert:%r Key:%r', tls_cert, tls_key )
                warnings = err
                break
    return ssl_ctx, warnings

def _load_tls_context( tls_cert, tls_key=None, tls_key_password=None, err_not_found=True ):
    err = []
    if tls_cert:
        try:
            # python 3.6+ only
            ssl_ctx = ssl.SSLContext( ssl.PROTOCOL_TLS_SERVER )
        except:
            ssl_ctx = ssl.SSLContext()

        ssl_ctx.sslsocket_class = TLSPeekableSocket
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

        try:
            ssl_ctx.load_cert_chain(tls_cert, keyfile=tls_key, password=tls_key_password)
            ##ssl_ctx.load_verify_locations(cafile='/etc/pki/tls/certs/.ca.crt') #, capath=None, cadata=None)
            #ss = ssl_ctx.wrap_socket(s, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True) #, server_hostname='example.com')
            ssl_ctx.certfiles = (tls_cert, tls_key, tls_key_password)
        except FileNotFoundError:
            if err_not_found:
                log.error( 'TLS cert or key file not found!  Cert:%r Key:%r', tls_cert, tls_key )
                raise
            ssl_ctx = None
            err.append( 'TLS cert or key file not found!  Cert:%r Key:%r' % (tls_cert, tls_key) )
    else:
        ssl_ctx = None
        log.error( 'No TLS cert given' )
        err.append( 'No TLS cert given' )

    return ssl_ctx, err

ssl_ctx, warnings = load_tls_context( args.tls_cert, args.tls_key, args.tls_key_password, default_tls_certs )

srv = socket.socket( socket.AF_INET6, socket.SOCK_STREAM )
#srv.setblocking( False )
srv.setsockopt( socket.SOL_SOCKET, socket.SO_REUSEADDR, 1 )
srv.bind( (args.listen_host, args.listen_port) )
srv.listen()

CLIENT_PROTO_NONE      = 0
CLIENT_PROTO_TCP       = 1
CLIENT_PROTO_WEBSOCKET_OR_HTTP = 2
CLIENT_PROTO_WEBSOCKET = 3
CLIENT_PROTO_HTTP      = 4
CLIENT_PROTO_MQTT      = 5
CLIENT_PROTO_UNKNOWN   = 6

SetMessage = namedtuple( 'SetMessage', 'device dps value')

NAME_STRIP_CHARS = { i: None for i in range(0, 256) if( (i < 0x23) or (i > 0x39 and i < 0x40) or (i == 0x60) or (i > 0x7f) ) }

class dataobj:
    def __init__( self, log, args, ssl_ctx ):
        self.clients = {}
        self.alldevs = {}
        self.dev_byname = {}
        self.dev_byid = {}
        self.searchdevs = {}
        self.actions = {}
        self.log = log
        self.args = args
        self.client_messages = []
        self.running = True
        self.ssl_ctx = ssl_ctx

    def load_files( self, devicelistfile, devicesfile, actionsfile ):
        wantdevs = {}
        olddevs = self.dev_byid
        self.dev_byname = {}
        self.dev_byid = {}
        self.searchdevs = {}
        warnings = []

        try:
            with open( devicelistfile, 'r' ) as fp:
                searchlist = json.load( fp )
        except:
            msg = 'Load device list file %r failed, ignoring' % devicelistfile
            self.log.info( msg )
            warnings.append( msg )
            searchlist = None

        if (not searchlist) and (not wantdevs):
            try:
                with open( devicesfile, 'r' ) as fp:
                    searchlist = json.load( fp )
            except:
                try:
                    with open( 'devices.json', 'r' ) as fp:
                        searchlist = json.load( fp )
                except:
                    pass

        try:
            with open( devicesfile, 'r' ) as fp:
                alldevices = json.load( fp )
        except:
            if devicesfile == 'devices.json':
                msg = 'Load all-devices file %r failed, ignoring' % devicesfile
                self.log.info( msg )
                warnings.append( msg )
            else:
                msg = 'Load all-devices file %r failed, falling back to %r' % (devicesfile, 'devices.json')
                self.log.info( msg )
                warnings.append( msg )
                try:
                    with open( 'devices.json', 'r' ) as fp:
                        alldevices = json.load( fp )
                except:
                    msg = 'Load backup all-devices file %r failed, ignoring' % 'devices.json'
                    self.log.info( msg )
                    warnings.append( msg )
                    alldevices = []

        self.alldevices = {}
        for i in alldevices:
            k = i['id']
            self.alldevices[k] = i
        del alldevices

        try:
            with open( actionsfile, 'r' ) as fp:
                self.actions = json.load( fp )
        except:
            msg = 'Load actions file %r failed, ignoring' % actionsfile
            self.log.info( msg )
            warnings.append( msg )
            self.actions = {}

        #for dname in wantdevs:
        #    did = wantdevs[dname]['id']
        #    if did in olddevs and olddevs[did].socket and olddevs[did].readable:
        #        self.dev_byid[did] = olddevs[did]
        #        del olddevs[did]
        #    else:
        #        self.searchdevs[did] = wantdevs[dname]

        if searchlist:
            for i in searchlist:
                did = i['id']
                if did in olddevs and olddevs[did].socket and olddevs[did].readable:
                    dname = olddevs[did].name
                    if dname in self.dev_byname:
                        idx = 1
                        dname2 = dname + '#' + str(idx)
                        while dname2 in self.dev_byname:
                            idx += 1
                            dname2 = dname + '#' + str(idx)
                        dname = dname2
                        olddevs[did].name = dname2
                    self.dev_byid[did] = olddevs[did]
                    self.dev_byname[dname] = olddevs[did]
                    del olddevs[did]
                elif did not in self.dev_byid:
                    if 'object' not in i:
                        i['object'] = 'Device'
                    self.searchdevs[did] = i
            del searchlist

        for did in olddevs:
            if olddevs[did].socket:
                olddevs[did].close()

        return warnings

    def found_device( self, did, devdata ):
        if 'dev_type' not in devdata: devdata['dev_type'] = 'default'
        name = orig_name = did if 'name' not in self.searchdevs[did] else self.searchdevs[did]['name']
        tdev = getattr(tinytuya, self.searchdevs[did]['object'])( did, devdata['ip'], self.searchdevs[did]['key'], version=devdata['version'], dev_type=devdata['dev_type'] )

        name = name.replace( ' ', '_' ).translate( NAME_STRIP_CHARS )

        if name in self.dev_byname:
            idx = 1
            name2 = name + '#' + str(idx)
            while name2 in self.dev_byname:
                idx += 1
                name2 = name + '#' + str(idx)
            name = name2

        tdev.set_socketPersistent( True )
        tdev.socketRetryLimit = 1
        tdev.connection_timeout = 2
        tdev.readable = False
        tdev.writeable = False
        tdev.errmsg = b''
        tdev.name = name
        tdev.orig_name = orig_name
        ##if dname == 'lobby_relays':
        ##    tdev.set_debug(True, True)
        ##log.info( 'Device %r status: %r', dname, tdev.status() )
        #tdev._get_socket( True ) # this will block!
        #device_socket_opened( tdev )
        #request_status( BigDataObj.dev_byname[dname] )
        tdev.reconnect_delay = 0
        tdev.errmsg = json.dumps( {'device':name, 'id':did, "error": "Waiting to connect to device"} )
        tdev.buf = b''
        tdev.need_status = True
        tdev.requested_status = False
        tdev.sending = False
        tdev.send_queue = []
        tdev.state = {}
        tdev.start_time = tdev.last_send_time = tdev.last_msg_time = time.time()

        self.dev_byname[name] = tdev
        self.dev_byid[did] = tdev

    def remove_client( self, sock ):
        if self.clients[sock].proto == CLIENT_PROTO_WEBSOCKET:
            del self.clients[sock].socket_handler
        elif self.clients[sock].proto == CLIENT_PROTO_HTTP:
            del self.clients[sock].socket_handler
        del self.clients[sock]

    def client_message( self, client, msg ):
        if type(msg) == str:
            msg = msg.encode( 'utf8' )
        if msg[-1:] != b"\n":
            msg += b"\n"
        self.client_messages.append( (client, msg) )

BigDataObj = dataobj( log, args, ssl_ctx )

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
        if isinstance( msg, dict ):
            msg = json.dumps( msg )

        if self.closed:
            log.debug( 'Client already closed, not sending msg' )
        elif not self.proto:
            log.debug( 'No client proto, not sending msg' )
        elif self.proto == CLIENT_PROTO_TCP or self.proto == CLIENT_PROTO_UNKNOWN:
            # raw or JSON
            try:
                if type(msg) == str:
                    msg = msg.encode(' utf8' )
                self.sock.sendall( msg + b"\n" )
            except:
                log.exception( 'Client send msg failed! addr:%r msg:%r', self.addr, msg )
        elif self.proto == CLIENT_PROTO_WEBSOCKET:
            try:
                if type(msg) == bytes:
                    msg = msg.decode()
            except:
                pass

            if self.socket_handler.closed:
                return
            elif self.socket_handler.opened:
                self.socket_handler.sendMessage( msg )
                self.socket_handler.trySend()
            else:
                self.socket_handler.send_queue.append( msg )
        else:
            log.debug( 'Unknown client proto %r, not sending msg', self.proto )

    def send_all_device_status( self, BigDataObj ):
        if self.closed:
            log.debug( 'Client already closed, not sending all' )
        elif not self.proto:
            log.debug( 'No client proto, not sending all' )
        else:
            for dname in BigDataObj.dev_byname:
                self.send_message( current_status( BigDataObj.dev_byname[dname] ) )

    def close( self ):
        log.debug( 'Client connection closed.', exc_info=True )
        self.closed = True
        if self.proto == CLIENT_PROTO_WEBSOCKET:
            self.socket_handler.close()
            return

        try:
            self.sock.close()
        except:
            pass


def device_socket_opened( tdev ):
    #log.info('opened: %r', tdev.socket)
    if tdev.socket:
        #tdev.set_socketPersistent( True )
        tdev.socket.setblocking( False )
        tdev.readable = True
        tdev.errmsg = b''
        tdev.reconnect_delay = 0
    else:
        log.warning( 'device_socket_opened(): socket not open! device %r', tdev.name )
        tdev.readable = False
        tdev.errmsg = json.dumps( {'device':tdev.name, 'id':tdev.id, "error": "Connect to device failed"} )
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
        return json.dumps( {'device':tdev.name, 'id':tdev.id, 'dps': tdev.state} )
    else:
        if not tdev.errmsg:
            tdev.errmsg = json.dumps( {'device':tdev.name, 'id':tdev.id, "error": "No connection to device"} )
        return tdev.errmsg

def request_status( tdev ):
    if tdev.socket and tdev.readable:
        tdev.need_status = False
        tdev.requested_status = True
        tdev._send_receive( tdev.generate_payload( tinytuya.DP_QUERY ), getresponse=False )
        tdev.last_send_time = time.time()
        return True
    return False

def request_status_from_all( BigDataObj, client=None ):
    for dname in BigDataObj.dev_byname:
        if BigDataObj.dev_byname[dname].socket and BigDataObj.dev_byname[dname].readable:
            BigDataObj.dev_byname[dname].need_status = True
        elif client:
            client.send_message( current_status( BigDataObj.dev_byname[dname] ) )

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
    global BigDataObj
    tdev = BigDataObj.dev_byname[msg.device]
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
    global BigDataObj

    tdev = BigDataObj.dev_byname[dname]
    dev_actions = {} if dname not in BigDataObj.actions else BigDataObj.actions[dname]
    num_dps = len(dps)
    have_change = []

    for dp in dps:
        dp = str(dp)
        if dp not in tdev.state:
            added = True
            changed = False
            old_val = None
            have_change.append( dp )
        else:
            added = False
            changed = tdev.state[dp] != dps[dp]
            old_val = tdev.state[dp]
            if changed: have_change.append( dp )

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
                    if dest_name not in BigDataObj.dev_byname:
                        log.warning( 'Cannot trigger action for %r/%r: dest device does not exist! %r', dname, dps, s )
                        continue
                    dev_msg( SetMessage( *s ) )

    return have_change

def process_client_messages( BigDataObj ):
    for client, msg in BigDataObj.client_messages:
        client_data( client, msg, BigDataObj )
    BigDataObj.client_messages = []

def client_data( client, data, BigDataObj ):
    pos = data.find( b"\x04" )
    if pos >= 0:
        log.debug( 'client sent <ctrl>-d, pos: %r', pos )
        client.close()
        data = data[:pos] + b"\n"

    pos = data.find( b"\n" )
    while pos >= 0:
        cmdstr = data[:pos].strip()
        data = data[pos+1:]
        pos = data.find( b"\n" )

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

        client_json_command( client, cmd, BigDataObj )

    return data

def client_json_command( client, cmd, BigDataObj ):
    if 'cmd' in cmd:
        log.info( 'client sent json cmd: %r', cmd['cmd'] )
        cmd_ok = True
        warnings = []
        if cmd['cmd'] == 'refresh':
            request_status_from_all( BigDataObj, client )
        elif cmd['cmd'] == 'norepeat':
            client.want_repeat = False
        elif cmd['cmd'] == 'repeat':
            client.want_repeat = True
        elif cmd['cmd'] == 'exit' or cmd['cmd'] == 'quit':
            client.close()
        elif cmd['cmd'] == 'DiE':
            BigDataObj.running = False
        elif cmd['cmd'] == 'reload_devices':
            # FIXME parse from JSON
            devicelist = self.args.device_list if( 'devicelist' not in cmd or not cmd['devicelist'] ) else cmd['devicelist']
            devices = self.args.all_devices if( 'alldevices' not in cmd or not cmd['alldevices'] ) else cmd['alldevices']
            actions = self.args.actions_list if( 'actions' not in cmd or not cmd['actions'] ) else cmd['actions']
            warnings = BigDataObj.load_files(  devicelist, devices, actions )
        elif cmd['cmd'] == 'reload_cert':
            if 'cert' in cmd and cmd['cert']:
                cert = cmd['cert']
                key = None if( 'key' not in cmd or not cmd['key'] ) else cmd['key']
                passwd = None if( 'password' not in cmd or not cmd['password'] ) else cmd['password']
            elif BigDataObj.ssl_ctx:
                cert, key, passwd = BigDataObj.ssl_ctx.certfiles
            else:
                cert = key = passwd = None

            ssl_ctx, warnings = load_tls_context( cert, tls_key=key, tls_key_password=passwd, default_tls_certs=default_tls_certs, err_not_found=False )
            BigDataObj.ssl_ctx = ssl_ctx
        else:
            cmd_ok = False

        if cmd_ok:
            cmd['success'] = True
            if warnings:
                cmd['error'] = warnings
        else:
            cmd['success'] = False
            cmd['error'] = 'No Such Command'

        cmd['response-for'] = cmd['cmd']
        del cmd['cmd']
        client.send_message( cmd )
        return

    if not (cmd and 'device' in cmd and cmd['device']):
        log.warning( 'client did not send device! %r', cmd )
        return

    dname = cmd['device']
    if dname not in BigDataObj.dev_byname:
        log.warning( 'client sent bad device id! %r', cmd )
        errstr = json.dumps( {'device':dname, "error": "Bad Device ID"} )
        client.send_message( errstr )
        return

    tdev = BigDataObj.dev_byname[dname]
    if 'dps' not in cmd or not cmd['dps']:
        log.warning( 'client did not send dps! %r', cmd )
        errstr = json.dumps( {'device':dname, 'id':tdev.id, "error": "Missing dp"} )
        client.send_message( errstr )
        return

    if 'value' not in cmd:
        log.warning( 'client did not send value! %r', cmd )
        errstr = json.dumps( {'device':dname, 'id':tdev.id, "error": "Missing value"} )
        client.send_message( errstr )
        return

    if not (BigDataObj.dev_byname[dname].socket and BigDataObj.dev_byname[dname].readable):
        log.warning( 'device connection not open! %r', cmd )
        if not BigDataObj.dev_byname[dname].errmsg:
            BigDataObj.dev_byname[dname].errmsg = json.dumps( {'device':dname, 'id':tdev.id, "error": "No connection to device"} )
        for csock in BigDataObj.clients:
            BigDataObj.clients[csock].send_message( BigDataObj.dev_byname[dname].errmsg )
        return

    dev_msg( SetMessage( dname, cmd['dps'], cmd['value'] ) )

BigDataObj.load_files(  args.device_list, args.all_devices, args.actions_list )

if not args.skip_initial_scan:
    searchlist = list(BigDataObj.searchdevs.keys())
    notfound = {}

    if searchlist:
        log.info( 'Searching for %d devices, please wait...', len(searchlist) )
        found = tinytuya.scanner.devices( verbose=False, scantime=8, poll=False, byID=True, wantids=searchlist )
        for i in BigDataObj.searchdevs.keys():
            if i in found:
                BigDataObj.found_device( i, found[i] )
            else:
                notfound[i] = '' if 'name' not in BigDataObj.searchdevs[i] else BigDataObj.searchdevs[i]['name']

    if notfound:
        log.warning( 'Warning: the following devices were not found: %r', notfound )
    else:
        log.info( 'All %d devices found', len(BigDataObj.searchdevs) )

heartbeat_timer = time.time() + heartbeat_time

while BigDataObj.running:
    try:
        process_client_messages( BigDataObj )

        if( heartbeat_timer < time.time() ):
            heartbeat_timer = time.time() + heartbeat_time
            refresh_counter -= 1
            max_connect = time.time() + 10
            log.debug( '                  HB                , poll in %r', refresh_counter )

            for sock in BigDataObj.clients:
                if BigDataObj.clients[sock].proto == CLIENT_PROTO_NONE:
                    if (BigDataObj.clients[sock].time_connected + 6) < time.time():
                        log.info( 'No data from no-proto client in 6 seconds, assuming raw TCP' )
                        BigDataObj.clients[sock].proto = CLIENT_PROTO_TCP #UNKNOWN
                        BigDataObj.clients[sock].send_all_device_status( BigDataObj )

            if refresh_counter == 0:
                refresh_counter = 6
                for dname in BigDataObj.dev_byname:
                    BigDataObj.dev_byname[dname].need_status = True

            for dname in BigDataObj.dev_byname:
                tdev = BigDataObj.dev_byname[dname]
                #log.debug( 'looking at %r', dname )
                if tdev.socket and tdev.readable:
                    #log.debug( 'HB %r', dname )
                    tdiff = tdev.last_msg_time - tdev.last_send_time
                    if tdiff < -1:
                        log.warning( 'Device %r no response to last message!', dname )
                    if tdev.need_status:
                        request_status( tdev )
                    else:
                        tdev.heartbeat(nowait=True)
                        tdev.last_send_time = time.time()
                elif tdev.reconnect_delay == 0:
                    if time.time() > max_connect:
                        log.info( 'Socket for %r not open but loop time exceded, delaying until next HB', dname )
                        continue
                    log.info( 'Socket for %r not open!  Reopening...', dname )
                    if tdev.socket:
                        try:
                            tdev.socket.close()
                        except:
                            pass
                        tdev.socket = None
                    tdev._get_socket( True ) # this will block!
                    device_socket_opened( tdev )
                    if tdev.socket:
                        request_status( tdev )
                    else:
                        for csock in BigDataObj.clients:
                            if BigDataObj.clients[csock].want_repeat:
                                BigDataObj.clients[csock].send_message( tdev.errmsg )
                else:
                    log.info( 'Socket for %r not open, delaying reopen for %r', dname, tdev.reconnect_delay )
                    tdev.reconnect_delay -= 1
                    

        inputs = list( BigDataObj.clients.keys() ) + [srv] + [BigDataObj.dev_byname[dname].socket for dname in BigDataObj.dev_byname if BigDataObj.dev_byname[dname].socket and BigDataObj.dev_byname[dname].readable]
        outputs = [BigDataObj.dev_byname[dname].socket for dname in BigDataObj.dev_byname if BigDataObj.dev_byname[dname].socket and BigDataObj.dev_byname[dname].writeable]
        outputs += [sock for sock in BigDataObj.clients if( hasattr( BigDataObj.clients[sock], 'socket_handler' ) and BigDataObj.clients[sock].socket_handler.sendq )]
        timeo = heartbeat_timer - time.time()

        if timeo <= 0:
            readable = []
            writable = []
        else:
            readable, writable, _ = select.select( inputs, outputs, [], timeo )

        for s in writable:
            log.info( 'FIXME: got a writable socket' )
            if sock in BigDataObj.clients:
                client = BigDataObj.clients[sock]
                if client.proto == CLIENT_PROTO_WEBSOCKET:
                    client.socket_handler.trySend()

                    if client.closed:
                        BigDataObj.remove_client( sock )
                elif client.proto == CLIENT_PROTO_HTTP:
                    client.socket_handler.send()
                    if (not client.socket_handler.sendq) and client.socket_handler.close:
                        #log.info( 'Closing client HTTP connection' )
                        client.close()
                        BigDataObj.remove_client( sock )

                continue

            log.info( 'FIXME: got a writable socket' )
            for dname in BigDataObj.dev_byname:
                if BigDataObj.dev_byname[dname].socket == s:
                    BigDataObj.dev_byname[dname].writeable = False
                    BigDataObj.dev_byname[dname].readable = True


        #if readable:
        #    log.info( 'got a readable socket' )

        for sock in readable:
            if sock == srv:
                newsock, addr = sock.accept()
                log.info( 'new client connected: %r', addr )
                newsock.setblocking( False )
                BigDataObj.clients[newsock] = clientobj( newsock, addr )
                continue

            if sock in BigDataObj.clients:
                client = BigDataObj.clients[sock]
                if client.need_ssl_detect:
                    client.need_ssl_detect = False
                    try:
                        # read the 5-byte TLS header
                        peek = sock.recv( 5, socket.MSG_PEEK )
                        # 0 = record type
                        # 1-2 = version
                        # 3-4 = length
                        if peek[0] in (0x16, chr(0x16)) and peek[1] in (0x03, chr(0x03)):
                            if not BigDataObj.ssl_ctx:
                                log.error( 'Client wants TLS but no certificates loaded!' )
                                client.close()
                                BigDataObj.remove_client( sock )
                                continue
                            ssl_sock = BigDataObj.ssl_ctx.wrap_socket(sock, server_side=True, do_handshake_on_connect=False, suppress_ragged_eofs=True)
                            BigDataObj.clients[ssl_sock] = client
                            del BigDataObj.clients[sock]
                            sock = ssl_sock
                            client = BigDataObj.clients[sock]
                            client.sock = sock
                            client.is_ssl = True
                            client.need_ssl_handshake = True
                            log.debug( 'Client is SSL: %r %r', vars(client), vars(sock) )
                    except:
                        log.exception( 'Exception in client SSL detect!' )
                        client.close()
                        BigDataObj.remove_client( sock )
                        continue

                if client.is_ssl:
                    if client.need_ssl_handshake:
                        try:
                            sock.do_handshake()
                            client.need_ssl_handshake = False
                            log.info( 'client SSL handshake complete!' ) # %r', sock.__class__ )
                            sock.peekable_sock_start()
                            # we probably don't have any data yet, so go back to select()
                            continue
                        except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                            log.debug( 'SSL socket not ready yet (handshake), try again later' )
                            continue
                        except:
                            log.exception( 'Exception in client SSL handshake' )
                            continue
                    #elif sock.peekable_recv_started and sock.peekable_recv_finished:
                    #    sock.peekable_sock_end()

                if not client.proto:
                    log.info( 'need client proto. %r', vars(client) )
                    peek = sock.recv( 12, socket.MSG_PEEK )
                    if len(peek) < 5:
                        log.debug( 'Not enough client data to peek, assuming raw TCP' )
                        client.proto = CLIENT_PROTO_TCP
                        client.send_all_device_status( BigDataObj )
                    # websocket or HTTP
                    elif peek[:5] == b'GET /':
                        log.debug( 'Client wants websocket or http' )
                        client.proto = CLIENT_PROTO_WEBSOCKET_OR_HTTP

                        if not client.is_ssl:
                            # ssl is already peekable, make non-ssl peekable_recv
                            newsock = PlainPeekableSocket.copy( sock )
                            sock.close()
                            BigDataObj.clients[newsock] = client
                            del BigDataObj.clients[sock]
                            sock = client.sock = newsock

                    # HTTP only
                    elif peek[:6] == b'HEAD /' or peek[:6] == b'POST /' or peek[:5] == b'PUT /' or peek[:8] == b'DELETE /' or peek[:9] == b'OPTIONS /':
                        log.debug( 'Client wants HTTP(S)' )
                        client.proto = CLIENT_PROTO_HTTP
                        client.socket_handler = ClientHTTPHandler( sock, BigDataObj )
                    # JSON
                    elif client.buf[0] in (ord('{'), '{'):
                        log.debug( 'Client wants JSON' )
                        client.proto = CLIENT_PROTO_TCP
                        client.send_all_device_status( BigDataObj )
                    # MQTT Protocol Name bytes
                    elif peek.find( b"\x00\x04MQTT" ) > 0:
                        log.warning( 'Got MQTT client, but MQTT not implemented yet!' )
                        client.proto = CLIENT_PROTO_MQTT
                        client.close()
                        BigDataObj.remove_client( sock )
                        continue
                    # probably telnet ot netcat
                    elif client.buf[:2] == b"\r\n":
                        log.debug( 'Client wants RAW' )
                        client.proto = CLIENT_PROTO_TCP
                        client.send_all_device_status( BigDataObj )
                    else:
                        log.debug( 'Unknown client wants, %r', peek )
                        client.proto = CLIENT_PROTO_UNKNOWN
                        client.send_all_device_status( BigDataObj )

                #if client.proto == CLIENT_PROTO_TCP:
                #    # raw or JSON
                #    pass


                if client.proto == CLIENT_PROTO_WEBSOCKET_OR_HTTP:
                    peek = sock.recv( 65536, socket.MSG_PEEK )
                    log.info( 'websocket-or-http peeked: %r', peek )
                    if b'\r\n\r\n' not in peek and len(peek) < 65536:
                        log.info( 'websocket-or-http: no \\r\\n\\r\\n' )
                        continue

                    peek = peek.lower()
                    if (b'\r\nsec-websocket-key: ' in peek) and (b'\r\nupgrade: websocket\r\n' in peek):
                        client.proto = CLIENT_PROTO_WEBSOCKET
                        client.socket_handler = ClientWebSocketHandler( sock, BigDataObj )
                        client.send_all_device_status( BigDataObj )
                    else:
                        client.proto = CLIENT_PROTO_HTTP
                        client.socket_handler = ClientHTTPHandler( sock, BigDataObj )

                if client.proto == CLIENT_PROTO_WEBSOCKET:
                    need_handshake = not client.socket_handler.handshaked
                    try:
                        client.socket_handler._handleData()
                        if need_handshake and client.socket_handler.handshaked:
                            client.send_all_device_status( BigDataObj )
                    except: # Exception as e:
                        log.exception( 'Exception in websocket._handleData()' )

                        if client.socket_handler.handshaked and not client.socket_handler.closed:
                            client.socket_handler.close()
                            continue

                        client.proto = CLIENT_PROTO_NONE
                        client.close()
                        del client.socket_handler
                        BigDataObj.remove_client( sock )
                        continue

                    process_client_messages( BigDataObj )

                    if client.socket_handler.closed:
                        del client.socket_handler
                        BigDataObj.remove_client( sock )
                    else:
                        client.socket_handler.trySend()
                        log.debug( '.socket_handler.trySend()' )

                    continue
                #else:
                #    data = sock.recv( 5000 )
                #    log.debug( 'Unknown client sent: %r', data )
                #    continue

                log.info('client: %r', vars(client) )

                #for dname in BigDataObj.dev_byname:
                #    if BigDataObj.dev_byname[dname].socket and BigDataObj.dev_byname[dname].readable:
                #        newsock.sendall( json.dumps( {'device':dname, 'dps': BigDataObj.dev_byname[dname].state} )
                #    else:
                #        if not BigDataObj.dev_byname[dname].errmsg:
                #            BigDataObj.dev_byname[dname].errmsg = json.dumps( {'device':dname, "error": "No connection to device"} )
                #        newsock.sendall( BigDataObj.dev_byname[dname].errmsg )

            try:
                data = sock.recv( 65536 )
            except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                log.debug( 'SSL socket not ready yet, try again later' )
                continue
            except:
                data = None

            if sock in BigDataObj.clients:
                if not data:
                    log.info( 'client socket closed' )
                    BigDataObj.remove_client( sock )
                    continue

                client = BigDataObj.clients[sock]
                client.buf += data
                log.info( "TCP rec'd: %r, full buf: %r", data, client.buf)

                if not client.proto:
                    if client.buf[0] in (ord('{'), '{'):
                        client.proto = 1
                elif client.proto == CLIENT_PROTO_HTTP:
                    client.socket_handler.recv( data )
                    client.buf = b''

                    if (not client.socket_handler.sendq) and client.socket_handler.close:
                        client.close()
                        BigDataObj.remove_client( sock )
                    #elif sock.peekable_recv_started and sock.peekable_recv_finished:
                    #    sock.peekable_sock_end()

                    continue

                client.buf = client_data( client, client.buf, BigDataObj )

                if client.closed:
                    BigDataObj.remove_client( sock )
                    del client

                continue

            tdid = None
            for did in BigDataObj.dev_byid:
                if BigDataObj.dev_byid[did].socket == sock:
                    tdid = did
                    break

            if tdid:
                tdev = BigDataObj.dev_byid[tdid]
                dname = tdev.name
                #if dname == 'lobby_relays':
                #    log.warning( '%r got data: %r', dname, data )

                if not data:
                    log.warning( 'tuya %r socket closed! time open: %r, last send: %r, last recv: %r - %r %r', dname, (time.time() - tdev.start_time), (time.time() - tdev.last_send_time), (time.time() - tdev.last_msg_time), tdev.id, tdev.address )
                    sock.close()
                    tdev.socket = None
                    tdev.readable = False
                    tdev.buf = b''
                    errmsg = {'device':dname, 'id':tdev.id, "error": "Lost connection to device", 'ts': datetime.now().isoformat(), 'last_msg': round(time.time() - tdev.last_msg_time, 3) }
                    tdev.errmsg = json.dumps( errmsg )
                    log.warning( tdev.errmsg )
                    for csock in BigDataObj.clients:
                        BigDataObj.clients[csock].send_message( tdev.errmsg )
                    continue

                data = tdev.buf + data

                while len(data):
                    try:
                        prefix_offset = data.find(tinytuya.PREFIX_BIN)
                        if prefix_offset > 0:
                            data = data[prefix_offset:]
                        elif prefix_offset < 0: # not found
                            data = b''
                            break
                        hmac_key = tdev.local_key if tdev.version == 3.4 else None
                        msg = tinytuya.unpack_message(data, hmac_key=hmac_key)
                    except:
                        break

                    #odata = data
                    # this will not strip everything, but it will be enough for data.find() to skip over it
                    data = data[len(msg.payload)+8:]

                    last_msg = round( time.time() - tdev.last_msg_time, 3 )
                    tdev.last_msg_time = time.time()

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
                        result = tdev._decode_payload( msg.payload )

                        if result is None:
                            log.warning("_decode_payload() failed!")
                    except:
                        log.warning("error unpacking or decoding tuya JSON payload", exc_info=True)
                        #result = error_json(ERR_PAYLOAD)
                        continue

                    result = tdev._process_response( result )

                    #log.info( 'Final result: %r', result )

                    tdev.sending = False
                    is_poll_response = tdev.requested_status
                    tdev.requested_status = False
                    dev_send( tdev )

                    if not result:
                        log.info( 'NOT result: %r', result )
                        result = { }

                    if 'dps' not in result and 'data' in result and 'dps' in result['data']:
                        result['dps'] = result['data']['dps']

                    if 'dps' in result and result['dps']:
                        send = { 'device': dname, 'id': tdev.id, 'dps': tdev.state } #result['dps'] }
                        send['changed'] = dps_changed( dname, result['dps'] )
                        if send['changed']:
                            log.info( 'Final result: %r', result )
                            is_poll_response = False
                    else:
                        log.info( 'Final result: %r', result )
                        send = { 'device': dname, 'id': tdev.id, 'rawdata': result }
                        is_poll_response = False

                    if 'ts' not in send:
                        send['ts'] = datetime.now().isoformat()
                    if 'last_msg' not in send:
                        send['last_msg'] = last_msg

                    send = json.dumps( send )

                    for csock in BigDataObj.clients:
                        if (not is_poll_response) or BigDataObj.clients[csock].want_repeat:
                            BigDataObj.clients[csock].send_message( send )

                tdev.buf = data

    except KeyboardInterrupt:
        log.exception( 'Main Loop Keyboard Interrupt!' )
        break
    except:
        log.exception( 'Main Loop Exception!' )
        break

srv.close()

for dname in BigDataObj.dev_byname:
    if BigDataObj.dev_byname[dname].socket:
        BigDataObj.dev_byname[dname].socket.close()

for s in BigDataObj.clients:
    BigDataObj.clients[s].close()
