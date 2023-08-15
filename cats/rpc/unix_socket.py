#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from .connection import RPCConnectionError, Stream, StreamConnection, IConnection
from struct import pack,unpack
from typing import BinaryIO
from ..utils import logutils
import select

import socket
import os

class SocketStream(Stream):
    """Stream with UNIX Domain Socket

    """
    def __init__(self, sock:socket.socket):
        self._socket:socket.socket = sock
        
    def recv_bytes(self, nbytes: int, timeout_sec: float = None) -> bytes | None:
        result = list()
        total_recvd = 0
        
        try:
            while total_recvd < nbytes:
                if self.wait_recvable(timeout_sec=timeout_sec) == False:
                    raise RPCConnectionError("timeout in recv")
                
                blob = self._socket.recv(nbytes-total_recvd)
                if len(blob) == 0:
                    return None
                
                total_recvd += len(blob)
                result.append(blob)
            
            return b''.join(result)
        except OSError as e:
            raise RPCConnectionError("failed in recv_bytes") from e

    
    def send_bytes(self, blob: bytes):
        total_sent = 0

        try:
            while total_sent < len(blob):
                sent = self._socket.send(blob[total_sent:])
                total_sent += sent
        except OSError as e:
            raise RPCConnectionError("failed in send_bytes") from e
    
    def wait_recvable(self, *, timeout_sec=None) -> bool:
        try:
            rlist = [self._socket]
            readable, *_ = select.select(rlist,[],[],timeout_sec)
            if len(readable) > 0:
                return True
            else:
                return False
        except OSError as e:
            raise RPCConnectionError("failed in select")
    
    def close_recv(self):
        try:
            self._socket.shutdown(socket.SHUT_RD)
        except OSError as e:
            raise RPCConnectionError("failed in shutdown(SHUT_RD)") from e
    
    def close_send(self):
        try:
            self._socket.shutdown(socket.SHUT_WR)
        except OSError as e:
            raise RPCConnectionError("failed in shutdown(SHUT_WR)") from e
        
    
    def close(self):
        try:
            self._socket.close()
        except OSError as e:
            raise RPCConnectionError("failed in close") from e

    
        
    

class ServerSocket:
    """Unix Domain Socket Server
    """
    
    def __init__(self,path_to_socket:str,*,backlog:int=None):
        """
        Parameters
        ----------
        path_to_socket : str
            UNIX Domain Socket path
        backlog : int, optional
            length of connection queue, by default None

        Raises
        ------
        RPCConnectionError
            failed in Unix Domain Socket
        """
        self._ssocket = None
        self._bound_to= None
        
        self._ssocket:socket.socket = socket.socket(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
        try:
            self._ssocket.bind(path_to_socket)
            self._bound_to=path_to_socket
        except OSError as e:
            self.close()                
            raise RPCConnectionError("failed in bind") from e
        
        try:
            if backlog is not None:
                self._ssocket.listen(backlog)
            else:
                self._ssocket.listen()
        except OSError as e:
            self.close()
            raise RPCConnectionError("failed in listen") from e
                
    def accept(self)->StreamConnection:
        """

        Returns
        -------
        IConnection
            Communication channel to client

        Raises
        ------
        RPCConnectionError
            failed in connection
        """
        if self.is_closed():
            raise RPCConnectionError("Call accept in close state")
        
        try:
            sock, peer_info = self._ssocket.accept()
        except OSError as e:
            raise RPCConnectionError("failed in accept") from e
        
        return StreamConnection(SocketStream(sock))
    
    def close(self):
        """
        """
        if self._ssocket is not None:
            self._ssocket.close()
            self._ssocket = None
        
        if self._bound_to is not None:
            os.unlink(self._bound_to)
            self._bound_to = None
    
    def is_closed(self)->bool:
        """
        if closed, return True

        Returns
        -------
        bool
            True: socket is close, False: socket is open
        """
        return self._bound_to is None
    
    def __enter__(self):
        return self
    
    def __exit__(self,exc_type, exc_value, traceback):
        self.close()
    
    
            


        
def connect(path_to_socket:str)->StreamConnection:
    """Connect server by Unix Domain Socket
    

    Parameters
    ----------
    path_to_socket : str
        Unix Domain Socket path

    Returns
    -------
    StreamConnection
        Communication channel

    Raises
    ------
    RPCConnectionError
        failed in connection to Unix Domain Socket
    """
    sock = socket.socket(family=socket.AF_UNIX, type=socket.SOCK_STREAM)
    try:
        sock.settimeout(0)
        sock.connect(path_to_socket)
        
        sock.settimeout(None)
    except OSError as e:
        sock.close()
        raise RPCConnectionError("failed in connect") from e
    
    return StreamConnection(SocketStream(sock))
        
        
        