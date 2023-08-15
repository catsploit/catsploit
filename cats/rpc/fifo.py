#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from .connection import IConnection, Stream, RPCConnectionError, StreamConnection
from struct import pack,unpack
from typing import BinaryIO
from ..utils import logutils
import select

class FifoStream(Stream):
    def __init__(self, fd_send:BinaryIO, fd_recv:BinaryIO):
        self._send_fifo = fd_send
        self._recv_fifo = fd_recv

    def send_bytes(self, blob:bytes):
        """
        Parameters
        ----------
        blob : bytes
            send data
        """
        total_sent = 0

        try:
            while total_sent < len(blob):
                sent = self._send_fifo.write(blob[total_sent:])
                total_sent += sent
        except OSError as e:
            raise RPCConnectionError("Failed in sending FIFO") from e

    def recv_bytes(self, nbytes:int,*,timeout_sec=None)->bytes|None:
        """
        Parameters
        ----------
        nbytes : int
            read data size

        Returns
        -------
        bytes
            recieved data
        """
        result = list()

        total_recvd = 0
        
        try:
            while total_recvd < nbytes:
                if self.wait_recvable(timeout_sec=timeout_sec) == False:
                    raise RPCConnectionError("Timeout in recv")
                
                blob = self._recv_fifo.read(nbytes-total_recvd)
                if len(blob) == 0:
                    return None
                
                total_recvd += len(blob)
                result.append(blob)
            
            return b''.join(result)
        except OSError as e:
            raise RPCConnectionError("Recieve failed from FIFO") from e
        
    
    def wait_recvable(self,*,timeout_sec=None)->bool:
        rlist=[self._recv_fifo]
        
        try:
            readable, *_ = select.select(rlist,[],[],timeout_sec)

            if len(readable) > 0:
                return True
            else:
                return False
        except OSError as e:
            raise RPCConnectionError("Error in waiting data") from e
    
    def close_recv(self):
        self._recv_fifo.close()
    
    def close_send(self):
        self._send_fifo.close()
        
    def close(self):
        self._send_fifo.close()
        self._recv_fifo.close()

class DualFifo:   
    _logger = None
    @classmethod
    def logger(cls):
        if cls._logger is None:
            cls._logger = logutils.get_classlogger(cls)
        return cls._logger

    
    def __init__(self, fifo_to_server:str, fifo_to_client:str):
        """
        
        Parameters
        ----------
        fifo_to_server : str
            file path of FIFO client->server
        fifo_to_client : str
            file path of FIFO server->client
        """
        self._fifo_client_to_server = fifo_to_server
        self._fifo_server_to_client = fifo_to_client
    
    def connect_to_client(self) -> IConnection:
        """
        
        Returns
        -------
        FifoConnection
            client communication channel

        """
        self.logger().info("Start connect_to_client")
        fd_from_client = open(self._fifo_client_to_server,"rb",buffering=0)
        fd_to_client = open(self._fifo_server_to_client,"wb",buffering=0)
        
        conn=FifoConnection(fd_to_client, fd_from_client)
        self.logger().info("Finished connect_to_client")
        return conn
            
    
    def connect_to_server(self) -> IConnection:
        """
        Returns
        -------
        FifoConnection
            server communication channel

        """
        self.logger().info("Start connect_to_server")
        fd_to_server = open(self._fifo_client_to_server,"wb",buffering=0)
        fd_from_server = open(self._fifo_server_to_client,"rb",buffering=0)
        
        conn=FifoConnection(fd_to_server, fd_from_server)
        self.logger().info("Finished connect_to_server")
        return conn        

        
class FifoConnection(StreamConnection):
    def __init__(self, fd_send:BinaryIO, fd_recv:BinaryIO):
        """
        Parameters
        ----------
        fd_send : file
            file object of writing send FIFO
        fd_recv : file
            file object of reading recieve FIFO
        """
        fifo = FifoStream(fd_send, fd_recv)
        super().__init__(fifo)

            
    def send(self, blob: bytes):
        """

        Parameters
        ----------
        blob : bytes
            send data
        """
        super().send(blob)
        

    def recv(self,*,timeout_sec:float=None) -> bytes | None:
        """

        Returns
        -------
        bytes | None
            _description_
        """
        return super().recv(timeout_sec=timeout_sec)
        
            
        
        
    def close(self,*,timeout_sec=None):
        super().close(timeout_sec=timeout_sec)        
        




