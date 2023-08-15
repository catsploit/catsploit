#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from ..utils import logutils
from struct import pack, unpack

class RPCConnectionError(Exception):
    pass

class IConnection:
    """Abstract class for two-way communication channels
    
    This class is an abstract class to clarify the interface. Not intended to be instantiated directly.
    An example of a concrete class is FifoConnection.
    
    """
    def send(self, blob:bytes):
        """

        Parameters
        ----------
        blob : bytes
            _description_
        """
        raise NotImplementedError("send")
    
    def recv(self, *,timeout_sec:float=None)->bytes|None:
        """

        Parameters
        ----------
        timeout: float
            receive timeout
        Returns
        -------
        bytes|None
            recieved byte stream
        """
        raise NotImplementedError("recv")
    
    def wait_recvable(self,*,timeout_sec=None)->bool:
        """

        Parameters
        ----------
        timeout : float, optional
            timeout, by default None

        Returns
        -------
        bool
            True:recievable False:timeout
        """
        raise NotImplementedError("wait_recvable")
    
    def close(self,*,timeout_sec:float=None):
        raise NotImplementedError("close")
        
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
    

class Stream:
    def recv_bytes(self, nbytes:int, timeout_sec:float=None)->bytes|None:
        """
        
        Parameters
        ----------
        nbytes : int
            read data size
        timeout_sec: float, optional
            timeout(second), by default None
            
        Returns
        -------
        bytes
            recieved data
        """        
        raise NotImplementedError()
    
    def send_bytes(self, blob:bytes):
        """

        Parameters
        ----------
        blob : bytes
            send byte data
        """        
        raise NotImplementedError()

    def wait_recvable(self, *, timeout_sec=None) -> bool:
        """
        Parameters
        ----------
        timeout : float, optional
            timeout, by default None

        Returns
        -------
        bool
            True:recievable False:timeout
        """
        raise NotImplementedError()
        
    def close_recv(self):
        raise NotImplementedError
    
    def close_send(self):
        raise NotImplementedError
    
    def close(self):
        raise NotImplementedError
   
class StreamConnection(IConnection):
    def logger(self):
        if getattr(self,"_logger",None) is None:
            self._logger = logutils.get_classlogger( type(self) )
        return self._logger
    
    def __init__(self, stream:Stream):
        """

        Parameters
        ----------
        stream : Stream
            
        """
        self._stream = stream
           
    def recv(self, *, timeout_sec: float = None) -> bytes | None:
        """
        
        Parameters
        ----------
        timeout_sec : float, optional
            timeout(sec), by default None

        Returns
        -------
        bytes | None
            recieved data | if EOF detected, None

        Raises
        ------
        RPCConnectionError
            Error in communication
        """
        logger=self.logger()
        logger.info("start recv")
        
        stream = self._stream
        try:
            encoded_len_blob = stream.recv_bytes(4,timeout_sec=timeout_sec)
            if encoded_len_blob is None:
                logger.info("recv finished(EOF)")
                return None
            
            len_of_blob,*_ = unpack(">L", encoded_len_blob)
            logger.debug("recv header len=%d",len_of_blob)
            if len_of_blob == 0:
                return b''
            
            blob = stream.recv_bytes(len_of_blob,timeout_sec=timeout_sec)
            if blob is not None:
                logger.info("recv finished size=%d",len(blob))
            else:
                logger.info("recv finished(EOF)")
            return blob
        except RPCConnectionError:
            raise
        
        except Exception as e:
            raise RPCConnectionError("Error in recv") from e
    
    def send(self, blob: bytes):
        """

        Parameters
        ----------
        blob : bytes
            send data

        Raises
        ------
        RPCConnectionError
            Error in communication
        """
        logger=self.logger()
        logger.info("Start sending size=%d",len(blob))
        
        stream = self._stream
        try:
            # sending header(4byte BIG endian)
            encoded_len_blob = pack(">L",len(blob))
            stream.send_bytes(encoded_len_blob)
            if len(blob) > 0:
                stream.send_bytes(blob)
        except RPCConnectionError:
            raise
        except Exception as e:
            raise RPCConnectionError('Error in sending') from e
        
        logger.info("send finished")
        
    def close(self, *, timeout_sec: float = None):
        """
        Parameters
        ----------
        timeout_sec : float, optional
            timeout(sec), by default None
        """
        logger=self.logger()
        logger.info("start closing")
        
        stream = self._stream
        
        # notify EOF
        try:
            logger.debug("send stream, start closing")
            stream.close_send()
            logger.debug("send stream, finish closing")
        except Exception as e:
            logger.warning("send stream, error in closing",exc_info=True)
        
        
        # waiting EOF
        try:
            self._wait_eof(timeout_sec=timeout_sec)
        except Exception as e:
            logger.warning("recieve stream,unexpected error in waiting EOF",exc_info=True)

        # closing stream
        try:                   
            stream.close()
        except Exception as e:
            logger.warning("closing stream, unexpected error in closing stream",exc_info=True)
            
        logger.info("finish closing")
        
    def wait_recvable(self, *, timeout_sec=None) -> bool:
        stream = self._stream
        return stream.wait_recvable(timeout_sec=timeout_sec)
    
    def _wait_eof(self,*,timeout_sec:float=None):
        """

        Parameters
        ----------
        timeout_sec : float, optional
            timeout(second), by default None
        """
        logger=self.logger()
        
        stream = self._stream
        while True:
            logger.debug("Recieve stream start waiting EOF")
            if stream.wait_recvable(timeout_sec=timeout_sec) == False:
                logger.warning("timeout in waiting EOF")
                break
            
            data = stream.recv_bytes(4096,timeout_sec=timeout_sec)
            if data is None:
                logger.debug("Recieve stream EOF detected")
                break
        


    