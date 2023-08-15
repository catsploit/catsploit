#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import multiprocessing as mp
from typing import Any
from ..utils import logutils
import queue

class NotForChildError(Exception):
    """Child process called parent-only method"""

    pass


class NotForParentError(Exception):
    """Parent process called a child-only method"""

    pass


class StatusError(Exception):
    """not callable"""

    pass


class Task:
    @classmethod
    def logger(cls):
        return logutils.get_logger(cls)

    def __init__(self):
        """constructor
        """
        self._reset_state()
        
        # init logger
        self.logger()
        

    def set_progress(self, value:int):
        if not self._is_child:
            raise NotForParentError()

        self._progress.value = value

    def get_progress(self):
        if not self._started:
            raise StatusError()

        return self._progress.value

    def start(self, *args, **kwargs):
        if self._is_child:
            raise NotForChildError

        if self._started:
            raise StatusError()

        result_queue = mp.Queue()
        log_queue    = mp.Queue()
        shm_progress = mp.Value("i", 0)

        p = mp.Process(
            target=Task._launch,
            args=[self, shm_progress, result_queue, log_queue] + list(args),
            kwargs=kwargs,
        )
        p.start()

        self._process = p
        self._result_queue = result_queue
        self._log_queue    = log_queue
        self._progress = shm_progress
        self._started = True
        self._log_closed=False

    def stop(self):
        if self._is_child:
            raise NotForChildError()

        if not self._started:
            raise StatusError()

        self._process.terminate()
        self._process.join()
        self._process.close()

        self._reset_state()

    def _launch(self, shm_progress, result_queue, log_queue, *args, **kwargs):
        logger=self.logger()
        
        self._progress = shm_progress
        self._log_queue= log_queue
        self._is_child = True
        self._started = True

        try:
            rval = self.task(*args, **kwargs)
        except BaseException as e:
            logger.exception("Exeption during running task")
            self.set_progress(-1)
            rval = e
            
        self._finish_put_log()
               

        result_queue.put(rval)
        result_queue.close()
        result_queue.join_thread()

    def _reset_state(self):
        self._process = None
        self._result_queue = None
        self._log_queue=None
        self._progress = None
        self._started = False
        self._is_child = False
        self._log_closed=False

    def task(self, *args, **kwargs):
        raise NotImplementedError()

    def is_running(self) -> bool:
        if self._is_child:
            raise NotForChildError()

        if not self._started:
            return False

        return self._process.is_alive()

    def get_result(self, *, raise_exception=True) -> Any:
        if self._is_child:
            raise NotForChildError()

        if not self._started:
            raise StatusError()

        rval = self._result_queue.get()
        self._process.join()
        self._process.close()

        self._reset_state()

        if raise_exception == True and isinstance(rval, BaseException):
            raise rval
        return rval
    
    def put_log(self, msg:str,*args):
        if not self._is_child:
            raise NotForParentError()
        
        if msg is None:
            msg = ""
        
        if len(args) > 0:
            msg = msg % args
        
        try:
            if not self._log_queue.full():
                self._log_queue.put_nowait(msg)
        except queue.Full:
            pass
    
    def _finish_put_log(self):
        if not self._is_child:
            raise NotForParentError()
        
        self._log_queue.put(None)
        self._log_queue.close()
        self._log_queue.join_thread()
        
    
    def log_available(self):
        if self._is_child:
            raise NotForChildError()
        
        if not self._started:
            raise StatusError()
        
        if self._log_closed:
            return True
        
        return not self._log_queue.empty()
        
    def get_log(self)->str:
        if self._is_child:
            raise NotForChildError()
        
        if not self._started:
            raise StatusError()
        
        if self._log_closed:
            return None
        
        msg = self._log_queue.get()
        
        if msg is None:
            self._log_closed = True
            
        return msg
    
    
    def get_progress_and_logs(self)->tuple[int,list[str]]:
        p = self.get_progress()
        logs = list()
        while self.log_available():
            log = self.get_log()
            
            if log is None:
                if len(logs) == 0:
                    return (p, None)
                else:
                    break
                
            logs.append(log)
        
        return (p, logs)
        
