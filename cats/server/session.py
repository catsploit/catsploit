#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from .task import Task
from ..errors import StatusError

class Session:
    STATE_UNINITIALIZED = "Uninitialize"
    STATE_READY = "Command acceptable"
    STATE_RUNNING="Running task"
    
    def __init__(self):
        """constructor
        """
        self._current_task = None
        self._state = Session.STATE_UNINITIALIZED
     
    def check_state(self, *, expected:str):
        if expected != self._state:
            raise StatusError(f"Not in callable state: Desired server state[{expected}], current state[{self._state}]") 
        
        
    def initialized(self):
        self._state = Session.STATE_READY
        
    def task_started(self, task:Task, state_name:str=None):
        self._current_task = task
        if state_name is None:
            state_name = Session.STATE_RUNNING
        self._state = state_name
        
    def get_current_task(self)->Task|None:
        return self._current_task
        
    def task_finished(self):
        self._state = Session.STATE_READY
        self._current_task = None
    
    def shutdowned(self):
        self._state = Session.STATE_UNINITIALIZED
        
    def abort_task(self):
        cur_task = self._current_task
        if cur_task is not None:
            cur_task.stop()
            self.task_finished()
            
        
    def close(self):
        self.abort_task()
        self.shutdowned()

