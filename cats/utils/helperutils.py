#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import subprocess as sp
from typing import Any
import tempfile
import json
import os
from logging import Logger
import re

def launch_helper(exe:list[str], param:dict[str,Any], logger:Logger,*,keep_tempfile=False):
    with tempfile.NamedTemporaryFile(mode="w",suffix=".json",prefix="cats_in-",delete=False) as wfp:
        param_file = wfp.name
        json.dump(param, wfp)
    
    # generate outfile
    fd, out_file = tempfile.mkstemp(suffix=".json", prefix="cats_out-", text=True)
    os.close(fd)
    
    try:
        # Start helper application
        rex_progress = re.compile(r"^\[#\]\s*(\d+)$")    
        rex_log = re.compile(r"^(DEBUG|INFO|WARNING|ERROR):(.*)$")
        logfunc_map = {
            "DEBUG": logger.debug,
            "INFO": logger.info,
            "WARNING": logger.warning,
            "ERROR": logger.error
        }
        
        args = exe + [param_file, out_file]
        proc = sp.Popen(args,bufsize=1, stdout=sp.PIPE,text=True)
        
        with proc:
            for l in proc.stdout:
                m = rex_progress.match(l)
                if m is not None:
                    yield int(m[1]), None
                    continue
                
                m = rex_log.match(l)
                if m is not None:
                    log_level, log_msg = m[1], m[2].strip()
                    logfunc_map[log_level](log_msg)
                else:
                    logger.debug(l)
        
        rc = proc.returncode   
        if rc != 0:
            raise RuntimeError("Error in helper application")
        
        # Read result files
        with open(out_file) as fp:
            rval = json.load(fp)        
            
    finally:        
        if keep_tempfile == False:
            os.unlink(param_file)
            os.unlink(out_file)

    yield 100, rval
    
