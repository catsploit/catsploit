#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from .server import Server
from .system import System
from .constants import COMPONENT_SERVER
from .task import Task

from .session import Session

def cui_system_init():
    sess = System.get_session()
    sess.check_state(expected=Session.STATE_UNINITIALIZED)
    System.build_system()
    
    sess.initialized()
    


def cui_system_shutdown():
    sess = System.get_session()
    sess.abort_task()

    System.shutdown_system()
    sess.shutdowned()


def cui_host_list():
    """return found/pwned host list

    [
        {
            "hostID": <str>,
            "IP": <str>,
            "Hostname": <str>?,
            "Platform":<str>?,
            "Pwned":<bool>
        },
        ...
    ]
    """
    System.get_session().check_state(expected=Session.STATE_READY)
    
    srv: Server = System.get_component(COMPONENT_SERVER)

    # get host_info from ks_list
    found_host_ids, pwned_host_ids = srv.get_host_list()

    rval = list()

    for host_id in pwned_host_ids + found_host_ids:
        host_info = srv.get_status(host_id)
        rval_info = {
            "hostID": host_info["host_id"],
            "IP": host_info["host_addr"],
            "Hostname": host_info["host_name"],
            "Platform": host_info["host_type"],
            "Pwned": host_info["is_exploited"],
        }
        rval.append(rval_info)

    return rval


def cui_host_detail(host_id: str, refresh:bool):
    """return host detail

    {
        "hostID": <str>,
        "IP": <str>,
        "Hostname": <str>,
        "Platform": <str>,
        "Pwned": <bool>,
        "IPs": [ (<ipv4,ipv4mask,ipv6,ipv6prefix)* ],
        "Ports": [ (ip, proto, port, service, product, version)* ],
        "Vulnerabilities: [(ip, proto, port, vuln_name, cve)*],
        "Users":[ (uname, groupname)* ]
    }
    """
    System.get_session().check_state(expected=Session.STATE_READY)    

    srv: Server = System.get_component(COMPONENT_SERVER)
    if refresh:
        _ = srv.get_system_info(host_id)
        
    host_detail = srv.get_status_ex(host_id)
    return host_detail


def cui_scenario_list():
    """return scenario list

    ```python

    {
        "src_ip": <str>,
        "dst_ip": <str>,
        "scenarios":[
            (
                <str:scenario_id>,
                {
                    "evc": <float:0..1>,
                    "evd": <float:0..1>,
                    "first_step": <str>
                }
            ),
            ...
        ]
    }

    """
    System.get_session().check_state(expected=Session.STATE_READY)
        
    srv: Server = System.get_component(COMPONENT_SERVER)
    plan_info = srv.get_result_calc_attack_scenario()

    if plan_info is None:
        return None

    src_host_id = plan_info["src_host_id"]
    dst_host_id = plan_info["dst_host_id"]

    try:
        src_host_info = srv.get_status(src_host_id)
        dst_host_info = srv.get_status(dst_host_id)
    except Exception as e:
        # No host_id
        return None

    src_host_ip = src_host_info["host_addr"]
    dst_host_ip = dst_host_info["host_addr"]

    rval = dict()
    rval["src_ip"] = src_host_ip
    rval["dst_ip"] = dst_host_ip
    rval["scenarios"] = list()

    # scenario_detail = {
    #   "scenario_id": <str>,
    #   "evc": <float:0..1>,
    #   "evd": <float:0..1>,
    #   "steps": [
    #       {
    #           "step": <str:step_name>,
    #           "var": dict[<str:var_name>,<Any:var_value>]
    #       },
    #       ...
    #   ]
    # }

    for scenario_id in plan_info["scenario_ids"]:
        sc_detail = srv.get_scenario_detail_2(scenario_id)
        sc_summary = {
            "evc": sc_detail["evc"],
            "evd": sc_detail["evd"],
            "first_step": sc_detail["steps"][0]["step"],
            "nsteps": len(sc_detail["steps"]),
        }

        rval["scenarios"].append((scenario_id, sc_summary))

    return rval


def cui_scenario_detail(scenario_id: str):
    """Return scenario list

    ```python
    {
      "scenario_id": <str>,
      "evc": <float:0..1>,
      "evd": <float:0..1>,
      "steps": [
          {
              "step": <str:step_name>,
              "var": dict[<str:var_name>,<Any:var_value>]
          },
          ...
      ],
      "src_host_ip": <str>,
      "dst_host_ip": <str>
    }
    ```

    """
    System.get_session().check_state(expected=Session.STATE_READY)
        
    srv: Server = System.get_component(COMPONENT_SERVER)

    scenario_detail_ex = srv.get_scenario_detail_ex(scenario_id)

    # scenario_detail_ex = {
    #   "scenario_id": <str>,
    #   "evc": <float:0..1>,
    #   "evd": <float:0..1>,
    #   "steps": [
    #       {
    #           "step": <str:step_name>,
    #           "var": dict[<str:var_name>,<Any:var_value>]
    #       },
    #       ...
    #   ],
    #   "src_host_id": <str>,
    #   "dst_host_id": <str>
    # }

    src_host_id = scenario_detail_ex["src_host_id"]
    dst_host_id = scenario_detail_ex["dst_host_id"]

    src_host_info = srv.get_status(src_host_id)
    dst_host_info = srv.get_status(dst_host_id)

    src_host_ip = src_host_info["host_addr"]
    dst_host_ip = dst_host_info["host_addr"]

    del scenario_detail_ex["src_host_id"]
    del scenario_detail_ex["dst_host_id"]
    scenario_detail_ex["src_host_ip"] = src_host_ip
    scenario_detail_ex["dst_host_ip"] = dst_host_ip

    return scenario_detail_ex


TASK_SCAN = "SCAN"
TASK_PLAN = "PLAN"
TASK_EXECUTE_SCENARIO = "EXECUTE_SCENARIO"
TASK_SEARCH_SECRET = "SEARCH_SECRET"

_current_task_obj = None


def _register_task(task: Task):
    global _current_task_obj

    assert _current_task_obj is None
    _current_task_obj = task


def _current_task():
    return _current_task_obj


def _unregister_task():
    global _current_task_obj

    assert _current_task_obj is not None
    _current_task_obj = None


def start_task(task_name: str, *task_args, **task_kwargs):
    sess = System.get_session()
    sess.check_state(expected=Session.STATE_READY)
    
    srv: Server = System.get_component(COMPONENT_SERVER)

    task_name = task_name.upper()

    tsk: Task = None
    if task_name == TASK_SCAN:
        tsk = srv.start_scan(*task_args, **task_kwargs)

    elif task_name == TASK_PLAN:
        tsk = srv.start_calc_attack_scenario(*task_args, **task_kwargs)
    elif task_name == TASK_EXECUTE_SCENARIO:
        tsk = srv.start_execute_scenario(*task_args, **task_kwargs)
    elif task_name == TASK_SEARCH_SECRET:
        tsk = srv.start_search_secret(*task_args, **task_kwargs)
    else:
        raise RuntimeError(f"Unknown Task:{task_name}")

    #_register_task(tsk)
    tsk.start()
    sess.task_started(tsk)


def get_progress_and_logs_of_task():
    sess = System.get_session()
    sess.check_state(expected=Session.STATE_RUNNING)

    task = sess.get_current_task()

    if task is None:
        raise RuntimeError("Not running task")

    return task.get_progress_and_logs()


def get_result_of_task():
    sess = System.get_session()
    sess.check_state(expected=Session.STATE_RUNNING)
    
    task = sess.get_current_task()

    if task is None:
        raise RuntimeError("Not running task")

    try:
        result = task.get_result()
    finally:
        sess.task_finished()
        
    return result


def cancel_task():
    sess = System.get_session()
    sess.check_state(expected=Session.STATE_RUNNING)
    
    sess.abort_task()
    
    
def reset_system():  
    sess = System.get_session()
    sess.abort_task()    
    System.reset_system()
    

def reset_component(component_name:str):
    sess = System.get_session()
    sess.abort_task()    
    
    component = System.get_component(component_name)
    component.reset()