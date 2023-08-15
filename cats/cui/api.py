#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from typing import Any, Union, List
from cats.rpc import RPCClient, StreamConnection
from cats.rpc import unix_socket as usock


class CatsServer:
    def __init__(self):
        self._rpc = None

    def open(self, sock: str):
        conn = usock.connect(sock)
        self._rpc = RPCClient(conn)

    def close(self):
        if self._rpc is not None:
            conn=self._rpc.get_connection()
            conn.close(timeout_sec=1.0)
            self._rpc = None

    def init_system(self):
        """initialize cats-server

        """
        return self._rpc.call("cui_system_init")

    def shutdown_system(self):
        """shutdown cats-server

        """
        return self._rpc.call("cui_system_shutdown")

    def host_list(self):
        """Get host list from KS
        
        ```python
        [ (host_id, host_addr, host_name, platform(os version), pwned) ]
        ```

        Returns
        -------
        list[tuple[str,str,str,str,str]]
            host list
        """
        return self._rpc.call("cui_host_list")

    def host_detail(self, host_id: str, refresh=False):
        """Get host detail
        
        ```python
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
        
        ```
        
        Returns
        -------
        dict[str, Any]
            host detail info
        """
        return self._rpc.call("cui_host_detail", host_id, refresh)

    def scenario_list(self):
        """ get scenario list
        
        
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
                        "first_step": <str> # 1st step name of attack step
                        "nsteps": <int> # num of attack step of scenario
                    }
                ),
                ...
            ]
        }
        ```
        
        Returns
        -------
        dict[str,Any]
            scenario list
        """
        return self._rpc.call("cui_scenario_list")

    def scenario_detail(self, scenario_id: str):
        """ Get scenario detail
        
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

        Returns
        -------
        dict[str,Any]
            scenario detail info
        """
        return self._rpc.call("cui_scenario_detail", scenario_id)

    def start_scan_task(
        self,
        src_host_id: str,
        scan_range: str | list[str],
        scan_type: str,
        scan_port: str = "1-1024",
        scan_protocol: str = "TCP",
    ):
        """Start scan as background task
        
        ```python
        [
            {
                "host_addr": <str:host_addr>,
                "host_name": <str:host_name>,
                "os_name": <str:osname>,
                "ports": [ <port_info>* ],
            },
            ...
        ]
            port_info ::= (proto, portid, service, product, version)
            proto ::= 'ip'|'tcp'|'udp'|'sctp'
        ```
        
        ```python
        [
            {
                "host_addr": <str:host ip address>,
                "protocol": <str:protocol>,
                "port": <str:port num>,
                "oid": <str:OpenVAS scan ID>,
                "vuln_name": <str>,
                "cves": [ <str:cve_id>* ]
            },
            ...
        ]
        
        ```       

        Parameters
        ----------
        src_host_id : str
            scan host ID
        scan_range : str | list[str]
            scanned ip address range
        scan_type : str
            type of scan "NW":port scan, "SEC":vul scan
        scan_port : str, optional
            scan port, by default "1-1024"
        scan_protocol : str, optional
            scan protocol, by default "TCP"

        Returns
        -------
        None
        """
        return self._rpc.call(
            "start_task",
            "SCAN",
            src_host_id,
            scan_range,
            scan_type,
            scan_port,
            scan_protocol,
        )

    def start_execute_scenario_task(self, scenario_id: str):
        """Execute scenario as background task
        

        Parameters
        ----------
        scenario_id : str

        Returns
        -------
        None
        """
        return self._rpc.call("start_task", "EXECUTE_SCENARIO", scenario_id)

    def start_plan_task(self, src_host_id: str, dst_host_id: str):
        """
        ```python
        [
            {
                "scenario_id": <str>,
                "evc": <float:0..1>,
                "evd": <float:0..1>,
                "steps": [
                    {
                        "step": <str:step_name>,
                        "var": {
                            <str:var_name>:<str:var_value>,
                            ...
                        }
                    },
                    ...
                ]
            },
            ...
        ]
        ```

        Parameters
        ----------
        src_host_id : str
            _description_
        dst_host_id : str
            _description_

        Returns
        -------
        _type_
            _description_
        """
        return self._rpc.call("start_task", "PLAN", src_host_id, dst_host_id)

    def start_search_secret(self, dst_host_id: str):
        """
        ```python
        [ <str:file_path>, ... ]
        ```        

        Parameters
        ----------
        dst_host_id : str
            target host ID

        Returns
        -------
        None
        """
        return self._rpc.call("start_task", "SEARCH_SECRET", dst_host_id)

    def get_progress_and_logs_of_task(self):
        """
        Returns
        -------
        int
            progress of task
        list[str] | None
            task log
        """
        return self._rpc.call("get_progress_and_logs_of_task")

    def get_result_of_task(self):
        """

        Returns
        -------
        Any
            result of task
        """
        return self._rpc.call("get_result_of_task")
    
    def cancel_task(self):
        return self._rpc.call("cancel_task")

    def reset_system(self):
        """reset system
        
        
        """
        return self._rpc.call("reset_system")
    
    def reset_component(self, component:str):
        """reset component
        """
        return self._rpc.call("reset_component", component)