#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from typing import Dict, Tuple, Union, List
import json

from .component import Component
from .config import Config
from .task import Task
from ..core import *
from ..utils.iputils import ipv4_to_int32, int32_to_ipv4, prefix_to_bitmask

import subprocess
from time import sleep

from . import constants as consts
from . import System
from . import KnowledgeBase
from . import AttackPlatform, MsfSession
from . import ScenarioMaker
from . import AttackStep


CONFIG_KEY_SERVER = consts.COMPONENT_SERVER
CONFIG_KEY_SEARCH_KEYWORD = f"{CONFIG_KEY_SERVER}.search_key"
DEFAULT_SEARCH_KEYWORD = "password|confidential|secret"


class Server(Component):
    def initialize(self, config: Config):
        search_keys = config.get(CONFIG_KEY_SEARCH_KEYWORD, DEFAULT_SEARCH_KEYWORD)

        if isinstance(search_keys, str):
            search_keys = [search_keys]
        elif not isinstance(search_keys, list):
            raise RuntimeError(f"Invalid keyword: {CONFIG_KEY_SEARCH_KEYWORD}")

        self._search_key = [k.split("|") for k in search_keys]
        
    def update_ks_list(self):
        logger = self.logger()
        
        kb:KnowledgeBase = System.get_component(consts.COMPONENT_KS)
        
        known_host_id_list, pwned_host_id_list = kb.get_host_list()
        
        ap:AttackPlatform = System.get_component(consts.COMPONENT_ATTACKPF)
        
        pwned_ips = set()
        for sinfo in ap.enum_sessions():
            ip = sinfo["ip"]
            pwned_ips.add(ip)
            
        known_ips = set()
        for hid in known_host_id_list + pwned_host_id_list:
            if hid == "attacker":
                continue
            
            hinfo = self.get_status(hid)
            ip = hinfo["host_addr"]
            
            known_ips.add(ip)
            
            if ip in pwned_ips:
                kb.set_exploited_flag(hid)
            else:
                kb.set_exploited_flag(hid,False)
        
        unmanaged_hosts = pwned_ips - known_ips
        if len(unmanaged_hosts) > 0:
            logger.warning("Unmanaged host detected: %s", str(unmanaged_hosts))
        

    def shutdown(self):
        pass
    
        


    def get_status(self, host_id: str) -> Dict[str, str]:
        logger = self.logger()
        logger.info("Start get_status: host_id=%s", host_id)

        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)
        host_info = kb.get_status(host_id)

        logger.info("Finished get_status: rval=%s", host_info)
        return host_info

    def get_status_ex(self, host_id: str):
        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)
        host_detail = kb.get_status_ex(host_id)
        return host_detail

    def get_host_list(self) -> Tuple[Tuple, Tuple]:
        logger = self.logger()
        logger.info("Start get_host_list")

        self.update_ks_list()
        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)

        (scanned_host_id_list, exploited_host_id_list) = kb.get_host_list()

        logger.info(
            "Finished get_host_list: scanned_host_id_list=%s, exploit_host_id_list=%s",
            scanned_host_id_list,
            exploited_host_id_list,
        )

        return scanned_host_id_list, exploited_host_id_list


    def set_ks(self, host_id: str, new_ks: Dict):
        logger = self.logger()
        logger.info("Start set_ks: host_id=%s, new_ks:%s", host_id, new_ks)

        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)


        kb.update_ks(host_id, new_ks)

        logger.info("Finished set_ks")

    def reset_ks(self):
        logger = self.logger()
        logger.info("Start reset_ks")

        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)

        kb.reset_ks()

        logger.info("Finished reset_ks")

    def start_scan(
        self,
        src_host_id: str,
        scan_range: Union[str, List],
        scan_type: str,
        scan_port: str = "1-1024",
        scan_protocol: str = "TCP",
    ) -> Task:
        logger = self.logger()
        logger.info(
            "Request to start scan: src_host_id=%s scan_range=%s scan_type=%s scan_port=%s scan_protocol=%s",
            src_host_id,
            scan_range,
            scan_type,
            scan_port,
            scan_protocol,
        )

        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)

        host_info = kb.get_status(src_host_id)
        src_ip = host_info["host_addr"]

        class _Task(Task):
            def task(_task):
                return self._do_scan(
                    _task, src_ip, scan_range, scan_type, scan_port, scan_protocol
                )

        logger.info("Finished request to start scan")

        return _Task()

    def _do_scan(
        self,
        task: Task,
        src_ip,
        scan_range,
        scan_type,
        scan_port,
        scan_protocol,
    ):
        ap: AttackPlatform = System.get_component(consts.COMPONENT_ATTACKPF)
        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)

        if scan_type == "NW":
            for progress, result in ap.port_scan(
                src_ip, scan_range, scan_port, scan_protocol
            ):
                task.set_progress(progress)

            kb.insert_host_infos(result)
            kb.insert_port_infos(result)
        elif scan_type == "SEC":
            for progress, result in ap.vulnerability_scan(
                src_ip, scan_range, scan_port, scan_protocol
            ):
                task.set_progress(progress)

            kb.insert_vuln_infos(result)
        else:
            raise RuntimeError("invalid scan_type")

        return result


    def start_calc_attack_scenario(self, src_host_id: str, dst_host_id: str) -> Task:
        logger = self.logger()
        logger.info(
            "Start request to scoring: src_host_id=%s dst_host_id=%s", src_host_id, dst_host_id
        )

        class _Task(Task):
            def task(_task):
                return self._do_calc_attack_scenario(_task, src_host_id, dst_host_id)

        logger.info("Finished request to scoring")

        return _Task()

    def _do_calc_attack_scenario(self, task: Task, src_host_id: str, dst_host_id: str):
        logger = self.logger()
        logger.info(
            "Start calc_attack_scenario: src_host_id=%s dst_host_id=%s",
            src_host_id,
            dst_host_id,
        )

        sm: ScenarioMaker = System.get_component(consts.COMPONENT_SCENARIO)
        for progress, result in sm.create_scenario(src_host_id, dst_host_id):
            task.set_progress(progress)

        return result

    def get_result_calc_attack_scenario(self):
        logger = self.logger()
        logger.info("Start get_result_calc_attack_scenario")

        sm: ScenarioMaker = System.get_component(consts.COMPONENT_SCENARIO)
        plan_info, plan_id = sm.get_last_plan()

        logger.info("Finished get_result_calc_attack_scenario")
        logger.debug("Result:%s", str(plan_info))

        return plan_info

    def get_scenario_detail(self, scenario_id: str) -> Tuple[Dict, ...]:
        logger = self.logger()
        logger.info("Start get_scenario_detail: scenario_id=%s", scenario_id)

        sm: ScenarioMaker = System.get_component(consts.COMPONENT_SCENARIO)
        scenario_detail = sm.get_scenario_detail(scenario_id)

        rval = list()
        for step in scenario_detail:
            step["module_params"] = json.dumps(step["module_params"])
            rval.append(step)

        logger.info("Finished get_scenario_detail: scenario_detail=%s", scenario_detail)

        return tuple(rval)

    def get_scenario_detail_2(self, scenario_id: str):
        logger = self.logger()
        logger.info("Start get_scenario_detail: scenario_id=%s", scenario_id)

        sm: ScenarioMaker = System.get_component(consts.COMPONENT_SCENARIO)
        scenario_detail = sm.get_scenario_detail_2(scenario_id)


        for step_info in scenario_detail["steps"]:
            astep: AttackStep = step_info["step"]
            step_info["step"] = astep.name
        
        return scenario_detail

    def get_scenario_detail_ex(self, scenario_id: str):
        logger = self.logger()

        logger.info("Start get_scenario_detail_ex scenario_id=%s", scenario_id)

        sm: ScenarioMaker = System.get_component(consts.COMPONENT_SCENARIO)
        plan_info = sm.find_plan_by_scenario_id(scenario_id)
        if plan_info is None:
            logger.error("No such sceneario")
            raise RuntimeError("No such scenario")

        src_host_id = plan_info["src_host_id"]
        dst_host_id = plan_info["dst_host_id"]

        scenario_detail = self.get_scenario_detail_2(scenario_id)

        scenario_detail["src_host_id"] = src_host_id
        scenario_detail["dst_host_id"] = dst_host_id

        logger.info("Finished get_scenario_detail_ex scenario_id=%s", scenario_id)
        logger.debug("Return :%s", str(scenario_detail))

        return scenario_detail


    def start_execute_scenario(self, scenario_id: str) -> Task:
        logger = self.logger()

        logger.info("Start request to attack: scenario_id=%s", scenario_id)

        class _Task(Task):
            def task(_task):
                return self._do_execute_scenario(_task, scenario_id)

        logger.info("Finished request to attack")

        return _Task()

    def _do_execute_scenario(self, task: Task, scenario_id: str):
        logger = self.logger()

        logger.info("Start execute_scenario: scenario_id=%s", scenario_id)

        sm: ScenarioMaker = System.get_component(consts.COMPONENT_SCENARIO)
        scenario_detail = sm.get_scenario_detail_2(scenario_id)

        ap: AttackPlatform = System.get_component(consts.COMPONENT_ATTACKPF)
        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)

        session_ids_before = set(ap.msf.sessions.list.keys())

        msg="Start attack scenario"
        logger.info(msg)
        task.put_log(msg)
        steps = scenario_detail["steps"]
        progress_par_step = int(90 / len(steps))
        current_progress = 0

        current_var = dict()
        for step_info in steps:
            attack_step_obj: AttackStep = step_info["step"]
            current_var.update(step_info["var"])

            provider = ap.runner_providers

            step_name = attack_step_obj.name
            logger.info("Start attack step %s args=%s", step_name, current_var)
            task.put_log("Start attack step %s args=%s", step_name, current_var)
            
            try:
                #attack_step_obj.execute(current_var, provider)
                attack_step_obj.start(current_var, provider)
                for log in attack_step_obj.readlines():
                    task.put_log(log)
                attack_step_obj.wait()
            except RuntimeError as e:
                logger.exception("Fail to execute attack step %s:%s", step_name, e)
                task.put_log("Fail to execute attack step %s:%s", step_name, e)
                return False
            logger.info("Finished attack step %s", step_name)
            task.put_log("Finished attack step %s", step_name)

            current_progress += progress_par_step
            task.set_progress(current_progress)

        logger.info("Finished attack scenario")
        task.put_log("Finished attack scenario")
        task.set_progress(90)

        session_ids_after = set(ap.msf.sessions.list.keys())

        if session_ids_before != session_ids_after:
            for new_id in session_ids_after - session_ids_before:
                new_session: MsfSession = ap.msf.sessions.session(new_id)

                sinfo = ap.get_session_info(new_session)
                ip = sinfo["ip"]
                logger.info("Get new step stone: IP=%s", ip)
                task.put_log("Get new step stone: IP=%s", ip)

                host_info = kb.get_status_by_ip(ip)
                if host_info is None:
                    logger.warning("ip %s is not registered in KB", ip)
                else:
                    host_id = host_info["host_id"]
                    kb.set_exploited_flag(host_id)

                    sys_info = ap.get_system_info(new_session)
                    task.put_log("Get system information")
                    kb.register_sys_info(host_id, sys_info)
                    
                    new_hinfo = {
                        "host_addr":ip,
                        "os_name":sys_info["os_name"],
                        "host_name":sys_info["hostname"]
                    }
                    kb.update_host_info(host_id, new_hinfo)
                    
                    for if_info in sys_info["interfaces"]:
                        if if_info[1] == ip:
                            mask = if_info[2]
                            kb.set_subnet_mask(ip, mask)
                            break
                    else:
                        logger.warning(
                            "ip %s is not bound with any NIC of the newly compromised host",
                            ip,
                        )

        logger.info("Finished attack")
        task.set_progress(100)

        return True


    def start_search_secret(
        self, dst_host_id: str, src_host_id: str = "Attacker"
    ) -> Task:
        logger = self.logger()

        logger.info(
            "Start request to search secret information: dst_host_id=%s src_host_id=%s", dst_host_id, src_host_id
        )

        class _Task(Task):
            def task(_task):
                return self._do_search_secret(_task, dst_host_id, src_host_id)

        logger.info("Finished request to search secret information")
        return _Task()

    def _do_search_secret(self, task: Task, dst_host_id: str, src_host_id: str) -> str:
        logger = self.logger()

        logger.info(
            "Start search_secret: dst_host_id=%s src_host_id=%s", dst_host_id, src_host_id
        )
        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)


        ap: AttackPlatform = System.get_component(consts.COMPONENT_ATTACKPF)

        dst_hinfo = kb.get_status(dst_host_id)
        dst_ip = dst_hinfo["host_addr"]

        sessions = ap.find_sessions(dst_ip)

        # TODO: It should be improved so as to select the most privileged session from found sessions.
        if len(sessions) > 0:
            session = sessions[0]
        else:
            raise RuntimeError(f"Host {dst_host_id} is not pwned")

        task.set_progress(50)

        secret_path = ap.find_files(session, self._search_key)

        #
        logger.info("Finished search_secret: rval=%s", secret_path)
        task.set_progress(100)
        return secret_path

    def get_system_info(self, host_id: str) -> Dict:
        logger = self.logger()
        logger.info("Start get_system_info: host_id=%s", host_id)

        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)
        ap: AttackPlatform = System.get_component(consts.COMPONENT_ATTACKPF)

        hinfo = kb.get_status(host_id)
        host_ip = hinfo["host_addr"]

        sessions = ap.find_sessions(host_ip)
        if len(sessions) > 0:
            session = sessions[0]
        else:
            raise RuntimeError(f"Host {host_id} is not pwned")

        sys_info = ap.get_system_info(session)

        # TODO: store sys_info into KS
        kb.register_sys_info(host_id, sys_info)

        # See. AttackPlatform.get_system_info, ”connections”: list[ (<proto>,<local_addr>,<local_port>, <remote_addr>, <remote_port>) ]
        connections = sys_info["connections"]
        remote_addrs = {entry[3] for entry in connections if entry[0] in ("tcp", "udp")}

        local_addrs = {ifinfo[1] for ifinfo in sys_info["interfaces"]}

        remote_addrs -= local_addrs

        host32 = ipv4_to_int32(host_ip)
        for ifinfo in sys_info["interfaces"]:
            ifip, mask = ifinfo[1], ifinfo[2]
            if ifip == "" or mask == "":
                continue

            mask32 = ipv4_to_int32(mask)
            net32 = ipv4_to_int32(ifip) & mask32

            if (host32 & mask32) == net32:
                host_net32 = net32
                host_mask32 = mask32
                break
        else:
            # host_ip does not belong to any segments... (is the host_ip IP_SELF? )
            logger.warning("failed to find network address of host_ip(%s)", host_ip)
            host_mask32 = 0xFFFFFFFF
            host_net32 = 0

        dsts = list()

        for raddr in remote_addrs:
            raddr32 = ipv4_to_int32(raddr)

            if (raddr32 & host_mask32) != host_net32:
                dsts.append(raddr)

        rval = {"dst_host_ip": tuple(dsts)}

        logger.info("Finished get_system_info: rval=%s", rval)

        return rval

    def get_remote_file(
        self,
        dst_host_id: str,
        remote_file_path: str,
        local_file_path: str,
        src_host_id: str = "d3f4ultm4ch1n3",
    ):
        self.logger().info(
            "Start to request to file download: dst_host_id=%s remote_file_path=%s local_file_path=%s src_host_id=%s",
            dst_host_id,
            remote_file_path,
            local_file_path,
            src_host_id,
        )
        self.logger().info("Finished file download")


if __name__ == "__main__":
    server = Server()
    # server.set_ks('ex11ample',new_ks={'active_user':50,'is_avs':True})
    # result = server.start_calc_attack_scenario('srchost001','dsthost001')
    result = server._do_calc_attack_scenario("src", "example")
    print(result)
