#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from .component import Component
from .config import Config
from .system import System
from .attack_db import AttackDB, CONFIG_KEY_ADB_FOLDER
from . import constants as consts
from .dbms import DBMS
from .knowledgebase import KnowledgeBase
from ..core.random import random_id_generator
from ..core.evc import *
from .system import System
from .attack_step import AttackStep
from .knowledgebase import KnowledgeBase
from . import AttackPlatform
from . import constants as consts
from ..utils import launch_helper

from typing import Dict
import json
import re
import itertools

# PDDL file path
CONFIG_KEY_SCENARIO_PROBLEM_PDDL_FILE = "SCENARIO.generator.pddl.problem"
CONFIG_KEY_SCENARIO_DOMAIN_PDDL_FILE = "SCENARIO.generator.pddl.domain"
# evc related file path
CONFIG_KEY_SCENARIO_VARPROB_FILE = "SCENARIO.evc.varprob"
CONFIG_KEY_SCENARIO_MAP_FILE = "SCENARIO.evc.map"
CONFIG_KEY_SCENARIO_TARGET_FILE = "SCENARIO.evc.target"

# helper file path
CONFIG_KEY_SCENARIO_HELPER_FILE = "SCENARIO.generator.helper"
# default file path
DEFAULT_PROBLEM_PDDL_FILE = "./cats/data/output/pddl/problem.pddl"
DEFAULT_DOMAIN_PDDL_FILE = "./cats/data/output/pddl/domain.pddl"
DEFAULT_SCENARIO_HELPER = ["python3","/tmp/scenario_helper.py"]
DEFAULT_DEFIND_VARPROB_FILE =  "./cats/data/input/evc/varprob_def.json"
DEFAULT_MAP_FILE =  "./cats/data/input/evc/festimated_map.json"
DEFAULT_TARGET_FILE =  "./cats/data/input/evc/targets.json"

CONFIG_KEY_SCENARIO_MAX_PATH_COUNT = "SCENARIO.generator.maxscenarios"
DEFAULT_MAX_PATH_COUNT = 15

DEFAULT_ACTION_NAME = ["port", "os", "CVE"]

DEFAULT_PREDICATES = """
    (connected ?a ?b)
    (located ?a)
    (exploited ?a)
    (cred-smb ?a)
"""

SM_TABLES_PLAN_HIST="plan_hist"
SM_TABLES_SCENARIO_LIST="scenario_list"
SM_SEQ_PLAN_HIST_PLAN_ID="plan_hist_plan_id_seq"

SM_TABLES_DYNAMIC=[
    SM_TABLES_PLAN_HIST,
    SM_TABLES_SCENARIO_LIST
]
SM_SEQS=[
    SM_SEQ_PLAN_HIST_PLAN_ID
]

class ScenarioMaker(Component):
    def __init__(self) -> None:
        super().__init__()

    def initialize(self, config: Config) -> None:        
        self._problem_pddl_filepath = config.get(CONFIG_KEY_SCENARIO_PROBLEM_PDDL_FILE, DEFAULT_PROBLEM_PDDL_FILE)
        self._domain_pddl_filepath = config.get(CONFIG_KEY_SCENARIO_DOMAIN_PDDL_FILE, DEFAULT_DOMAIN_PDDL_FILE)
        self._scenario_helper = config.get(CONFIG_KEY_SCENARIO_HELPER_FILE, DEFAULT_SCENARIO_HELPER)
        self._max_count = config.get(CONFIG_KEY_SCENARIO_MAX_PATH_COUNT, DEFAULT_MAX_PATH_COUNT)
        self._map_file = config.get(CONFIG_KEY_SCENARIO_MAP_FILE, DEFAULT_MAP_FILE)
        self._vardef_file = config.get(CONFIG_KEY_SCENARIO_VARPROB_FILE, DEFAULT_DEFIND_VARPROB_FILE)
        self._targets_file = config.get(CONFIG_KEY_SCENARIO_TARGET_FILE,DEFAULT_TARGET_FILE)

    def shutdown(self) -> None:
        pass
    
    def reset(self):
        dbms = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            tables = ",".join(SM_TABLES_DYNAMIC)
            sql="TRUNCATE TABLE {}".format(tables)
            cur.execute(sql)
                            
            for seq in SM_SEQS:
                sql="ALTER SEQUENCE {} RESTART WITH 1".format(seq)
                cur.execute(sql)

        dbms.commit()
        

    def create_scenario(self, src_host_id, dst_host_id) -> list:
        logger = self.logger()
        logger.info("Start create_scenario")

        ad:AttackDB = System.get_component(consts.COMPONENT_ATTACKDB)
        attack_modules = ad.attack_steps
        
        scenario_list = list()


        plan_id = self.register_new_plan(src_host_id, dst_host_id)
        yield 10, None
        logger.info("Start _create_problem")
        self._create_problem(src_host_id, dst_host_id, attack_modules)
        yield 30, None
        

        logger.info("Start attack path generation")
        params = dict()
        params["problem_pddl_filepath"] = self._problem_pddl_filepath
        params["domain_pddl_filepath"]  = self._domain_pddl_filepath
        params["max_scenarios"] = self._max_count

        # Call helper
        for progress, result in launch_helper(self._scenario_helper, params, logger):
            yield 30 + int(progress/2), None
        attack_path_pddl = result["path_result"]
        logger.info("Finish attack path generation:attack_path_pddl= %s " % attack_path_pddl)

        logger.info("Start _pddl2scenario")
        scenarios = self._pddl2scenario(attack_path_pddl,ad, plan_id)

        yield 99, None

        for scenario in scenarios:
            scenario_list.append(scenario['scenario_id'])
        
        logger.info("Finished create_scenario scenario_list: %s", scenario_list)
        
        yield 100, scenario_list

    def get_scenario_detail(self, scenario_id):

        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.dict_cursor() as cur:
            cur.execute(
                "SELECT attack_step_id,src_host_id, dst_host_id, module_name, module_params FROM scenario_list WHERE scenario_id = %s ORDER BY step_number",
                (scenario_id,),
            )
            result = cur.fetchall()

        rval = list()
        for row in result:
            item = dict(row)
            item["module_params"] = json.loads(item["module_params"])
            rval.append(item)

        scenario_detail = tuple(rval)
       
        return scenario_detail
    
    
    def get_scenario_detail_2(self, scenario_id:str) -> Dict:
        ad:AttackDB = System.get_component(consts.COMPONENT_ATTACKDB)
        kb:KnowledgeBase = System.get_component(consts.COMPONENT_KS)
        logger = self.logger()
        
        logger.info("Start get_scenario_detail_2 scenario_id:%s" % scenario_id)
        scenario_info = dict()
        evcs = list()
        evds = list()
        steps = list()
        
        scenario_details = kb.get_scenario_all_status(scenario_id)
        
        for scenario_detail in scenario_details:
            step = dict()
            evcs.append(scenario_detail['evc'])
            evds.append(scenario_detail['evd'])
            
            atstep = ad.get_attack_step(scenario_detail['module_name'])
            
            param = json.loads(scenario_detail['module_params'])
            step['step'] = atstep
            step['var'] = param
            steps.append(step)
        
        scenario_info['scenario_id'] = scenario_id

        scenario_info['evc'] = self._calc_scenario_evc(evcs)
        scenario_info['evd'] = self._calc_scenario_evd(evds)

        scenario_info['steps'] = steps
        
        logger.info("Finished get_scenario_detail_2")
        
        return scenario_info
    

    def _create_problem(
        self, src_host_id: str, dst_host_id: str, attack_modules: tuple
    ):
        init_pddl_and_pred = self._create_init(src_host_id, attack_modules)
        init_pddl = init_pddl_and_pred[0]
        preds = init_pddl_and_pred[1]
        pred = self._merge_duplicates(preds)

        goal_pddl = self._create_goal(dst_host_id)

        action_pddl = self._create_actions(attack_modules, pred)

        problem_file = self._problem_pddl_filepath
        domain_file = self._domain_pddl_filepath
        
        
        with open(problem_file, "w", encoding="utf_8") as f:
            f.write(init_pddl)
            f.write(goal_pddl)

        with open(domain_file, "w", encoding="utf_8") as f:
            f.write(action_pddl)

    def _create_init(self, src_host_id: str, attack_modules: tuple) -> str:

        kb:KnowledgeBase = System.get_component(consts.COMPONENT_KS)

        logger = self.logger()

        hosts_info = kb.get_hosts_condition_except_id(src_host_id)

        attacker_info = kb.get_condition(src_host_id)

        init_pddl = """
        (define (problem example)
            (:domain find_path)
            (:objects
        """
        for host_info in hosts_info:
            init_pddl += host_info["host_id"] + " "
        init_pddl += attacker_info["host_id"]
        init_pddl += """
            )
            (:init 
                (located {})
                
            """.format(
            attacker_info["host_id"]
        )
        init_pddl += """
        (exploited {})
        """.format(
            attacker_info["host_id"]
        )

        all_hosts_info = kb.get_all_hosts_condition()
        init = self._comb_hosts_connection(all_hosts_info)
        
        init_pddl += init
        
        init_pddl += """
                """

        pred_list = []
        for host_info in hosts_info:
            init_and_pred = self._ks2pddl(host_info["host_id"], attack_modules)
            init_pddl += init_and_pred[0]
            pred_list.append(init_and_pred[1])

        init_pddl += """
            )
        """
        logger.info("Finished init part generation")

        return init_pddl, pred_list

    def _comb_hosts_connection(self, hosts_info: list) -> str:
        init_pddl = str()
        for host_info in itertools.combinations(hosts_info,2):
            init_pddl += """
                        (connected {} {})
                        (connected {} {})
                        """.format(
                        host_info[0]["host_id"],
                        host_info[1]["host_id"],
                        host_info[1]["host_id"],
                        host_info[0]["host_id"],
                    )
        return init_pddl
    
    def _create_goal(self, dst_host_id: str) -> str:
        logger = self.logger()

        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)

        target_info = kb.get_status(dst_host_id)
        target = target_info["host_id"]

        goal_pddl = """
            (:goal 
                (exploited {})
                (located {})
            )
        )""".format(
            target, target
        )

        logger.info("Start goal part generation")

        return goal_pddl

    def _create_actions(self, attack_modules: tuple, pred: Dict) -> str:

        logger = self.logger()
        logger.info("Start _create_action")

        domain_pddl = """
        (define (domain find_path)
        
            ;remove requirements that are not needed
            (:requirements :strips :fluents :durative-actions :timed-initial-literals :typing :conditional-effects :negative-preconditions :duration-inequalities :equality)

            (:types 

            )
            (:predicates
            {}
        """.format(
            DEFAULT_PREDICATES
        )

        # OS
        oss = pred["os"]
        for os in oss:
            domain_pddl += """
                (os-{} ?b)
            """.format(
                os
            )
        # CVE
        cves = pred["cve"]
        for cve in cves:
            domain_pddl += """
                ({} ?b)
            """.format(
                cve
            )

        # Port
        ports = pred["port"]
        for port in ports:
            domain_pddl += """
                ({} ?b)
            """.format(
                port
            )

        domain_pddl += """
            )
        """
        for atstep in attack_modules:
            domain_pddl += atstep.pddl_action

        domain_pddl += ")"

        logger.info("Start _create_action")

        return domain_pddl

    def _pddl2scenario(self, path_pddl: list, ad: any, plan_id: int) -> list:
        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)
        logger = self.logger()

        scenario_list = []
        scenario = {}

        for path in path_pddl:
            scenario_id = random_id_generator()
            step_number = 0

            steps = []
            steps_evc = []
            steps_evd = []

            for step in path:
                parse_result = self._parse_result(step)
                action_name = parse_result[0]
                src_host_id = parse_result[1]
                dst_host_id = parse_result[2]
                logger.info("_pddl2scenario: Get name of action:action_name= %s " % action_name)
                logger.info("_pddl2scenario: Get attack src_host_id:src_host_id= %s " % src_host_id)
                logger.info("_pddl2scenario: Get attack dst_host_id:dst_host_id= %s " % dst_host_id)

                atstep = ad.get_attack_step(action_name)
                step_evc = self.evaluate_step_evc(dst_host_id, atstep)

                step_evd = self.evaluate_step_evd(atstep,src_host_id,dst_host_id)
                
                logger.info("step_evc:%s"% step_evc)
                logger.info("step_evd:%s"% step_evd)
                
                
                params = self._get_action_params(action_name, ad)
                var = {}

                dst_host_info = kb.get_condition(dst_host_id)
                logger.info("dst:%s" % dst_host_info)
                dst_host_addr = dst_host_info["host_addr"]
                src_host_info = kb.get_condition(src_host_id)
                logger.info("src:%s" % src_host_info)
                src_host_addr = src_host_info["host_addr"]

                for param in params:
                    if param == "RHOSTS":
                        var["RHOSTS"] = dst_host_addr
                    elif param == "LHOST":
                        var["LHOST"] = self._convert_attacker_ip(src_host_addr)

                step_result = {"step": atstep, "var": var}
                self._insert_atstep(
                    action_name,
                    step_evc,
                    step_evd,
                    step_result["var"],
                    step_number,
                    scenario_id,
                    src_host_id,
                    dst_host_id,
                    plan_id,
                )
                steps.append(step_result)
                steps_evc.append(step_evc)
                steps_evd.append(step_evd)
                step_number += 1
                
            evc = self._calc_scenario_evc(steps_evc)
            evd = self._calc_scenario_evd(steps_evd)
            scenario = {
                "scenario_id": scenario_id,
                "evc": evc,
                "evd": evd,
                "steps": steps,
            }

            scenario_list.append(scenario)
        logger.info("Finished _pddl2scenario")

        return scenario_list

    def _get_action_params(self, action_name: str, ad: any) -> list:
        atstep = ad.get_attack_step(action_name)
        atstep_script = atstep.script
        # param_pattern = r'\{([a-zA-Z]+)\}'
        param_pattern = r"\{(.*?)\}"
        params = re.findall(param_pattern, atstep_script)

        return params

    def _insert_atstep(
        self,
        module_name: str,
        evc: int,
        evd: int,
        module_params: Dict,
        step_number: int,
        scenario_id: str,
        src_host_id: str,
        dst_host_id: str,
        plan_id: int,
    ):
        atstep_id = random_id_generator()

        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)
        kb.insert_attack_step(
            atstep_id,
            module_name,
            evc,
            evd,
            module_params,
            step_number,
            scenario_id,
            src_host_id,
            dst_host_id,
            plan_id,
        )

    def _ks2pddl(self, host_id: str, attack_modules: tuple) -> tuple:
        logger = self.logger()
        logger.info("Start ks2pddl host_id: %s" % host_id)

        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)
        host_info = kb.get_condition(host_id)
        
        host_cond = ""
        pred = {}
        pred_oss = []
        pred_cves = []
        pred_ports = []
        # OS
        for atmodule in attack_modules:
            action_pddl = atmodule.pddl_action
            action_cond = self._pddl2cond(action_pddl, DEFAULT_ACTION_NAME)

            for key in action_cond.keys():
                # CVE
                if key.startswith("CVE"):
                    host_cond += """
                        ({} {})
                    """.format(
                        key, host_info["host_id"]
                    )
                    pred_cves.append(key)

                # Port
                elif key.startswith("port"):
                    host_cond += """
                        ({} {})
                    """.format(
                        key, host_info["host_id"]
                    )
                    pred_ports.append(key)

                # OS
                elif key.startswith("os"):
                    for os in action_cond["os"]:
                        host_cond += """
                            (os-{} {})
                        """.format(
                            os.replace(" ", "-"), host_info["host_id"]
                        )
                        pred_oss.append(os.replace(" ", "-"))
        pred["port"] = pred_ports
        pred["os"] = pred_oss
        pred["cve"] = pred_cves

        if host_info["is_exploited"] == "t":
            host_cond += """
                (exploited {})
                """.format(
                host_id
            )

        logger.info("Finished ks2pddl")

        return host_cond, pred

    def _map_os(self, os_name: str) -> list:
        map_file = self._map_file
        with open(map_file, mode="rt", encoding="utf-8") as f:
            os_map = json.load(f)
        if os_name in os_map:
            rval = os_map[os_name]
        else:
            rval = ["OTHER"]
        return rval

    def _is_festimated(self, name: str) -> bool:
        
        map_file = self._map_file   
        with open(map_file, mode="rt", encoding="utf-8") as f:
            map = json.load(f)

        if name in map:
            rval = True
        else:
            rval = False
        
        return rval

    def _merge_duplicates(self, lst: list) -> Dict:
        result = {}
        for item in lst:
            for key, value in item.items():
                if key not in result:
                    result[key] = list(set(value))
                else:
                    if isinstance(result[key], list):
                        result[key].extend(list(set(value) - set(result[key])))
                    else:
                        result[key] = list[set([result[key]] + value)]
        return result

    def _calc_scenario_evc(self, steps_evc: list) -> int:
        
        scenario_evc = 1
        for step_evc in steps_evc:
            try:
                scenario_evc *= step_evc/100
            except ZeroDivisionError:
                scenario_evc *= 0
        rval = round(scenario_evc *100, 2)
        
        return rval
    
    
    def _calc_scenario_evd(self, steps_evd: list) -> int:

        scenario_evd = 1
        for step_evd in steps_evd:
            try:
                scenario_evd *= 1 - step_evd/100
            except ZeroDivisionError:
                scenario_evd *= 1
        scenario_evd = 1 - scenario_evd
        rval = round(scenario_evd *100, 2)
        
        return rval

    def _parse_result(self, step: str) -> list:

        match = re.search(r"<Op \((.*?)\)>", step)
        action_name = match.group(1).split(" ", 1)[0]
        hosts = match.group(1).split(" ", 1)[1]
        src_host_id = hosts.split(" ", 1)[0]
        dst_host_id = hosts.split(" ", 1)[1]

        parse_result = [action_name, src_host_id, dst_host_id]

        return parse_result

    def _convert_attacker_ip(self, ipaddr):
        ap: AttackPlatform = System.get_component(consts.COMPONENT_ATTACKPF)
        
        if ipaddr == "0.0.0.0":
            network_info = ap.get_system_info(None)
            nics_list = network_info["interfaces"]
            for nic in nics_list:
                if nic[0] == 'eth0':
                    rval = nic[1]
        else:
            rval = ipaddr
        
        return rval


    def evaluate_step_evc(self, host_id:str , atstep:any) -> float:
        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)

        logger = self.logger()
        vardef_file = self._vardef_file
        logger.info("[*] Load stochastic variable definition file %s", vardef_file)
        with open(vardef_file, mode="rt", encoding="utf-8") as f:
            vardefs = json.load(f)
        states = dict()
        for var_def in vardefs:
            varname = var_def["varname"]
            varvalues = var_def["values"]
            states[varname] = varvalues

        logger.info("[*] Finish load states states:%s" % states)
        ptables = kb.get_festimated()
        logger.info("[*]  ptables length:%s" % len(ptables))
        logger.info("[*] Start generation Bayesian network")
        # bn = createBayesianNetworkFromPTables( ptables.values(), states )
        bn = createBayesianNetworkFromPTables(ptables, states)
        logger.info("[*] Finished generation Bayesian network")
        ks = {}
        host_info = kb.get_condition(host_id)

        # OS
        if host_info["host_type"] is not None:
            host_os = self._map_os(host_info["host_type"])
            ks["os"]= host_os[0]
        else:
            ks["os"] = 'OTHER'
            
        # CVE        
        cves = kb.get_cves(host_info["host_addr"])
        for cve in cves:
            if self._is_festimated(cve):
                ks[cve] = "yes"

        # ポート
        ports = kb.get_ports(host_info["host_addr"])
        for port in ports:
            port_name = "port-{}".format(str(port[0]))
            if self._is_festimated(port_name):
                ks[port_name] = "Open"

        if ks is not None and len(ks) > 0:
            logger.info("[*] Knowledge=%s" % repr(ks))
            c_ks = COND(ks)
            p_ks = PROB(c_ks, bn)
            logger.info("[*] Pre-knowledge joint probability=%s" % p_ks)
            if p_ks == 0:
                logger.info(
                    "[X] Prior knowledge joint probability is 0. Check for undefined values ​​and conflicting knowledge"
                )
        else:
            c_ks = Condition()
            p_ks = 1
        cond_pddl = atstep.pddl_action
        cond = COND(self._pddl2cond(cond_pddl, DEFAULT_ACTION_NAME))
        name = atstep.name

        targets = None
        targets_file = self._targets_file
        
        with open(targets_file, mode="rt", encoding="utf-8") as f:
            target_def = json.load(f)
        for key in target_def.keys():
            if key == name:
                targets = target_def[name]

        dist = DIST(cond & c_ks, bn, target_vars=targets)
        dist._P = dist._P / p_ks

        if targets is not None:
            srates = list()
            for val in dist[targets[0]]:
                srate = atstep.calc_success_rate(val)
                srates.append(srate)
            succ_rates = pd.Series(data=srates)
        else:
            succ_rates = dist.apply(atstep.calc_success_rate, axis=1)

        eVc = sum(dist._P * succ_rates)
        logger.info(f"[*] {name} ==> {eVc}")

        return eVc * 100

    def _pddl2cond(self, action_pddl: str, words: list) -> Dict:
        predicates = {}

        lines = action_pddl.split("\n")

        process_line = False
        for line in lines:
            line = line.strip()

            if line.startswith(":precondition"):
                process_line = True
                continue
            elif line.startswith(":effect"):
                process_line = False

            if process_line:
                if "(" in line and ")" in line:
                    predicate = line[line.index("(") + 1 : line.index(")")]

                    predicate = re.sub(r"\?[^\s\(\)]+", "", predicate)
                    predicate = predicate.strip()

                    os_list = []
                    for word in words:
                        if re.search(r"\b{}\b".format(word), predicate):
                            if re.search(r"os-", predicate):
                                predicate = predicate.strip("os-").replace("-", " ")
                                os_list.append(predicate)
                                predicates["os"] = os_list
                            elif re.search(r"port-", predicate):
                                predicates[predicate] = "Open"
                            elif re.search(r"CVE-", predicate):
                                predicates[predicate] = "yes"

        return predicates

    @staticmethod
    def _guess_log_detectability(log_quantity: int, log_anomality: int) -> float:
        log_quantity = min(
            5, max(0, log_quantity)
        )  # 0 means no log ( never detecable )
        log_anomality = min(5, max(1, log_anomality))  # 1 means absolutely normal

        return (log_quantity * log_anomality) / 25.0

    def evaluate_step_evd(self, astep: AttackStep, src_host_id: str, dst_host_id: str):
        kb: KnowledgeBase = System.get_component(consts.COMPONENT_KS)

        evd_factors = astep.evd_factors

        detectable_nids = evd_factors.get("NIDS", None)

        if detectable_nids is not None:
            nids_probability = kb.guess_nids_probability(
                src_host_id, dst_host_id, detectable_nids
            )

            detectability_nids = nids_probability
        else:
            detectability_nids = 0

        detectable_avs = evd_factors.get("AVS", None)

        if detectable_avs is not None:
            avs_probability = kb.guess_avs_probability(dst_host_id, detectable_avs)

            detectability_avs = avs_probability
        else:
            detectability_avs = 0

        log_factor = evd_factors.get("LOG", None)
        if log_factor is not None:
            log_quantity = log_factor.get("Q", 0)
            log_anomality = log_factor.get("A", 1)
            detectability_log = self._guess_log_detectability(
                log_quantity, log_anomality
            )
        else:
            detectability_log = 0

        eVd = 1.0 - (1.0 - detectability_nids) * (1.0 - detectability_avs) * (
            1.0 - detectability_log
        )

        return eVd *100

    def register_new_plan(self, src_host_id: str, dst_host_id: str) -> int:
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            sql = """
            INSERT INTO plan_hist (created_time, src_host_id, dst_host_id) VALUES (now(), %s, %s);
            """
            cur.execute(sql, (src_host_id, dst_host_id))

            cur.execute("SELECT currval('plan_hist_plan_id_seq'::regclass);")
            (plan_id,) = cur.fetchone()

        return plan_id

    def get_last_plan(self):
        result = self.get_last_plans(1)
        if len(result["plan_ids"]) == 0:
            return (None, None)

        plan_id = result["plan_ids"][0]
        plan_info = result["plan"][plan_id]
        return (plan_info, plan_id)

    def get_last_plans(self, nplans=1):

        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)
        rval = dict()
        rval["plan_ids"] = list()
        rval["plan"] = dict()

        with dbms.cursor() as cur:
            if nplans > 0:
                sql_limit = f"LIMIT {nplans}"
            else:
                sql_limit = ""

            sql = f"""
            SELECT
                plan_id,
                created_time,
                src_host_id,
                dst_host_id
            FROM
                plan_hist
            ORDER BY
                plan_id DESC
            {sql_limit}
            ;
            """

            cur.execute(sql)

            plan_result = cur.fetchall()
            for plan_id, created_time, src_host_id, dst_host_id in plan_result:
                sql = """
                SELECT
                    DISTINCT scenario_id
                FROM
                    scenario_list
                WHERE
                    plan_id=%s
                ;
                """

                cur.execute(sql, (plan_id,))
                scenario_ids = [e[0] for e in cur.fetchall()]

                rval["plan_ids"].append(plan_id)
                rval["plan"][plan_id] = {
                    "created_time": created_time,
                    "src_host_id": src_host_id,
                    "dst_host_id": dst_host_id,
                    "scenario_ids": scenario_ids,
                }

        return rval

    def find_plan_by_scenario_id(self, scenario_id: str):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            sql = """
            SELECT
                plan_id,
                created_time,
                src_host_id,
                dst_host_id
            FROM
                plan_hist
            WHERE
                plan_id IN (
                    SELECT
                        plan_id
                    FROM
                        scenario_list
                    WHERE
                        scenario_id=%s
                    LIMIT 1                    
                )
            ;
            """

            cur.execute(sql, (scenario_id,))
            result = cur.fetchone()
            if result is None:
                return None

        plan_id, created_time, src_host_id, dst_host_id = result
        return {
            "plan_id": plan_id,
            "created_time": created_time,
            "src_host_id": src_host_id,
            "dst_host_id": dst_host_id,
        }
