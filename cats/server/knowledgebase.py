#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
from typing import Any
from .component import Component
from .config import Config
from .system import System
from . import constants as consts
from .dbms import DBMS
from ..core import random_id_generator
from .attack_platform import AttackPlatform

from ..errors import IDValueError


KS_TABLENAME_DETECTOR_ADOPTION_RATE = "detector_adoption_rate"
KS_TABLENAME_DETECTOR_MARKET_SHARE = "detector_share"

# knowledges collected during attack
KS_TABLENAME_FACTS_INSTALLED_DETECTORS = "facts_detectors"
KS_TABLENAME_FACTS_HOST_INFO = "facts_host_info"
KS_TABLENAME_FACTS_OPEN_PORTS = "facts_open_ports"
KS_TABLENAME_FACTS_VULNS = "facts_vulns"
KS_TABLENAME_FACTS_SYSINFO_BASE = "facts_sysinfo_base"
KS_TABLENAME_FACTS_SYSINFO_NICS = "facts_sysinfo_nics"
KS_TABLENAME_FACTS_SYSINFO_OPENPORTS = "facts_sysinfo_openports"
KS_TABLENAME_KS_LIST="ks_list"

KS_TABLES_DYNAMIC = [
    KS_TABLENAME_FACTS_INSTALLED_DETECTORS,
    KS_TABLENAME_FACTS_HOST_INFO,
    KS_TABLENAME_FACTS_OPEN_PORTS,
    KS_TABLENAME_FACTS_VULNS,
    KS_TABLENAME_FACTS_SYSINFO_BASE,
    KS_TABLENAME_FACTS_SYSINFO_NICS,
    KS_TABLENAME_FACTS_SYSINFO_OPENPORTS,
    KS_TABLENAME_KS_LIST
]

def _mult_dict_by_num(d: dict[str, float], num: float):
    return {k: v * num for k, v in d.items()}


import json
import pandas as pd

import logging


class KnowledgeBase(Component):
    def __init__(self) -> None:
        pass

    def initialize(self, config: Config) -> None:
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        try:
            self.get_status("attacker")
            return
        except IDValueError:
            pass
        
        ap: AttackPlatform = System.get_component(consts.COMPONENT_ATTACKPF)
        sys_info = ap.get_system_info(None)            
        
        with dbms.cursor() as cur:
            host_id = "attacker"
            host_addr = ap.IP_SELF
            host_name = sys_info["hostname"]
            host_type = sys_info["os_name"]
            host_mask = ap.IP_SELF
            is_exploited = True

            cur.execute(
                """INSERT INTO ks_list (
                host_id, 
                host_addr,
                host_type,
                host_name,
                host_mask,
                is_exploited
                )
                VALUES (%s,%s,%s,%s,%s,%s)
                """,
                (host_id, host_addr, host_type, host_name, host_mask, is_exploited),
            )
        

    def shutdown(self) -> None:
        pass
    
    def reset(self):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)
        with dbms.cursor() as cur:
            tables = ",".join(KS_TABLES_DYNAMIC)
            sql="TRUNCATE TABLE {}".format(tables)
            cur.execute(sql)

        ap: AttackPlatform = System.get_component(consts.COMPONENT_ATTACKPF)
        sys_info = ap.get_system_info(None)            

        with dbms.cursor() as cur:
            host_id = "attacker"
            host_addr = ap.IP_SELF
            host_name = sys_info["hostname"]
            host_type = sys_info["os_name"]
            host_mask = ap.IP_SELF
            is_exploited = True

            cur.execute(
                """INSERT INTO ks_list (
                host_id, 
                host_addr,
                host_type,
                host_name,
                host_mask,
                is_exploited
                )
                VALUES (%s,%s,%s,%s,%s,%s)
                """,
                (host_id, host_addr, host_type, host_name, host_mask, is_exploited),
            )

        dbms.commit()
        self.register_sys_info(host_id, sys_info)
        
    @classmethod
    def depends(cls):
        return [consts.COMPONENT_ATTACKPF, consts.COMPONENT_DBMS]
        

    def get_status(self, host_id):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.dict_cursor() as cur:
            cur.execute(
                """
                        SELECT 
                            host_id, 
                            host_addr, 
                            host_type, 
                            host_name, 
                            host_mask,
                            is_exploited
                        FROM 
                            ks_list 
                        WHERE 
                            host_id like %s
                        LIMIT 1
                        """,
                (host_id,),
            )

            rval = [dict(dict_row) for dict_row in cur.fetchall()]

        if len(rval) == 0:
            raise IDValueError("Invalid host ID")

        return rval[0]

    def get_status_ex(self, host_id):
        logger = self.logger()

        hinfo = self.get_status(host_id)
        pwned = hinfo["is_exploited"]

        rval = dict()
        rval["hostID"] = host_id
        rval["IP"] = hinfo["host_addr"]
        rval["Hostname"] = hinfo["host_name"]
        rval["Platform"] = hinfo["host_type"]
        rval["Arch"] = None
        rval["Pwned"] = hinfo["is_exploited"]

        host_ip = hinfo["host_addr"]

        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)
        with dbms.cursor() as cur:
            sysinfo_openports_exists = False
            sysinfo_nics_exists = False

            if pwned:
                # Get host_name, os, arch from facts_sysinfo_base
                sql = """
                SELECT
                    host_name, os, arch
                FROM
                    facts_sysinfo_base
                WHERE
                    host_id=%s
                """
                cur.execute(sql, (host_id,))
                hit = cur.fetchone()
                if hit is None:
                    logger.warning(
                        "ID:%s is pwned, but there is no entry in facts_sysinfo_base",
                        host_id,
                    )
                else:
                    host_name, os, arch = hit
                    rval["Hostname"] = host_name
                    rval["Platform"] = os
                    rval["Arch"] = arch

                # Get ipv4, ipv4mask, ipv6, ipv6prefix from facts_sysinfo_nics
                sql = """
                SELECT
                    ipv4, ipv4mask, ipv6, ipv6prefix
                FROM
                    facts_sysinfo_nics
                WHERE
                    host_id=%s
                """
                cur.execute(sql, (host_id,))
                host_nics = list()
                host_nics = cur.fetchall()
                if len(host_nics) > 0:
                    sysinfo_nics_exists = True

                sql = """
                SELECT
                    1
                FROM
                    facts_sysinfo_openports
                WHERE
                    host_id=%s
                LIMIT 1
                """
                cur.execute(sql, (host_id,))
                result = cur.fetchone()
                if result is not None:
                    sysinfo_openports_exists = True

            if not sysinfo_nics_exists:
                host_nics = [(hinfo["host_addr"], None, None, None)]

            # IPs
            rval["IPs"] = host_nics

            # Ports

            if sysinfo_openports_exists and sysinfo_nics_exists:

                sql = """
                    SELECT 
                        s.ip, s.protocol, s.port,
                        p.service, p.product, p.version
                    FROM
                        (
                            SELECT
                                *
                            FROM
                                facts_sysinfo_openports 
                            WHERE 
                                host_id=%s
                        ) as s
                        LEFT JOIN 
                        (
                            SELECT 
                                * 
                            FROM 
                                facts_open_ports 
                            WHERE 
                                host_addr IN 
                                    (
                                        SELECT 
                                            ipv4 
                                        FROM 
                                            facts_sysinfo_nics 
                                        WHERE 
                                            host_id=%s
                                    )
                        ) as p 
                        ON 
                            s.protocol=p.protocol 
                            AND s.port=p.port 
                            AND (
                                s.ip=p.host_addr 
                                OR 
                                s.ip='0.0.0.0'
                            ) 
                    ;
                """
                params=[host_id,host_id]
            elif sysinfo_openports_exists and not sysinfo_nics_exists:
                sql = """
                    SELECT 
                        s.ip, s.protocol, s.port,
                        p.service, p.product, p.version
                    FROM
                        (
                            SELECT
                                *
                            FROM
                                facts_sysinfo_openports 
                            WHERE 
                                host_id=%s
                        ) as s
                        LEFT JOIN 
                        (
                            SELECT 
                                * 
                            FROM 
                                facts_open_ports 
                            WHERE 
                                host_addr=%s 
                                OR
                                host_addr IN (
                                    SELECT 
                                        ip
                                    FROM
                                        facts_sysinfo_openports
                                    WHERE
                                        host_id=%s
                                    GROUP BY
                                        ip
                                    )
                        ) as p 
                        ON 
                            s.protocol=p.protocol 
                            AND s.port=p.port 
                            AND (
                                s.ip=p.host_addr 
                                OR 
                                s.ip='0.0.0.0'
                            ) 
                    ;
                """
                params=[host_id,host_ip,host_id]
                
            elif not sysinfo_openports_exists and sysinfo_nics_exists:
                sql = """
                    SELECT 
                        host_addr, protocol, port,
                        service, product, version
                    FROM
                        facts_open_ports
                    WHERE 
                        host_addr IN (
                            SELECT 
                                ipv4
                            FROM
                                facts_sysinfo_nics
                            WHERE
                                host_id=%s
                    ;
                """
                params=[host_id]
            else:
                sql = """
                    SELECT 
                        host_addr, protocol, port,
                        service, product, version
                    FROM
                        facts_open_ports
                    WHERE 
                        host_addr=%s
                    ;
                """
                params=[host_ip]

            
            cur.execute(sql, params)
            
            rval["Ports"] = cur.fetchall()

            if sysinfo_nics_exists:
                sql = """
                    SELECT
                        host_addr, protocol, port, vuln_name, cve
                    FROM
                        facts_vulns
                    WHERE
                        host_addr IN (
                            SELECT
                                ipv4
                            FROM
                                facts_sysinfo_nics
                            WHERE
                                host_id=%s
                        )
                """
                params=[host_id]
            elif sysinfo_openports_exists:
                sql = """
                    SELECT
                        host_addr, protocol, port, vuln_name, cve
                    FROM
                        facts_vulns
                    WHERE
                        host_addr = %s
                        OR
                        host_addr IN (
                            SELECT
                                ip
                            FROM
                                facts_sysinfo_openports
                            WHERE
                                host_id=%s
                            GROUP BY
                                ip
                        )
                """
                params=[host_ip,host_id]
            else:
                sql = """
                    SELECT
                        host_addr, protocol, port, vuln_name, cve
                    FROM
                        facts_vulns
                    WHERE
                        host_addr = %s
                """
                params=[host_ip]
                
            cur.execute(sql, params)
            rval["Vulnerabilities"] = cur.fetchall()

            sql = """
                SELECT
                    user_name, group_name
                FROM
                    facts_sysinfo_users
                WHERE
                    host_id=%s
            """
            cur.execute(sql, [host_id])
            rval["Users"] = cur.fetchall()

        return rval

    def get_condition(self, host_id):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)


        with dbms.dict_cursor() as cur:
            cur.execute(
                """
                        SELECT  
                            host_id, 
                            host_addr, 
                            host_type, 
                            host_mask,
                            is_exploited
                        FROM 
                            ks_list 
                        WHERE 
                            host_id like %s
                        LIMIT 1
                        """,
                (host_id,),
            )

            rval = [dict(dict_row) for dict_row in cur.fetchall()]

        if len(rval) == 0:
            raise IDValueError("Invalid host ID")

        return rval[0]

    def get_status_by_ip(self, host_ip):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.dict_cursor() as cur:
            cur.execute(
                """
                        SELECT 
                            host_id, 
                            host_addr, 
                            host_type, 
                            host_name, 
                            host_mask,
                            active_user,
                            is_avs,
                            is_exploited,
                            vuln_info
                        FROM 
                            ks_list 
                        WHERE host_addr like %s""",
                (host_ip,),
            )

            rval = [dict(dict_row) for dict_row in cur.fetchall()]

        if len(rval) == 0:
            return None

        return rval[0]

    def get_host_list(self):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            cur.execute("SELECT host_id, is_exploited FROM ks_list")

            exploited_hosts = list()
            found_hosts = list()

            for host_id, is_exploited in cur.fetchall():
                if is_exploited:
                    exploited_hosts.append(host_id)
                else:
                    found_hosts.append(host_id)

        return (tuple(found_hosts), tuple(exploited_hosts))

    def get_hosts_condition_except_id(self, host_id):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.dict_cursor() as cur:
            cur.execute(
                """
                        SELECT 
                            host_id, 
                            host_addr, 
                            host_type,
                            host_mask, 
                            is_exploited
                        FROM 
                            ks_list 
                        where 
                            host_id != %s
                        """,
                (host_id,),
            )

            rval = [dict(dict_row) for dict_row in cur.fetchall()]

        if len(rval) == 0:
            raise IDValueError("Invalid host ID")

        return rval
    
    def get_scenario_all_status(self, scenario_id):
        dbms:DBMS = System.get_component(consts.COMPONENT_DBMS)
        
        with dbms.dict_cursor() as cur:
            cur.execute("""
                        SELECT 
                            *
                        FROM 
                            scenario_list 
                        WHERE 
                            scenario_id = %s 
                        ORDER BY 
                            step_number
                        """,(scenario_id,))
            
            result = [dict(dict_row) for dict_row in cur.fetchall()]
        
        return result
    
    
    def get_all_hosts_condition(self):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.dict_cursor() as cur:
            cur.execute(
                """
                        SELECT 
                            host_id, 
                            host_addr, 
                            host_type, 
                            is_exploited
                        FROM 
                            ks_list 
                        """
            )

            rval = [dict(dict_row) for dict_row in cur.fetchall()]

        if len(rval) == 0:
            return None

        return rval

    def get_cves(self, host_ip):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            cur.execute(
                """
                        SELECT 
                            cve
                        FROM 
                             facts_vulns
                        WHERE 
                            host_addr like %s
                        """,
                (host_ip,),
            )

            cves = cur.fetchall()
        return [cve[0].replace("_", "-").upper() for cve in cves]

    def get_ports(self, host_ip):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            cur.execute(
                """
                        SELECT 
                            port
                        FROM 
                             facts_open_ports
                        WHERE 
                            host_addr like %s
                        """,
                (host_ip,),
            )

            ports = cur.fetchall()

        return ports
    
    def update_ks(self, host_id:str, host_info:dict):
        
        dbms:DBMS = System.get_component(consts.COMPONENT_DBMS)
        
        with dbms.cursor() as cur:
            if host_info.get("is_avs") is not None:
                cur.execute(
                    "UPDATE ks_list SET is_avs=%s WHERE host_id=%s",
                    (host_info["is_avs"], host_id)
                )
            if host_info.get("active_user") is not None:
                cur.execute(
                    "UPDATE ks_list SET active_user=%s WHERE host_id=%s", 
                    (host_info["active_user"], host_id)
                )
                
        dbms.commit()
    
    def update_host_info(self, host_id:str, host_info:dict):
        
        dbms:DBMS = System.get_component(consts.COMPONENT_DBMS)
        
        
        with dbms.cursor() as cur:
            self._update_host_info(cur, host_id, host_info)

        dbms.commit()

    def reset_ks(self):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            cur.execute("TRUNCATE TABLE ks_list")

    def insert_host_infos(self, list_host_infos):

        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            for host_info in list_host_infos:
                cur.execute(
                    "SELECT host_id FROM ks_list WHERE host_addr=%s LIMIT 1",
                    (host_info["host_addr"],),
                )
                r = list(cur.fetchall())
                if len(r) == 0:
                    self._insert_host_info(cur, host_info)

        dbms.commit()

    def insert_port_infos(self, list_host_infos):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        updates = list()
        for host_info in list_host_infos:
            host_addr = host_info["host_addr"]
            for port_info in host_info["ports"]:
                updates.append((host_addr,) + port_info)

        with dbms.cursor() as cur:
            cur.executemany(
                f""" INSERT INTO {KS_TABLENAME_FACTS_OPEN_PORTS} (host_addr, protocol, port, service, product, version)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (host_addr, protocol, port) 
                        DO UPDATE SET 
                            service=CASE WHEN EXCLUDED.service IS NOT NULL THEN EXCLUDED.service ELSE {KS_TABLENAME_FACTS_OPEN_PORTS}.service END,
                            product=CASE WHEN EXCLUDED.product IS NOT NULL THEN EXCLUDED.product ELSE {KS_TABLENAME_FACTS_OPEN_PORTS}.product END,
                            version=CASE WHEN EXCLUDED.version IS NOT NULL THEN EXCLUDED.version ELSE {KS_TABLENAME_FACTS_OPEN_PORTS}.version END
                """,
                updates,
            )
            dbms.commit()

    def insert_vuln_infos(self, list_vuln_infos):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        updates = list()
        for vuln_info in list_vuln_infos:
            host_addr = vuln_info["host_addr"]
            protocol = vuln_info["protocol"]
            port = vuln_info["port"]
            oid = vuln_info["oid"]
            vuln_name = vuln_info["vuln_name"]
            cves = vuln_info["cves"]
            if len(cves) == 0:
                cves = ["N/A"]

            for cve in cves:
                updates.append((host_addr, protocol, port, oid, vuln_name, cve))

        with dbms.cursor() as cur:
            cur.executemany(
                f""" INSERT INTO {KS_TABLENAME_FACTS_VULNS} (host_addr, protocol, port, oid, vuln_name, cve) 
                        VALUES (%s, %s, %s, %s, %s, %s)
                    ON CONFLICT (host_addr, protocol, port, oid, cve) 
                        DO NOTHING
                """,
                list(updates),
            )
            dbms.commit()

    def _new_host_id(self):
        hid = random_id_generator()
        return f"h_{hid}"

    def insert_attack_step(
        self,
        attack_step_id,
        module_name,
        evc_score,
        evd_score,
        module_param,
        step_number,
        scenario_id,
        src_host_id,
        dst_host_id,
        plan_id,
    ):
        module_param_str = json.dumps(module_param)

        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)
        with dbms.cursor() as cur:
            cur.execute(
                """
                        INSERT INTO 
                            scenario_list 
                            (
                                attack_step_id, 
                                module_name, 
                                evc, 
                                evd,
                                module_params, 
                                step_number, 
                                scenario_id, 
                                src_host_id, 
                                dst_host_id,
                                plan_id
                            ) 
                            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                (
                    attack_step_id,
                    module_name,
                    evc_score,
                    evd_score,
                    module_param_str,
                    step_number,
                    scenario_id,
                    src_host_id,
                    dst_host_id,
                    plan_id,
                ),
            )

        dbms.commit()

    def _insert_host_info(self, cur, host_info):
        host_id = self._new_host_id()
        host_addr = host_info["host_addr"]
        host_type = host_info["os_name"]
        host_name = host_info["host_name"]

        value = (host_id, host_addr, host_type, host_name)

        cur.execute(
            "INSERT INTO ks_list (host_id, host_addr, host_type, host_name) VALUES (%s, %s, %s, %s)",
            value,
        )

    def get_festimated(self):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            cur.execute(
                "SELECT table_name FROM information_schema.tables WHERE table_name LIKE 'festimated\_%';"
            )
            table_names = cur.fetchall()
            result = []
            for table_name in table_names:
                cur.execute(f"SELECT * FROM {table_name[0]}")
                rows = cur.fetchall()
                columns = [desc[0] for desc in cur.description]
                df = pd.DataFrame(rows, columns=columns)
                result.append(df)

        return result

    def _update_host_info(self, cur, host_id, host_info):
        host_addr, host_type, host_name = [
            host_info[k] for k in ("host_addr", "os_name", "host_name")
        ]

        sql = "UPDATE ks_list SET host_addr=%s, host_type=%s, host_name=%s WHERE host_id=%s"

        cur.execute(sql, [host_addr, host_type, host_name, host_id])

    def set_exploited_flag(self, host_id, flag=True):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            cur.execute(
                "UPDATE ks_list SET is_exploited=%s WHERE host_id=%s", (flag, host_id,)
            )

        dbms.commit()

    def set_subnet_mask(self, host_ip, subnetmask):
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            cur.execute(
                "UPDATE ks_list SET host_mask=%s WHERE host_addr=%s",
                (subnetmask, host_ip),
            )

        dbms.commit()

    def _get_traversing_networks(self, src_host_id, dst_host_id):

        return (None,)

    def _guess_default_product_dist(
        self,
        detector_type: str,
        detectable_products_set: set[str],
        condp_target_is_monitored_when_some_other_target_is_found_monitored: float,
        condp_target_is_monitored_by_the_same_product_used_in_other_location: float,
    ) -> tuple[float, dict[str, float]]:
        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        with dbms.cursor() as cur:
            cur.execute(
                f"SELECT rate FROM {KS_TABLENAME_DETECTOR_ADOPTION_RATE} WHERE detector_type=%s",
                (detector_type,),
            )
            (default_apply_rate,) = cur.fetchone()

            cur.execute(
                f"SELECT product, share FROM {KS_TABLENAME_DETECTOR_MARKET_SHARE} WHERE detector_type=%s",
                (detector_type,),
            )
            product_share = {p: v for p, v in cur.fetchall()}

            cur.execute(
                f"SELECT 1 FROM {KS_TABLENAME_FACTS_INSTALLED_DETECTORS} WHERE detector_type=%s AND installed=TRUE LIMIT 1",
                (detector_type,),
            )
            fact_monitored = cur.fetchone() is not None

            cur.execute(
                f"SELECT product, COUNT(product) FROM {KS_TABLENAME_FACTS_INSTALLED_DETECTORS} WHERE detector_type=%s AND installed=TRUE AND product IS NOT NULL GROUP BY product",
                (detector_type,),
            )

            result = cur.fetchall()
            fact_product_num = {prod: num for prod, num in result}
            total = sum(fact_product_num.values())
            fact_product_dist = {
                product: float(num) / total for product, num in fact_product_num.items()
            }

            if len(fact_product_dist) > 0:
                p_monitored = (
                    condp_target_is_monitored_when_some_other_target_is_found_monitored
                )

                p_monitored_by_unused_products = (
                    1
                    - condp_target_is_monitored_by_the_same_product_used_in_other_location
                )

                conditional_default_dist = _mult_dict_by_num(
                    fact_product_dist, (1 - p_monitored_by_unused_products)
                )

                popular_but_not_found_products_set = set(product_share.keys()) - set(
                    fact_product_dist.keys()
                )
                popular_but_not_found_products_share = {
                    p: s
                    for p, s in product_share.items()
                    if p in popular_but_not_found_products_set
                }
                popular_and_used_products_share_total = sum(
                    [
                        v
                        for p, v in product_share.items()
                        if p in set(fact_product_dist.keys())
                    ]
                )
                for p, s in popular_but_not_found_products_share.items():
                    conditional_default_dist[p] = (
                        p_monitored_by_unused_products
                        * s
                        / (1 - popular_and_used_products_share_total)
                    )

                detectable_but_neither_popular_nor_used_products_set = (
                    set(detectable_products_set)
                    - {"*"}
                    - set(conditional_default_dist.keys())
                )
                detectable_but_neither_popular_nor_used_products_dist_total = 1 - sum(
                    conditional_default_dist.values()
                )
                if len(detectable_but_neither_popular_nor_used_products_set) > 0:
                    n = len(detectable_but_neither_popular_nor_used_products_set)
                    for product in detectable_but_neither_popular_nor_used_products_set:
                        conditional_default_dist[product] = (
                            detectable_but_neither_popular_nor_used_products_dist_total
                            / n
                        )
                else:
                    conditional_default_dist[
                        "_OTHER_"
                    ] = detectable_but_neither_popular_nor_used_products_dist_total

            else:
                if fact_monitored == False:
                    p_monitored = default_apply_rate
                else:
                    p_monitored = condp_target_is_monitored_when_some_other_target_is_found_monitored

                conditional_default_dist = product_share

                detectable_but_nonpopular_products = (
                    detectable_products_set - {"*"} - set(product_share.keys())
                )
                total_share_of_popular_products = sum(product_share.values())

                for product in detectable_but_nonpopular_products:
                    conditional_default_dist[product] = (
                        1 - total_share_of_popular_products
                    ) / len(detectable_but_nonpopular_products)
        return p_monitored, conditional_default_dist

    def guess_nids_probability(
        self, src_host_id: str, dst_host_id: str, detectable_nids_set: set[str]
    ) -> float:


        CONDP_MONITOR_NETWORKS = 0.9
        CONDP_MONITORED_BY_FOUND_PRODUCTS = (
            0.9
        )

        p_monitored, conditional_default_dists = self._guess_default_product_dist(
            "NIDS",
            detectable_nids_set,
            CONDP_MONITOR_NETWORKS,
            CONDP_MONITORED_BY_FOUND_PRODUCTS,
        )
        default_dist = _mult_dict_by_num(conditional_default_dists, p_monitored)

        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)
        with dbms.cursor() as cur:
            cur.execute(
                f"SELECT 1 FROM {KS_TABLENAME_FACTS_INSTALLED_DETECTORS} WHERE installed=TRUE and detector_type='NIDS' LIMIT 1"
            )
            if len(list(cur.fetchall())):
                nids_installed = True
            else:
                nids_installed = False

        if nids_installed == False:

            networks = (None,)
        else:
            networks = self._get_traversing_networks(src_host_id, dst_host_id)

        nids_dists = list()
        for nw in networks:
            if nw is None:
                nids_dists.append(default_dist)
                continue

            with dbms.cursor() as cur:
                cur.execute(
                    f"SELECT installed, product FROM {KS_TABLENAME_FACTS_INSTALLED_DETECTORS} where location=%s and detector_type='NIDS' and installed IS NOT NULL LIMIT 1",
                    (nw,),
                )
                r = cur.fetchone()
                if r is None:
                    nids_dists.append(default_dist)
                    continue
                else:
                    installed, product = r

            if installed == False:
                continue

            assert installed == True

            if product is None:
                nids_dists.append(conditional_default_dists)
            else:
                nids_dists.append({product: 1.0})

        p_not_installed = 1
        for nids_dist_of_each_nw in nids_dists:
            if "*" in detectable_nids_set:
                p_installed = sum(nids_dist_of_each_nw.values())
            else:
                p_installed = sum(
                    [
                        nids_dist_of_each_nw[prod]
                        for prod in detectable_nids_set
                        if prod in nids_dist_of_each_nw
                    ]
                )

            p_not_installed *= 1 - p_installed

        dist_detectable_nids_exists = 1 - p_not_installed

        return dist_detectable_nids_exists

    def guess_avs_probability(
        self, host_id: str, detectable_avs_set: set[str]
    ) -> float:

        CONDP_MONITOR_HOSTS = 0.99
        CONDP_MONITORED_BY_FOUND_PRODUCTS = (
            0.99
        )

        p_monitored, conditional_default_dist = self._guess_default_product_dist(
            "AVS",
            detectable_avs_set,
            CONDP_MONITOR_HOSTS,
            CONDP_MONITORED_BY_FOUND_PRODUCTS,
        )

        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)
        with dbms.cursor() as cur:
            cur.execute(
                f"SELECT installed, product FROM {KS_TABLENAME_FACTS_INSTALLED_DETECTORS} WHERE location=%s AND detector_type='AVS' AND installed IS NOT NULL LIMIT 1",
                (host_id,),
            )
            result = cur.fetchone()
            if result is None:
                dist = _mult_dict_by_num(conditional_default_dist, p_monitored)
            else:
                installed, product = result

                if installed == False:
                    return 0.0

                if product is not None:
                    dist = {product: 1.0}
                else:
                    dist = conditional_default_dist

        dist_detectable_avs_exists = 0.0
        for product, prob in dist.items():
            if "*" in detectable_avs_set or product in detectable_avs_set:
                dist_detectable_avs_exists += prob

        return dist_detectable_avs_exists

    def register_sys_info(self, host_id: str, sys_info: dict[str, Any]):
        # sys_info = {
        #     “hostname”: <hostname>,
        #     “interfaces”: list[ (<ifname>, <ipv4>, <ipv4mask>, <ipv6>, <ipv6prefix>) ],
        #     “open_ports”: list[ (<proto>, <local_addr>, <local_port>) ],
        #     ”connections”: list[ (<proto>,<local_addr>,<local_port>, <remote_addr>, <remote_port>) ],
        #     “os_name” : <osname >,
        #     “arch”: <hwtype>,
        #     “users”: list[ ( <user_name>, list[ <group_name> ] ) ],
        # }

        dbms: DBMS = System.get_component(consts.COMPONENT_DBMS)

        # basic info
        sql = """
        INSERT
            INTO facts_sysinfo_base
            VALUES (
                %s, %s, %s, %s
            )
            ON CONFLICT ON CONSTRAINT facts_sysinfo_base_pkey 
            DO NOTHING
        ;
        """

        with dbms.cursor() as cur:
            cur.execute(
                sql,
                [host_id, sys_info["hostname"], sys_info["os_name"], sys_info["arch"]],
            )

        # interface
        sql = """
        INSERT
            INTO facts_sysinfo_nics
            VALUES (
                %s, %s, %s, %s, %s, %s
            )
            ON CONFLICT ON CONSTRAINT facts_sysinfo_nics_pkey 
            DO NOTHING
        ;
        """

        with dbms.cursor() as cur:
            cur.executemany(
                sql, [[host_id] + list(ifinfo) for ifinfo in sys_info["interfaces"]]
            )

        # open ports
        sql = """
        INSERT
            INTO facts_sysinfo_openports
            VALUES (
                %s, %s, %s, %s
            )
            ON CONFLICT ON CONSTRAINT facts_sysinfo_openports_pkey
            DO NOTHING
        ;
        """

        with dbms.cursor() as cur:
            cur.executemany(
                sql, [[host_id] + list(openport) for openport in sys_info["open_ports"]]
            )

        # users
        sql = """
        INSERT
            INTO facts_sysinfo_users
            VALUES (
                %s, %s, %s
            )
            ON CONFLICT ON CONSTRAINT facts_sysinfo_users_pkey
            DO NOTHING
        ;
        """

        insert_values = list()
        for user, groups in sys_info["users"]:
            for group in groups:
                insert_values.append([host_id, user, group])

        with dbms.cursor() as cur:
            cur.executemany(sql, insert_values)

        dbms.commit()

