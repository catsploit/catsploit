#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import readline
import sys
import time
from argparse import ArgumentParser, ArgumentError, ArgumentTypeError
from typing import Iterable

from rich.table import Table
from rich.console import Console
import pandas as pd
import numpy as np

from .parse import string2args
from .api import CatsServer
from . import console as con

class CanceledException(Exception):
    pass

def load_args():
    argp = ArgumentParser()
    argp.add_argument(
        "--socket",
        "-s",
        help="server socket",
        required=False,
        default="/tmp/cats.usock",
    )

    args = argp.parse_args()
    config = {"socket": args.socket}
    return config


_cats_server: CatsServer = None


def register_server(srv: CatsServer):
    global _cats_server
    _cats_server = srv


def get_server() -> CatsServer:
    return _cats_server


def get_console() -> Console:
    return Console()


def create_table(values: Iterable[Iterable[str]], headers: Iterable[str]):
    table = Table(*headers)
    fn = lambda v: "" if v is None else str(v)
    for row in values:
        str_row = [fn(v) for v in row]
        table.add_row(*str_row)
    return table


def create_table_from_df(df: pd.DataFrame):
    headers = df.columns
    values = df.to_numpy(na_value="")
    return create_table(values, headers)


def cmd_host_list(args):
    console = get_console()
    srv: CatsServer = get_server()
    rval = srv.host_list()

    table_values = [hinfo.values() for hinfo in rval]
    table_columns = ["hostID", "IP", "Hostname", "Platform", "Pwned"]

    table = create_table(table_values, table_columns)

    console.print(table)


def cmd_host_detail(args):
    console = get_console()
    srv: CatsServer = get_server()
    rval = srv.host_detail(args.host_id, args.refresh)


    # base attributes
    cols = ["hostID", "IP", "Hostname", "Platform", "Pwned"]
    values = [rval[col] for col in cols]
    table = create_table([values], cols)

    console.print(table)

    f_show_ips = args.ips
    f_show_ports = args.ports
    f_show_vulns = args.vulns
    f_show_users = args.users

    if (f_show_ips, f_show_ports, f_show_vulns, f_show_users) == (
        False,
        False,
        False,
        False,
    ):
        f_show_ips, f_show_ports, f_show_vulns, f_show_users = (True, True, True, True)

    if f_show_ips:
        values = rval["IPs"]
        cols = ["ipv4", "ipv4mask", "ipv6", "ipv6prefix"]

        df = pd.DataFrame(values, columns=cols).replace("", np.nan)

        table = create_table_from_df(df.sort_values(["ipv4", "ipv6"]))

        console.print("")
        console.print("[IP address]")
        console.print(table)

    if f_show_ports:
        values = rval["Ports"]
        cols = ["ip", "proto", "port", "service", "product", "version"]

        df = pd.DataFrame(values, columns=cols).sort_values(["ip", "proto", "port"])
        table = create_table_from_df(df)

        console.print("")
        console.print("[Open ports]")
        console.print(table)

    if f_show_vulns:
        values = rval["Vulnerabilities"]
        cols = ["ip", "proto", "port", "vuln_name", "cve"]
        df = pd.DataFrame(values, columns=cols).sort_values(["ip", "proto", "port"])
        table = create_table_from_df(df)

        console.print("")
        console.print("[Vulnerabilities]")
        console.print(table)

    if f_show_users:
        values = rval["Users"]
        cols = ["user name", "group"]
        df = pd.DataFrame(values, columns=cols)
        sr_users = df["user name"].drop_duplicates()
        df_groups = df.groupby("user name").agg(lambda gs: ", ".join(gs))

        df = df_groups.loc[sr_users, :].reset_index()

        table = create_table_from_df(df)

        console.print("")
        console.print("[Users]")
        console.print(table)


def wait_task(*, update_sec=1.0, template="{}%"):
    srv = get_server()

    while True:
        try:
            progress, logs = srv.get_progress_and_logs_of_task()
            if logs is None:
                break
            if len(logs) > 0:
                print(" "*(len(template)+3),end="\r")
                for log in logs:
                    print(">",log.rstrip())
            msg = template.format(progress)
            print(msg, end="\r", flush=True)

            if progress < 0 or progress >= 100:
                break
            time.sleep(update_sec)
        except KeyboardInterrupt:
            print("")
            ans = input("Abort? (yes/No): ")
            if ans.lower() in ('yes', 'y'):
                srv.cancel_task()
                raise CanceledException("Task aborted.")
            
    print("")


def cmd_plan(args):
    srv = get_server()
    srv.start_plan_task(args.src_host_id, args.dst_host_id)

    wait_task(template="Planning attack scenario...{}%")

    result = srv.get_result_of_task()
    con.info("Done. {} scenarios were planned.".format(len(result)))
    con.info("To check each scenario, try 'scenario list' and/or 'scenario detail'.")


def cmd_scan(args):
    srv = get_server()

    DEFAULT_PORTS = "1-1024"

    target_hosts = args.target_host
    target_port = args.port
    if target_port is None:
        target_port = DEFAULT_PORTS

    # port scan
    srv.start_scan_task("attacker", target_hosts, "NW", target_port)
    wait_task(template="Network Scanning ... {}%")
    result = srv.get_result_of_task()

    found_hosts_num = len(result)
    con.info("Total {} hosts were discovered.".format(found_hosts_num))

    # vuln scan
    srv.start_scan_task("attacker", target_hosts, "SEC", target_port)
    wait_task(template="Vulnerability Scanning ... {}%")
    result = srv.get_result_of_task()

    found_vulns_num = len(result)
    con.info("Total {} vulnerabilities were discovered.".format(found_vulns_num))

def cmd_attack(args):
    srv = get_server()
    scenario_id = args.scenario_id
    
    srv.start_execute_scenario_task(scenario_id)
    wait_task(template="Executing attack scenario ... {}%")
    
    rval = srv.get_result_of_task()
    if rval  == True:
        con.success("Attack scenario succeeded!")
    else:
        con.error("Attack scenario failed, please check cats-server.log for the reason.")
        
def cmd_find_secret(args):
    srv = get_server()
    host_id = args.host_id
    
    srv.start_search_secret(host_id)
    wait_task(template="Searching secrets ... {}%")
    
    result = srv.get_result_of_task()
    
    if len(result) == 0:
        con.warn("Sorry, nothing found...")
        return
    
    con.success("Some files are found.")
    
    values = [ [f] for f in result ]
    cols = ["file path"]
    table = create_table(values, cols)
    
    console = get_console()
    console.print(table)


def cmd_scenario_list(args):
    srv = get_server()
    result = srv.scenario_list()
    if result is None:
        con.warn("No scenario.")
        return
    
    src_host_ip = result["src_ip"]
    dst_host_ip = result["dst_ip"]
    scenario_infos = result["scenarios"]
    
    values = list()
    for sid, sinfo in scenario_infos:
        evc = sinfo["evc"]
        evd = sinfo["evd"]
        first_step = sinfo["first_step"]
        nsteps = sinfo["nsteps"]
        
        values.append( (sid, src_host_ip, dst_host_ip, evc, evd, nsteps, first_step) )
    
    cols = ["scenario id", "src host ip", "target host ip", "eVc", "eVd", "steps", "first attack step"]
    table = create_table( values, cols )
    
    console = get_console()
    console.print(table)
    

def cmd_scenario_detail(args):
    console = get_console()
    srv = get_server()
    scenario_id = args.scenario_id
    
    result = srv.scenario_detail(scenario_id)
    
    src_host_ip = result["src_host_ip"]
    dst_host_ip = result["dst_host_ip"]
    evc = result["evc"]
    evd = result["evd"]
    
    cols=["src host ip","target host ip","eVc","eVd"]
    values=[(src_host_ip, dst_host_ip, evc, evd)]
    table = create_table(values, cols)
    
    console.print(table)
    console.print("")
    
    step_values = list()
    step_no=1
    for step_info in result["steps"]:
        step_name = step_info["step"]
        step_var  = step_info["var"]
        
        step_var_str = "\n".join( [ f"{k}: {v}" for k, v in step_var.items() ] )
        step_values.append( (step_no, step_name, step_var_str) )
        
        step_no += 1
    
    cols = ["#", "step", "params"]
    step_table = create_table(step_values, cols)
    
    console.print("[Steps]")
    console.print(step_table)
    console.print("")

def cmd_reset_system(args):
    con.warn("THIS COMMAND WILL DELETE ALL DATA AND FOOTHOLDS.")
    confirm = input("Confirm to proceed ? (yes/No): ")
    if confirm.lower() in ("y","yes"):
        srv = get_server()
        srv.reset_system()
        con.info("Done.")
    else:
        con.info("Canceled.")

def cmd_reset_msf(args):
    con.warn("THIS COMMAND WILL STOP ALL METERSPLOIT SESSIONS.")
    confirm = input("Confirm to proceed ? (yes/No): ")
    if confirm.lower() in ("y","yes"):
        srv = get_server()
        srv.reset_component("ATTACKPF")
        con.info("Done.")
    else:
        con.info("Canceled.")
    

def cmd_help(args):
    rootp=args.rootp
    
    rootp.print_help()
    

def cmd_exit(args):
    srv = get_server()
    srv.close()
    print("Bye.")
    sys.exit(0)


class ParseError(Exception):
    pass


class CommandInterpreter(ArgumentParser):
    def exit(self, status=0, message=None):
        pass

    def error(self, message):
        raise ParseError(message)

def splash():
    logo=(
        "   _________  ___________       __      _ __",
        "  / ____/   |/_  __/ ___/____  / /___  (_) /_",
        " / /   / /| | / /  \__ \/ __ \/ / __ \/ / __/",
        "/ /___/ ___ |/ /  ___/ / /_/ / / /_/ / / /_",
        "\____/_/  |_/_/  /____/ .___/_/\____/_/\__/",
        "                     /_/",
        ""
    )
    print("\n".join(logo))

def main():
    splash()
    
    con.info("Connecting to cats-server")
    conf = load_args()

    srv: CatsServer = CatsServer()
    srv.open(conf["socket"])
    con.info("Done.")
    con.info("Initializing server")
    srv.init_system()
    con.info("Done.")
    
    register_server(srv)
    
    

    rootp = CommandInterpreter(prog="", exit_on_error=False)
    subp = rootp.add_subparsers()

    #
    # HOST XX
    #
    hostp = subp.add_parser("host")

    host_subp = hostp.add_subparsers()
    host_listp = host_subp.add_parser("list")
    host_listp.set_defaults(func=cmd_host_list)

    host_detailp = host_subp.add_parser("detail")
    host_detailp.add_argument("host_id")
    host_detailp.add_argument("--refresh", action="store_true", help="re-scan system info of the specified host")
    host_detailp.add_argument("--ips", "-i", action="store_true", help="IP addresses")
    host_detailp.add_argument("--ports", "-p", action="store_true", help="open ports")
    host_detailp.add_argument(
        "--vulns", "-v", action="store_true", help="vulnerabilities"
    )
    host_detailp.add_argument("--users", "-u", action="store_true", help="users")
    host_detailp.set_defaults(func=cmd_host_detail)

    #
    # SCENARIO
    #
    scenariop = subp.add_parser("scenario")
    scenario_subp=scenariop.add_subparsers()
    
    # ... LIST
    scenario_listp=scenario_subp.add_parser("list")
    scenario_listp.set_defaults(func=cmd_scenario_list)
    
    # ... DETAIL
    scenario_detailp=scenario_subp.add_parser("detail")
    scenario_detailp.add_argument("scenario_id")
    scenario_detailp.set_defaults(func=cmd_scenario_detail)
    

    #
    # SCAN
    #
    scanp = subp.add_parser("scan")
    scanp.add_argument("target_host", nargs="+")
    scanp.add_argument("--port", "-p")
    scanp.set_defaults(func=cmd_scan)

    #
    # PLAN
    #
    planp = subp.add_parser("plan")
    planp.add_argument("src_host_id", help="originating host")
    planp.add_argument("dst_host_id", help="target host")
    planp.set_defaults(func=cmd_plan)

    #
    # ATTACK
    #
    attackp = subp.add_parser("attack")
    attackp.add_argument("scenario_id")
    attackp.set_defaults(func=cmd_attack)

    #
    # POST
    #
    postp = subp.add_parser("post")
    post_subp=postp.add_subparsers()
    post_find_secretp = post_subp.add_parser("find-secret")
    post_find_secretp.add_argument("host_id")
    post_find_secretp.set_defaults(func=cmd_find_secret)
    
    #
    # RESET
    #
    resetp = subp.add_parser("reset")
    resetp_subp = resetp.add_subparsers()
    resetp_systemp = resetp_subp.add_parser("system")
    resetp_systemp.set_defaults(func=cmd_reset_system)
    
    resetp_msfp = resetp_subp.add_parser("msf")
    resetp_msfp.set_defaults(func=cmd_reset_msf)

    #
    # HELP
    #
    helpp = subp.add_parser("help",aliases=['?'])
    helpp.set_defaults(rootp=rootp)
    helpp.set_defaults(func=cmd_help)

    #
    # EXIT
    #
    exitp = subp.add_parser("exit")
    exitp.set_defaults(func=cmd_exit)

    while True:
        cmdline = input("catsploit> ")
        argv, last_index = string2args(cmdline)

        try:
            args = rootp.parse_args(argv)
        except ParseError as e:
            con.error(str(e))
            continue
        except (ArgumentError, ArgumentTypeError) as e:
            continue

        cmd = getattr(args, "func", None)
        try:
            if cmd is not None:
                cmd(args)
        except Exception as e:
            con.error(str(e))
