#  Copyright (C) 2023 Mitsubishi Electric Corporation.
#
# Licensed according to the license at the following URL
#
# https://github.com/catsploit/catsploit/LICENSE
#
# You may not use this file except in compliance with the License.
#
import re
from pathlib import Path

from .component import Component
from .. import utils
from .config import Config
from . import constants as consts
from .attack_step import AttackStep

CONFIG_KEY_ATTACK_DB = consts.COMPONENT_ATTACKDB
CONFIG_KEY_ADB_FOLDER = f"{CONFIG_KEY_ATTACK_DB}.attack_db_dir"

DEFAULT_ADB_DBFOLDER = consts.DEFAULT_FOLDER_DB + "/attack_db/"

_EVD_FACTORS_SCHEMA = {
    "NIDS": "set",
    "AVS": "set",
    "LOG": "log",
}


class AttackDB(Component):

    def initialize(self, config: Config) -> None:
        dbdir = config.get(CONFIG_KEY_ADB_FOLDER, DEFAULT_ADB_DBFOLDER)
        evd_factors_schema = _EVD_FACTORS_SCHEMA

        self.load(dbdir, evd_factors_schema)

    def shutdown(self) -> None:
        pass

    @staticmethod
    def _parse_evd_factors_set(val_str: str):
        vals = [v.strip() for v in val_str.split(",")]
        return {v for v in vals if v != ""}

    @staticmethod
    def _parse_evd_factors_int(val_str: str):
        try:
            valnum = int(val_str)
        except ValueError as e:
            raise RuntimeError("string that cannot be parsed into an integer value'{}'".format(val_str)) from e
        
    @staticmethod
    def _parse_evd_factors_dict(val_str: str)->dict[str,str]:
        rval = dict()
        dict_defs = [dict_elem.strip() for dict_elem in val_str.split(",")]
        for dict_def in dict_defs:
            dict_key, dict_value = dict_def.split("=",1)
            dict_key = dict_key.strip().upper()
            dict_value= int( dict_value.strip() )
            rval[dict_key] = dict_value
        return rval
        
        
    @staticmethod
    def _parse_evd_factors_log(val_str:str)->dict[str,int]:
        attrs = AttackDB._parse_evd_factors_dict(val_str)
        rval = dict()
        for k,v in attrs.items():
            try:
                rval[k] = int(v)          
            except ValueError as e:
                raise RuntimeError("Integer conversion failed for attribute '{}' value '{}'".format(k,v))
        return rval
        

    @staticmethod
    def _load_astep_from_file(asfile: str, evd_factors_schema: dict[str, str]):
        logger = AttackDB.logger()

        mandatory_sections = ("pddl", "script")
        optional_secions = ("evc", "evd")
        valid_sections = mandatory_sections + optional_secions

        sections = dict()

        cur_section_name = None
        cur_section_lines = None

        rexSectionTag = re.compile(r"^\[\s*([^\]]+)\s*\]")
        with open(asfile) as fp:
            for line in fp:
                m = rexSectionTag.match(line)
                if m is not None:
                    section_name = m[1]
                    if section_name not in valid_sections:
                        raise RuntimeError(
                            "Unknown section ({}) in attack step definition file {}".format(section_name, asfile)
                        )

                    if cur_section_name is not None:
                        sections[cur_section_name] = "".join(cur_section_lines).strip()
                    cur_section_name = section_name
                    cur_section_lines = list()
                elif cur_section_name is not None:
                    cur_section_lines.append(line)
                else:
                    pass
        if cur_section_name is not None:
            sections[cur_section_name] = "".join(cur_section_lines).strip()

        if not all([s in sections for s in mandatory_sections]):
            raise RuntimeError("Missing required section in attack step definition file {}".format(asfile))

        rexName = re.compile(r":action\s+([^\s:]+)")
        m = rexName.search(sections["pddl"])
        if m is not None:
            name = m[1]
        else:
            raise RuntimeError("Action name not found in attack step definition file {}".format(asfile))

        # compile evc function (=success_rate)
        if "evc" in sections:
            g = {}
            exec(sections["evc"], g)
            evc = g.get("evc", None)
            if evc is None:
                logger.warning("eVc section is empty")

        else:
            evc = None

        evd_factors = dict()
        if "evd" in sections:
            lines = [l.strip() for l in sections["evd"].splitlines()]
            evd_defs = [elem.strip() for elem in lines if elem != ""]
            for evd_def in evd_defs:
                if ":" not in evd_def:
                    logger.error("Bad string in eVd section:%s", evd_def)
                    raise RuntimeError("Bad string in eVd section:{}".format(evd_def))

                factor_key, factor_val = [v.strip() for v in evd_def.split(":", 1)]
                factor_key = factor_key.upper()

                data_type = evd_factors_schema.get(factor_key, None)
                if data_type is None:
                    evd_factors[factor_key] = factor_val
                else:
                    parser = getattr(AttackDB, f"_parse_evd_factors_{data_type}", None)
                    if parser is None:
                        logger.critical(
                            "Internal Error: parser for evd_factor[%s](type=%s) is not defined.",
                            factor_key,
                            data_type,
                        )
                        raise RuntimeError(
                            "Internal Error: parser for evd_factor[{}](type={}) is not defined.".format(
                                factor_key, data_type
                            )
                        )

                    try:
                        evd_factors[factor_key] = parser(factor_val)
                    except RuntimeError as e:
                        logger.exception("Failed to parse eVd section %s:%s", factor_key, str(e))
                        raise RuntimeError(
                            "Failed to parse eVd section {}:{}".format(factor_key, str(e))
                        )

        astep = AttackStep(name, sections["pddl"], sections["script"], evc, evd_factors)
        return astep

    def __init__(self):
        self._attack_steps = dict()

    def load(self, dbfolder, evd_factors_schema):
        logger = self.logger()
        logger.info("Start loading in the attack definition file folder (folder:%s)", dbfolder)

        for asfile in Path(dbfolder).glob("*.step"):
            try:
                astep = AttackDB._load_astep_from_file(asfile, evd_factors_schema)
                self._attack_steps[astep.name] = astep
                logger.debug("Finished loading attack definition file %s", asfile)
            except Exception:
                logger.exception("Failed to load attack definition file (%s)", asfile)

        logger.info("Finished loading of the attack definition file storage folder")

    @property
    def attack_steps(self):
        return tuple(self._attack_steps.values())

    def get_attack_step(self, name) -> AttackStep | None:
        return self._attack_steps.get(name, None)
