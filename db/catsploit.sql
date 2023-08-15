--
-- PostgreSQL database dump
--

-- Dumped from database version 15.3 (Debian 15.3-1.pgdg120+1)
-- Dumped by pg_dump version 15.2 (Debian 15.2-2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: public; Type: SCHEMA; Schema: -; Owner: postgres
--

-- *not* creating schema, since initdb creates it


ALTER SCHEMA public OWNER TO postgres;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: detector_adoption_rate; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.detector_adoption_rate (
    detector_type text,
    rate real
);


ALTER TABLE public.detector_adoption_rate OWNER TO postgres;

--
-- Name: detector_share; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.detector_share (
    detector_type text,
    product text,
    share real
);


ALTER TABLE public.detector_share OWNER TO postgres;

--
-- Name: facts_detectors; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.facts_detectors (
    detector_type text,
    location text,
    installed boolean,
    product text
);


ALTER TABLE public.facts_detectors OWNER TO postgres;

--
-- Name: festimated_arch; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_arch (
    arch text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_arch OWNER TO postgres;

--
-- Name: festimated_cve_2014_3120; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_cve_2014_3120 (
    "CVE-2014-3120" text,
    "port-9200" text,
    _p double precision
);


ALTER TABLE public.festimated_cve_2014_3120 OWNER TO postgres;

--
-- Name: festimated_cve_2014_3704; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_cve_2014_3704 (
    "CVE-2014-3704" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_cve_2014_3704 OWNER TO postgres;

--
-- Name: festimated_cve_2015_8249; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_cve_2015_8249 (
    "CVE-2015-8249" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_cve_2015_8249 OWNER TO postgres;

--
-- Name: festimated_cve_2016_3087; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_cve_2016_3087 (
    "CVE-2016-3087" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_cve_2016_3087 OWNER TO postgres;

--
-- Name: festimated_domain_join; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_domain_join (
    domain_join text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_domain_join OWNER TO postgres;

--
-- Name: festimated_jenkins_auth; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_jenkins_auth (
    jenkins_auth text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_jenkins_auth OWNER TO postgres;

--
-- Name: festimated_login_attempt_limit; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_login_attempt_limit (
    login_attempt_limit text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_login_attempt_limit OWNER TO postgres;

--
-- Name: festimated_option_dmi; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_option_dmi (
    dmi text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_option_dmi OWNER TO postgres;

--
-- Name: festimated_option_dynamicscript; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_option_dynamicscript (
    dynamicscript text,
    "elastic-version" text,
    _p double precision
);


ALTER TABLE public.festimated_option_dynamicscript OWNER TO postgres;

--
-- Name: festimated_os; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_os (
    os text NOT NULL,
    _p double precision
);


ALTER TABLE public.festimated_os OWNER TO postgres;

--
-- Name: festimated_port_22; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_port_22 (
    "port-22" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_port_22 OWNER TO postgres;

--
-- Name: festimated_port_443; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_port_443 (
    "port-443" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_port_443 OWNER TO postgres;

--
-- Name: festimated_port_445; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_port_445 (
    "port-445" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_port_445 OWNER TO postgres;

--
-- Name: festimated_port_80; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_port_80 (
    "port-80" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_port_80 OWNER TO postgres;

--
-- Name: festimated_port_8020; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_port_8020 (
    "port-8020" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_port_8020 OWNER TO postgres;

--
-- Name: festimated_port_8040; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_port_8040 (
    "port-8040" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_port_8040 OWNER TO postgres;

--
-- Name: festimated_port_8484; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_port_8484 (
    "port-8484" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_port_8484 OWNER TO postgres;

--
-- Name: festimated_port_9200; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_port_9200 (
    "port-9200" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_port_9200 OWNER TO postgres;

--
-- Name: festimated_reg_localaccounttokenfilterpolicy; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_reg_localaccounttokenfilterpolicy (
    localaccounttokenfilterpolicy text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_reg_localaccounttokenfilterpolicy OWNER TO postgres;

--
-- Name: festimated_save_credential; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_save_credential (
    save_credential text,
    _p double precision
);


ALTER TABLE public.festimated_save_credential OWNER TO postgres;

--
-- Name: festimated_service_elastic; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_service_elastic (
    "elastic-version" text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_service_elastic OWNER TO postgres;

--
-- Name: festimated_service_manageengine; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_service_manageengine (
    manageengine_version text,
    os text,
    _p double precision
);


ALTER TABLE public.festimated_service_manageengine OWNER TO postgres;

--
-- Name: festimated_ssh_auth; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.festimated_ssh_auth (
    auth_type text,
    _p double precision
);


ALTER TABLE public.festimated_ssh_auth OWNER TO postgres;

--
-- Name: metasploit_module_list; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.metasploit_module_list (
    module_name text NOT NULL,
    server text,
    rank text,
    creds text,
    options text
);


ALTER TABLE public.metasploit_module_list OWNER TO postgres;

--
-- Name: plan_hist_plan_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.plan_hist_plan_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.plan_hist_plan_id_seq OWNER TO postgres;

--
-- Data for Name: detector_adoption_rate; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.detector_adoption_rate (detector_type, rate) FROM stdin;
AVS	0.98
NIDS	0.13
\.


--
-- Data for Name: detector_share; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.detector_share (detector_type, product, share) FROM stdin;
NIDS	cisco	0.2
NIDS	mcafee	0.2
NIDS	fortinet	0.2
NIDS	sonicwall	0.2
NIDS	OTHER	0.2
AVS	trendmicro	0.2
AVS	symantec	0.2
AVS	mcafee	0.2
AVS	kaspersky	0.2
AVS	OTHER	0.2
\.


--
-- Data for Name: facts_detectors; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.facts_detectors (detector_type, location, installed, product) FROM stdin;
\.


--
-- Data for Name: festimated_arch; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_arch (arch, os, _p) FROM stdin;
x64	Windows 10 21H2	1
x86	Windows 10 21H2	0
x64	Windows 10 21H1	1
x86	Windows 10 21H1	0
x64	Windows 10 20H2	1
x86	Windows 10 20H2	0
x64	Windows 10 2004	1
x86	Windows 10 2004	0
x64	Windows 10 1909	1
x86	Windows 10 1909	0
x64	Windows 10 1903	1
x86	Windows 10 1903	0
x64	Windows 10 1809 BEFORE	1
x86	Windows 10 1809 BEFORE	0
x64	Windows 7 SP1	1
x86	Windows 7 SP1	0
x64	Windows Server 2008 R2 SP1	1
x86	Windows Server 2008 R2 SP1	0
x64	Desktop Windows OTHER	1
x86	Desktop Windows OTHER	0
x64	Windows Server OTHER	1
x86	Windows Server OTHER	0
x64	Linux	1
x86	Linux	0
x64	Mac OS X	1
x86	Mac OS X	0
x64	OTHER	1
x86	OTHER	0
\.


--
-- Data for Name: festimated_cve_2014_3120; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_cve_2014_3120 ("CVE-2014-3120", "port-9200", _p) FROM stdin;
yes	Open	0.3
no	Open	0.7
yes	Close	0.01
no	Close	0.99
\.


--
-- Data for Name: festimated_cve_2014_3704; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_cve_2014_3704 ("CVE-2014-3704", os, _p) FROM stdin;
no	Linux	0.9
no	Mac OS X	0.9
no	OTHER	0.9
no	Windows 10 21H2	0.9
no	Windows 10 21H1	0.9
no	Windows 10 20H2	0.9
no	Windows 10 2004	0.9
no	Windows 10 1909	0.9
no	Windows 10 1809 BEFORE	0.9
no	Desktop Windows OTHER	0.9
no	Windows Server OTHER	0.9
no	Windows Server 2008 R2 SP1	0.9
no	Windows 7 SP1	0.9
yes	Linux	0.1
yes	Mac OS X	0.1
yes	OTHER	0.1
yes	Windows 10 21H2	0.1
yes	Windows 10 21H1	0.1
yes	Windows 10 20H2	0.1
yes	Windows 10 2004	0.1
yes	Windows 10 1909	0.1
yes	Windows 10 1809 BEFORE	0.1
yes	Desktop Windows OTHER	0.1
yes	Windows Server OTHER	0.1
yes	Windows Server 2008 R2 SP1	0.1
yes	Windows 7 SP1	0.1
\.


--
-- Data for Name: festimated_cve_2015_8249; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_cve_2015_8249 ("CVE-2015-8249", os, _p) FROM stdin;
yes	Linux	0
yes	Mac OS X	0
yes	Windows 10 21H2	0
yes	Windows 10 21H1	0
yes	Windows 10 20H2	0
yes	Windows 10 2004	0
yes	Windows 10 1909	0
yes	Windows 10 1809 BEFORE	0
yes	Desktop Windows OTHER	0
yes	Windows Server OTHER	0
no	Linux	1
no	Mac OS X	1
no	Windows 10 21H2	1
no	Windows 10 21H1	1
no	Windows 10 20H2	1
no	Windows 10 2004	1
no	Windows 10 1909	1
no	Windows 10 1809 BEFORE	1
no	Desktop Windows OTHER	1
no	Windows Server OTHER	1
no	Windows Server 2008 R2 SP1	0.01
yes	Windows Server 2008 R2 SP1	0.99
no	Windows 7 SP1	0.01
yes	Windows 7 SP1	0.99
yes	OTHER	0.001
no	OTHER	0.999
\.


--
-- Data for Name: festimated_cve_2016_3087; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_cve_2016_3087 ("CVE-2016-3087", os, _p) FROM stdin;
yes	Linux	0
yes	Mac OS X	0
yes	Windows 10 21H2	0
yes	Windows 10 21H1	0
yes	Windows 10 20H2	0
yes	Windows 10 2004	0
yes	Windows 10 1909	0
yes	Windows 10 1809 BEFORE	0
yes	Desktop Windows OTHER	0
yes	Windows Server OTHER	0
no	Linux	1
no	Mac OS X	1
no	Windows 10 21H2	1
no	Windows 10 21H1	1
no	Windows 10 20H2	1
no	Windows 10 2004	1
no	Windows 10 1909	1
no	Windows 10 1809 BEFORE	1
no	Desktop Windows OTHER	1
no	Windows Server OTHER	1
no	Windows Server 2008 R2 SP1	0.01
yes	Windows Server 2008 R2 SP1	0.99
no	Windows 7 SP1	0.01
yes	Windows 7 SP1	0.99
no	OTHER	0.999
yes	OTHER	0.001
\.


--
-- Data for Name: festimated_domain_join; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_domain_join (domain_join, os, _p) FROM stdin;
yes	Windows 10 21H2	0.9
yes	Windows 10 21H1	0.9
yes	Windows 10 20H2	0.9
yes	Windows 10 2004	0.9
yes	Windows 10 1909	0.9
yes	Windows 10 1809 BEFORE	0.9
yes	Windows 7 SP1	0.9
yes	Windows Server 2008 R2 SP1	0.9
yes	Desktop Windows OTHER	0.9
yes	Windows Server OTHER	0.9
no	Windows 10 21H2	0.1
no	Windows 10 21H1	0.1
no	Windows 10 20H2	0.1
no	Windows 10 2004	0.1
no	Windows 10 1909	0.1
no	Windows 10 1809 BEFORE	0.1
no	Windows 7 SP1	0.1
no	Windows Server 2008 R2 SP1	0.1
no	Desktop Windows OTHER	0.1
no	Windows Server OTHER	0.1
yes	Linux	0
yes	Mac OS X	0
yes	OTHER	0
no	Linux	1
no	Mac OS X	1
no	OTHER	1
\.


--
-- Data for Name: festimated_jenkins_auth; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_jenkins_auth (jenkins_auth, os, _p) FROM stdin;
no	Windows Server 2008 R2 SP1	0.1
no	Windows 7 SP1	0.1
yes	Windows Server 2008 R2 SP1	0.9
yes	Windows 7 SP1	0.9
yes	Linux	0.1
yes	Mac OS X	0.1
yes	OTHER	0.1
yes	Windows 10 21H2	0.1
yes	Windows 10 21H1	0.1
yes	Windows 10 20H2	0.1
yes	Windows 10 2004	0.1
yes	Windows 10 1909	0.1
yes	Windows 10 1809 BEFORE	0.1
yes	Desktop Windows OTHER	0.1
yes	Windows Server OTHER	0.1
no	Linux	0.9
no	Mac OS X	0.9
no	OTHER	0.9
no	Windows 10 21H2	0.9
no	Windows 10 21H1	0.9
no	Windows 10 20H2	0.9
no	Windows 10 2004	0.9
no	Windows 10 1909	0.9
no	Windows 10 1809 BEFORE	0.9
no	Desktop Windows OTHER	0.9
no	Windows Server OTHER	0.9
\.


--
-- Data for Name: festimated_login_attempt_limit; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_login_attempt_limit (login_attempt_limit, os, _p) FROM stdin;
Unlimited	Windows 10 21H2	0.7
10	Windows 10 21H2	0.3
Unlimited	Windows 10 21H1	0.7
10	Windows 10 21H1	0.3
Unlimited	Windows 10 20H2	0.7
10	Windows 10 20H2	0.3
Unlimited	Windows 10 2004	0.7
Unlimited	Windows 10 1909	0.7
10	Windows 10 1909	0.3
Unlimited	Windows 10 1903	0.7
10	Windows 10 1903	0.3
Unlimited	Windows 10 1809 BEFORE	0.7
10	Windows 10 1809 BEFORE	0.3
Unlimited	Windows 7 SP1	0.7
10	Windows 7 SP1	0.3
Unlimited	Windows Server 2008 R2 SP1	0.7
10	Windows Server 2008 R2 SP1	0.3
Unlimited	Desktop Windows OTHER	0.7
10	Desktop Windows OTHER	0.3
Unlimited	Windows Server OTHER	0.7
10	Windows Server OTHER	0.3
Unlimited	Linux	0.7
10	Linux	0
3	Linux	0.3
Unlimited	Mac OS X	0.7
10	Mac OS X	0
3	Mac OS X	0.3
Unlimited	OTHER	0.7
10	OTHER	0
3	OTHER	0.3
3	Windows 10 21H2	0
3	Windows 10 21H1	0
3	Windows 10 20H2	0
3	Windows 10 2004	0
3	Windows 10 1909	0
3	Windows 10 1903	0
3	Windows 10 1809 BEFORE	0
3	Windows 7 SP1	0
3	Windows Server 2008 R2 SP1	0
3	Desktop Windows OTHER	0
3	Windows Server OTHER	0
10	Windows 10 2004	0.3
\.


--
-- Data for Name: festimated_option_dmi; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_option_dmi (dmi, os, _p) FROM stdin;
yes	Linux	0.01
yes	Mac OS X	0.01
yes	OTHER	0.01
yes	Windows 10 21H2	0.01
yes	Windows 10 21H1	0.01
yes	Windows 10 20H2	0.01
yes	Windows 10 2004	0.01
yes	Windows 10 1909	0.01
yes	Windows 10 1809 BEFORE	0.01
yes	Desktop Windows OTHER	0.01
yes	Windows Server OTHER	0.01
no	Linux	0.99
no	Mac OS X	0.99
no	OTHER	0.99
no	Windows 10 21H2	0.99
no	Windows 10 21H1	0.99
no	Windows 10 20H2	0.99
no	Windows 10 2004	0.99
no	Windows 10 1909	0.99
no	Windows 10 1809 BEFORE	0.99
no	Desktop Windows OTHER	0.99
no	Windows Server OTHER	0.99
no	Windows Server 2008 R2 SP1	0.1
no	Windows 7 SP1	0.1
yes	Windows Server 2008 R2 SP1	0.9
yes	Windows 7 SP1	0.9
\.


--
-- Data for Name: festimated_option_dynamicscript; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_option_dynamicscript (dynamicscript, "elastic-version", _p) FROM stdin;
t	1.3 AFTER	0.1
t	1.2 BEFORE	1
f	1.3 AFTER	0.9
f	1.2 BEFORE	0
\.


--
-- Data for Name: festimated_os; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_os (os, _p) FROM stdin;
Windows 10 21H2	0.132804
Windows 10 21H1	0.132804
Windows 10 20H2	0.132804
Windows 10 2004	0.132804
Windows 10 1909	0.132804
Windows 10 1903	0.000838
Windows 10 1809 BEFORE	0.005869
Windows 7 SP1	0.188793
Windows Server 2008 R2 SP1	0.00056
Desktop Windows OTHER	0.03099
Windows Server OTHER	0.000561
Linux	0.01517
Mac OS X	0.054351
OTHER	0.03885
\.


--
-- Data for Name: festimated_port_22; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_port_22 ("port-22", os, _p) FROM stdin;
Open	Windows 10 21H2	0.01
Close	Windows 10 21H2	0.99
Open	Windows 10 21H1	0.01
Close	Windows 10 21H1	0.99
Open	Windows 10 20H2	0.01
Close	Windows 10 20H2	0.99
Open	Windows 10 2004	0.01
Close	Windows 10 2004	0.99
Open	Windows 10 1909	0.01
Close	Windows 10 1909	0.99
Open	Windows 10 1903	0.01
Close	Windows 10 1903	0.99
Open	Windows 10 1809 BEFORE	0.01
Close	Windows 10 1809 BEFORE	0.99
Open	Windows 7 SP1	0.01
Close	Windows 7 SP1	0.99
Open	Windows Server 2008 R2 SP1	0.01
Close	Windows Server 2008 R2 SP1	0.99
Open	Desktop Windows OTHER	0.01
Close	Desktop Windows OTHER	0.99
Open	Windows Server OTHER	0.01
Close	Windows Server OTHER	0.99
Open	Linux	0.9
Close	Linux	0.1
Open	Mac OS X	0.1
Close	Mac OS X	0.9
Open	OTHER	0.01
Close	OTHER	0.99
\.


--
-- Data for Name: festimated_port_443; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_port_443 ("port-443", os, _p) FROM stdin;
Open	Windows 10 21H2	0.01
Close	Windows 10 21H2	0.99
Open	Windows 10 21H1	0.01
Close	Windows 10 21H1	0.99
Open	Windows 10 20H2	0.01
Close	Windows 10 20H2	0.99
Open	Windows 10 2004	0.01
Close	Windows 10 2004	0.99
Open	Windows 10 1909	0.01
Close	Windows 10 1909	0.99
Open	Windows 10 1903	0.01
Close	Windows 10 1903	0.99
Open	Windows 10 1809 BEFORE	0.01
Close	Windows 10 1809 BEFORE	0.99
Open	Windows 7 SP1	0.01
Close	Windows 7 SP1	0.99
Open	Desktop Windows OTHER	0.01
Close	Desktop Windows OTHER	0.99
Open	OTHER	0.01
Close	OTHER	0.99
Open	Mac OS X	0.01
Close	Mac OS X	0.99
Close	Linux	0.9
Open	Linux	0.1
Close	Windows Server 2008 R2 SP1	0.9
Open	Windows Server 2008 R2 SP1	0.1
Close	Windows Server OTHER	0.9
Open	Windows Server OTHER	0.1
\.


--
-- Data for Name: festimated_port_445; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_port_445 ("port-445", os, _p) FROM stdin;
Open	Windows 10 21H2	1
Close	Windows 10 21H2	0
Open	Windows 10 21H1	1
Close	Windows 10 21H1	0
Open	Windows 10 20H2	1
Close	Windows 10 20H2	0
Open	Windows 10 2004	1
Close	Windows 10 2004	0
Open	Windows 10 1909	1
Close	Windows 10 1909	0
Open	Windows 10 1903	1
Close	Windows 10 1903	0
Open	Windows 10 1809 BEFORE	1
Close	Windows 10 1809 BEFORE	0
Open	Windows 7 SP1	1
Close	Windows 7 SP1	0
Open	Windows Server 2008 R2 SP1	1
Close	Windows Server 2008 R2 SP1	0
Open	Desktop Windows OTHER	1
Close	Desktop Windows OTHER	0
Open	Windows Server OTHER	1
Close	Windows Server OTHER	0
Open	Linux	0.01
Close	Linux	0.99
Open	Mac OS X	0
Close	Mac OS X	1
Close	OTHER	0.99
Open	OTHER	0.01
\.


--
-- Data for Name: festimated_port_80; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_port_80 ("port-80", os, _p) FROM stdin;
Open	Windows 10 21H2	0.01
Close	Windows 10 21H2	0.99
Open	Windows 10 21H1	0.01
Close	Windows 10 21H1	0.99
Open	Windows 10 20H2	0.01
Close	Windows 10 20H2	0.99
Open	Windows 10 2004	0.01
Close	Windows 10 2004	0.99
Open	Windows 10 1909	0.01
Close	Windows 10 1909	0.99
Open	Windows 10 1903	0.01
Close	Windows 10 1903	0.99
Open	Windows 10 1809 BEFORE	0.01
Close	Windows 10 1809 BEFORE	0.99
Open	Windows 7 SP1	0.01
Close	Windows 7 SP1	0.99
Open	Desktop Windows OTHER	0.01
Close	Desktop Windows OTHER	0.99
Open	OTHER	0.01
Close	OTHER	0.99
Open	Mac OS X	0.01
Close	Mac OS X	0.99
Close	Linux	0.9
Open	Linux	0.1
Close	Windows Server 2008 R2 SP1	0.9
Open	Windows Server 2008 R2 SP1	0.1
Close	Windows Server OTHER	0.9
Open	Windows Server OTHER	0.1
\.


--
-- Data for Name: festimated_port_8020; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_port_8020 ("port-8020", os, _p) FROM stdin;
Open	Windows 10 21H2	0.01
Open	Windows 10 21H1	0.01
Open	Windows 10 20H2	0.01
Open	Windows 10 2004	0.01
Open	Windows 10 1909	0.01
Open	Windows 10 1903	0.01
Open	Windows 10 1809 BEFORE	0.01
Open	Windows 7 SP1	0.01
Open	Desktop Windows OTHER	0.01
Open	OTHER	0.01
Open	Mac OS X	0.01
Open	Linux	0.01
Open	Windows Server 2008 R2 SP1	0.01
Open	Windows Server OTHER	0.01
Close	Windows 10 21H2	0.99
Close	Windows 10 21H1	0.99
Close	Windows 10 20H2	0.99
Close	Windows 10 2004	0.99
Close	Windows 10 1909	0.99
Close	Windows 10 1903	0.99
Close	Windows 10 1809 BEFORE	0.99
Close	Windows 7 SP1	0.99
Close	Desktop Windows OTHER	0.99
Close	OTHER	0.99
Close	Mac OS X	0.99
Close	Linux	0.99
Close	Windows Server 2008 R2 SP1	0.99
Close	Windows Server OTHER	0.99
\.


--
-- Data for Name: festimated_port_8040; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_port_8040 ("port-8040", os, _p) FROM stdin;
Close	Windows 10 21H2	0.99
Close	Windows 10 21H1	0.99
Close	Windows 10 20H2	0.99
Close	Windows 10 2004	0.99
Close	Windows 10 1909	0.99
Close	Windows 10 1903	0.99
Close	Windows 10 1809 BEFORE	0.99
Close	Windows 7 SP1	0.99
Close	Desktop Windows OTHER	0.99
Close	OTHER	0.99
Close	Mac OS X	0.99
Close	Linux	0.99
Close	Windows Server 2008 R2 SP1	0.99
Close	Windows Server OTHER	0.99
Open	Windows 10 21H2	0.01
Open	Windows 10 21H1	0.01
Open	Windows 10 20H2	0.01
Open	Windows 10 2004	0.01
Open	Windows 10 1909	0.01
Open	Windows 10 1903	0.01
Open	Windows 10 1809 BEFORE	0.01
Open	Windows 7 SP1	0.01
Open	Desktop Windows OTHER	0.01
Open	OTHER	0.01
Open	Mac OS X	0.01
Open	Linux	0.01
Open	Windows Server 2008 R2 SP1	0.01
Open	Windows Server OTHER	0.01
\.


--
-- Data for Name: festimated_port_8484; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_port_8484 ("port-8484", os, _p) FROM stdin;
Open	Windows 10 21H2	0.01
Close	Windows 10 21H2	0.99
Open	Windows 10 21H1	0.01
Close	Windows 10 21H1	0.99
Open	Windows 10 20H2	0.01
Close	Windows 10 20H2	0.99
Open	Windows 10 2004	0.01
Close	Windows 10 2004	0.99
Open	Windows 10 1909	0.01
Close	Windows 10 1909	0.99
Open	Windows 10 1903	0.01
Close	Windows 10 1903	0.99
Open	Windows 10 1809 BEFORE	0.01
Close	Windows 10 1809 BEFORE	0.99
Open	Windows 7 SP1	0.01
Close	Windows 7 SP1	0.99
Open	Desktop Windows OTHER	0.01
Close	Desktop Windows OTHER	0.99
Open	OTHER	0.01
Close	OTHER	0.99
Open	Mac OS X	0.01
Close	Mac OS X	0.99
Close	Linux	0.9
Open	Linux	0.1
Close	Windows Server 2008 R2 SP1	0.9
Open	Windows Server 2008 R2 SP1	0.1
Close	Windows Server OTHER	0.9
Open	Windows Server OTHER	0.1
\.


--
-- Data for Name: festimated_port_9200; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_port_9200 ("port-9200", os, _p) FROM stdin;
Open	Windows 10 21H2	0.01
Close	Windows 10 21H2	0.99
Open	Windows 10 21H1	0.01
Close	Windows 10 21H1	0.99
Open	Windows 10 20H2	0.01
Close	Windows 10 20H2	0.99
Open	Windows 10 2004	0.01
Close	Windows 10 2004	0.99
Open	Windows 10 1909	0.01
Close	Windows 10 1909	0.99
Open	Windows 10 1903	0.01
Close	Windows 10 1903	0.99
Open	Windows 10 1809 BEFORE	0.01
Close	Windows 10 1809 BEFORE	0.99
Open	Windows 7 SP1	0.01
Close	Windows 7 SP1	0.99
Open	Desktop Windows OTHER	0.01
Close	Desktop Windows OTHER	0.99
Open	OTHER	0.01
Close	OTHER	0.99
Open	Mac OS X	0.01
Close	Mac OS X	0.99
Close	Linux	0.9
Open	Linux	0.1
Close	Windows Server 2008 R2 SP1	0.9
Open	Windows Server 2008 R2 SP1	0.1
Close	Windows Server OTHER	0.9
Open	Windows Server OTHER	0.1
\.


--
-- Data for Name: festimated_reg_localaccounttokenfilterpolicy; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_reg_localaccounttokenfilterpolicy (localaccounttokenfilterpolicy, os, _p) FROM stdin;
0	Windows 10 21H2	0.9
0 OTHER	Windows 10 21H2	0.1
0	Windows 10 21H1	0.9
0 OTHER	Windows 10 21H1	0.1
0	Windows 10 20H2	0.9
0 OTHER	Windows 10 20H2	0.1
0	Windows 10 2004	0.9
0 OTHER	Windows 10 2004	0.1
0	Windows 10 1909	0.9
0 OTHER	Windows 10 1909	0.1
0	Windows 10 1809 BEFORE	0.9
0 OTHER	Windows 10 1809 BEFORE	0.1
0	Windows 7 SP1	0.9
0 OTHER	Windows 7 SP1	0.1
0	Windows Server 2008 R2 SP1	0.9
0 OTHER	Windows Server 2008 R2 SP1	0.1
0	Desktop Windows OTHER	0.9
0 OTHER	Desktop Windows OTHER	0.1
0	Windows Server OTHER	0.9
0 OTHER	Windows Server OTHER	0.1
0	Linux	0
0 OTHER	Linux	1
0	Mac OS X	0
0 OTHER	Mac OS X	1
0	OTHER	0
0 OTHER	OTHER	1
\.


--
-- Data for Name: festimated_save_credential; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_save_credential (save_credential, _p) FROM stdin;
None	0.333333
User	0.333333
Admin	0.333333
\.


--
-- Data for Name: festimated_service_elastic; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_service_elastic ("elastic-version", os, _p) FROM stdin;
1.3 AFTER	Linux	0.99
1.3 AFTER	Mac OS X	0.99
1.3 AFTER	OTHER	0.99
1.3 AFTER	Windows 10 21H2	0.99
1.3 AFTER	Windows 10 21H1	0.99
1.3 AFTER	Windows 10 20H2	0.99
1.3 AFTER	Windows 10 2004	0.99
1.3 AFTER	Windows 10 1909	0.99
1.3 AFTER	Windows 10 1809 BEFORE	0.99
1.3 AFTER	Desktop Windows OTHER	0.99
1.3 AFTER	Windows Server OTHER	0.99
1.2 BEFORE	Linux	0.01
1.2 BEFORE	Mac OS X	0.01
1.2 BEFORE	OTHER	0.01
1.2 BEFORE	Windows 10 21H2	0.01
1.2 BEFORE	Windows Server 2008 R2 SP1	0.5
1.2 BEFORE	Windows 7 SP1	0.5
1.3 AFTER	Windows 7 SP1	0.5
1.3 AFTER	Windows Server 2008 R2 SP1	0.5
1.2 BEFORE	Windows 10 21H1	0.01
1.2 BEFORE	Windows 10 20H2	0.01
1.2 BEFORE	Windows 10 2004	0.01
1.2 BEFORE	Windows 10 1909	0.01
1.2 BEFORE	Windows 10 1809 BEFORE	0.01
1.2 BEFORE	Desktop Windows OTHER	0.01
1.2 BEFORE	Windows Server OTHER	0.01
\.


--
-- Data for Name: festimated_service_manageengine; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_service_manageengine (manageengine_version, os, _p) FROM stdin;
91092 BEFORE	Linux	0.01
91092 BEFORE	Mac OS X	0.01
91092 BEFORE	OTHER	0.01
91092 BEFORE	Windows 10 21H2	0.01
91092 BEFORE	Windows Server 2008 R2 SP1	0.5
91092 BEFORE	Windows 7 SP1	0.5
91092 BEFORE	Windows 10 21H1	0.01
91092 BEFORE	Windows 10 20H2	0.01
91092 BEFORE	Windows 10 2004	0.01
91092 BEFORE	Windows 10 1909	0.01
91092 BEFORE	Windows 10 1809 BEFORE	0.01
91092 BEFORE	Desktop Windows OTHER	0.01
91092 BEFORE	Windows Server OTHER	0.01
91093 AFTER	Linux	0.99
91093 AFTER	Mac OS X	0.99
91093 AFTER	OTHER	0.99
91093 AFTER	Windows 10 21H2	0.99
91093 AFTER	Windows 10 21H1	0.99
91093 AFTER	Windows 10 20H2	0.99
91093 AFTER	Windows 10 2004	0.99
91093 AFTER	Windows 10 1909	0.99
91093 AFTER	Windows 10 1809 BEFORE	0.99
91093 AFTER	Desktop Windows OTHER	0.99
91093 AFTER	Windows Server OTHER	0.99
91093 AFTER	Windows 7 SP1	0.5
91093 AFTER	Windows Server 2008 R2 SP1	0.5
\.


--
-- Data for Name: festimated_ssh_auth; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.festimated_ssh_auth (auth_type, _p) FROM stdin;
Password	0.7
OTHER	0.3
\.


--
-- Data for Name: metasploit_module_list; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.metasploit_module_list (module_name, server, rank, creds, options) FROM stdin;
exploit/multi/elasticsearch/script_mvel_rce	ElasticSearch	excellent	NOT required	Proxies,RHOSTS,RPORT,SSL,TARGETURI,TMPPATH,VHOST
exploit/windows/http/manageengine_connectionid_write	ManageEngine	excellent	NOT required	Proxies,RHOSTS,RPORT,SSL,TARGETURI,TMPPATH,VHOST
exploit/multi/http/struts_dmi_rest_exec	Apache Struts	excellent	NOT required	Proxies,RHOSTS,RPORT,SSL,TARGETURI,TMPPATH,VHOST
exploits/multi/http/jenkins_script_console	Jenkins	good	required	Proxies,RHOSTS,RPORT,SSL,TARGETURI,TMPPATH,VHOST
exploit/windows/smb/psexec	\N	excellent	\N	RHOSTS,LHOST,SMBUser,SMBPass
\.


--
-- Name: plan_hist_plan_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.plan_hist_plan_id_seq', 172, true);


--
-- Name: festimated_os festimated_os_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.festimated_os
    ADD CONSTRAINT festimated_os_pkey PRIMARY KEY (os);


--
-- Name: metasploit_module_list metasploit_module_list_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.metasploit_module_list
    ADD CONSTRAINT metasploit_module_list_pkey PRIMARY KEY (module_name);


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: postgres
--

REVOKE USAGE ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO PUBLIC;


--
-- PostgreSQL database dump complete
--

--
-- PostgreSQL database dump
--

-- Dumped from database version 15.3 (Debian 15.3-1.pgdg120+1)
-- Dumped by pg_dump version 15.2 (Debian 15.2-2)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: facts_detectors; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.facts_detectors (
    detector_type text,
    location text,
    installed boolean,
    product text
);


ALTER TABLE public.facts_detectors OWNER TO postgres;

--
-- Name: facts_host_info; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.facts_host_info (
    host_id text NOT NULL,
    os_name text,
    arch text
);


ALTER TABLE public.facts_host_info OWNER TO postgres;

--
-- Name: facts_open_ports; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.facts_open_ports (
    host_addr text NOT NULL,
    protocol text NOT NULL,
    port integer NOT NULL,
    service text,
    product text,
    version text
);


ALTER TABLE public.facts_open_ports OWNER TO postgres;

--
-- Name: facts_sysinfo_base; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.facts_sysinfo_base (
    host_id text NOT NULL,
    host_name text,
    os text,
    arch text
);


ALTER TABLE public.facts_sysinfo_base OWNER TO postgres;

--
-- Name: facts_sysinfo_nics; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.facts_sysinfo_nics (
    host_id text NOT NULL,
    ifname text NOT NULL,
    ipv4 text,
    ipv4mask text,
    ipv6 text,
    ipv6prefix text
);


ALTER TABLE public.facts_sysinfo_nics OWNER TO postgres;

--
-- Name: facts_sysinfo_openports; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.facts_sysinfo_openports (
    host_id text NOT NULL,
    protocol text NOT NULL,
    ip text NOT NULL,
    port integer NOT NULL
);


ALTER TABLE public.facts_sysinfo_openports OWNER TO postgres;

--
-- Name: facts_sysinfo_users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.facts_sysinfo_users (
    host_id text NOT NULL,
    user_name text NOT NULL,
    group_name text NOT NULL
);


ALTER TABLE public.facts_sysinfo_users OWNER TO postgres;

--
-- Name: facts_users; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.facts_users (
    host_id text,
    group_name text,
    user_name text
);


ALTER TABLE public.facts_users OWNER TO postgres;

--
-- Name: facts_vulns; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.facts_vulns (
    host_addr text NOT NULL,
    protocol text NOT NULL,
    port integer NOT NULL,
    oid text NOT NULL,
    vuln_name text NOT NULL,
    cve text NOT NULL
);


ALTER TABLE public.facts_vulns OWNER TO postgres;

--
-- Name: ks_list; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.ks_list (
    host_id text NOT NULL,
    host_addr text,
    host_type text,
    host_name text,
    host_mask text,
    active_user integer DEFAULT 0,
    is_avs boolean DEFAULT false,
    is_exploited boolean DEFAULT false,
    vuln_info text
);


ALTER TABLE public.ks_list OWNER TO postgres;

--
-- Name: plan_hist; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.plan_hist (
    plan_id integer NOT NULL,
    created_time timestamp without time zone NOT NULL,
    src_host_id text NOT NULL,
    dst_host_id text NOT NULL
);


ALTER TABLE public.plan_hist OWNER TO postgres;

--
-- Name: plan_hist_plan_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.plan_hist_plan_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.plan_hist_plan_id_seq OWNER TO postgres;

--
-- Name: plan_hist_plan_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.plan_hist_plan_id_seq OWNED BY public.plan_hist.plan_id;


--
-- Name: scenario_list; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.scenario_list (
    attack_step_id character varying(10),
    module_name text,
    evc real,
    evd real,
    module_params text,
    step_number integer,
    scenario_id character varying(10),
    src_host_id character varying(10),
    dst_host_id character varying(10),
    plan_id integer NOT NULL
);


ALTER TABLE public.scenario_list OWNER TO postgres;

--
-- Name: plan_hist plan_id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.plan_hist ALTER COLUMN plan_id SET DEFAULT nextval('public.plan_hist_plan_id_seq'::regclass);


--
-- Name: facts_host_info facts_host_info_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.facts_host_info
    ADD CONSTRAINT facts_host_info_pkey PRIMARY KEY (host_id);


--
-- Name: facts_open_ports facts_open_ports_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.facts_open_ports
    ADD CONSTRAINT facts_open_ports_pkey PRIMARY KEY (host_addr, protocol, port);


--
-- Name: facts_sysinfo_base facts_sysinfo_base_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.facts_sysinfo_base
    ADD CONSTRAINT facts_sysinfo_base_pkey PRIMARY KEY (host_id);


--
-- Name: facts_sysinfo_nics facts_sysinfo_nics_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.facts_sysinfo_nics
    ADD CONSTRAINT facts_sysinfo_nics_pkey PRIMARY KEY (host_id, ifname);


--
-- Name: facts_sysinfo_openports facts_sysinfo_openports_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.facts_sysinfo_openports
    ADD CONSTRAINT facts_sysinfo_openports_pkey PRIMARY KEY (host_id, ip, protocol, port);


--
-- Name: facts_sysinfo_users facts_sysinfo_users_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.facts_sysinfo_users
    ADD CONSTRAINT facts_sysinfo_users_pkey PRIMARY KEY (host_id, user_name, group_name);


--
-- Name: facts_vulns facts_vulns_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.facts_vulns
    ADD CONSTRAINT facts_vulns_pkey PRIMARY KEY (host_addr, protocol, port, oid, cve);


--
-- Name: ks_list ks_list_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.ks_list
    ADD CONSTRAINT ks_list_pkey PRIMARY KEY (host_id);


--
-- Name: plan_hist plan_hist_pkey; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.plan_hist
    ADD CONSTRAINT plan_hist_pkey PRIMARY KEY (plan_id);


--
-- Name: scenario_list scenario_list_plan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.scenario_list
    ADD CONSTRAINT scenario_list_plan_id_fkey FOREIGN KEY (plan_id) REFERENCES public.plan_hist(plan_id);


--
-- PostgreSQL database dump complete
--

