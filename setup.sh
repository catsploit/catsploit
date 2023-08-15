#!/bin/bash -x
apt update && apt install -y python3-gvm python3-numpy python3-pandas python3-psycopg2 python3-pymetasploit3 python3-rich python3-ruamel.yaml python3-torch gvm greenbone-security-assistant postgresql
pip3 install pgmpy pyperplan pg8000

systemctl stop postgresql
cp /etc/postgresql/15/main/pg_hba.conf /etc/postgresql/15/main/pg_hba.conf.orig
cat /etc/postgresql/15/main/pg_hba.conf.orig | awk '{if($1 == "local"){ gsub("peer","trust",$4) }print $0}' > /etc/postgresql/15/main/pg_hba.conf

systemctl start postgresql
psql -U postgres << EOF
  alter user postgres with password 'password';
  create database catsdb;
EOF
psql -U postgres catsdb < db/catsploit.sql
systemctl stop postgresql

systemctl stop ospd-openvas
gvm-setup
usermod -aG _gvm kali
sudo -u _gvm gvmd --user=admin --new-password=password
gvm-check-setup
chmod u+s /usr/bin/nmap
