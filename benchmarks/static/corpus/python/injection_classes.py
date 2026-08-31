# SPDX-License-Identifier: Apache-2.0
# New injection CWE classes via the interprocedural taint engine: XXE (BHF-430),
# unsafe reflection (BHF-434), LDAP injection (BHF-432). A literal/constant argument
# is not tainted and is not flagged.
from lxml import etree
import importlib


def parse_xml(request):
    data = request.get("xml")
    etree.fromstring(data)                       # EXPECT BHF-430


def safe_xml():
    etree.fromstring("<root/>")                  # literal: not tainted


def load_class(request):
    name = request.get("cls")
    importlib.import_module(name)                 # EXPECT BHF-434


def ldap_lookup(request, conn):
    uid = request.get("uid")
    conn.search_s("dc=example", 2, "(uid=" + uid + ")")  # EXPECT BHF-432
