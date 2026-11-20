"""
SysVoidScan Modules - Export all testing module classes.
"""

from modules.recon import ReconModule
from modules.portscan import PortscanModule
from modules.vuln_scanner import VulnScannerModule
from modules.fuzzing import FuzzingModule
from modules.sqli import SQLiModule
from modules.xss import XSSModule
from modules.lfi import LFIModule
from modules.command_injection import CommandInjectionModule
from modules.open_redirect import OpenRedirectModule
from modules.ssrf import SSRFModule
from modules.ssti import SSTIModule
from modules.xxe import XXEModule
from modules.crlf import CRLFModule
from modules.smuggling import SmugglingModule
from modules.cache_poisoning import CachePoisoningModule
from modules.api_testing import APITestingModule
from modules.wordpress import WordPressModule
from modules.active_directory import ActiveDirectoryModule
from modules.brute_force import BruteForceModule
from modules.spider import SpiderModule
from modules.source_code import SourceCodeModule
from modules.nosql_injection import NoSQLInjectionModule
from modules.ldap_injection import LDAPInjectionModule
from modules.deserialization import DeserializationModule
from modules.oauth_testing import OAuthTestingModule
from modules.graphql_attacks import GraphQLAttacksModule
from modules.websocket_testing import WebSocketTestingModule

__all__ = [
    "ReconModule",
    "PortscanModule",
    "VulnScannerModule",
    "FuzzingModule",
    "SQLiModule",
    "XSSModule",
    "LFIModule",
    "CommandInjectionModule",
    "OpenRedirectModule",
    "SSRFModule",
    "SSTIModule",
    "XXEModule",
    "CRLFModule",
    "SmugglingModule",
    "CachePoisoningModule",
    "APITestingModule",
    "WordPressModule",
    "ActiveDirectoryModule",
    "BruteForceModule",
    "SpiderModule",
    "SourceCodeModule",
    "NoSQLInjectionModule",
    "LDAPInjectionModule",
    "DeserializationModule",
    "OAuthTestingModule",
    "GraphQLAttacksModule",
    "WebSocketTestingModule",
]
