"""
SaaS Application Logs Adapter
Entities: User, Session, IP, APICall, Resource
Scenario: Insider threat via Tor
"""

from dataclasses import dataclass
from typing import Optional
from core import Rel, SecurityGraph, _h

# --- Entities ---

@dataclass
class SaaSUser:
    node_id: str
    user_id: str
    email: str
    role: Optional[str] = None

@dataclass
class SaaSSession:
    node_id: str
    session_id: str
    ip_address: Optional[str] = None
    geo: Optional[str] = None
    timestamp: Optional[str] = None

@dataclass
class SaaSIP:
    node_id: str
    ip_address: str
    geo: Optional[str] = None
    is_tor: Optional[bool] = None

@dataclass
class SaaSAPICall:
    node_id: str
    method: str
    endpoint: str
    status_code: int
    timestamp: str
    response_summary: Optional[str] = None

@dataclass
class SaaSResource:
    node_id: str
    resource_type: str
    resource_id: str
    resource_name: Optional[str] = None
    sensitivity: Optional[str] = None

# --- Parser ---

def parse_saas(event: dict) -> tuple[list, list]:
    e = event
    ts = e.get('timestamp', '')
    et = e.get('event_type', '')
    nodes, rels = [], []
    
    uid = _h(e['user_id']) if e.get('user_id') else None
    if uid:
        nodes.append(SaaSUser(uid, e['user_id'], e.get('email',''), e.get('role')))
    
    sid = _h(e['session_id']) if e.get('session_id') else None
    if sid:
        nodes.append(SaaSSession(sid, e['session_id'], e.get('ip_address',''),
                                 e.get('geo_location',''), ts))
        if uid:
            rels.append(Rel(uid, sid, 'authenticated_as', ts))
    
    ip = e.get('ip_address', '')
    if ip:
        ipid = _h(ip)
        nodes.append(SaaSIP(ipid, ip, e.get('geo_location',''), e.get('is_tor')))
        if sid:
            rels.append(Rel(sid, ipid, 'from_ip', ts))
    
    if et in ('api_call', 'resource_access', 'data_export', 'permission_change'):
        ck = f"{e.get('session_id','')}:{e.get('method','')}:{e.get('endpoint','')}:{ts}"
        cid = _h(ck)
        nodes.append(SaaSAPICall(cid, e.get('method',''), e.get('endpoint',''),
                                 e.get('status_code',0), ts, e.get('response_summary')))
        if sid:
            rels.append(Rel(sid, cid, 'performed', ts))
    
    rid_val = e.get('resource_id', '')
    if rid_val:
        rid = _h(rid_val)
        nodes.append(SaaSResource(rid, e.get('resource_type',''), rid_val,
                                  e.get('resource_name',''), e.get('sensitivity')))
        if et in ('resource_access', 'data_export', 'permission_change'):
            rtype = {'data_export': 'exported', 'permission_change': 'modified_permissions'
                     }.get(et, 'accessed')
            rels.append(Rel(cid, rid, rtype, ts))
    
    if et == 'permission_change' and e.get('target_user_id'):
        tuid = _h(e['target_user_id'])
        nodes.append(SaaSUser(tuid, e['target_user_id'], e.get('target_email',''),
                              e.get('new_role')))
        rels.append(Rel(cid, tuid, 'escalated_to', ts))
    
    return nodes, rels


# --- Heuristics ---

class SaaSHeuristics:
    def __init__(self, g: SecurityGraph):
        self.g = g
        self.G = g.G
    
    def tor_sensitive_access(self):
        results = []
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'SaaSSession': continue
            for _, ip, ed in self.G.edges(n, data=True):
                if ed.get('rel_type') != 'from_ip': continue
                if not self.G.nodes[ip].get('is_tor'): continue
                for _, call, ed2 in self.G.edges(n, data=True):
                    if ed2.get('rel_type') != 'performed': continue
                    for _, res, ed3 in self.G.edges(call, data=True):
                        if ed3.get('rel_type') in ('accessed','exported'):
                            sens = self.G.nodes[res].get('sensitivity','')
                            if sens in ('confidential', 'restricted'):
                                results.append(self.g.neighborhood(n, 3))
                                return results  # Deduplicate: one per session
        return results
    
    def bulk_data_access(self, threshold=3):
        results = []
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'SaaSSession': continue
            resources = set()
            for _, call, ed in self.G.edges(n, data=True):
                if ed.get('rel_type') != 'performed': continue
                for _, res, ed2 in self.G.edges(call, data=True):
                    if ed2.get('rel_type') in ('accessed', 'exported'):
                        resources.add(res)
            if len(resources) >= threshold:
                results.append(self.g.neighborhood(n, 3))
        return results
    
    def priv_escalation_chain(self):
        results = []
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'SaaSSession': continue
            did_perm, did_sens = False, False
            for _, call, ed in self.G.edges(n, data=True):
                if ed.get('rel_type') != 'performed': continue
                for _, t, ed2 in self.G.edges(call, data=True):
                    if ed2.get('rel_type') == 'modified_permissions': did_perm = True
                    if ed2.get('rel_type') in ('accessed','exported'):
                        if self.G.nodes[t].get('sensitivity') in ('confidential','restricted'):
                            did_sens = True
            if did_perm and did_sens:
                results.append(self.g.neighborhood(n, 3))
        return results


# --- Test Data ---

def saas_test_events():
    return [
        {"timestamp":"2026-04-27T22:14:01Z","event_type":"auth","user_id":"usr_jdoe","email":"jdoe@acme.com","role":"engineer","session_id":"sess_001","ip_address":"185.220.101.33","geo_location":"Frankfurt, DE","is_tor":True},
        {"timestamp":"2026-04-27T22:15:12Z","event_type":"permission_change","user_id":"usr_jdoe","email":"jdoe@acme.com","session_id":"sess_001","ip_address":"185.220.101.33","is_tor":True,"method":"PUT","endpoint":"/api/v2/admin/users/svc_pipeline/role","status_code":200,"target_user_id":"usr_svc_pipeline","target_email":"svc@acme.com","new_role":"admin","resource_type":"user_role","resource_id":"role_svc","resource_name":"Service Account Role","sensitivity":"restricted"},
        {"timestamp":"2026-04-27T22:16:30Z","event_type":"resource_access","user_id":"usr_jdoe","email":"jdoe@acme.com","session_id":"sess_001","ip_address":"185.220.101.33","is_tor":True,"method":"GET","endpoint":"/api/v2/secrets/prod_db","status_code":200,"resource_type":"secret","resource_id":"sec_prod_db","resource_name":"Production DB Credentials","sensitivity":"restricted"},
        {"timestamp":"2026-04-27T22:17:45Z","event_type":"resource_access","user_id":"usr_jdoe","email":"jdoe@acme.com","session_id":"sess_001","ip_address":"185.220.101.33","is_tor":True,"method":"GET","endpoint":"/api/v2/customers/export","status_code":200,"resource_type":"dataset","resource_id":"ds_pii","resource_name":"Customer PII Dataset","sensitivity":"confidential"},
        {"timestamp":"2026-04-27T22:18:03Z","event_type":"data_export","user_id":"usr_jdoe","email":"jdoe@acme.com","session_id":"sess_001","ip_address":"185.220.101.33","is_tor":True,"method":"POST","endpoint":"/api/v2/exports/download","status_code":200,"resource_type":"export","resource_id":"exp_full","resource_name":"Customer Full Export","sensitivity":"confidential","response_summary":"245MB CSV, 1.2M records"},
        {"timestamp":"2026-04-27T22:19:22Z","event_type":"resource_access","user_id":"usr_jdoe","email":"jdoe@acme.com","session_id":"sess_001","ip_address":"185.220.101.33","is_tor":True,"method":"GET","endpoint":"/api/v2/docs/roadmap","status_code":200,"resource_type":"document","resource_id":"doc_roadmap","resource_name":"2026 Product Roadmap","sensitivity":"restricted"},
    ]


SAAS_RULES = [
    ('is_tor', 'T1090.003 - Proxy: Tor', 25, 'Session from Tor exit node', 'Block Tor IP at WAF'),
    ('modified_permissions', 'T1098 - Account Manipulation', 25, 'Service account escalated to admin', 'Revert permission changes'),
    ('restricted', 'T1530 - Data from Cloud Storage', 20, 'Restricted resources accessed', None),
    ('exported', 'T1567 - Exfiltration Over Web Service', 25, 'Bulk data export executed', 'Revoke session tokens'),
]
