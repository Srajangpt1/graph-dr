"""
AppSec / SDLC Security Pipeline Adapter
Entities: Repo, Commit, PR, Pipeline, Finding, Dependency, Deploy, CodeFile
Scenario: SQLi + secret shipped to production
"""

from dataclasses import dataclass
from typing import Optional
from core import Rel, SecurityGraph, _h

# --- Entities ---

@dataclass
class RepoNode:
    """A code repository."""
    node_id: str
    repo_name: str
    default_branch: Optional[str] = None
    visibility: Optional[str] = None  # public, internal, private

@dataclass
class CommitNode:
    """A git commit."""
    node_id: str
    sha: str
    author: str
    message: Optional[str] = None
    timestamp: Optional[str] = None
    branch: Optional[str] = None

@dataclass
class PRNode:
    """A pull request."""
    node_id: str
    pr_id: str
    title: str
    author: str
    state: Optional[str] = None  # open, merged, closed
    reviewers: Optional[list] = None
    approved: Optional[bool] = None
    timestamp: Optional[str] = None

@dataclass
class PipelineNode:
    """A CI/CD pipeline run."""
    node_id: str
    pipeline_id: str
    trigger: str  # pr, push, manual, schedule
    status: Optional[str] = None  # running, passed, failed
    stages_passed: Optional[list] = None
    stages_failed: Optional[list] = None
    timestamp: Optional[str] = None

@dataclass
class FindingNode:
    """A security finding from SAST/DAST/SCA/secrets scan."""
    node_id: str
    finding_type: str  # sast, dast, sca, secret
    rule_id: str
    severity: str  # critical, high, medium, low
    title: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    tool: Optional[str] = None
    timestamp: Optional[str] = None

@dataclass
class DependencyNode:
    """A software dependency / package."""
    node_id: str
    package_name: str
    version: str
    ecosystem: Optional[str] = None  # npm, pypi, maven
    cve_id: Optional[str] = None
    is_direct: Optional[bool] = None

@dataclass
class DeployNode:
    """A deployment event."""
    node_id: str
    deploy_id: str
    environment: str  # staging, production
    deployer: Optional[str] = None
    timestamp: Optional[str] = None
    status: Optional[str] = None

@dataclass
class CodeFileNode:
    """A source code file."""
    node_id: str
    file_path: str
    language: Optional[str] = None


# --- Parser ---

def parse_appsec(event: dict) -> tuple[list, list]:
    et = event.get('event_type', '')
    ts = event.get('timestamp', '')
    nodes, rels = [], []
    
    # Repo — often a context field
    repo = event.get('repo', '')
    if repo:
        repo_id = _h(repo)
        nodes.append(RepoNode(repo_id, repo,
                              event.get('default_branch'),
                              event.get('visibility')))
    
    if et == 'commit':
        sha = event.get('sha', '')
        cid = _h(sha)
        nodes.append(CommitNode(cid, sha, event.get('author',''),
                                event.get('message',''), ts, event.get('branch')))
        if repo:
            rels.append(Rel(cid, repo_id, 'pushed_to', ts))
        # Files changed
        for f in event.get('files_changed', []):
            fid = _h(f)
            nodes.append(CodeFileNode(fid, f, event.get('language')))
            rels.append(Rel(cid, fid, 'modified', ts))
    
    elif et == 'pull_request':
        pr_key = event.get('pr_id', '')
        pid = _h(pr_key)
        nodes.append(PRNode(pid, pr_key, event.get('title',''), event.get('author',''),
                            event.get('state'), event.get('reviewers'),
                            event.get('approved'), ts))
        if repo:
            rels.append(Rel(pid, repo_id, 'targets', ts))
        # Link commits to PR
        for sha in event.get('commits', []):
            cid = _h(sha)
            rels.append(Rel(pid, cid, 'contains_commit', ts))
    
    elif et == 'pipeline_run':
        plid = _h(event.get('pipeline_id', ''))
        nodes.append(PipelineNode(plid, event.get('pipeline_id',''),
                                  event.get('trigger',''), event.get('status'),
                                  event.get('stages_passed'), event.get('stages_failed'), ts))
        # Link to PR or commit that triggered
        trigger_ref = event.get('trigger_ref', '')
        if trigger_ref:
            trid = _h(trigger_ref)
            rels.append(Rel(trid, plid, 'triggered', ts))
    
    elif et == 'finding':
        fkey = f"{event.get('rule_id','')}:{event.get('file_path','')}:{event.get('line_number','')}"
        fid = _h(fkey)
        nodes.append(FindingNode(fid, event.get('finding_type',''), event.get('rule_id',''),
                                 event.get('severity',''), event.get('title',''),
                                 event.get('file_path'), event.get('line_number'),
                                 event.get('cwe'), event.get('cvss'),
                                 event.get('tool'), ts))
        # Link finding to file
        fp = event.get('file_path', '')
        if fp:
            file_id = _h(fp)
            nodes.append(CodeFileNode(file_id, fp))
            rels.append(Rel(fid, file_id, 'found_in', ts))
        # Link finding to pipeline run
        pl = event.get('pipeline_id', '')
        if pl:
            plid = _h(pl)
            rels.append(Rel(plid, fid, 'produced_finding', ts))
        # Link finding to commit
        sha = event.get('commit_sha', '')
        if sha:
            cid = _h(sha)
            rels.append(Rel(fid, cid, 'introduced_by', ts))
    
    elif et == 'dependency_alert':
        dep_key = f"{event.get('package','')}:{event.get('version','')}"
        did = _h(dep_key)
        nodes.append(DependencyNode(did, event.get('package',''), event.get('version',''),
                                    event.get('ecosystem'), event.get('cve_id'),
                                    event.get('is_direct')))
        # Link to file (requirements.txt, package.json, etc.)
        manifest = event.get('manifest_file', '')
        if manifest:
            mfid = _h(manifest)
            nodes.append(CodeFileNode(mfid, manifest))
            rels.append(Rel(did, mfid, 'declared_in', ts))
        # Link CVE finding if present
        if event.get('cve_id'):
            fkey = f"sca:{event['cve_id']}:{event.get('package','')}"
            fid = _h(fkey)
            nodes.append(FindingNode(fid, 'sca', event['cve_id'],
                                     event.get('severity','high'),
                                     f"{event['cve_id']} in {event.get('package','')}",
                                     manifest, cwe=event.get('cwe'),
                                     cvss=event.get('cvss'), tool='sca'))
            rels.append(Rel(did, fid, 'has_vulnerability', ts))
    
    elif et == 'deploy':
        dep_id = _h(event.get('deploy_id', ''))
        nodes.append(DeployNode(dep_id, event.get('deploy_id',''),
                                event.get('environment',''), event.get('deployer'),
                                ts, event.get('status')))
        # Link to pipeline that produced the artifact
        pl = event.get('pipeline_id', '')
        if pl:
            plid = _h(pl)
            rels.append(Rel(plid, dep_id, 'deployed_to', ts))
        # Link to commit
        sha = event.get('commit_sha', '')
        if sha:
            cid = _h(sha)
            rels.append(Rel(cid, dep_id, 'shipped_in', ts))
    
    elif et == 'secret_detected':
        fkey = f"secret:{event.get('secret_type','')}:{event.get('file_path','')}:{event.get('line_number','')}"
        fid = _h(fkey)
        nodes.append(FindingNode(fid, 'secret', event.get('secret_type',''),
                                 'critical', f"Exposed {event.get('secret_type','')}",
                                 event.get('file_path'), event.get('line_number'),
                                 tool='gitleaks', timestamp=ts))
        fp = event.get('file_path', '')
        if fp:
            file_id = _h(fp)
            nodes.append(CodeFileNode(file_id, fp))
            rels.append(Rel(fid, file_id, 'found_in', ts))
        sha = event.get('commit_sha', '')
        if sha:
            cid = _h(sha)
            rels.append(Rel(fid, cid, 'introduced_by', ts))
    
    return nodes, rels


# --- Heuristics ---

class AppSecHeuristics:
    def __init__(self, g: SecurityGraph):
        self.g = g
        self.G = g.G
    
    def critical_finding_shipped_to_prod(self):
        """A critical/high finding exists in code that was deployed to production.
        Walk: Finding(critical) → found_in → File ← modified ← Commit → shipped_in → Deploy(prod)
        This is the core AppSec graph query: was this vuln shipped?"""
        results = []
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'FindingNode': continue
            if a.get('severity') not in ('critical', 'high'): continue
            
            # Find which file this finding is in
            for _, file_node, ed in self.G.edges(n, data=True):
                if ed.get('rel_type') != 'found_in': continue
                # Find which commit modified this file
                for commit, _, ed2 in self.G.in_edges(file_node, data=True):
                    if ed2.get('rel_type') != 'modified': continue
                    # Check if that commit was deployed to prod
                    for _, deploy, ed3 in self.G.edges(commit, data=True):
                        if ed3.get('rel_type') != 'shipped_in': continue
                        env = self.G.nodes[deploy].get('environment', '')
                        if env == 'production':
                            results.append(self.g.neighborhood(n, 4))
                            return results  # Deduplicate
        return results
    
    def secret_in_commit(self):
        """Secret detected in a commit. Always bad."""
        results = []
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'FindingNode': continue
            if a.get('finding_type') != 'secret': continue
            results.append(self.g.neighborhood(n, 3))
        return results
    
    def vuln_dependency_in_prod(self):
        """A dependency with a known CVE is in a manifest that shipped to prod."""
        results = []
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'DependencyNode': continue
            if not a.get('cve_id'): continue
            # Walk: Dep → declared_in → manifest_file ← modified ← commit → shipped_in → deploy(prod)
            for _, manifest, ed in self.G.edges(n, data=True):
                if ed.get('rel_type') != 'declared_in': continue
                for commit, _, ed2 in self.G.in_edges(manifest, data=True):
                    if ed2.get('rel_type') != 'modified': continue
                    for _, deploy, ed3 in self.G.edges(commit, data=True):
                        if ed3.get('rel_type') != 'shipped_in': continue
                        if self.G.nodes[deploy].get('environment') == 'production':
                            results.append(self.g.neighborhood(n, 4))
                            return results
        return results
    
    def pipeline_failure_bypassed(self):
        """Pipeline had security stage failures, but code was deployed anyway.
        Someone overrode the gate."""
        results = []
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'PipelineNode': continue
            failed = a.get('stages_failed', [])
            security_failed = any(s in str(failed).lower() 
                                 for s in ['sast', 'dast', 'sca', 'secret', 'security'])
            if not security_failed: continue
            # Check if this pipeline led to a production deploy
            for _, deploy, ed in self.G.edges(n, data=True):
                if ed.get('rel_type') != 'deployed_to': continue
                if self.G.nodes[deploy].get('environment') == 'production':
                    results.append(self.g.neighborhood(n, 3))
        return results
    
    def unreviewed_pr_with_findings(self):
        """PR merged without approval that introduced findings."""
        results = []
        for n, a in self.G.nodes(data=True):
            if a.get('node_type') != 'PRNode': continue
            if a.get('state') != 'merged': continue
            if a.get('approved'): continue  # Was approved — fine
            # Check if any finding was introduced by commits in this PR
            for _, commit, ed in self.G.edges(n, data=True):
                if ed.get('rel_type') != 'contains_commit': continue
                for finding, _, ed2 in self.G.in_edges(commit, data=True):
                    if ed2.get('rel_type') != 'introduced_by': continue
                    if self.G.nodes[finding].get('node_type') == 'FindingNode':
                        results.append(self.g.neighborhood(n, 4))
                        return results
        return results


# --- Test Data ---

def appsec_test_events():
    """
    Scenario: A developer pushes a commit with an SQL injection vuln
    and a hardcoded AWS key. The PR is merged without review. The 
    pipeline's SAST stage flags the SQLi but the deploy proceeds anyway
    because the gate was set to warn-only. A vulnerable dependency
    ships too. The whole thing ends up in production.
    """
    return [
        # Commit with changes
        {"event_type":"commit","timestamp":"2026-05-10T09:15:00Z","repo":"acme/payments-api",
         "sha":"a1b2c3d","author":"jdoe","branch":"feature/checkout-v2",
         "message":"Add new checkout endpoint",
         "files_changed":["src/api/checkout.py","src/utils/db.py","requirements.txt"]},
        
        # SAST finding: SQL injection in the new code
        {"event_type":"finding","timestamp":"2026-05-10T09:20:00Z","repo":"acme/payments-api",
         "finding_type":"sast","rule_id":"CWE-89","severity":"critical",
         "title":"SQL Injection via unsanitized user input in checkout query",
         "file_path":"src/api/checkout.py","line_number":42,
         "cwe":"CWE-89","cvss":9.8,"tool":"semgrep",
         "pipeline_id":"pipeline-8801","commit_sha":"a1b2c3d"},
        
        # Secret detected in commit
        {"event_type":"secret_detected","timestamp":"2026-05-10T09:20:05Z",
         "repo":"acme/payments-api","secret_type":"AWS Access Key",
         "file_path":"src/utils/db.py","line_number":7,"commit_sha":"a1b2c3d"},
        
        # SCA: vulnerable dependency
        {"event_type":"dependency_alert","timestamp":"2026-05-10T09:20:10Z",
         "repo":"acme/payments-api","package":"pyjwt","version":"1.7.1",
         "ecosystem":"pypi","cve_id":"CVE-2022-29217","severity":"high",
         "cvss":7.5,"manifest_file":"requirements.txt"},
        
        # PR created and merged without approval
        {"event_type":"pull_request","timestamp":"2026-05-10T09:30:00Z",
         "repo":"acme/payments-api","pr_id":"PR-447",
         "title":"Add checkout v2 endpoint","author":"jdoe",
         "state":"merged","approved":False,"reviewers":[],
         "commits":["a1b2c3d"]},
        
        # Pipeline run — SAST failed but deploy proceeded (warn-only gate)
        {"event_type":"pipeline_run","timestamp":"2026-05-10T09:35:00Z",
         "repo":"acme/payments-api","pipeline_id":"pipeline-8801",
         "trigger":"pr","trigger_ref":"PR-447",
         "status":"passed_with_warnings",
         "stages_passed":["build","test","dast"],
         "stages_failed":["sast","secret-scan"]},
        
        # Deployed to production anyway
        {"event_type":"deploy","timestamp":"2026-05-10T10:00:00Z",
         "repo":"acme/payments-api","deploy_id":"deploy-prod-552",
         "environment":"production","deployer":"auto-deploy-bot",
         "pipeline_id":"pipeline-8801","commit_sha":"a1b2c3d",
         "status":"success"},
    ]


APPSEC_RULES = [
    ('cwe-89', 'CWE-89 - SQL Injection', 30, 'Critical SQL injection finding in codebase', 'Remediate SQLi before next deploy'),
    ('aws access key', 'CWE-798 - Hardcoded Credentials', 25, 'Hardcoded AWS key committed to repo', 'Rotate AWS key immediately'),
    ('cve-', 'T1195.002 - Supply Chain: Compromise Software Supply Chain', 20, 'Known CVE in dependency shipped to prod', 'Upgrade vulnerable dependency'),
    ('stages_failed', 'T1562 - Impair Defenses', 15, 'Security pipeline stage failed but deploy proceeded', 'Enforce security gates as blocking'),
    ('approved": false', 'CWE-284 - Improper Access Control', 15, 'PR merged without required review', 'Require approval for PRs touching sensitive paths'),
]


# ############################################################
