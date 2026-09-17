import hashlib, ipaddress
from collections import defaultdict
from itertools import product
import networkx as nx
from app.core.models import FirewallConfig, Severity
from app.core.graph import DependencyGraphBuilder, NodeType, get_recursive_dependents, resolve_node
from .models import AnalysisCounts, AnalysisFinding, AnalysisReport, Confidence, FindingType, ImpactResult, RelatedObject

class AnalysisEngine:
    def analyze(self,cfg:FirewallConfig):
        g=DependencyGraphBuilder().build(cfg); findings=[]; warnings=[]
        for analyzer in (self._unresolved,self._cycles,self._unused_orphan_empty,self._duplicates,self._rules,self._shadowing):
            try: findings.extend(analyzer(cfg,g))
            except Exception as exc: warnings.append(f"{analyzer.__name__}: {type(exc).__name__}")
        findings.sort(key=lambda x:(x.type,x.primary_object_name,x.id))
        counts=AnalysisCounts(total_findings=len(findings),info=sum(x.severity==Severity.INFO for x in findings),warning=sum(x.severity==Severity.WARNING for x in findings),error=sum(x.severity==Severity.ERROR for x in findings))
        mapping={FindingType.UNUSED_OBJECT:"unused_objects",FindingType.DUPLICATE_OBJECT:"duplicate_objects",FindingType.UNRESOLVED_REFERENCE:"unresolved_references",FindingType.EMPTY_GROUP:"empty_groups",FindingType.ORPHAN_GROUP:"orphan_groups",FindingType.DISABLED_RULE:"disabled_rules",FindingType.POTENTIAL_DUPLICATE_POLICY:"duplicate_policies",FindingType.POTENTIAL_SHADOWING:"potential_shadowing",FindingType.GROUP_CYCLE:"group_cycles"}
        for finding in findings:
            if finding.type in mapping: setattr(counts,mapping[finding.type],getattr(counts,mapping[finding.type])+1)
        counts.broad_rules=sum(x.type in {FindingType.ANY_SOURCE,FindingType.ANY_DESTINATION,FindingType.ANY_SERVICE,FindingType.ANY_ANY_RULE} for x in findings)
        return AnalysisReport(counts=counts,findings=findings,analyzer_warnings=warnings),g
    def impact(self,g,object_id):
        node=resolve_node(g,object_id)
        if not node: return None
        direct=list(g.predecessors(node)); recursive=get_recursive_dependents(g,node); typed=defaultdict(list)
        for key in recursive:
            dto=g.nodes[key]["dto"]; typed[dto.type].append(dto)
        high=bool(typed[NodeType.SECURITY_POLICY] or typed[NodeType.NAT_POLICY]); level="HIGH" if high else "MEDIUM" if recursive else "LOW"
        chains=[]
        for key in recursive:
            dto=g.nodes[key]["dto"]
            if dto.type in {NodeType.SECURITY_POLICY,NodeType.NAT_POLICY,NodeType.ADDRESS_GROUP,NodeType.SERVICE_GROUP}:
                try: chains.append(nx.shortest_path(g,key,node))
                except nx.NetworkXNoPath: pass
        return ImpactResult(object=g.nodes[node]["dto"],direct_references=len(direct),recursive_references=len(recursive),security_policies=typed[NodeType.SECURITY_POLICY],nat_policies=typed[NodeType.NAT_POLICY],groups=typed[NodeType.ADDRESS_GROUP]+typed[NodeType.SERVICE_GROUP],routes=typed[NodeType.STATIC_ROUTE],impact_level=level,dependency_chains=chains)
    def _finding(self,kind,obj,description,*,severity=Severity.WARNING,related=(),evidence=None,confidence=Confidence.HIGH):
        raw=f"{kind}:{obj.id}:{description}"; fid=hashlib.sha256(raw.encode()).hexdigest()[:16]
        return AnalysisFinding(id=fid,type=kind,severity=severity,title=kind.value.replace("_"," ").title(),description=description,primary_object_type=obj.type.value,primary_object_id=obj.object_id,primary_object_name=obj.name,related_objects=[RelatedObject(type=x.type.value,id=x.object_id,name=x.name) for x in related],evidence=evidence or {},confidence=confidence)
    def _unresolved(self,cfg,g):
        out=[]
        for node,data in g.nodes(data=True):
            obj=data["dto"]
            if obj.type!=NodeType.UNKNOWN_REFERENCE: continue
            parents=[g.nodes[x]["dto"] for x in g.predecessors(node)]
            for parent in parents: out.append(self._finding(FindingType.UNRESOLVED_REFERENCE,parent,f"{parent.name} references missing {obj.unknown_kind} {obj.name}.",related=[obj],evidence={"reference":obj.name,"expected_type":obj.unknown_kind}))
        return out
    def _cycles(self,cfg,g):
        kinds={NodeType.ADDRESS_GROUP,NodeType.SERVICE_GROUP}; sub=g.subgraph([n for n,d in g.nodes(data=True) if d["dto"].type in kinds]); out=[]
        for cycle in nx.simple_cycles(sub):
            if not cycle: continue
            obj=g.nodes[cycle[0]]["dto"]; related=[g.nodes[x]["dto"] for x in cycle[1:]]
            out.append(self._finding(FindingType.GROUP_CYCLE,obj,"Group membership cycle detected.",related=related,evidence={"cycle":cycle+[cycle[0]]}))
        return out
    def _unused_orphan_empty(self,cfg,g):
        out=[]; operational={NodeType.SECURITY_POLICY,NodeType.NAT_POLICY,NodeType.STATIC_ROUTE}
        object_kinds={NodeType.ADDRESS,NodeType.ADDRESS_GROUP,NodeType.SERVICE,NodeType.SERVICE_GROUP}
        for node,data in g.nodes(data=True):
            obj=data["dto"]
            if obj.type not in object_kinds: continue
            ancestors=get_recursive_dependents(g,node); used=any(g.nodes[x]["dto"].type in operational for x in ancestors)
            if not used and obj.type in {NodeType.ADDRESS,NodeType.SERVICE}: out.append(self._finding(FindingType.UNUSED_OBJECT,obj,"Object has no operational reverse reference.",severity=Severity.INFO))
            if obj.type in {NodeType.ADDRESS_GROUP,NodeType.SERVICE_GROUP}:
                children=list(g.successors(node)); valid=[x for x in children if g.nodes[x]["dto"].type!=NodeType.UNKNOWN_REFERENCE]; missing=[g.nodes[x]["dto"].name for x in children if g.nodes[x]["dto"].type==NodeType.UNKNOWN_REFERENCE]
                declared=next((x.members for x in cfg.address_groups+cfg.service_groups if x.id==obj.object_id),[])
                if not valid: out.append(self._finding(FindingType.EMPTY_GROUP,obj,"Group has zero valid members.",evidence={"declared_members":declared,"valid_members":[],"missing_members":missing}))
                elif not used: out.append(self._finding(FindingType.ORPHAN_GROUP,obj,"Group has valid members but no operational reverse reference.",severity=Severity.INFO,evidence={"valid_members":[g.nodes[x]["dto"].name for x in valid],"missing_members":missing}))
        return out
    def _duplicates(self,cfg,g):
        out=[]
        sets=[(cfg.addresses,lambda x:(x.type,self._network(x.value))), (cfg.address_groups,lambda x:tuple(sorted(set(x.members)))),(cfg.services,lambda x:(x.protocol,tuple(sorted(x.source_ports)),tuple(sorted(x.destination_ports)))),(cfg.service_groups,lambda x:tuple(sorted(set(x.members))))]
        for items,keyfn in sets:
            seen={}
            for item in items:
                key=keyfn(item)
                if key in seen:
                    a=resolve_node(g,seen[key].id); b=resolve_node(g,item.id)
                    if a and b: out.append(self._finding(FindingType.DUPLICATE_OBJECT,g.nodes[b]["dto"],f"Semantically duplicates {seen[key].name}.",related=[g.nodes[a]["dto"]],evidence={"normalized_value":repr(key)}))
                else: seen[key]=item
        return out
    def _rules(self,cfg,g):
        out=[]; seen={}
        for rule in cfg.security_policies:
            obj=g.nodes[resolve_node(g,rule.id)]["dto"]
            topology=rule.vendor_extensions.get("topology",{})
            if rule.vendor_extensions.get("attached") is False: out.append(self._finding(FindingType.UNATTACHED_ACL,obj,"ACL is preserved but has no access-group attachment.",severity=Severity.INFO))
            if topology.get("status") in {"AMBIGUOUS","MULTIPLE"}: out.append(self._finding(FindingType.AMBIGUOUS_POLICY_TOPOLOGY,obj,topology.get("reason") or "Policy destination spans contexts.",evidence=topology))
            elif topology.get("status")=="UNRESOLVED": out.append(self._finding(FindingType.UNRESOLVED_POLICY_TOPOLOGY,obj,topology.get("reason") or "Policy topology is unresolved.",evidence=topology))
            if not rule.enabled: out.append(self._finding(FindingType.DISABLED_RULE,obj,"Security policy is disabled.",severity=Severity.INFO))
            anys=[self._is_any(x) for x in (rule.sources,rule.destinations,rule.services)]
            for flag,kind,label in zip(anys,(FindingType.ANY_SOURCE,FindingType.ANY_DESTINATION,FindingType.ANY_SERVICE),("source","destination","service")):
                if flag: out.append(self._finding(kind,obj,f"Broad rule — {label} is any; review recommended.",severity=Severity.INFO))
            if anys[0] and anys[1]: out.append(self._finding(FindingType.ANY_ANY_RULE,obj,"Broad rule — source and destination are any; review recommended.",severity=Severity.WARNING))
            key=tuple(tuple(sorted(x)) for x in (rule.source_zones,rule.destination_zones,rule.sources,rule.destinations,rule.services))+(rule.action,)
            if key in seen:
                prior=seen[key]; prior_obj=g.nodes[resolve_node(g,prior.id)]["dto"]
                out.append(self._finding(FindingType.POTENTIAL_DUPLICATE_POLICY,obj,f"Matching criteria and action equal {prior.name}.",related=[prior_obj],evidence={"positions":[prior.position,rule.position],"equivalent_fields":["source_zones","destination_zones","sources","destinations","services","action"]}))
            else: seen[key]=rule
        return out
    def _shadowing(self,cfg,g):
        out=[]; buckets=defaultdict(list); objects={x.name:x for x in cfg.addresses}
        for rule in sorted((x for x in cfg.security_policies if x.enabled),key=lambda x:x.position): buckets[rule.action].append(rule)
        for rules in buckets.values():
            index=defaultdict(list); network_broad=[]
            for later in rules:
                signature=self._rule_signature(later)
                choices=[[part,"*"] for part in signature]
                candidates=[]; seen_candidates=set()
                for candidate_key in product(*choices):
                    for candidate in index[candidate_key]:
                        if candidate.id not in seen_candidates: candidates.append(candidate); seen_candidates.add(candidate.id)
                candidates += [x for x in network_broad if x.id not in seen_candidates]
                for earlier in candidates:
                    if all(self._superset(cfg,a,b,k) for a,b,k in ((earlier.source_zones,later.source_zones,"zone"),(earlier.destination_zones,later.destination_zones,"zone"),(earlier.sources,later.sources,"address"),(earlier.destinations,later.destinations,"address"),(earlier.services,later.services,"service"))):
                        obj=g.nodes[resolve_node(g,later.id)]["dto"]; prior=g.nodes[resolve_node(g,earlier.id)]["dto"]
                        out.append(self._finding(FindingType.POTENTIAL_SHADOWING,obj,f"Earlier policy {earlier.name} deterministically covers this policy.",related=[prior],evidence={"earlier_position":earlier.position,"later_position":later.position},confidence=Confidence.HIGH)); break
                key=tuple("*" if self._is_any(values) else part for values,part in zip((later.source_zones,later.destination_zones,later.sources,later.destinations,later.services),signature))
                index[key].append(later)
                if self._has_parent_network(later,objects): network_broad.append(later)
        return out
    @staticmethod
    def _rule_signature(rule): return tuple(tuple(sorted(x)) for x in (rule.source_zones,rule.destination_zones,rule.sources,rule.destinations,rule.services))
    def _has_parent_network(self,rule,objects):
        for name in rule.sources+rule.destinations:
            obj=objects.get(name)
            if obj and obj.type=="network":
                try:
                    if ipaddress.ip_network(obj.value,strict=False).prefixlen not in {32,128}: return True
                except (ValueError,TypeError): pass
        return False
    @staticmethod
    def _is_any(values): return not values or any(x.lower() in {"any","any4","any6","all"} for x in values)
    @staticmethod
    def _network(value):
        if not value: return value
        try: return str(ipaddress.ip_network(value,strict=False))
        except ValueError: return value.lower()
    def _superset(self,cfg,left,right,kind):
        if self._is_any(left): return True
        if self._is_any(right): return False
        if set(right)<=set(left): return True
        if kind!="address": return False
        objects={x.name:x for x in cfg.addresses}; networks=[]
        try:
            for value in left:
                obj=objects.get(value); networks.append(ipaddress.ip_network(obj.value,strict=False) if obj and obj.type in {"host","network"} else ipaddress.ip_network(value,strict=False))
            for value in right:
                obj=objects.get(value); target=ipaddress.ip_network(obj.value,strict=False) if obj and obj.type in {"host","network"} else ipaddress.ip_network(value,strict=False)
                if not any(net.version==target.version and target.subnet_of(net) for net in networks): return False
            return True
        except (ValueError,TypeError): return False