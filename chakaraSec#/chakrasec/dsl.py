"""
ChakraSec DSL Parser and Policy Definitions
Implements the declarative security language for defining layer policies
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Union, Any
from enum import Enum
import json
from lark import Lark, Transformer, v_args

class PolicyAtom(Enum):
    """Atomic policy types supported by ChakraSec"""
    MFA = "MFA"
    DEVICE = "DEVICE"
    TIME_WINDOW = "TIME_WINDOW"
    GEO = "GEO"
    THRESHOLD = "THRESHOLD"
    PUZZLE = "PUZZLE"
    HSM_UNSEAL = "HSM_UNSEAL"
    RISK_LEQ = "RISK_LEQ"
    RATE_LIMIT = "RATE_LIMIT"

class ActionType(Enum):
    """Actions to take on policy failure"""
    ALLOW_EXECUTE = "ALLOW_EXECUTE"
    RETURN_DECOY = "RETURN_DECOY"
    ALERT = "ALERT"
    DENY = "DENY"

@dataclass
class PolicyRule:
    """Individual policy rule with atom type and parameters"""
    atom: PolicyAtom
    params: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "atom": self.atom.value,
            "params": self.params
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PolicyRule':
        return cls(
            atom=PolicyAtom(data["atom"]),
            params=data.get("params", {})
        )

@dataclass
class LayerPolicy:
    """Policy definition for a single layer"""
    layer_id: int
    rules: List[PolicyRule] = field(default_factory=list)
    action_on_fail: ActionType = ActionType.DENY
    fail_params: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer_id": self.layer_id,
            "rules": [rule.to_dict() for rule in self.rules],
            "action_on_fail": self.action_on_fail.value,
            "fail_params": self.fail_params
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LayerPolicy':
        return cls(
            layer_id=data["layer_id"],
            rules=[PolicyRule.from_dict(rule) for rule in data.get("rules", [])],
            action_on_fail=ActionType(data.get("action_on_fail", "DENY")),
            fail_params=data.get("fail_params", {})
        )

@dataclass
class AssetDefinition:
    """Complete asset definition with all layer policies"""
    name: str
    layers: int = 7
    layer_policies: Dict[int, LayerPolicy] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "layers": self.layers,
            "layer_policies": {
                str(k): v.to_dict() for k, v in self.layer_policies.items()
            },
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AssetDefinition':
        layer_policies = {}
        for k, v in data.get("layer_policies", {}).items():
            layer_policies[int(k)] = LayerPolicy.from_dict(v)
        
        return cls(
            name=data["name"],
            layers=data.get("layers", 7),
            layer_policies=layer_policies,
            metadata=data.get("metadata", {})
        )

# ChakraSec Grammar
CHAKRASEC_GRAMMAR = r"""
    start: asset_def+
    
    asset_def: "asset" STRING "{" asset_body "}"
    
    asset_body: (layers_decl | layer_def | metadata_def)*
    
    layers_decl: "layers" "=" NUMBER ";"
    
    layer_def: "layer" NUMBER "{" layer_body "}"
    
    layer_body: (policy_stmt | action_stmt)*
    
    policy_stmt: "policy" "=" policy_expr ";"
    
    policy_expr: policy_rule ("&&" policy_rule)*
    
    policy_rule: atom_type "(" param_list? ")"
    
    atom_type: "MFA" | "DEVICE" | "TIME_WINDOW" | "GEO" | "THRESHOLD" 
             | "PUZZLE" | "HSM_UNSEAL" | "RISK_LEQ" | "RATE_LIMIT"
    
    action_stmt: "action_on_fail" "=" action_type "(" param_list? ")" ";"
    
    action_type: "ALLOW_EXECUTE" | "RETURN_DECOY" | "ALERT" | "DENY"
    
    param_list: param ("," param)*
    
    param: STRING | NUMBER | BOOLEAN
    
    metadata_def: "metadata" "{" metadata_body "}"
    
    metadata_body: (metadata_item)*
    
    metadata_item: STRING ":" (STRING | NUMBER | BOOLEAN) ";"
    
    STRING: /"[^"]*"/
    NUMBER: /\d+(\.\d+)?/
    BOOLEAN: "true" | "false"
    
    %import common.WS
    %ignore WS
    %import common.CPP_COMMENT
    %ignore CPP_COMMENT
    %import common.C_COMMENT
    %ignore C_COMMENT
"""

class ChakraSecTransformer(Transformer):
    """Transforms parsed ChakraSec AST into policy objects"""
    
    def start(self, assets):
        return {asset.name: asset for asset in assets}
    
    def asset_def(self, items):
        name = items[0].strip('"')
        asset = AssetDefinition(name=name)
        
        for item in items[1:]:
            if isinstance(item, int):  # layers count
                asset.layers = item
            elif isinstance(item, LayerPolicy):
                asset.layer_policies[item.layer_id] = item
            elif isinstance(item, dict):  # metadata
                asset.metadata.update(item)
            elif hasattr(item, '__iter__') and not isinstance(item, str):
                # Handle nested items
                for subitem in item:
                    if isinstance(subitem, int):
                        asset.layers = subitem
                    elif isinstance(subitem, LayerPolicy):
                        asset.layer_policies[subitem.layer_id] = subitem
                    elif isinstance(subitem, dict):
                        asset.metadata.update(subitem)
        
        return asset
    
    def layers_decl(self, items):
        return int(items[0])
    
    def layer_def(self, items):
        layer_id = int(items[0])
        policy = LayerPolicy(layer_id=layer_id)
        
        for item in items[1:]:
            if isinstance(item, list):  # policy rules
                policy.rules = item
            elif isinstance(item, tuple) and len(item) == 2:  # action_on_fail
                policy.action_on_fail, policy.fail_params = item
            elif hasattr(item, '__iter__') and not isinstance(item, str):
                # Handle nested items
                for subitem in item:
                    if isinstance(subitem, list):
                        policy.rules = subitem
                    elif isinstance(subitem, tuple) and len(subitem) == 2:
                        policy.action_on_fail, policy.fail_params = subitem
        
        return policy
    
    def policy_expr(self, rules):
        return rules
    
    def policy_rule(self, items):
        atom_type = PolicyAtom(items[0])
        params = {}
        if len(items) > 1:
            param_list = items[1]
            # Convert parameter list to dict based on atom type
            params = self._parse_params(atom_type, param_list)
        
        return PolicyRule(atom=atom_type, params=params)
    
    def action_stmt(self, items):
        action_type = ActionType(items[0])
        params = {}
        if len(items) > 1:
            params = {"value": items[1][0]} if items[1] else {}
        return (action_type, params)
    
    def param_list(self, params):
        return params
    
    def param(self, value):
        val = value[0]
        if isinstance(val, str):
            return val.strip('"')
        return val
    
    def metadata_def(self, items):
        return items[0] if items else {}
    
    def metadata_body(self, items):
        metadata = {}
        for item in items:
            if isinstance(item, tuple) and len(item) == 2:
                key, value = item
                metadata[key] = value
        return metadata
    
    def metadata_item(self, items):
        key = items[0].strip('"')
        value = items[1]
        if isinstance(value, str):
            value = value.strip('"')
        return (key, value)
    
    def atom_type(self, name):
        return str(name[0]) if name else ""
    
    def action_type(self, name):
        return str(name[0]) if name else ""
    
    def STRING(self, s):
        return str(s)
    
    def NUMBER(self, n):
        return float(n) if '.' in str(n) else int(n)
    
    def BOOLEAN(self, b):
        return str(b) == "true"
    
    def _parse_params(self, atom_type: PolicyAtom, param_list: List[Any]) -> Dict[str, Any]:
        """Parse parameters based on atom type"""
        params = {}
        
        if atom_type == PolicyAtom.MFA:
            if param_list:
                params["level"] = param_list[0]
        elif atom_type == PolicyAtom.DEVICE:
            if param_list:
                params["pubkey"] = param_list[0]
        elif atom_type == PolicyAtom.TIME_WINDOW:
            if len(param_list) >= 2:
                params["start"] = param_list[0]
                params["end"] = param_list[1]
        elif atom_type == PolicyAtom.GEO:
            if len(param_list) >= 3:
                params["lat"] = param_list[0]
                params["lon"] = param_list[1]
                params["radius"] = param_list[2]
        elif atom_type == PolicyAtom.THRESHOLD:
            if len(param_list) >= 2:
                params["threshold"] = param_list[0]
                params["custodians"] = param_list[1:]
        elif atom_type == PolicyAtom.PUZZLE:
            if len(param_list) >= 2:
                params["type"] = param_list[0]
                params["difficulty"] = param_list[1]
        elif atom_type == PolicyAtom.HSM_UNSEAL:
            if param_list:
                params["key_id"] = param_list[0]
        elif atom_type == PolicyAtom.RISK_LEQ:
            if param_list:
                params["max_risk"] = param_list[0]
        elif atom_type == PolicyAtom.RATE_LIMIT:
            if len(param_list) >= 2:
                params["count"] = param_list[0]
                params["seconds"] = param_list[1]
        
        return params

class ChakraSecParser:
    """Main parser for ChakraSec DSL"""
    
    def __init__(self):
        self.parser = Lark(CHAKRASEC_GRAMMAR, parser='lalr', transformer=ChakraSecTransformer())
    
    def parse(self, chakrasec_code: str) -> Dict[str, AssetDefinition]:
        """Parse ChakraSec code and return asset definitions"""
        try:
            return self.parser.parse(chakrasec_code)
        except Exception as e:
            raise ValueError(f"ChakraSec parsing error: {e}")
    
    def parse_file(self, filepath: str) -> Dict[str, AssetDefinition]:
        """Parse ChakraSec file and return asset definitions"""
        with open(filepath, 'r') as f:
            return self.parse(f.read())

class PolicyDefinition:
    """Helper class for programmatic policy creation"""
    
    @staticmethod
    def create_mfa_policy(level: int = 2) -> PolicyRule:
        """Create MFA policy rule"""
        return PolicyRule(PolicyAtom.MFA, {"level": level})
    
    @staticmethod
    def create_device_policy(pubkey: str) -> PolicyRule:
        """Create device attestation policy rule"""
        return PolicyRule(PolicyAtom.DEVICE, {"pubkey": pubkey})
    
    @staticmethod
    def create_time_window_policy(start: str, end: str) -> PolicyRule:
        """Create time window policy rule"""
        return PolicyRule(PolicyAtom.TIME_WINDOW, {"start": start, "end": end})
    
    @staticmethod
    def create_geo_policy(lat: float, lon: float, radius: float) -> PolicyRule:
        """Create geofencing policy rule"""
        return PolicyRule(PolicyAtom.GEO, {"lat": lat, "lon": lon, "radius": radius})
    
    @staticmethod
    def create_threshold_policy(threshold: int, custodians: List[str]) -> PolicyRule:
        """Create threshold/custodian policy rule"""
        return PolicyRule(PolicyAtom.THRESHOLD, {"threshold": threshold, "custodians": custodians})
    
    @staticmethod
    def create_puzzle_policy(puzzle_type: str = "matrix", difficulty: int = 128) -> PolicyRule:
        """Create dynamic puzzle policy rule"""
        return PolicyRule(PolicyAtom.PUZZLE, {"type": puzzle_type, "difficulty": difficulty})
    
    @staticmethod
    def create_hsm_policy(key_id: str) -> PolicyRule:
        """Create HSM unseal policy rule"""
        return PolicyRule(PolicyAtom.HSM_UNSEAL, {"key_id": key_id})
    
    @staticmethod
    def create_risk_policy(max_risk: float) -> PolicyRule:
        """Create risk assessment policy rule"""
        return PolicyRule(PolicyAtom.RISK_LEQ, {"max_risk": max_risk})
    
    @staticmethod
    def create_rate_limit_policy(count: int, seconds: int) -> PolicyRule:
        """Create rate limiting policy rule"""
        return PolicyRule(PolicyAtom.RATE_LIMIT, {"count": count, "seconds": seconds})
