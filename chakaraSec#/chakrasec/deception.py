"""
ChakraSec Deception Engine
Provides sophisticated decoy responses and honeypot functionality for failed authentications
"""

import json
import time
import random
import secrets
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
import logging

class DecoyType(Enum):
    """Types of decoy responses"""
    STATIC = "static"           # Pre-defined static responses
    DYNAMIC = "dynamic"         # Generated responses based on context
    HONEYPOT = "honeypot"       # Interactive honeypot environments
    MIRRORED = "mirrored"       # Mirror legitimate data with modifications

@dataclass
class DecoyTemplate:
    """Template for generating decoy responses"""
    decoy_id: str
    decoy_type: DecoyType
    category: str
    template_data: Dict[str, Any]
    generation_rules: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "decoy_id": self.decoy_id,
            "decoy_type": self.decoy_type.value,
            "category": self.category,
            "template_data": self.template_data,
            "generation_rules": self.generation_rules
        }

@dataclass
class DecoyInteraction:
    """Record of decoy interaction for analysis"""
    interaction_id: str
    decoy_id: str
    timestamp: float
    client_info: Dict[str, Any]
    interaction_data: Dict[str, Any]
    duration: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "interaction_id": self.interaction_id,
            "decoy_id": self.decoy_id,
            "timestamp": self.timestamp,
            "client_info": self.client_info,
            "interaction_data": self.interaction_data,
            "duration": self.duration
        }

class DecoyGenerator:
    """Generates realistic decoy data"""
    
    def __init__(self):
        self.generators: Dict[str, Callable] = {
            "financial": self._generate_financial_decoy,
            "medical": self._generate_medical_decoy,
            "corporate": self._generate_corporate_decoy,
            "personal": self._generate_personal_decoy,
            "technical": self._generate_technical_decoy
        }
        
        # Sample data for realistic generation
        self.sample_data = {
            "names": ["John Smith", "Jane Doe", "Michael Johnson", "Sarah Wilson"],
            "companies": ["TechCorp Inc", "Global Solutions", "DataSystems LLC"],
            "addresses": ["123 Main St", "456 Oak Ave", "789 Pine Rd"],
            "cities": ["New York", "Los Angeles", "Chicago", "Houston"],
            "medical_conditions": ["Hypertension", "Diabetes", "Arthritis", "Allergies"]
        }
    
    def generate_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate decoy response based on template and context"""
        
        if template.decoy_type == DecoyType.STATIC:
            return self._generate_static_decoy(template, context)
        
        elif template.decoy_type == DecoyType.DYNAMIC:
            return self._generate_dynamic_decoy(template, context)
        
        elif template.decoy_type == DecoyType.HONEYPOT:
            return self._generate_honeypot_decoy(template, context)
        
        elif template.decoy_type == DecoyType.MIRRORED:
            return self._generate_mirrored_decoy(template, context)
        
        else:
            return {"error": "Unknown decoy type"}
    
    def _generate_static_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate static decoy from template"""
        decoy_data = template.template_data.copy()
        
        # Add timestamp and session info
        decoy_data["generated_at"] = time.time()
        decoy_data["session_id"] = context.get("session_nonce", "unknown")
        
        return decoy_data
    
    def _generate_dynamic_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate dynamic decoy based on rules"""
        category = template.category
        
        if category in self.generators:
            return self.generators[category](template, context)
        else:
            # Fallback to generic generation
            return self._generate_generic_decoy(template, context)
    
    def _generate_financial_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate financial decoy data"""
        return {
            "account_number": f"ACC{random.randint(100000, 999999)}",
            "balance": round(random.uniform(1000, 100000), 2),
            "currency": "USD",
            "account_type": random.choice(["checking", "savings", "investment"]),
            "last_transaction": {
                "amount": round(random.uniform(10, 1000), 2),
                "date": time.time() - random.randint(3600, 86400),
                "description": random.choice(["ATM Withdrawal", "Online Purchase", "Direct Deposit"])
            },
            "credit_score": random.randint(600, 850),
            "generated_at": time.time(),
            "decoy_marker": "financial_v1"
        }
    
    def _generate_medical_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate medical decoy data"""
        return {
            "patient_id": f"P{random.randint(100000, 999999)}",
            "name": random.choice(self.sample_data["names"]),
            "age": random.randint(18, 80),
            "conditions": random.sample(self.sample_data["medical_conditions"], 
                                      random.randint(1, 3)),
            "last_visit": time.time() - random.randint(86400, 2592000),  # 1-30 days ago
            "medications": [
                f"Med-{random.randint(100, 999)}" for _ in range(random.randint(1, 4))
            ],
            "allergies": random.choice(["None", "Penicillin", "Shellfish", "Peanuts"]),
            "insurance": f"INS{random.randint(10000, 99999)}",
            "generated_at": time.time(),
            "decoy_marker": "medical_v1"
        }
    
    def _generate_corporate_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate corporate decoy data"""
        return {
            "employee_id": f"EMP{random.randint(1000, 9999)}",
            "name": random.choice(self.sample_data["names"]),
            "department": random.choice(["Engineering", "Sales", "Marketing", "HR"]),
            "position": random.choice(["Manager", "Analyst", "Director", "Specialist"]),
            "salary": random.randint(50000, 200000),
            "hire_date": time.time() - random.randint(31536000, 157680000),  # 1-5 years ago
            "access_level": random.choice(["Basic", "Elevated", "Admin"]),
            "projects": [
                f"Project-{chr(65 + i)}" for i in range(random.randint(1, 4))
            ],
            "generated_at": time.time(),
            "decoy_marker": "corporate_v1"
        }
    
    def _generate_personal_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate personal decoy data"""
        return {
            "user_id": f"U{random.randint(100000, 999999)}",
            "name": random.choice(self.sample_data["names"]),
            "email": f"user{random.randint(100, 999)}@example.com",
            "phone": f"+1-555-{random.randint(100, 999)}-{random.randint(1000, 9999)}",
            "address": {
                "street": random.choice(self.sample_data["addresses"]),
                "city": random.choice(self.sample_data["cities"]),
                "zip": f"{random.randint(10000, 99999)}"
            },
            "preferences": {
                "theme": random.choice(["light", "dark"]),
                "notifications": random.choice([True, False]),
                "language": "en-US"
            },
            "generated_at": time.time(),
            "decoy_marker": "personal_v1"
        }
    
    def _generate_technical_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate technical decoy data"""
        return {
            "system_id": f"SYS{random.randint(1000, 9999)}",
            "hostname": f"server-{random.randint(100, 999)}.internal",
            "ip_address": f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}",
            "os": random.choice(["Ubuntu 20.04", "CentOS 8", "Windows Server 2019"]),
            "services": [
                {"name": "nginx", "port": 80, "status": "running"},
                {"name": "mysql", "port": 3306, "status": "running"},
                {"name": "ssh", "port": 22, "status": "running"}
            ],
            "uptime": random.randint(3600, 2592000),  # 1 hour to 30 days
            "load_average": round(random.uniform(0.1, 2.0), 2),
            "disk_usage": f"{random.randint(20, 80)}%",
            "generated_at": time.time(),
            "decoy_marker": "technical_v1"
        }
    
    def _generate_generic_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate generic decoy data"""
        return {
            "id": f"GEN{random.randint(100000, 999999)}",
            "data": template.template_data,
            "timestamp": time.time(),
            "context": context.get("layer_id", "unknown"),
            "generated_at": time.time(),
            "decoy_marker": "generic_v1"
        }
    
    def _generate_honeypot_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate honeypot environment decoy"""
        return {
            "honeypot_id": f"HP{random.randint(1000, 9999)}",
            "environment": template.template_data.get("environment", "web_app"),
            "endpoints": [
                "/api/users",
                "/api/admin",
                "/api/sensitive-data",
                "/api/config"
            ],
            "fake_vulnerabilities": [
                "SQL Injection in /api/users",
                "XSS in search parameter",
                "Directory traversal in /files"
            ],
            "interaction_hooks": template.template_data.get("hooks", []),
            "generated_at": time.time(),
            "decoy_marker": "honeypot_v1"
        }
    
    def _generate_mirrored_decoy(self, template: DecoyTemplate, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate mirrored decoy (modified real data)"""
        base_data = template.template_data.copy()
        
        # Apply modifications to make data fake but realistic
        modifications = template.generation_rules.get("modifications", {})
        
        for field, modification in modifications.items():
            if field in base_data:
                if modification == "randomize_numbers":
                    # Replace numbers with random ones
                    original = str(base_data[field])
                    modified = ''.join(
                        str(random.randint(0, 9)) if c.isdigit() else c 
                        for c in original
                    )
                    base_data[field] = modified
                
                elif modification == "alter_names":
                    # Replace with fake names
                    base_data[field] = random.choice(self.sample_data["names"])
        
        base_data["generated_at"] = time.time()
        base_data["decoy_marker"] = "mirrored_v1"
        
        return base_data

class HoneypotManager:
    """Manages interactive honeypot environments"""
    
    def __init__(self):
        self.active_honeypots: Dict[str, Dict[str, Any]] = {}
        self.interaction_log: List[DecoyInteraction] = []
    
    def create_honeypot(self, decoy_id: str, template: DecoyTemplate) -> str:
        """Create new honeypot environment"""
        honeypot_id = f"hp_{int(time.time())}_{random.randint(1000, 9999)}"
        
        self.active_honeypots[honeypot_id] = {
            "decoy_id": decoy_id,
            "template": template,
            "created_at": time.time(),
            "interactions": [],
            "status": "active"
        }
        
        return honeypot_id
    
    def interact_with_honeypot(self, honeypot_id: str, interaction_data: Dict[str, Any],
                             client_info: Dict[str, Any]) -> Dict[str, Any]:
        """Process interaction with honeypot"""
        if honeypot_id not in self.active_honeypots:
            return {"error": "Honeypot not found"}
        
        honeypot = self.active_honeypots[honeypot_id]
        
        # Log interaction
        interaction = DecoyInteraction(
            interaction_id=f"int_{int(time.time())}_{random.randint(100, 999)}",
            decoy_id=honeypot["decoy_id"],
            timestamp=time.time(),
            client_info=client_info,
            interaction_data=interaction_data
        )
        
        honeypot["interactions"].append(interaction)
        self.interaction_log.append(interaction)
        
        # Generate response based on interaction
        return self._generate_honeypot_response(honeypot, interaction_data)
    
    def _generate_honeypot_response(self, honeypot: Dict[str, Any], 
                                  interaction_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate realistic response for honeypot interaction"""
        
        # Simulate realistic delays
        import time
        time.sleep(random.uniform(0.1, 0.5))
        
        # Generate response based on interaction type
        if interaction_data.get("type") == "api_request":
            return {
                "status": "success",
                "data": self._generate_fake_api_data(interaction_data),
                "timestamp": time.time()
            }
        
        elif interaction_data.get("type") == "file_access":
            return {
                "files": [
                    {"name": "config.txt", "size": 1024, "modified": time.time()},
                    {"name": "secrets.json", "size": 512, "modified": time.time()},
                    {"name": "database.sql", "size": 8192, "modified": time.time()}
                ]
            }
        
        else:
            return {
                "message": "Command executed successfully",
                "output": "fake_command_output",
                "timestamp": time.time()
            }
    
    def _generate_fake_api_data(self, interaction_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate fake API response data"""
        endpoint = interaction_data.get("endpoint", "/api/data")
        
        if "users" in endpoint:
            return [
                {
                    "id": i,
                    "username": f"user{i}",
                    "email": f"user{i}@fake.com",
                    "role": random.choice(["user", "admin", "moderator"])
                }
                for i in range(1, random.randint(5, 15))
            ]
        
        elif "admin" in endpoint:
            return [
                {
                    "admin_id": i,
                    "permissions": ["read", "write", "delete"],
                    "last_login": time.time() - random.randint(3600, 86400)
                }
                for i in range(1, 5)
            ]
        
        else:
            return [
                {"id": i, "data": f"fake_data_{i}"}
                for i in range(1, 10)
            ]

class DeceptionEngine:
    """
    Main deception engine that coordinates decoy responses and honeypots
    """
    
    def __init__(self):
        self.decoy_generator = DecoyGenerator()
        self.honeypot_manager = HoneypotManager()
        
        # Decoy templates storage
        self.decoy_templates: Dict[str, DecoyTemplate] = {}
        
        # Interaction analytics
        self.interaction_stats: Dict[str, Any] = {
            "total_decoys_served": 0,
            "honeypot_interactions": 0,
            "attacker_sessions": set()
        }
        
        # Setup logging
        self.logger = logging.getLogger("DeceptionEngine")
        
        # Load default templates
        self._load_default_templates()
    
    def _load_default_templates(self):
        """Load default decoy templates"""
        
        # Financial decoy template
        self.add_decoy_template(DecoyTemplate(
            decoy_id="financial_basic",
            decoy_type=DecoyType.DYNAMIC,
            category="financial",
            template_data={
                "institution": "First National Bank",
                "account_types": ["checking", "savings", "credit"]
            }
        ))
        
        # Medical decoy template
        self.add_decoy_template(DecoyTemplate(
            decoy_id="medical_basic",
            decoy_type=DecoyType.DYNAMIC,
            category="medical",
            template_data={
                "hospital": "General Hospital",
                "departments": ["cardiology", "oncology", "emergency"]
            }
        ))
        
        # Corporate decoy template
        self.add_decoy_template(DecoyTemplate(
            decoy_id="corporate_basic",
            decoy_type=DecoyType.DYNAMIC,
            category="corporate",
            template_data={
                "company": "TechCorp Industries",
                "divisions": ["engineering", "sales", "hr"]
            }
        ))
        
        # Honeypot template
        self.add_decoy_template(DecoyTemplate(
            decoy_id="web_honeypot",
            decoy_type=DecoyType.HONEYPOT,
            category="technical",
            template_data={
                "environment": "web_application",
                "hooks": ["login_attempt", "file_access", "api_call"]
            }
        ))
    
    def add_decoy_template(self, template: DecoyTemplate):
        """Add new decoy template"""
        self.decoy_templates[template.decoy_id] = template
        self.logger.info(f"Added decoy template: {template.decoy_id}")
    
    def generate_decoy_response(self, decoy_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Generate decoy response for failed authentication"""
        
        if decoy_id not in self.decoy_templates:
            # Use default template
            decoy_id = "corporate_basic"
        
        template = self.decoy_templates[decoy_id]
        
        # Generate decoy data
        decoy_data = self.decoy_generator.generate_decoy(template, context)
        
        # Update statistics
        self.interaction_stats["total_decoys_served"] += 1
        
        # Log the deception attempt
        self._log_deception_attempt(decoy_id, context, decoy_data)
        
        return decoy_data
    
    def create_interactive_honeypot(self, decoy_id: str, client_info: Dict[str, Any]) -> str:
        """Create interactive honeypot for sophisticated attackers"""
        
        if decoy_id not in self.decoy_templates:
            decoy_id = "web_honeypot"
        
        template = self.decoy_templates[decoy_id]
        honeypot_id = self.honeypot_manager.create_honeypot(decoy_id, template)
        
        # Update statistics
        self.interaction_stats["attacker_sessions"].add(
            client_info.get("session_id", "unknown")
        )
        
        self.logger.warning(f"Created honeypot {honeypot_id} for potential attacker")
        
        return honeypot_id
    
    def handle_honeypot_interaction(self, honeypot_id: str, interaction_data: Dict[str, Any],
                                  client_info: Dict[str, Any]) -> Dict[str, Any]:
        """Handle interaction with honeypot"""
        
        response = self.honeypot_manager.interact_with_honeypot(
            honeypot_id, interaction_data, client_info
        )
        
        # Update statistics
        self.interaction_stats["honeypot_interactions"] += 1
        
        # Alert security team about honeypot interaction
        self._alert_honeypot_interaction(honeypot_id, interaction_data, client_info)
        
        return response
    
    def _log_deception_attempt(self, decoy_id: str, context: Dict[str, Any], 
                             decoy_data: Dict[str, Any]):
        """Log deception attempt for analysis"""
        
        log_entry = {
            "timestamp": time.time(),
            "decoy_id": decoy_id,
            "context": context,
            "decoy_marker": decoy_data.get("decoy_marker", "unknown"),
            "client_info": context.get("client_info", {})
        }
        
        self.logger.warning(f"DECEPTION: Served decoy {decoy_id} to potential attacker")
        
        # In production, send to SIEM system
        self._send_to_siem("deception_attempt", log_entry)
    
    def _alert_honeypot_interaction(self, honeypot_id: str, interaction_data: Dict[str, Any],
                                  client_info: Dict[str, Any]):
        """Alert about honeypot interaction"""
        
        alert_data = {
            "timestamp": time.time(),
            "honeypot_id": honeypot_id,
            "interaction_type": interaction_data.get("type", "unknown"),
            "client_info": client_info,
            "severity": "HIGH"
        }
        
        self.logger.critical(f"HONEYPOT INTERACTION: {honeypot_id} - {interaction_data}")
        
        # In production, send immediate alert
        self._send_to_siem("honeypot_interaction", alert_data)
    
    def _send_to_siem(self, event_type: str, data: Dict[str, Any]):
        """Send event to SIEM system (mock implementation)"""
        # In production, integrate with actual SIEM
        siem_event = {
            "source": "chakrasec_deception",
            "event_type": event_type,
            "timestamp": time.time(),
            "data": data
        }
        
        # Mock SIEM logging
        self.logger.info(f"SIEM EVENT: {json.dumps(siem_event)}")
    
    def get_deception_statistics(self) -> Dict[str, Any]:
        """Get deception engine statistics"""
        return {
            "total_decoys_served": self.interaction_stats["total_decoys_served"],
            "honeypot_interactions": self.interaction_stats["honeypot_interactions"],
            "unique_attacker_sessions": len(self.interaction_stats["attacker_sessions"]),
            "active_honeypots": len(self.honeypot_manager.active_honeypots),
            "available_templates": len(self.decoy_templates)
        }
    
    def get_interaction_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent honeypot interactions"""
        return [
            interaction.to_dict() 
            for interaction in self.honeypot_manager.interaction_log[-limit:]
        ]


