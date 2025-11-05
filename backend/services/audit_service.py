"""
Audit Service Module
===================
Performs rule-based compliance auditing against multiple frameworks.
"""

from typing import Dict, Any, List, Tuple
from pathlib import Path
import json
import yaml
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger("audit_service")


class ComplianceRuleEngine:
    """Rule-based compliance evaluation engine."""
    
    def __init__(self, rules: List[Dict[str, Any]]):
        """Initialize rule engine with rules."""
        self.rules = rules
    
    def evaluate_rule(
        self, 
        rule: Dict[str, Any], 
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluate a single compliance rule.
        
        Args:
            rule: Rule definition
            data: Compliance data
        
        Returns:
            Evaluation result
        """
        field_path = rule["field"]
        operator = rule["operator"]
        expected = rule["expected_value"]
        weight = rule.get("weight", 1)
        severity = rule.get("severity", "MEDIUM")
        
        # Extract value from nested path
        value = self._get_nested_value(data, field_path)
        
        # Evaluate condition
        passed = self._evaluate_condition(value, operator, expected)
        
        result = {
            "rule_id": rule["id"],
            "description": rule["description"],
            "category": rule.get("category", "General"),
            "severity": severity,
            "weight": weight,
            "field": field_path,
            "expected_value": expected,
            "actual_value": value,
            "operator": operator,
            "status": "PASS" if passed else "FAIL",
            "score": weight if passed else 0,
            "remediation": rule.get("remediation", "No remediation guidance available")
        }
        
        return result
    
    def _get_nested_value(
        self, 
        data: Dict[str, Any], 
        path: str,
        default: Any = None
    ) -> Any:
        """Get value from nested dictionary using dot notation."""
        keys = path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key, default)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def _evaluate_condition(
        self, 
        actual: Any, 
        operator: str, 
        expected: Any
    ) -> bool:
        """Evaluate comparison condition."""
        if actual is None:
            return False
        
        try:
            if operator == "==":
                return actual == expected
            elif operator == "!=":
                return actual != expected
            elif operator == ">=":
                return float(actual) >= float(expected)
            elif operator == "<=":
                return float(actual) <= float(expected)
            elif operator == ">":
                return float(actual) > float(expected)
            elif operator == "<":
                return float(actual) < float(expected)
            elif operator == "contains":
                return expected in actual if isinstance(actual, (list, str)) else False
            elif operator == "not_contains":
                return expected not in actual if isinstance(actual, (list, str)) else True
            elif operator == "in":
                return actual in expected if isinstance(expected, list) else False
            elif operator == "not_in":
                return actual not in expected if isinstance(expected, list) else True
            else:
                logger.warning(f"Unknown operator: {operator}")
                return False
        except Exception as e:
            logger.debug(f"Evaluation error: {e}")
            return False
    
    def evaluate_all(
        self, 
        data: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Evaluate all rules against data.
        
        Args:
            data: Compliance data
        
        Returns:
            List of evaluation results
        """
        results = []
        
        for rule in self.rules:
            result = self.evaluate_rule(rule, data)
            results.append(result)
        
        return results


class AuditService:
    """Main compliance audit service."""
    
    def __init__(self, config_path: str = "config.yaml"):
        """Initialize audit service."""
        with open(config_path) as f:
            self.config = yaml.safe_load(f)
        
        self.config_dir = Path(self.config['paths']['config_dir'])
        self.frameworks = self._load_frameworks()
    
    def _load_frameworks(self) -> Dict[str, List[Dict[str, Any]]]:
        """Load compliance framework rules."""
        frameworks = {}
        frameworks_dir = self.config_dir / "frameworks"
        
        if not frameworks_dir.exists():
            logger.warning(f"Frameworks directory not found: {frameworks_dir}")
            return frameworks
        
        for framework_file in frameworks_dir.glob("*.json"):
            framework_name = framework_file.stem.upper()
            
            try:
                with open(framework_file) as f:
                    rules = json.load(f)
                
                frameworks[framework_name] = rules
                logger.info(f"✓ Loaded {len(rules)} rules for {framework_name}")
            except Exception as e:
                logger.error(f"Failed to load {framework_name}: {e}")
        
        return frameworks
    
    def audit_compliance(
        self, 
        data: Dict[str, Any],
        frameworks: List[str]
    ) -> Dict[str, Any]:
        """
        Perform comprehensive compliance audit.
        
        Args:
            data: Compliance data to audit
            frameworks: List of frameworks to audit against
        
        Returns:
            Audit results
        """
        logger.info(f"🔍 Starting audit for {data.get('company_name', 'Unknown')}")
        
        audit_results = {
            "company_name": data.get("company_name", "Unknown"),
            "company_type": data.get("company_type", "Unknown"),
            "audit_timestamp": datetime.now().isoformat(),
            "frameworks": {},
            "overall_compliance": {}
        }
        
        all_framework_results = []
        
        # Audit each framework
        for framework_name in frameworks:
            if framework_name not in self.frameworks:
                logger.warning(f"Framework not found: {framework_name}")
                continue
            
            logger.info(f"  📋 Auditing {framework_name}...")
            
            rules = self.frameworks[framework_name]
            rule_engine = ComplianceRuleEngine(rules)
            
            # Evaluate rules
            rule_results = rule_engine.evaluate_all(data)
            
            # Calculate metrics
            framework_metrics = self._calculate_framework_metrics(
                framework_name,
                rule_results
            )
            
            audit_results["frameworks"][framework_name] = framework_metrics
            all_framework_results.append(framework_metrics)
            
            logger.info(
                f"    ✓ {framework_name}: {framework_metrics['compliance_percentage']:.1f}% "
                f"({framework_metrics['passed_rules']}/{framework_metrics['total_rules']} passed)"
            )
        
        # Calculate overall compliance
        if all_framework_results:
            audit_results["overall_compliance"] = self._calculate_overall_compliance(
                all_framework_results
            )
        
        return audit_results
    
    def _calculate_framework_metrics(
        self,
        framework_name: str,
        rule_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate framework-level metrics."""
        
        total_rules = len(rule_results)
        passed_rules = sum(1 for r in rule_results if r["status"] == "PASS")
        failed_rules = sum(1 for r in rule_results if r["status"] == "FAIL")
        
        total_weight = sum(r["weight"] for r in rule_results)
        achieved_weight = sum(r["score"] for r in rule_results)
        
        compliance_percentage = (
            (achieved_weight / total_weight * 100) 
            if total_weight > 0 else 0
        )
        
        # Categorize by severity
        severity_breakdown = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for result in rule_results:
            if result["status"] == "FAIL":
                severity = result["severity"]
                if severity in severity_breakdown:
                    severity_breakdown[severity] += 1
        
        # Categorize by category
        category_breakdown = {}
        for result in rule_results:
            category = result["category"]
            if category not in category_breakdown:
                category_breakdown[category] = {
                    "total": 0,
                    "passed": 0,
                    "failed": 0,
                    "compliance_pct": 0
                }
            
            category_breakdown[category]["total"] += 1
            if result["status"] == "PASS":
                category_breakdown[category]["passed"] += 1
            else:
                category_breakdown[category]["failed"] += 1
        
        # Calculate category compliance percentages
        for category, stats in category_breakdown.items():
            if stats["total"] > 0:
                stats["compliance_pct"] = round(
                    (stats["passed"] / stats["total"]) * 100, 2
                )
        
        # Determine risk level
        risk_level = self._determine_risk_level(compliance_percentage)
        
        # Get critical gaps (failed rules with high severity)
        critical_gaps = [
            {
                "rule_id": r["rule_id"],
                "description": r["description"],
                "category": r["category"],
                "severity": r["severity"],
                "field": r["field"],
                "expected": r["expected_value"],
                "actual": r["actual_value"],
                "remediation": r["remediation"]
            }
            for r in rule_results
            if r["status"] == "FAIL" and r["severity"] in ["CRITICAL", "HIGH"]
        ]
        
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        critical_gaps.sort(
            key=lambda x: (severity_order.get(x["severity"], 99), -x.get("weight", 0))
        )
        
        return {
            "framework": framework_name,
            "total_rules": total_rules,
            "passed_rules": passed_rules,
            "failed_rules": failed_rules,
            "compliance_percentage": round(compliance_percentage, 2),
            "risk_level": risk_level,
            "total_weight": total_weight,
            "achieved_weight": achieved_weight,
            "severity_breakdown": severity_breakdown,
            "category_breakdown": category_breakdown,
            "critical_gaps": critical_gaps[:10],  # Top 10
            "all_rule_results": rule_results
        }
    
    def _calculate_overall_compliance(
        self,
        framework_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate overall compliance across frameworks."""
        
        # Weighted average compliance
        weights = self.config['audit']['scoring']['weights']
        
        weighted_compliance = sum(
            r["compliance_percentage"] for r in framework_results
        ) / len(framework_results)
        
        # Overall risk level
        risk_level = self._determine_risk_level(weighted_compliance)
        
        # Total critical and high issues
        total_critical = sum(
            r["severity_breakdown"].get("CRITICAL", 0)
            for r in framework_results
        )
        
        total_high = sum(
            r["severity_breakdown"].get("HIGH", 0)
            for r in framework_results
        )
        
        # Get top gaps across all frameworks
        all_gaps = []
        for fw_result in framework_results:
            all_gaps.extend(fw_result["critical_gaps"])
        
        # Sort and deduplicate
        severity_order = {"CRITICAL": 0, "HIGH": 1}
        all_gaps.sort(key=lambda x: severity_order.get(x["severity"], 99))
        
        # Keep top 15 unique gaps
        seen = set()
        top_gaps = []
        for gap in all_gaps:
            gap_key = f"{gap['category']}:{gap['field']}"
            if gap_key not in seen:
                top_gaps.append(gap)
                seen.add(gap_key)
                if len(top_gaps) >= 15:
                    break
        
        return {
            "compliance_percentage": round(weighted_compliance, 2),
            "risk_level": risk_level,
            "frameworks_count": len(framework_results),
            "total_critical_issues": total_critical,
            "total_high_issues": total_high,
            "total_issues": total_critical + total_high,
            "top_priority_gaps": top_gaps,
            "assessment_date": datetime.now().isoformat()
        }
    
    def _determine_risk_level(self, compliance_percentage: float) -> str:
        """Determine risk level based on compliance percentage."""
        thresholds = self.config['audit']['thresholds']
        
        if compliance_percentage >= thresholds['compliant']:
            return "LOW"
        elif compliance_percentage >= thresholds['partial']:
            return "MEDIUM"
        else:
            return "HIGH"