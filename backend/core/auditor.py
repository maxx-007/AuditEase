"""
Core Auditor Module
===================
Core compliance auditing logic with rule evaluation and scoring.
"""

from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import json
from datetime import datetime
from utils.logger import setup_logger
from utils.helpers import get_nested_value, calculate_risk_level

logger = setup_logger("auditor")


class ComplianceRule:
    """Represents a single compliance rule."""
    
    def __init__(self, rule_data: Dict[str, Any]):
        """Initialize rule from dictionary."""
        self.id = rule_data["id"]
        self.description = rule_data["description"]
        self.category = rule_data.get("category", "General")
        self.field = rule_data["field"]
        self.operator = rule_data["operator"]
        self.expected_value = rule_data["expected_value"]
        self.weight = rule_data.get("weight", 1)
        self.severity = rule_data.get("severity", "MEDIUM")
        self.remediation = rule_data.get("remediation", "No remediation provided")
        self.references = rule_data.get("references", [])
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary."""
        return {
            "id": self.id,
            "description": self.description,
            "category": self.category,
            "field": self.field,
            "operator": self.operator,
            "expected_value": self.expected_value,
            "weight": self.weight,
            "severity": self.severity,
            "remediation": self.remediation,
            "references": self.references
        }


class RuleEvaluator:
    """Evaluates compliance rules against data."""
    
    OPERATORS = {
        "==": lambda a, e: a == e,
        "!=": lambda a, e: a != e,
        ">=": lambda a, e: float(a) >= float(e),
        "<=": lambda a, e: float(a) <= float(e),
        ">": lambda a, e: float(a) > float(e),
        "<": lambda a, e: float(a) < float(e),
        "contains": lambda a, e: e in a if isinstance(a, (list, str)) else False,
        "not_contains": lambda a, e: e not in a if isinstance(a, (list, str)) else True,
        "in": lambda a, e: a in e if isinstance(e, list) else False,
        "not_in": lambda a, e: a not in e if isinstance(e, list) else True,
    }
    
    def evaluate(
        self, 
        rule: ComplianceRule, 
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluate a single rule against data.
        
        Args:
            rule: Compliance rule to evaluate
            data: Data to evaluate against
        
        Returns:
            Evaluation result with status and details
        """
        # Extract actual value from data
        actual_value = get_nested_value(data, rule.field)
        
        # Handle missing data
        if actual_value is None:
            return self._create_result(
                rule=rule,
                status="MISSING_DATA",
                actual_value=None,
                passed=False,
                message=f"Missing field: {rule.field}"
            )
        
        # Evaluate condition
        try:
            passed = self._evaluate_condition(
                actual_value,
                rule.operator,
                rule.expected_value
            )
            
            status = "PASS" if passed else "FAIL"
            message = self._generate_message(
                rule, actual_value, passed
            )
            
            return self._create_result(
                rule=rule,
                status=status,
                actual_value=actual_value,
                passed=passed,
                message=message
            )
            
        except Exception as e:
            logger.debug(f"Evaluation error for rule {rule.id}: {e}")
            return self._create_result(
                rule=rule,
                status="ERROR",
                actual_value=actual_value,
                passed=False,
                message=f"Evaluation error: {str(e)}"
            )
    
    def _evaluate_condition(
        self,
        actual: Any,
        operator: str,
        expected: Any
    ) -> bool:
        """Evaluate comparison condition."""
        if operator not in self.OPERATORS:
            raise ValueError(f"Unsupported operator: {operator}")
        
        try:
            return self.OPERATORS[operator](actual, expected)
        except Exception as e:
            logger.debug(f"Condition evaluation error: {e}")
            return False
    
    def _generate_message(
        self,
        rule: ComplianceRule,
        actual_value: Any,
        passed: bool
    ) -> str:
        """Generate human-readable result message."""
        if passed:
            return f"Compliant: {rule.description}"
        else:
            return (
                f"Non-compliant: Expected {rule.operator} {rule.expected_value}, "
                f"but got {actual_value}"
            )
    
    def _create_result(
        self,
        rule: ComplianceRule,
        status: str,
        actual_value: Any,
        passed: bool,
        message: str
    ) -> Dict[str, Any]:
        """Create standardized evaluation result."""
        return {
            "rule_id": rule.id,
            "description": rule.description,
            "category": rule.category,
            "severity": rule.severity,
            "weight": rule.weight,
            "field": rule.field,
            "operator": rule.operator,
            "expected_value": rule.expected_value,
            "actual_value": actual_value,
            "status": status,
            "passed": passed,
            "score": rule.weight if passed else 0,
            "message": message,
            "remediation": rule.remediation,
            "references": rule.references,
            "evaluated_at": datetime.now().isoformat()
        }


class ComplianceScoreCalculator:
    """Calculates compliance scores and metrics."""
    
    def __init__(self, evaluation_results: List[Dict[str, Any]]):
        """Initialize with evaluation results."""
        self.results = evaluation_results
    
    def calculate_overall_score(self) -> Dict[str, Any]:
        """Calculate overall compliance score."""
        total_weight = sum(r["weight"] for r in self.results)
        achieved_weight = sum(r["score"] for r in self.results)
        
        compliance_percentage = (
            (achieved_weight / total_weight * 100) 
            if total_weight > 0 else 0
        )
        
        return {
            "total_rules": len(self.results),
            "total_weight": total_weight,
            "achieved_weight": achieved_weight,
            "compliance_percentage": round(compliance_percentage, 2),
            "passed_rules": sum(1 for r in self.results if r["passed"]),
            "failed_rules": sum(1 for r in self.results if not r["passed"] and r["status"] == "FAIL"),
            "missing_data_rules": sum(1 for r in self.results if r["status"] == "MISSING_DATA"),
            "error_rules": sum(1 for r in self.results if r["status"] == "ERROR")
        }
    
    def calculate_category_scores(self) -> Dict[str, Dict[str, Any]]:
        """Calculate scores by category."""
        categories = {}
        
        for result in self.results:
            category = result["category"]
            
            if category not in categories:
                categories[category] = {
                    "total_rules": 0,
                    "passed_rules": 0,
                    "failed_rules": 0,
                    "total_weight": 0,
                    "achieved_weight": 0,
                    "compliance_percentage": 0
                }
            
            cat_data = categories[category]
            cat_data["total_rules"] += 1
            cat_data["total_weight"] += result["weight"]
            cat_data["achieved_weight"] += result["score"]
            
            if result["passed"]:
                cat_data["passed_rules"] += 1
            elif result["status"] == "FAIL":
                cat_data["failed_rules"] += 1
        
        # Calculate percentages
        for cat_data in categories.values():
            if cat_data["total_weight"] > 0:
                cat_data["compliance_percentage"] = round(
                    (cat_data["achieved_weight"] / cat_data["total_weight"]) * 100,
                    2
                )
        
        return categories
    
    def calculate_severity_breakdown(self) -> Dict[str, int]:
        """Calculate breakdown by severity."""
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for result in self.results:
            if not result["passed"] and result["status"] == "FAIL":
                severity = result["severity"]
                if severity in severity_counts:
                    severity_counts[severity] += 1
        
        return severity_counts
    
    def get_critical_gaps(self, max_gaps: int = 10) -> List[Dict[str, Any]]:
        """Get top critical gaps ordered by severity and weight."""
        # Filter failed rules
        failed_rules = [
            r for r in self.results 
            if not r["passed"] and r["status"] in ["FAIL", "MISSING_DATA"]
        ]
        
        # Sort by severity (Critical > High > Medium > Low) then by weight
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        
        sorted_gaps = sorted(
            failed_rules,
            key=lambda x: (
                severity_order.get(x["severity"], 99),
                -x["weight"]
            )
        )
        
        # Format gaps
        critical_gaps = []
        for gap in sorted_gaps[:max_gaps]:
            critical_gaps.append({
                "rule_id": gap["rule_id"],
                "description": gap["description"],
                "category": gap["category"],
                "severity": gap["severity"],
                "weight": gap["weight"],
                "field": gap["field"],
                "expected": gap["expected_value"],
                "actual": gap["actual_value"],
                "remediation": gap["remediation"],
                "references": gap["references"]
            })
        
        return critical_gaps


class ComplianceAuditor:
    """Main compliance auditor orchestrator."""
    
    def __init__(self, frameworks_dir: Path):
        """
        Initialize auditor with frameworks directory.
        
        Args:
            frameworks_dir: Path to frameworks configuration directory
        """
        self.frameworks_dir = frameworks_dir
        self.frameworks = {}
        self.evaluator = RuleEvaluator()
        
        self._load_frameworks()
    
    def _load_frameworks(self):
        """Load all compliance frameworks."""
        if not self.frameworks_dir.exists():
            logger.warning(f"Frameworks directory not found: {self.frameworks_dir}")
            return
        
        for framework_file in self.frameworks_dir.glob("*.json"):
            framework_name = framework_file.stem.upper()
            
            try:
                with open(framework_file) as f:
                    rules_data = json.load(f)
                
                rules = [ComplianceRule(r) for r in rules_data]
                self.frameworks[framework_name] = rules
                
                logger.info(f"✓ Loaded {len(rules)} rules for {framework_name}")
            except Exception as e:
                logger.error(f"Failed to load {framework_name}: {e}")
    
    def audit_single_framework(
        self,
        framework_name: str,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Audit data against a single framework.
        
        Args:
            framework_name: Name of framework
            data: Compliance data to audit
        
        Returns:
            Audit results for the framework
        """
        if framework_name not in self.frameworks:
            raise ValueError(f"Framework not found: {framework_name}")
        
        rules = self.frameworks[framework_name]
        
        # Evaluate all rules
        evaluation_results = []
        for rule in rules:
            result = self.evaluator.evaluate(rule, data)
            evaluation_results.append(result)
        
        # Calculate metrics
        calculator = ComplianceScoreCalculator(evaluation_results)
        
        overall_score = calculator.calculate_overall_score()
        category_scores = calculator.calculate_category_scores()
        severity_breakdown = calculator.calculate_severity_breakdown()
        critical_gaps = calculator.get_critical_gaps()
        
        # Determine risk level
        risk_level = calculate_risk_level(overall_score["compliance_percentage"])
        
        return {
            "framework": framework_name,
            "overall": overall_score,
            "risk_level": risk_level,
            "category_breakdown": category_scores,
            "severity_breakdown": severity_breakdown,
            "critical_gaps": critical_gaps,
            "all_results": evaluation_results,
            "audit_timestamp": datetime.now().isoformat()
        }
    
    def audit_all_frameworks(
        self,
        data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Audit data against all loaded frameworks.
        
        Args:
            data: Compliance data to audit
        
        Returns:
            Complete audit results
        """
        company_name = data.get("company_name", "Unknown")
        logger.info(f"🔍 Starting comprehensive audit for {company_name}")
        
        audit_results = {
            "company_name": company_name,
            "company_type": data.get("company_type", "Unknown"),
            "audit_date": datetime.now().isoformat(),
            "frameworks": {},
            "overall_summary": {}
        }
        
        framework_results = []
        
        # Audit each framework
        for framework_name in self.frameworks.keys():
            logger.info(f"  📋 Auditing {framework_name}...")
            
            framework_result = self.audit_single_framework(
                framework_name,
                data
            )
            
            audit_results["frameworks"][framework_name] = framework_result
            framework_results.append(framework_result)
            
            logger.info(
                f"    ✓ {framework_name}: {framework_result['overall']['compliance_percentage']:.1f}% "
                f"({framework_result['overall']['passed_rules']}/{framework_result['overall']['total_rules']} passed)"
            )
        
        # Calculate overall summary
        if framework_results:
            audit_results["overall_summary"] = self._calculate_overall_summary(
                framework_results
            )
        
        logger.info(f"✅ Audit complete for {company_name}")
        
        return audit_results
    
    def _calculate_overall_summary(
        self,
        framework_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate overall summary across all frameworks."""
        # Average compliance percentage
        avg_compliance = sum(
            fr["overall"]["compliance_percentage"] 
            for fr in framework_results
        ) / len(framework_results)
        
        # Total critical and high issues
        total_critical = sum(
            fr["severity_breakdown"].get("CRITICAL", 0)
            for fr in framework_results
        )
        
        total_high = sum(
            fr["severity_breakdown"].get("HIGH", 0)
            for fr in framework_results
        )
        
        # Overall risk level
        overall_risk = calculate_risk_level(avg_compliance)
        
        # Aggregate top gaps
        all_gaps = []
        for fr in framework_results:
            for gap in fr["critical_gaps"]:
                gap["framework"] = fr["framework"]
                all_gaps.append(gap)
        
        # Sort and deduplicate
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        all_gaps.sort(
            key=lambda x: (severity_order.get(x["severity"], 99), -x["weight"])
        )
        
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
            "compliance_percentage": round(avg_compliance, 2),
            "risk_level": overall_risk,
            "frameworks_assessed": len(framework_results),
            "total_critical_issues": total_critical,
            "total_high_issues": total_high,
            "total_issues": total_critical + total_high,
            "top_priority_gaps": top_gaps,
            "assessment_date": datetime.now().isoformat()
        }
    
    def get_available_frameworks(self) -> List[str]:
        """Get list of available framework names."""
        return list(self.frameworks.keys())