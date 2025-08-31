#!/usr/bin/env python3
"""
Dataset Validation Script
Validates the quality, reliability, and weaponizability of extracted CVE datasets.
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import difflib
import re

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DatasetValidator:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.validation_results = {}
        
    def validate_all_cves(self) -> Dict:
        """Validate all CVEs in the dataset"""
        logger.info("🔍 Starting comprehensive dataset validation...")
        
        if not os.path.exists(self.dataset_dir):
            logger.error(f"Dataset directory {self.dataset_dir} not found!")
            return {}
        
        cve_dirs = [d for d in os.listdir(self.dataset_dir) if d.startswith('CVE-')]
        logger.info(f"Found {len(cve_dirs)} CVE directories to validate")
        
        for cve_id in cve_dirs:
            logger.info(f"\n📋 Validating {cve_id}...")
            self.validation_results[cve_id] = self.validate_single_cve(cve_id)
        
        self.generate_validation_report()
        return self.validation_results
    
    def validate_single_cve(self, cve_id: str) -> Dict:
        """Validate a single CVE dataset"""
        cve_dir = os.path.join(self.dataset_dir, cve_id)
        result = {
            'cve_id': cve_id,
            'status': 'unknown',
            'issues': [],
            'warnings': [],
            'metrics': {}
        }
        
        try:
            # Check directory structure
            if not self._check_directory_structure(cve_dir, result):
                result['status'] = 'failed'
                return result
            
            # Validate code differences
            if not self._validate_code_differences(cve_dir, result):
                result['status'] = 'failed'
                return result
            
            # Check weaponizability
            if not self._check_weaponizability(cve_dir, result):
                result['status'] = 'warning'
            
            # Validate metadata
            self._validate_metadata(cve_dir, result)
            
            # Calculate quality metrics
            self._calculate_quality_metrics(cve_dir, result)
            
            if not result['issues']:
                result['status'] = 'passed'
            elif not result['issues'] and result['warnings']:
                result['status'] = 'warning'
            
        except Exception as e:
            result['status'] = 'error'
            result['issues'].append(f"Validation error: {str(e)}")
            logger.error(f"Error validating {cve_id}: {e}")
        
        return result
    
    def _check_directory_structure(self, cve_dir: str, result: Dict) -> bool:
        """Check if CVE directory has proper structure"""
        required_dirs = ['vulnerable', 'fixed']
        
        for req_dir in required_dirs:
            req_path = os.path.join(cve_dir, req_dir)
            if not os.path.exists(req_path):
                result['issues'].append(f"Missing required directory: {req_dir}")
                return False
            
            # Check if directories contain files
            files = [f for f in os.listdir(req_path) if f.endswith(('.c', '.cpp', '.java', '.h', '.hpp'))]
            if not files:
                result['issues'].append(f"No source files found in {req_dir} directory")
                return False
        
        return True
    
    def _validate_code_differences(self, cve_dir: str, result: Dict) -> bool:
        """Validate that vulnerable and fixed code are actually different"""
        vulnerable_dir = os.path.join(cve_dir, 'vulnerable')
        fixed_dir = os.path.join(cve_dir, 'fixed')
        
        # Get all source files
        vulnerable_files = set()
        fixed_files = set()
        
        for root, dirs, files in os.walk(vulnerable_dir):
            for file in files:
                if file.endswith(('.c', '.cpp', '.java', '.h', '.hpp')):
                    rel_path = os.path.relpath(os.path.join(root, file), vulnerable_dir)
                    vulnerable_files.add(rel_path)
        
        for root, dirs, files in os.walk(fixed_dir):
            for file in files:
                if file.endswith(('.c', '.cpp', '.java', '.h', '.hpp')):
                    rel_path = os.path.relpath(os.path.join(root, file), fixed_dir)
                    fixed_files.add(rel_path)
        
        # Check for common files
        common_files = vulnerable_files.intersection(fixed_files)
        if not common_files:
            result['issues'].append("No common source files between vulnerable and fixed versions")
            return False
        
        # Analyze differences in common files
        different_files = 0
        identical_files = 0
        total_lines_changed = 0
        
        for file_path in common_files:
            vuln_file = os.path.join(vulnerable_dir, file_path)
            fixed_file = os.path.join(fixed_dir, file_path)
            
            try:
                with open(vuln_file, 'rb') as f1, open(fixed_file, 'rb') as f2:
                    vuln_content = f1.read()
                    fixed_content = f2.read()
                
                if vuln_content == fixed_content:
                    identical_files += 1
                    result['warnings'].append(f"File {file_path} is identical in both versions")
                else:
                    different_files += 1
                    
                    # Calculate line differences
                    try:
                        with open(vuln_file, 'r', encoding='utf-8', errors='ignore') as f1, \
                             open(fixed_file, 'r', encoding='utf-8', errors='ignore') as f2:
                            vuln_lines = f1.readlines()
                            fixed_lines = f2.readlines()
                            
                            # Use difflib to count changes
                            diff = difflib.unified_diff(vuln_lines, fixed_lines, n=0)
                            changes = list(diff)
                            total_lines_changed += len([line for line in changes if line.startswith('+') or line.startswith('-')])
                            
                    except Exception as e:
                        result['warnings'].append(f"Could not analyze line differences for {file_path}: {e}")
                        
            except Exception as e:
                result['warnings'].append(f"Could not compare file {file_path}: {e}")
        
        if different_files == 0:
            result['issues'].append("All source files are identical - extraction failed")
            return False
        
        # Store metrics
        result['metrics']['total_files'] = len(common_files)
        result['metrics']['different_files'] = different_files
        result['metrics']['identical_files'] = identical_files
        result['metrics']['total_lines_changed'] = total_lines_changed
        result['metrics']['difference_ratio'] = different_files / len(common_files)
        
        logger.info(f"  ✅ Found {different_files} different files out of {len(common_files)} total")
        logger.info(f"  📊 {total_lines_changed} total lines changed")
        
        return True
    
    def _check_weaponizability(self, cve_dir: str, result: Dict) -> bool:
        """Check if the vulnerability is weaponizable (exploitable)"""
        # Load metadata if available
        metadata_file = os.path.join(cve_dir, 'metadata.json')
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
                
                # Check CVSS score
                cvss_score = metadata.get('cvss_score', 0)
                if cvss_score >= 7.0:
                    result['metrics']['cvss_score'] = cvss_score
                    result['metrics']['severity'] = 'high'
                elif cvss_score >= 4.0:
                    result['metrics']['cvss_score'] = cvss_score
                    result['metrics']['severity'] = 'medium'
                else:
                    result['metrics']['cvss_score'] = cvss_score
                    result['metrics']['severity'] = 'low'
                
                # Check CWE for weaponizable vulnerability types
                cwe = metadata.get('cwe', '').lower()
                weaponizable_cwes = [
                    'buffer overflow', 'stack overflow', 'heap overflow',
                    'integer overflow', 'use after free', 'double free',
                    'format string', 'sql injection', 'command injection',
                    'deserialization', 'path traversal', 'race condition'
                ]
                
                is_weaponizable = any(cwe_type in cwe for cwe_type in weaponizable_cwes)
                result['metrics']['is_weaponizable'] = is_weaponizable
                
                if is_weaponizable:
                    logger.info(f"  🔥 CWE {cwe} indicates weaponizable vulnerability")
                else:
                    logger.info(f"  ⚠️  CWE {cwe} may not be easily weaponizable")
                
            except Exception as e:
                result['warnings'].append(f"Could not parse metadata: {e}")
        
        # Analyze source code for vulnerability patterns
        vulnerable_dir = os.path.join(cve_dir, 'vulnerable')
        vulnerability_patterns = self._find_vulnerability_patterns(vulnerable_dir)
        
        if vulnerability_patterns:
            result['metrics']['vulnerability_patterns'] = vulnerability_patterns
            logger.info(f"  🎯 Found {len(vulnerability_patterns)} vulnerability patterns in code")
        
        return True
    
    def _find_vulnerability_patterns(self, code_dir: str) -> List[str]:
        """Find common vulnerability patterns in source code"""
        patterns = []
        
        # Common vulnerability indicators
        vuln_indicators = {
            'buffer_overflow': [
                r'strcpy\s*\(',
                r'strcat\s*\(',
                r'sprintf\s*\(',
                r'gets\s*\(',
                r'memcpy\s*\(',
                r'strncpy\s*\(',
                r'strncat\s*\('
            ],
            'integer_overflow': [
                r'\+\s*[0-9]+\s*[><]\s*[a-zA-Z_][a-zA-Z0-9_]*',
                r'[a-zA-Z_][a-zA-Z0-9_]*\s*\+\s*[0-9]+\s*[><]\s*[a-zA-Z_][a-zA-Z0-9_]*'
            ],
            'format_string': [
                r'printf\s*\([^"]*"[^"]*%[^"]*"[^)]*\)',
                r'sprintf\s*\([^"]*"[^"]*%[^"]*"[^)]*\)'
            ],
            'use_after_free': [
                r'free\s*\([^)]+\)\s*;[^}]*[a-zA-Z_][a-zA-Z0-9_]*\s*=',
                r'free\s*\([^)]+\)\s*;[^}]*[a-zA-Z_][a-zA-Z0-9_]*\s*\('
            ]
        }
        
        for root, dirs, files in os.walk(code_dir):
            for file in files:
                if file.endswith(('.c', '.cpp', '.java')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for vuln_type, regex_list in vuln_indicators.items():
                            for regex in regex_list:
                                matches = re.findall(regex, content, re.IGNORECASE)
                                if matches:
                                    patterns.append(f"{vuln_type}: {len(matches)} instances in {os.path.basename(file_path)}")
                                    
                    except Exception as e:
                        continue
        
        return patterns
    
    def _validate_metadata(self, cve_dir: str, result: Dict):
        """Validate metadata completeness and accuracy"""
        metadata_file = os.path.join(cve_dir, 'metadata.json')
        
        if not os.path.exists(metadata_file):
            result['warnings'].append("No metadata.json file found")
            return
        
        try:
            with open(metadata_file, 'r') as f:
                metadata = json.load(f)
            
            required_fields = ['cve_id', 'description', 'cvss_score', 'cwe']
            missing_fields = [field for field in required_fields if field not in metadata]
            
            if missing_fields:
                result['warnings'].append(f"Missing metadata fields: {', '.join(missing_fields)}")
            
            # Validate CVSS score range
            cvss_score = metadata.get('cvss_score', 0)
            if not (0 <= cvss_score <= 10):
                result['warnings'].append(f"Invalid CVSS score: {cvss_score}")
            
        except Exception as e:
            result['warnings'].append(f"Metadata validation error: {e}")
    
    def _calculate_quality_metrics(self, cve_dir: str, result: Dict):
        """Calculate overall quality metrics for the CVE"""
        # File size metrics
        vulnerable_dir = os.path.join(cve_dir, 'vulnerable')
        fixed_dir = os.path.join(cve_dir, 'fixed')
        
        try:
            vuln_size = sum(os.path.getsize(os.path.join(root, file)) 
                           for root, dirs, files in os.walk(vulnerable_dir) 
                           for file in files if file.endswith(('.c', '.cpp', '.java', '.h', '.hpp')))
            fixed_size = sum(os.path.getsize(os.path.join(root, file)) 
                           for root, dirs, files in os.walk(fixed_dir) 
                           for file in files if file.endswith(('.c', '.cpp', '.java', '.h', '.hpp')))
            
            result['metrics']['vulnerable_size_bytes'] = vuln_size
            result['metrics']['fixed_size_bytes'] = fixed_size
            result['metrics']['size_difference_bytes'] = abs(vuln_size - fixed_size)
            
        except Exception as e:
            result['warnings'].append(f"Could not calculate size metrics: {e}")
    
    def generate_validation_report(self):
        """Generate a comprehensive validation report"""
        total_cves = len(self.validation_results)
        passed = sum(1 for r in self.validation_results.values() if r['status'] == 'passed')
        failed = sum(1 for r in self.validation_results.values() if r['status'] == 'failed')
        warnings = sum(1 for r in self.validation_results.values() if r['status'] == 'warning')
        errors = sum(1 for r in self.validation_results.values() if r['status'] == 'error')
        
        logger.info("\n" + "="*80)
        logger.info("📊 DATASET VALIDATION REPORT")
        logger.info("="*80)
        logger.info(f"Total CVEs: {total_cves}")
        logger.info(f"✅ Passed: {passed}")
        logger.info(f"❌ Failed: {failed}")
        logger.info(f"⚠️  Warnings: {warnings}")
        logger.info(f"🚨 Errors: {errors}")
        logger.info(f"Success Rate: {(passed/total_cves)*100:.1f}%" if total_cves > 0 else "N/A")
        
        # Detailed results
        logger.info("\n📋 DETAILED RESULTS:")
        for cve_id, result in self.validation_results.items():
            status_emoji = {
                'passed': '✅',
                'failed': '❌',
                'warning': '⚠️',
                'error': '🚨',
                'unknown': '❓'
            }
            
            logger.info(f"\n{status_emoji.get(result['status'], '❓')} {cve_id}: {result['status'].upper()}")
            
            if result['issues']:
                for issue in result['issues']:
                    logger.info(f"  ❌ Issue: {issue}")
            
            if result['warnings']:
                for warning in result['warnings']:
                    logger.info(f"  ⚠️  Warning: {warning}")
            
            if result['metrics']:
                logger.info(f"  📊 Metrics: {result['metrics']}")
        
        # Save detailed report
        report_file = f"dataset_validation_report_{len(self.validation_results)}_cves.json"
        with open(report_file, 'w') as f:
            json.dump(self.validation_results, f, indent=2)
        
        logger.info(f"\n💾 Detailed report saved to: {report_file}")

def main():
    """Main validation function"""
    validator = DatasetValidator()
    results = validator.validate_all_cves()
    
    # Print summary
    print("\n" + "="*80)
    print("🎯 DATASET VALIDATION COMPLETE")
    print("="*80)
    
    if results:
        total = len(results)
        passed = sum(1 for r in results.values() if r['status'] == 'passed')
        print(f"📊 Overall Success Rate: {(passed/total)*100:.1f}% ({passed}/{total})")
        
        # Show weaponizable CVEs
        weaponizable = [cve_id for cve_id, result in results.items() 
                       if result.get('metrics', {}).get('is_weaponizable', False)]
        if weaponizable:
            print(f"🔥 Weaponizable CVEs: {', '.join(weaponizable)}")
        else:
            print("⚠️  No clearly weaponizable CVEs identified")
    else:
        print("❌ No CVEs found to validate")

if __name__ == "__main__":
    main()
