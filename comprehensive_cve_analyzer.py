#!/usr/bin/env python3
"""
Comprehensive CVE Analyzer
Analyzes the entire dataset to find ALL critical, weaponizable CVEs in C language.
"""

import os
import json
import re
import logging
from pathlib import Path
from typing import List, Dict, Set
from collections import defaultdict

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ComprehensiveCVEAnalyzer:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.all_cves = []
        self.critical_cves = []
        self.weaponizable_cves = []
        
        # C language file extensions
        self.c_extensions = {'.c', '.h', '.cpp', '.cc', '.cxx', '.hpp'}
        
        # Critical vulnerability patterns in C (high weaponizability)
        self.critical_patterns = {
            'buffer_overflow': [
                r'\bstrcpy\s*\(', r'\bstrcat\s*\(', r'\bsprintf\s*\(',
                r'\bgets\s*\(', r'\bstrncpy\s*\(', r'\bstrncat\s*\(',
                r'\bmemcpy\s*\(', r'\bmemmove\s*\(', r'\bmemset\s*\(',
                r'\bfread\s*\(', r'\bfwrite\s*\(', r'\bfgets\s*\('
            ],
            'use_after_free': [
                r'\bfree\s*\(', r'\bmalloc\s*\(', r'\bcalloc\s*\(',
                r'\brealloc\s*\(', r'\bdelete\s*', r'\bnew\s*'
            ],
            'integer_overflow': [
                r'\+\+|--|\+=|\-=|\*=|/=', r'\bint\s+\w+\s*[+\-*/]\s*\w+',
                r'\blong\s+\w+\s*[+\-*/]\s*\w+', r'\bsize_t\s+\w+\s*[+\-*/]\s*\w+'
            ],
            'format_string': [
                r'\bprintf\s*\(', r'\bfprintf\s*\(', r'\bsprintf\s*\(',
                r'\bsnprintf\s*\(', r'\bvsprintf\s*\(', r'\bvsnprintf\s*\('
            ],
            'null_pointer': [
                r'->\s*\w+', r'\*\w+\s*=', r'\bif\s*\(\s*!\s*\w+\s*\)',
                r'\bif\s*\(\s*\w+\s*==\s*NULL\s*\)'
            ],
            'command_injection': [
                r'\bsystem\s*\(', r'\bexec\s*\(', r'\bpopen\s*\(',
                r'\bexecl\s*\(', r'\bexeclp\s*\(', r'\bexecle\s*\('
            ],
            'sql_injection': [
                r'\bSELECT\b', r'\bINSERT\b', r'\bUPDATE\b', r'\bDELETE\b',
                r'\bCREATE\b', r'\bDROP\b', r'\bALTER\b'
            ]
        }
        
        # High-priority projects (critical infrastructure)
        self.high_priority_projects = {
            'openssl', 'sqlite', 'curl', 'zlib', 'libpng', 'libjpeg',
            'linux', 'ffmpeg', 'imagemagick', 'wireshark', 'tcpdump',
            'nginx', 'apache', 'mysql', 'postgresql', 'redis',
            'python', 'php', 'java', 'nodejs', 'golang', 'kernel'
        }
        
    def is_c_language_file(self, filepath: str) -> bool:
        """Check if a file is written in C language"""
        if not os.path.exists(filepath):
            return False
        
        # Check file extension
        ext = Path(filepath).suffix.lower()
        if ext in self.c_extensions:
            return True
        
        # Check file content for C language indicators
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(2048)  # Read first 2KB
                
                # C language indicators
                c_indicators = [
                    r'#include\s*[<"]',  # Include statements
                    r'\bint\s+main\s*\(',  # Main function
                    r'\bvoid\s+\w+\s*\(',  # Function declarations
                    r'\bchar\s*\*',  # Char pointers
                    r'\bstruct\s+\w+',  # Struct definitions
                    r'\btypedef\s+',  # Typedefs
                    r'\b#define\s+',  # Preprocessor directives
                    r'\breturn\s+',  # Return statements
                    r'\bif\s*\(',  # If statements
                    r'\bfor\s*\(',  # For loops
                    r'\bwhile\s*\(',  # While loops
                    r'\bswitch\s*\(',  # Switch statements
                    r'\bstatic\s+',  # Static declarations
                    r'\bextern\s+',  # Extern declarations
                    r'\bconst\s+',  # Const declarations
                ]
                
                for pattern in c_indicators:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
                        
        except Exception as e:
            logger.debug(f"Error reading file {filepath}: {e}")
            
        return False
    
    def analyze_vulnerability_patterns(self, filepath: str) -> Dict:
        """Analyze a file for vulnerability patterns"""
        if not os.path.exists(filepath):
            return {}
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            pattern_counts = {}
            total_patterns = 0
            
            for vuln_type, patterns in self.critical_patterns.items():
                count = 0
                for pattern in patterns:
                    matches = len(re.findall(pattern, content, re.IGNORECASE))
                    count += matches
                    total_patterns += matches
                
                if count > 0:
                    pattern_counts[vuln_type] = count
            
            pattern_counts['total'] = total_patterns
            return pattern_counts
            
        except Exception as e:
            logger.debug(f"Error analyzing file {filepath}: {e}")
            return {}
    
    def check_code_differences(self, cve_dir: str) -> Dict:
        """Check if vulnerable and fixed code are actually different"""
        vulnerable_dir = os.path.join(cve_dir, "vulnerable")
        fixed_dir = os.path.join(cve_dir, "fixed")
        
        if not os.path.exists(vulnerable_dir) or not os.path.exists(fixed_dir):
            return {'has_differences': False, 'reason': 'Missing vulnerable or fixed directory'}
        
        # Get all C language files in both directories
        vulnerable_files = []
        fixed_files = []
        
        for root, dirs, files in os.walk(vulnerable_dir):
            for file in files:
                filepath = os.path.join(root, file)
                if self.is_c_language_file(filepath):
                    vulnerable_files.append(filepath)
        
        for root, dirs, files in os.walk(fixed_dir):
            for file in files:
                filepath = os.path.join(root, file)
                if self.is_c_language_file(filepath):
                    fixed_files.append(filepath)
        
        if not vulnerable_files or not fixed_files:
            return {'has_differences': False, 'reason': 'No C language files found'}
        
        # Check for actual differences and analyze vulnerability patterns
        differences_found = False
        total_vulnerability_patterns = 0
        pattern_analysis = defaultdict(int)
        
        for vuln_file in vulnerable_files:
            # Find corresponding fixed file
            rel_path = os.path.relpath(vuln_file, vulnerable_dir)
            fixed_file = os.path.join(fixed_dir, rel_path)
            
            if os.path.exists(fixed_file):
                # Check if files are different
                try:
                    with open(vuln_file, 'r', encoding='utf-8', errors='ignore') as f:
                        vuln_content = f.read()
                    with open(fixed_file, 'r', encoding='utf-8', errors='ignore') as f:
                        fixed_content = f.read()
                    
                    if vuln_content != fixed_content:
                        differences_found = True
                        # Analyze vulnerability patterns in vulnerable version
                        patterns = self.analyze_vulnerability_patterns(vuln_file)
                        for vuln_type, count in patterns.items():
                            if vuln_type != 'total':
                                pattern_analysis[vuln_type] += count
                        total_vulnerability_patterns += patterns.get('total', 0)
                        
                except Exception as e:
                    logger.debug(f"Error comparing files: {e}")
        
        return {
            'has_differences': differences_found,
            'vulnerable_files': len(vulnerable_files),
            'fixed_files': len(fixed_files),
            'vulnerability_patterns': total_vulnerability_patterns,
            'pattern_breakdown': dict(pattern_analysis),
            'reason': 'Code differences found' if differences_found else 'No code differences'
        }
    
    def analyze_cve(self, cve_id: str) -> Dict:
        """Analyze a single CVE comprehensively"""
        cve_dir = os.path.join(self.dataset_dir, cve_id)
        
        if not os.path.exists(cve_dir):
            return {'status': 'failed', 'reason': 'Directory not found'}
        
        # Check metadata
        metadata_file = os.path.join(cve_dir, "metadata.json")
        metadata = {}
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except Exception as e:
                logger.debug(f"Error reading metadata for {cve_id}: {e}")
        
        # Check code differences and vulnerability patterns
        diff_check = self.check_code_differences(cve_dir)
        
        # Calculate weaponization score
        weaponization_score = self._calculate_weaponization_score(metadata, diff_check)
        
        # Determine criticality
        is_critical = weaponization_score >= 7.0
        is_weaponizable = weaponization_score >= 5.0
        
        return {
            'cve_id': cve_id,
            'status': 'passed' if diff_check['has_differences'] else 'failed',
            'reason': diff_check['reason'],
            'weaponization_score': weaponization_score,
            'is_critical': is_critical,
            'is_weaponizable': is_weaponizable,
            'metadata': metadata,
            'diff_check': diff_check,
            'project': metadata.get('project', 'Unknown'),
            'cwe_id': metadata.get('cwe_id', 'Unknown'),
            'cwe_name': metadata.get('cwe_name', 'Unknown')
        }
    
    def _calculate_weaponization_score(self, metadata: Dict, diff_check: Dict) -> float:
        """Calculate comprehensive weaponization score"""
        score = 0.0
        
        # Base score from vulnerability patterns
        if diff_check['vulnerability_patterns'] > 0:
            score += min(diff_check['vulnerability_patterns'] * 0.5, 5.0)  # Max 5 points
        
        # Pattern type scoring
        pattern_breakdown = diff_check.get('pattern_breakdown', {})
        if 'buffer_overflow' in pattern_breakdown:
            score += 3.0  # High weaponizability
        if 'use_after_free' in pattern_breakdown:
            score += 3.0  # High weaponizability
        if 'integer_overflow' in pattern_breakdown:
            score += 2.0  # Medium weaponizability
        if 'format_string' in pattern_breakdown:
            score += 2.5  # High weaponizability
        if 'command_injection' in pattern_breakdown:
            score += 4.0  # Very high weaponizability
        if 'sql_injection' in pattern_breakdown:
            score += 2.0  # Medium weaponizability
        
        # Project priority bonus
        project = metadata.get('project', '').lower()
        if project in self.high_priority_projects:
            score += 2.0
        
        # CWE-based scoring
        cwe_id = metadata.get('cwe_id', '')
        if cwe_id in ['CWE-119', 'CWE-787', 'CWE-78', 'CWE-89', 'CWE-502']:
            score += 2.0  # Memory corruption, RCE
        elif cwe_id in ['CWE-125', 'CWE-190', 'CWE-191', 'CWE-415', 'CWE-416']:
            score += 1.5  # Memory issues, integer problems
        
        # Metadata weaponization score
        if metadata.get('weaponization_score', 0) > 0:
            score += min(metadata['weaponization_score'] * 0.5, 3.0)
        
        return min(score, 10.0)
    
    def analyze_all_cves(self):
        """Analyze all CVEs in the dataset"""
        logger.info(f"🔍 Starting comprehensive analysis of dataset: {self.dataset_dir}")
        
        if not os.path.exists(self.dataset_dir):
            logger.error(f"Dataset directory {self.dataset_dir} not found!")
            return
        
        # Get all CVE directories
        cve_dirs = [item for item in os.listdir(self.dataset_dir) 
                   if item.startswith("CVE-") and os.path.isdir(os.path.join(self.dataset_dir, item))]
        
        logger.info(f"📊 Found {len(cve_dirs)} CVE directories to analyze")
        
        # Analyze each CVE
        for cve_id in cve_dirs:
            logger.info(f"📋 Analyzing {cve_id}...")
            analysis = self.analyze_cve(cve_id)
            
            if analysis['status'] == 'passed':
                self.all_cves.append(analysis)
                
                if analysis['is_critical']:
                    self.critical_cves.append(analysis)
                    logger.info(f"🚨 {cve_id} - CRITICAL (Score: {analysis['weaponization_score']:.1f}/10.0)")
                
                if analysis['is_weaponizable']:
                    self.weaponizable_cves.append(analysis)
                    logger.info(f"⚠️  {cve_id} - Weaponizable (Score: {analysis['weaponization_score']:.1f}/10.0)")
            else:
                logger.info(f"❌ {cve_id} - Failed: {analysis['reason']}")
        
        # Sort by weaponization score
        self.critical_cves.sort(key=lambda x: x['weaponization_score'], reverse=True)
        self.weaponizable_cves.sort(key=lambda x: x['weaponization_score'], reverse=True)
        
        logger.info(f"✅ Analysis complete!")
        logger.info(f"📊 Total CVEs analyzed: {len(self.all_cves)}")
        logger.info(f"🚨 Critical CVEs found: {len(self.critical_cves)}")
        logger.info(f"⚠️  Weaponizable CVEs found: {len(self.weaponizable_cves)}")
    
    def generate_comprehensive_report(self, output_file: str = "comprehensive_cve_analysis.json"):
        """Generate a comprehensive analysis report"""
        report = {
            'summary': {
                'total_cves_analyzed': len(self.all_cves),
                'critical_cves_found': len(self.critical_cves),
                'weaponizable_cves_found': len(self.weaponizable_cves),
                'target_count': 50,
                'success_rate': f"{(len(self.critical_cves) / 50) * 100:.1f}%"
            },
            'critical_cves': self.critical_cves,
            'weaponizable_cves': self.weaponizable_cves,
            'all_cves': self.all_cves
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📋 Comprehensive report saved to {output_file}")
        return report
    
    def print_comprehensive_summary(self):
        """Print a comprehensive summary of the analysis"""
        print("\n" + "="*80)
        print("🚨 COMPREHENSIVE CVE ANALYSIS RESULTS")
        print("="*80)
        print(f"📊 Total CVEs analyzed: {len(self.all_cves)}")
        print(f"🚨 Critical CVEs found: {len(self.critical_cves)}")
        print(f"⚠️  Weaponizable CVEs found: {len(self.weaponizable_cves)}")
        print(f"📈 Success rate: {(len(self.critical_cves) / 50) * 100:.1f}%")
        
        if self.critical_cves:
            print(f"\n🔥 Top 15 Most Critical CVEs:")
            for i, cve in enumerate(self.critical_cves[:15], 1):
                project = cve.get('project', 'Unknown')
                weapon_score = cve['weaponization_score']
                vuln_patterns = cve['diff_check']['vulnerability_patterns']
                pattern_breakdown = cve['diff_check'].get('pattern_breakdown', {})
                
                print(f"{i:2d}. {cve['cve_id']} - {project}")
                print(f"    🎯 Weaponization Score: {weapon_score:.1f}/10.0")
                print(f"    📋 Total Patterns: {vuln_patterns}")
                if pattern_breakdown:
                    print(f"    🚨 Pattern Types: {dict(pattern_breakdown)}")
                print()
        
        # Pattern analysis
        if self.critical_cves:
            print(f"\n📊 Vulnerability Pattern Distribution:")
            pattern_totals = defaultdict(int)
            for cve in self.critical_cves:
                for pattern_type, count in cve['diff_check'].get('pattern_breakdown', {}).items():
                    pattern_totals[pattern_type] += count
            
            for pattern_type, count in sorted(pattern_totals.items(), key=lambda x: x[1], reverse=True):
                print(f"  {pattern_type}: {count} instances")
        
        print(f"\n🎯 Next Steps:")
        if len(self.critical_cves) >= 50:
            print(f"🎉 SUCCESS! We found {len(self.critical_cves)} critical CVEs!")
            print("Ready to move to LLM-guided variant generation!")
        else:
            print(f"📈 We found {len(self.critical_cves)} critical CVEs")
            print(f"📊 Need {50 - len(self.critical_cves)} more to reach our target")
            print("💡 Consider LLM-guided variant generation to create variants")

def main():
    """Main function"""
    analyzer = ComprehensiveCVEAnalyzer()
    
    # Run comprehensive analysis
    analyzer.analyze_all_cves()
    
    # Generate report
    report = analyzer.generate_comprehensive_report()
    
    # Print summary
    analyzer.print_comprehensive_summary()
    
    print(f"\n💡 Comprehensive Analysis Complete!")
    print(f"📊 Critical CVEs: {len(analyzer.critical_cves)}")
    print(f"📋 Detailed report saved to: comprehensive_cve_analysis.json")

if __name__ == "__main__":
    main()
