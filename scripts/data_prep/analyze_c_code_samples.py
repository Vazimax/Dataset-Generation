#!/usr/bin/env python3
"""
C Code Samples Analyzer
Analyzes the c-code-samples-selection.json file to find the most critical, weaponizable CVEs.
"""

import json
import re
import logging
from typing import List, Dict, Set
from collections import defaultdict, Counter

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CCodeSamplesAnalyzer:
    def __init__(self, samples_file: str = "c-code-samples-selection.json"):
        self.samples_file = samples_file
        self.samples = []
        self.critical_cves = []
        self.weaponizable_cves = []
        
        # Critical CWE categories (high weaponizability)
        self.critical_cwes = {
            'CWE-119': 'Buffer Overflow',      # Memory corruption - HIGH
            'CWE-125': 'Out-of-bounds Read',   # Information disclosure - HIGH
            'CWE-787': 'Out-of-bounds Write',  # Memory corruption - HIGH
            'CWE-190': 'Integer Overflow',     # Memory corruption - HIGH
            'CWE-191': 'Integer Underflow',    # Memory corruption - HIGH
            'CWE-476': 'NULL Pointer Dereference', # Crash/DoS - HIGH
            'CWE-415': 'Double Free',          # Memory corruption - HIGH
            'CWE-416': 'Use After Free',       # Memory corruption - HIGH
            'CWE-78': 'OS Command Injection',  # Remote code execution - VERY HIGH
            'CWE-89': 'SQL Injection',         # Data manipulation - HIGH
            'CWE-20': 'Improper Input Validation', # Various attacks - MEDIUM
            'CWE-22': 'Path Traversal',        # File access - HIGH
            'CWE-287': 'Improper Authentication', # Access control - MEDIUM
            'CWE-434': 'Unrestricted Upload',  # Malicious file upload - HIGH
            'CWE-502': 'Deserialization',      # Remote code execution - VERY HIGH
            'CWE-74': 'Command Injection',     # Remote code execution - VERY HIGH
            'CWE-617': 'Reachable Assertion',  # Crash/DoS - MEDIUM
            'CWE-674': 'Uncontrolled Recursion', # Crash/DoS - HIGH
            'CWE-772': 'Missing Release of Memory', # Memory leak - MEDIUM
            'CWE-000': 'Unknown/Uncategorized', # Potentially dangerous - MEDIUM
        }
        
        # High-priority projects (critical infrastructure)
        self.high_priority_projects = {
            'openssl', 'sqlite', 'curl', 'zlib', 'libpng', 'libjpeg',
            'linux', 'ffmpeg', 'imagemagick', 'wireshark', 'tcpdump',
            'nginx', 'apache', 'mysql', 'postgresql', 'redis',
            'python', 'php', 'java', 'nodejs', 'golang', 'kernel',
            'libvpx', 'krb5', 'neomutt', 'tor', 'ndpi', 'radare',
            'libmspack', 'libvips', 'jasper', 'mujs'
        }
        
        # Critical vulnerability patterns in C code
        self.critical_patterns = {
            'buffer_overflow': [
                r'\bstrcpy\s*\(', r'\bstrcat\s*\(', r'\bsprintf\s*\(',
                r'\bgets\s*\(', r'\bstrncpy\s*\(', r'\bstrncat\s*\(',
                r'\bmemcpy\s*\(', r'\bmemmove\s*\(', r'\bmemset\s*\(',
                r'\bfread\s*\(', r'\bfwrite\s*\(', r'\bfgets\s*\(',
                r'\bvpx_memset\s*\(', r'\bvpx_memcpy\s*\('
            ],
            'use_after_free': [
                r'\bfree\s*\(', r'\bmalloc\s*\(', r'\bcalloc\s*\(',
                r'\brealloc\s*\(', r'\bdelete\s*', r'\bnew\s*',
                r'\bkfree\s*\(', r'\bvfree\s*\('
            ],
            'integer_overflow': [
                r'\+\+|--|\+=|\-=|\*=|/=', r'\bint\s+\w+\s*[+\-*/]\s*\w+',
                r'\blong\s+\w+\s*[+\-*/]\s*\w+', r'\bsize_t\s+\w+\s*[+\-*/]\s*\w+',
                r'\buint\d+\s+\w+\s*[+\-*/]\s*\w+'
            ],
            'format_string': [
                r'\bprintf\s*\(', r'\bfprintf\s*\(', r'\bsprintf\s*\(',
                r'\bsnprintf\s*\(', r'\bvsprintf\s*\(', r'\bvsnprintf\s*\('
            ],
            'null_pointer': [
                r'->\s*\w+', r'\*\w+\s*=', r'\bif\s*\(\s*!\s*\w+\s*\)',
                r'\bif\s*\(\s*\w+\s*==\s*NULL\s*\)', r'\bif\s*\(\s*!\s*\w+\s*\)'
            ],
            'command_injection': [
                r'\bsystem\s*\(', r'\bexec\s*\(', r'\bpopen\s*\(',
                r'\bexecl\s*\(', r'\bexeclp\s*\(', r'\bexecle\s*\('
            ],
            'sql_injection': [
                r'\bSELECT\b', r'\bINSERT\b', r'\bUPDATE\b', r'\bDELETE\b',
                r'\bCREATE\b', r'\bDROP\b', r'\bALTER\b'
            ],
            'memory_leak': [
                r'\bmalloc\s*\(', r'\bcalloc\s*\(', r'\brealloc\s*\(',
                r'\bg_malloc\s*\(', r'\bvzalloc\s*\(', r'\bkmalloc\s*\('
            ]
        }
        
    def load_samples(self):
        """Load the C code samples"""
        try:
            with open(self.samples_file, 'r') as f:
                self.samples = json.load(f)
            logger.info(f"📊 Loaded {len(self.samples)} C code samples")
        except Exception as e:
            logger.error(f"Failed to load samples: {e}")
            return False
        return True
    
    def analyze_vulnerability_patterns(self, source_code: str) -> Dict:
        """Analyze source code for vulnerability patterns"""
        pattern_counts = {}
        total_patterns = 0
        
        for vuln_type, patterns in self.critical_patterns.items():
            count = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, source_code, re.IGNORECASE))
                count += matches
                total_patterns += matches
            
            if count > 0:
                pattern_counts[vuln_type] = count
        
        pattern_counts['total'] = total_patterns
        return pattern_counts
    
    def check_code_differences(self, source: str, target: str) -> bool:
        """Check if vulnerable and fixed code are actually different"""
        # Clean up the code for comparison
        source_clean = re.sub(r'\s+', ' ', source.strip())
        target_clean = re.sub(r'\s+', ' ', target.strip())
        
        return source_clean != target_clean
    
    def extract_project_name(self, project_commit: str) -> str:
        """Extract project name from project_and_commit_id"""
        if '@' in project_commit:
            return project_commit.split('@')[0]
        return project_commit
    
    def analyze_sample(self, sample: Dict) -> Dict:
        """Analyze a single C code sample"""
        cve_id = sample.get('cve_id', '')
        cwe_id = sample.get('cwe_id', '')
        source_code = sample.get('source', '')
        target_code = sample.get('target', '')
        project_commit = sample.get('project_and_commit_id', '')
        
        if not cve_id or not cwe_id or not source_code or not target_code:
            return {}
        
        # Extract project name
        project_name = self.extract_project_name(project_commit)
        
        # Check if code is actually different
        has_differences = self.check_code_differences(source_code, target_code)
        if not has_differences:
            return {}
        
        # Analyze vulnerability patterns in source code
        vulnerability_patterns = self.analyze_vulnerability_patterns(source_code)
        
        # Calculate weaponization score
        weaponization_score = self._calculate_weaponization_score(
            cwe_id, project_name, vulnerability_patterns
        )
        
        # Determine criticality
        is_critical = weaponization_score >= 7.0
        is_weaponizable = weaponization_score >= 5.0
        
        return {
            'cve_id': cve_id,
            'cwe_id': cwe_id,
            'cwe_name': self.critical_cwes.get(cwe_id, 'Unknown'),
            'project': project_name,
            'weaponization_score': weaponization_score,
            'is_critical': is_critical,
            'is_weaponizable': is_weaponizable,
            'vulnerability_patterns': vulnerability_patterns,
            'source_code_length': len(source_code),
            'target_code_length': len(target_code),
            'has_differences': has_differences,
            'is_high_priority_project': project_name.lower() in self.high_priority_projects,
            'original_address': sample.get('original_address', ''),
            'time': sample.get('time', '')
        }
    
    def _calculate_weaponization_score(self, cwe_id: str, project: str, patterns: Dict) -> float:
        """Calculate weaponization score based on CWE, project, and patterns"""
        score = 0.0
        
        # Base score from CWE criticality
        if cwe_id in self.critical_cwes:
            if cwe_id in ['CWE-78', 'CWE-74', 'CWE-502']:
                score += 5.0  # Command injection, RCE (VERY HIGH)
            elif cwe_id in ['CWE-119', 'CWE-787', 'CWE-89']:
                score += 4.0  # Memory corruption, SQL injection (HIGH)
            elif cwe_id in ['CWE-125', 'CWE-190', 'CWE-191', 'CWE-415', 'CWE-416']:
                score += 3.5  # Memory issues, integer problems (HIGH)
            elif cwe_id in ['CWE-476', 'CWE-434', 'CWE-674']:
                score += 3.0  # Crashes, recursion, access control (HIGH)
            elif cwe_id in ['CWE-287', 'CWE-772', 'CWE-617']:
                score += 2.0  # Authentication, memory leak, assertion (MEDIUM)
            else:
                score += 1.5  # Other vulnerabilities
        
        # Project priority bonus
        if project.lower() in self.high_priority_projects:
            score += 2.0
        
        # Pattern-based scoring
        total_patterns = patterns.get('total', 0)
        if total_patterns > 0:
            score += min(total_patterns * 0.3, 3.0)  # Max 3 points
        
        # Specific pattern bonuses
        if 'buffer_overflow' in patterns:
            score += 1.5  # High weaponizability
        if 'use_after_free' in patterns:
            score += 1.5  # High weaponizability
        if 'command_injection' in patterns:
            score += 2.0  # Very high weaponizability
        if 'sql_injection' in patterns:
            score += 1.0  # High weaponizability
        
        # CWE-000 indicates unknown/uncategorized (potentially dangerous)
        if cwe_id == 'CWE-000':
            score += 1.0
        
        return min(score, 10.0)
    
    def analyze_all_samples(self):
        """Analyze all C code samples"""
        logger.info("🔍 Analyzing all C code samples...")
        
        for i, sample in enumerate(self.samples):
            if i % 100 == 0:
                logger.info(f"📋 Progress: {i}/{len(self.samples)} samples analyzed")
            
            analysis = self.analyze_sample(sample)
            if analysis:
                if analysis['is_critical']:
                    self.critical_cves.append(analysis)
                    logger.info(f"🚨 {analysis['cve_id']} - CRITICAL (Score: {analysis['weaponization_score']:.1f}/10.0)")
                
                if analysis['is_weaponizable']:
                    self.weaponizable_cves.append(analysis)
        
        # Sort by weaponization score
        self.critical_cves.sort(key=lambda x: x['weaponization_score'], reverse=True)
        self.weaponizable_cves.sort(key=lambda x: x['weaponization_score'], reverse=True)
        
        logger.info(f"✅ Analysis complete!")
        logger.info(f"📊 Total samples analyzed: {len(self.samples)}")
        logger.info(f"🚨 Critical CVEs found: {len(self.critical_cves)}")
        logger.info(f"⚠️  Weaponizable CVEs found: {len(self.weaponizable_cves)}")
    
    def get_critical_cves(self, min_score: float = 7.0, max_count: int = 50) -> List[Dict]:
        """Get the most critical CVEs based on weaponization score"""
        critical_cves = [
            cve for cve in self.critical_cves 
            if cve['weaponization_score'] >= min_score
        ]
        
        # Sort by weaponization score (descending)
        critical_cves.sort(key=lambda x: x['weaponization_score'], reverse=True)
        
        # Limit to requested count
        return critical_cves[:max_count]
    
    def get_cwe_statistics(self) -> Dict:
        """Get statistics about CWE distribution"""
        cwe_counts = Counter(cve['cwe_id'] for cve in self.critical_cves)
        return dict(cwe_counts.most_common())
    
    def get_project_statistics(self) -> Dict:
        """Get statistics about project distribution"""
        project_counts = Counter(cve['project'] for cve in self.critical_cves)
        return dict(project_counts.most_common())
    
    def generate_report(self, output_file: str = "c_code_samples_analysis.json"):
        """Generate a comprehensive report of critical CVEs"""
        critical_cves = self.get_critical_cves()
        
        report = {
            'summary': {
                'total_samples_analyzed': len(self.samples),
                'critical_cves_found': len(self.critical_cves),
                'weaponizable_cves_found': len(self.weaponizable_cves),
                'top_critical_cves': len(critical_cves),
                'target_count': 50,
                'success_rate': f"{(len(critical_cves) / 50) * 100:.1f}%"
            },
            'cwe_distribution': self.get_cwe_statistics(),
            'project_distribution': self.get_project_statistics(),
            'top_critical_cves': critical_cves,
            'all_critical_cves': self.critical_cves
        }
        
        # Save report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📋 Report saved to {output_file}")
        return report
    
    def print_summary(self):
        """Print a summary of the analysis"""
        critical_cves = self.get_critical_cves()
        
        print("\n" + "="*80)
        print("🚨 C CODE SAMPLES ANALYSIS RESULTS")
        print("="*80)
        print(f"📊 Total samples analyzed: {len(self.samples)}")
        print(f"🚨 Critical CVEs found: {len(self.critical_cves)}")
        print(f"⚠️  Weaponizable CVEs found: {len(self.weaponizable_cves)}")
        print(f"🎯 Top critical CVEs: {len(critical_cves)}")
        print(f"📈 Success rate: {(len(critical_cves) / 50) * 100:.1f}%")
        
        if critical_cves:
            print(f"\n🔥 Top 20 Most Critical CVEs:")
            for i, cve in enumerate(critical_cves[:20], 1):
                priority_icon = "🚨" if cve['weaponization_score'] >= 8.0 else "⚠️"
                project_icon = "🔥" if cve['is_high_priority_project'] else "⚪"
                print(f"{i:2d}. {priority_icon} {cve['cve_id']} - {cve['cwe_name']}")
                print(f"    {project_icon} Project: {cve['project']}")
                print(f"    🎯 Score: {cve['weaponization_score']:.1f}/10.0")
                print(f"    📋 Patterns: {cve['vulnerability_patterns'].get('total', 0)}")
                print()
        
        print(f"\n📋 CWE Distribution (Top 10):")
        cwe_stats = self.get_cwe_statistics()
        for i, (cwe, count) in enumerate(list(cwe_stats.items())[:10], 1):
            cwe_name = self.critical_cwes.get(cwe, 'Unknown')
            print(f"{i:2d}. {cwe} - {cwe_name}: {count} CVEs")
        
        print(f"\n🏗️  Project Distribution (Top 10):")
        project_stats = self.get_project_statistics()
        for i, (project, count) in enumerate(list(project_stats.items())[:10], 1):
            priority = "🔥 HIGH" if project.lower() in self.high_priority_projects else "⚪ Normal"
            print(f"{i:2d}. {project}: {count} CVEs {priority}")
        
        print(f"\n🎯 Next Steps:")
        if len(critical_cves) >= 50:
            print(f"🎉 SUCCESS! We found {len(critical_cves)} critical CVEs!")
            print("This dataset is perfect for our weaponizable CVE collection!")
        else:
            print(f"📈 We found {len(critical_cves)} critical CVEs")
            print(f"📊 Need {50 - len(critical_cves)} more to reach our target")

def main():
    """Main function"""
    analyzer = CCodeSamplesAnalyzer()
    
    # Load and analyze samples
    if not analyzer.load_samples():
        return
    
    analyzer.analyze_all_samples()
    
    # Generate report
    report = analyzer.generate_report()
    
    # Print summary
    analyzer.print_summary()
    
    print(f"\n💡 C Code Samples Analysis Complete!")
    print(f"📊 Critical CVEs: {len(analyzer.critical_cves)}")
    print(f"📋 Detailed report saved to: c_code_samples_analysis.json")

if __name__ == "__main__":
    main()
