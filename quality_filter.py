#!/usr/bin/env python3
"""
Quality Filter Script
Filters the dataset to keep only truly vulnerable, critical CVEs in C language.
"""

import os
import json
import re
import logging
from pathlib import Path
from typing import List, Dict, Set

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QualityFilter:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.quality_cves = []
        self.failed_cves = []
        
        # C language file extensions
        self.c_extensions = {'.c', '.h', '.cpp', '.cc', '.cxx', '.hpp'}
        
        # Critical vulnerability patterns in C
        self.critical_patterns = [
            r'\bstrcpy\s*\(', r'\bstrcat\s*\(', r'\bsprintf\s*\(',
            r'\bgets\s*\(', r'\bstrncpy\s*\(', r'\bstrncat\s*\(',
            r'\bmemcpy\s*\(', r'\bmemmove\s*\(', r'\bmemset\s*\(',
            r'\bfree\s*\(', r'\bmalloc\s*\(', r'\bcalloc\s*\(',
            r'\brealloc\s*\(', r'\bstrlen\s*\(', r'\bstrcmp\s*\(',
            r'\batoi\s*\(', r'\batol\s*\(', r'\batof\s*\(',
            r'\bscanf\s*\(', r'\bprintf\s*\(', r'\bfprintf\s*\(',
            r'\bsnprintf\s*\(', r'\bvsnprintf\s*\(', r'\bvsprintf\s*\('
        ]
        
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
                content = f.read(1024)  # Read first 1KB
                
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
                ]
                
                for pattern in c_indicators:
                    if re.search(pattern, content, re.IGNORECASE):
                        return True
                        
        except Exception as e:
            logger.debug(f"Error reading file {filepath}: {e}")
            
        return False
    
    def has_vulnerability_patterns(self, filepath: str) -> List[str]:
        """Check if a file contains critical vulnerability patterns"""
        if not os.path.exists(filepath):
            return []
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            patterns_found = []
            for pattern in self.critical_patterns:
                if re.search(pattern, content):
                    pattern_name = pattern.strip().replace(r'\b', '').replace(r'\s*', '')
                    patterns_found.append(pattern_name)
                    
            return patterns_found
            
        except Exception as e:
            logger.debug(f"Error reading file {filepath}: {e}")
            return []
    
    def check_code_differences(self, cve_dir: str) -> Dict:
        """Check if vulnerable and fixed code are actually different"""
        vulnerable_dir = os.path.join(cve_dir, "vulnerable")
        fixed_dir = os.path.join(cve_dir, "fixed")
        
        if not os.path.exists(vulnerable_dir) or not os.path.exists(fixed_dir):
            return {'has_differences': False, 'reason': 'Missing vulnerable or fixed directory'}
        
        # Get all files in both directories
        vulnerable_files = []
        fixed_files = []
        
        for root, dirs, files in os.walk(vulnerable_dir):
            for file in files:
                if self.is_c_language_file(os.path.join(root, file)):
                    vulnerable_files.append(os.path.join(root, file))
        
        for root, dirs, files in os.walk(fixed_dir):
            for file in files:
                if self.is_c_language_file(os.path.join(root, file)):
                    fixed_files.append(os.path.join(root, file))
        
        if not vulnerable_files or not fixed_files:
            return {'has_differences': False, 'reason': 'No C language files found'}
        
        # Check for actual differences
        differences_found = False
        total_vulnerability_patterns = 0
        
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
                        # Count vulnerability patterns in vulnerable version
                        patterns = self.has_vulnerability_patterns(vuln_file)
                        total_vulnerability_patterns += len(patterns)
                        
                except Exception as e:
                    logger.debug(f"Error comparing files: {e}")
        
        return {
            'has_differences': differences_found,
            'vulnerable_files': len(vulnerable_files),
            'fixed_files': len(fixed_files),
            'vulnerability_patterns': total_vulnerability_patterns,
            'reason': 'Code differences found' if differences_found else 'No code differences'
        }
    
    def check_cve_quality(self, cve_id: str) -> Dict:
        """Check the quality of a single CVE"""
        cve_dir = os.path.join(self.dataset_dir, cve_id)
        
        if not os.path.exists(cve_dir):
            return {'quality_score': 0, 'status': 'failed', 'reason': 'Directory not found'}
        
        # Check metadata
        metadata_file = os.path.join(cve_dir, "metadata.json")
        metadata = {}
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    metadata = json.load(f)
            except Exception as e:
                logger.debug(f"Error reading metadata for {cve_id}: {e}")
        
        # Check code differences
        diff_check = self.check_code_differences(cve_dir)
        
        # Calculate quality score
        quality_score = 0
        status = 'failed'
        reason = ''
        
        if diff_check['has_differences']:
            quality_score += 40  # Base score for having differences
            
            if diff_check['vulnerable_files'] > 0:
                quality_score += 20  # Has vulnerable files
                
            if diff_check['fixed_files'] > 0:
                quality_score += 20  # Has fixed files
                
            if diff_check['vulnerability_patterns'] > 0:
                quality_score += 20  # Has vulnerability patterns
                
            if metadata.get('weaponization_score', 0) >= 6.0:
                quality_score += 10  # High weaponization score
                
            if metadata.get('is_high_priority_project', False):
                quality_score += 10  # High priority project
                
            status = 'passed' if quality_score >= 60 else 'failed'
            reason = f"Quality score: {quality_score}/100"
        else:
            reason = diff_check['reason']
        
        return {
            'cve_id': cve_id,
            'quality_score': quality_score,
            'status': status,
            'reason': reason,
            'metadata': metadata,
            'diff_check': diff_check
        }
    
    def filter_dataset(self) -> Dict:
        """Filter the entire dataset for quality"""
        logger.info(f"🔍 Starting quality filter for dataset: {self.dataset_dir}")
        
        if not os.path.exists(self.dataset_dir):
            logger.error(f"Dataset directory {self.dataset_dir} not found!")
            return {}
        
        # Get all CVE directories
        cve_dirs = [item for item in os.listdir(self.dataset_dir) 
                   if item.startswith("CVE-") and os.path.isdir(os.path.join(self.dataset_dir, item))]
        
        logger.info(f"📊 Found {len(cve_dirs)} CVE directories to check")
        
        # Check quality of each CVE
        for cve_id in cve_dirs:
            logger.info(f"📋 Checking quality of {cve_id}...")
            quality_result = self.check_cve_quality(cve_id)
            
            if quality_result['status'] == 'passed':
                self.quality_cves.append(quality_result)
                logger.info(f"✅ {cve_id} PASSED quality check (Score: {quality_result['quality_score']}/100)")
            else:
                self.failed_cves.append(quality_result)
                logger.info(f"❌ {cve_id} FAILED quality check: {quality_result['reason']}")
        
        # Sort by quality score
        self.quality_cves.sort(key=lambda x: x['quality_score'], reverse=True)
        
        logger.info(f"✅ Quality filter complete!")
        logger.info(f"📊 Passed: {len(self.quality_cves)} CVEs")
        logger.info(f"❌ Failed: {len(self.failed_cves)} CVEs")
        
        return {
            'total_cves': len(cve_dirs),
            'passed': len(self.quality_cves),
            'failed': len(self.failed_cves),
            'success_rate': f"{(len(self.quality_cves) / len(cve_dirs)) * 100:.1f}%"
        }
    
    def generate_quality_report(self, output_file: str = "quality_filter_report.json"):
        """Generate a detailed quality report"""
        report = {
            'summary': {
                'total_cves_checked': len(self.quality_cves) + len(self.failed_cves),
                'passed_cves': len(self.quality_cves),
                'failed_cves': len(self.failed_cves),
                'success_rate': f"{(len(self.quality_cves) / (len(self.quality_cves) + len(self.failed_cves))) * 100:.1f}%"
            },
            'quality_cves': self.quality_cves,
            'failed_cves': self.failed_cves
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📋 Quality report saved to {output_file}")
        return report
    
    def print_summary(self):
        """Print a summary of the quality filter results"""
        print("\n" + "="*80)
        print("🎯 DATASET QUALITY FILTER RESULTS")
        print("="*80)
        print(f"📊 Total CVEs checked: {len(self.quality_cves) + len(self.failed_cves)}")
        print(f"✅ Passed quality check: {len(self.quality_cves)}")
        print(f"❌ Failed quality check: {len(self.failed_cves)}")
        print(f"📈 Success rate: {(len(self.quality_cves) / (len(self.quality_cves) + len(self.failed_cves))) * 100:.1f}%")
        
        if self.quality_cves:
            print(f"\n🔥 Top 10 High-Quality CVEs:")
            for i, cve in enumerate(self.quality_cves[:10], 1):
                project = cve['metadata'].get('project', 'Unknown')
                weapon_score = cve['metadata'].get('weaponization_score', 0.0)
                vuln_patterns = cve['diff_check']['vulnerability_patterns']
                print(f"{i:2d}. {cve['cve_id']} - {project}")
                print(f"    Quality Score: {cve['quality_score']}/100")
                print(f"    Weaponization: {weapon_score:.1f}/10.0")
                print(f"    Vulnerability Patterns: {vuln_patterns}")
                print()
        
        if self.failed_cves:
            print(f"\n❌ Failed CVEs (Top 10):")
            for i, cve in enumerate(self.failed_cves[:10], 1):
                print(f"{i:2d}. {cve['cve_id']}: {cve['reason']}")
        
        print(f"\n🎯 Next Steps:")
        if len(self.quality_cves) >= 50:
            print(f"🎉 SUCCESS! We have {len(self.quality_cves)} high-quality CVEs!")
            print("Ready to move to LLM-guided variant generation!")
        else:
            print(f"⚠️  We need {50 - len(self.quality_cves)} more high-quality CVEs")
            print("Consider improving extraction or finding additional sources")

def main():
    """Main function"""
    filter_tool = QualityFilter()
    
    # Run quality filter
    results = filter_tool.filter_dataset()
    
    # Generate report
    report = filter_tool.generate_quality_report()
    
    # Print summary
    filter_tool.print_summary()
    
    print(f"\n💡 Quality Filter Complete!")
    print(f"📊 Final high-quality dataset: {len(filter_tool.quality_cves)} CVEs")
    print(f"📋 Detailed report saved to: quality_filter_report.json")

if __name__ == "__main__":
    main()
