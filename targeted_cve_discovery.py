#!/usr/bin/env python3
"""
Targeted CVE Discovery Script

This script focuses on discovering high-quality CVEs from specific high-priority projects
that are most likely to yield weaponizable vulnerabilities.
"""

import os
import json
import requests
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TargetedCVEDiscovery:
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.cve_details_base = "https://cve.circl.lu/api/cve"
        
        # High-priority projects with known high-quality CVEs
        self.target_projects = {
            'openssl': {
                'keywords': ['openssl', 'ssl', 'tls', 'crypto'],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'use after free', 'cryptographic weakness'],
                'min_cvss': 7.0,
                'priority': 'critical'
            },
            'libpng': {
                'keywords': ['libpng', 'png', 'image'],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'use after free'],
                'min_cvss': 7.0,
                'priority': 'high'
            },
            'zlib': {
                'keywords': ['zlib', 'compression', 'deflate'],
                'vulnerability_types': ['buffer overflow', 'integer overflow'],
                'min_cvss': 7.0,
                'priority': 'high'
            },
            'curl': {
                'keywords': ['curl', 'libcurl', 'http', 'ftp'],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'use after free'],
                'min_cvss': 7.0,
                'priority': 'high'
            },
            'log4j': {
                'keywords': ['log4j', 'logging', 'apache'],
                'vulnerability_types': ['deserialization', 'injection', 'remote code execution'],
                'min_cvss': 7.0,
                'priority': 'critical'
            },
            'libxml2': {
                'keywords': ['libxml2', 'xml', 'parsing'],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'use after free'],
                'min_cvss': 7.0,
                'priority': 'high'
            },
            'sqlite': {
                'keywords': ['sqlite', 'database'],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'sql injection'],
                'min_cvss': 7.0,
                'priority': 'high'
            },
            'ffmpeg': {
                'keywords': ['ffmpeg', 'media', 'video', 'audio'],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'use after free'],
                'min_cvss': 7.0,
                'priority': 'high'
            }
        }
        
        # Known high-quality CVE patterns
        self.vulnerability_patterns = {
            'buffer_overflow': {
                'keywords': ['buffer overflow', 'stack overflow', 'heap overflow', 'out of bounds', 'boundary'],
                'cwe': ['CWE-119', 'CWE-120', 'CWE-122', 'CWE-124', 'CWE-125', 'CWE-131'],
                'severity': 'critical'
            },
            'integer_overflow': {
                'keywords': ['integer overflow', 'integer underflow', 'arithmetic overflow', 'size_t overflow'],
                'cwe': ['CWE-190', 'CWE-191'],
                'severity': 'high'
            },
            'use_after_free': {
                'keywords': ['use after free', 'use-after-free', 'dangling pointer', 'double free'],
                'cwe': ['CWE-416', 'CWE-415', 'CWE-825'],
                'severity': 'critical'
            },
            'format_string': {
                'keywords': ['format string', 'printf', 'sprintf', 'format string vulnerability'],
                'cwe': ['CWE-134'],
                'severity': 'high'
            },
            'cryptographic_weakness': {
                'keywords': ['cryptographic', 'crypto', 'encryption', 'hash', 'random', 'entropy'],
                'cwe': ['CWE-327', 'CWE-328', 'CWE-329', 'CWE-330', 'CWE-331'],
                'severity': 'high'
            },
            'deserialization': {
                'keywords': ['deserialization', 'unmarshal', 'unpickle', 'gadget chain'],
                'cwe': ['CWE-502'],
                'severity': 'critical'
            }
        }
    
    def query_nvd_api(self, query: str, start_index: int = 0, results_per_page: int = 20) -> Optional[Dict]:
        """Query NVD API with rate limiting"""
        try:
            params = {
                'keywordSearch': query,
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            
            response = requests.get(self.nvd_api_base, params=params, timeout=30)
            response.raise_for_status()
            
            # Rate limiting - NVD allows 5 requests per minute
            time.sleep(12)  # Wait 12 seconds between requests
            
            return response.json()
        except Exception as e:
            logger.error(f"Failed to query NVD API: {e}")
            return None
    
    def search_project_cves(self, project: str, project_config: Dict) -> List[Dict]:
        """Search for CVEs related to a specific project"""
        logger.info(f"Searching for CVEs in project: {project}")
        
        cves = []
        
        # Search using project keywords
        for keyword in project_config['keywords']:
            logger.info(f"Searching with keyword: {keyword}")
            
            start_index = 0
            while True:
                result = self.query_nvd_api(keyword, start_index)
                if not result:
                    break
                
                vulnerabilities = result.get('vulnerabilities', [])
                if not vulnerabilities:
                    break
                
                for vuln in vulnerabilities:
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id')
                    
                    # Check CVSS score
                    metrics = cve.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] or metrics.get('cvssMetricV30', [{}])[0]
                    
                    if cvss_v3:
                        cvss_score = cvss_v3.get('cvssData', {}).get('baseScore', 0)
                        if cvss_score >= project_config['min_cvss']:
                            # Check if it matches vulnerability types
                            description = cve.get('descriptions', [{}])[0].get('value', '').lower()
                            matches_vuln_type = any(
                                vuln_type in description 
                                for vuln_type in project_config['vulnerability_types']
                            )
                            
                            if matches_vuln_type:
                                cve_info = {
                                    'cve_id': cve_id,
                                    'project': project,
                                    'description': cve.get('descriptions', [{}])[0].get('value', ''),
                                    'cvss_score': cvss_score,
                                    'severity': cvss_v3.get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                                    'search_keyword': keyword,
                                    'published_date': cve.get('published', ''),
                                    'last_modified': cve.get('lastModified', ''),
                                    'priority': project_config['priority']
                                }
                                cves.append(cve_info)
                
                start_index += len(vulnerabilities)
                if len(vulnerabilities) < 20:  # Last page
                    break
        
        return cves
    
    def search_vulnerability_patterns(self, pattern_name: str, pattern_config: Dict) -> List[Dict]:
        """Search for CVEs matching specific vulnerability patterns"""
        logger.info(f"Searching for vulnerability pattern: {pattern_name}")
        
        cves = []
        
        for keyword in pattern_config['keywords']:
            logger.info(f"Searching with pattern keyword: {keyword}")
            
            start_index = 0
            while True:
                result = self.query_nvd_api(keyword, start_index)
                if not result:
                    break
                
                vulnerabilities = result.get('vulnerabilities', [])
                if not vulnerabilities:
                    break
                
                for vuln in vulnerabilities:
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id')
                    
                    # Check CVSS score (higher threshold for pattern search)
                    metrics = cve.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] or metrics.get('cvssMetricV30', [{}])[0]
                    
                    if cvss_v3:
                        cvss_score = cvss_v3.get('cvssData', {}).get('baseScore', 0)
                        if cvss_score >= 8.0:  # Higher threshold for pattern search
                            cve_info = {
                                'cve_id': cve_id,
                                'vulnerability_pattern': pattern_name,
                                'description': cve.get('descriptions', [{}])[0].get('value', ''),
                                'cvss_score': cvss_score,
                                'severity': cvss_v3.get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                                'search_keyword': keyword,
                                'published_date': cve.get('published', ''),
                                'last_modified': cve.get('lastModified', ''),
                                'cwe': pattern_config['cwe'],
                                'pattern_severity': pattern_config['severity']
                            }
                            cves.append(cve_info)
                
                start_index += len(vulnerabilities)
                if len(vulnerabilities) < 20:  # Last page
                    break
        
        return cves
    
    def discover_high_quality_cves(self, max_cves_per_project: int = 10) -> Dict[str, List[Dict]]:
        """Discover high-quality CVEs from target projects and patterns"""
        logger.info("Starting targeted CVE discovery...")
        
        discovered_cves = {
            'project_cves': {},
            'pattern_cves': {},
            'summary': {
                'total_discovered': 0,
                'by_project': {},
                'by_pattern': {},
                'discovery_date': datetime.now().isoformat()
            }
        }
        
        # Search by project
        for project, config in self.target_projects.items():
            logger.info(f"Discovering CVEs for project: {project}")
            project_cves = self.search_project_cves(project, config)
            
            # Sort by CVSS score and limit results
            project_cves.sort(key=lambda x: x['cvss_score'], reverse=True)
            project_cves = project_cves[:max_cves_per_project]
            
            discovered_cves['project_cves'][project] = project_cves
            discovered_cves['summary']['by_project'][project] = len(project_cves)
            
            logger.info(f"Discovered {len(project_cves)} CVEs for {project}")
        
        # Search by vulnerability patterns
        for pattern_name, pattern_config in self.vulnerability_patterns.items():
            logger.info(f"Discovering CVEs for pattern: {pattern_name}")
            pattern_cves = self.search_vulnerability_patterns(pattern_name, pattern_config)
            
            # Sort by CVSS score and limit results
            pattern_cves.sort(key=lambda x: x['cvss_score'], reverse=True)
            pattern_cves = pattern_cves[:max_cves_per_project]
            
            discovered_cves['pattern_cves'][pattern_name] = pattern_cves
            discovered_cves['summary']['by_pattern'][pattern_name] = len(pattern_cves)
            
            logger.info(f"Discovered {len(pattern_cves)} CVEs for pattern {pattern_name}")
        
        # Calculate totals
        total_project_cves = sum(len(cves) for cves in discovered_cves['project_cves'].values())
        total_pattern_cves = sum(len(cves) for cves in discovered_cves['pattern_cves'].values())
        discovered_cves['summary']['total_discovered'] = total_project_cves + total_pattern_cves
        
        logger.info(f"Discovery complete. Total CVEs: {discovered_cves['summary']['total_discovered']}")
        
        return discovered_cves
    
    def save_discovery_results(self, results: Dict, filename: str = None):
        """Save discovery results to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cve_discovery_results_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Discovery results saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save discovery results: {e}")
    
    def generate_discovery_report(self, results: Dict) -> str:
        """Generate a human-readable discovery report"""
        report = f"""# Targeted CVE Discovery Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- **Total CVEs Discovered**: {results['summary']['total_discovered']}
- **Projects Analyzed**: {len(results['summary']['by_project'])}
- **Vulnerability Patterns**: {len(results['summary']['by_pattern'])}

## CVEs by Project
"""
        
        for project, count in results['summary']['by_project'].items():
            report += f"- **{project}**: {count} CVEs\n"
        
        report += "\n## CVEs by Vulnerability Pattern\n"
        for pattern, count in results['summary']['by_pattern'].items():
            report += f"- **{pattern}**: {count} CVEs\n"
        
        report += "\n## Top CVEs by Project\n"
        for project, cves in results['project_cves'].items():
            if cves:
                report += f"\n### {project.upper()}\n"
                for cve in cves[:5]:  # Top 5
                    report += f"- **{cve['cve_id']}** (CVSS: {cve['cvss_score']}) - {cve['description'][:100]}...\n"
        
        report += "\n## Top CVEs by Pattern\n"
        for pattern, cves in results['pattern_cves'].items():
            if cves:
                report += f"\n### {pattern.replace('_', ' ').title()}\n"
                for cve in cves[:5]:  # Top 5
                    report += f"- **{cve['cve_id']}** (CVSS: {cve['cvss_score']}) - {cve['description'][:100]}...\n"
        
        report += f"""

## Next Steps
1. Review discovered CVEs for quality and relevance
2. Prioritize CVEs based on CVSS score and exploitability
3. Begin repository analysis for selected CVEs
4. Extract vulnerable and fixed code
5. Validate vulnerabilities through testing

## Notes
- Results are sorted by CVSS score (highest first)
- Focus on CVEs with CVSS 7.0+ for high-quality dataset
- Some CVEs may require manual review for relevance
"""
        
        return report
    
    def save_discovery_report(self, report: str, filename: str = None):
        """Save discovery report to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cve_discovery_report_{timestamp}.md"
        
        try:
            with open(filename, 'w') as f:
                f.write(report)
            logger.info(f"Discovery report saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save discovery report: {e}")

def main():
    """Main function"""
    discovery = TargetedCVEDiscovery()
    
    # Discover high-quality CVEs
    logger.info("Starting targeted CVE discovery...")
    results = discovery.discover_high_quality_cves(max_cves_per_project=15)
    
    # Save results
    discovery.save_discovery_results(results)
    
    # Generate and save report
    report = discovery.generate_discovery_report(results)
    discovery.save_discovery_report(report)
    
    logger.info("Discovery process complete!")

if __name__ == "__main__":
    main()
