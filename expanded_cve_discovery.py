#!/usr/bin/env python3
"""
Expanded CVE Discovery Script

This script expands the discovery to more projects and vulnerability types
to reach our target of 50-100 high-quality CVEs.
"""

import os
import json
import requests
import time
from datetime import datetime
from typing import Dict, List, Optional
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ExpandedCVEDiscovery:
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Expanded target projects with more variety
        self.target_projects = {
            'openssl': {
                'keywords': [
                    'openssl buffer overflow',
                    'openssl integer overflow', 
                    'openssl use after free',
                    'openssl cryptographic weakness'
                ],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'use after free', 'cryptographic'],
                'min_cvss': 7.5,
                'priority': 'critical',
                'max_results': 8
            },
            'log4j': {
                'keywords': [
                    'log4j deserialization',
                    'log4j rce',
                    'log4j injection',
                    'log4j remote code execution'
                ],
                'vulnerability_types': ['deserialization', 'remote code execution', 'injection'],
                'min_cvss': 7.5,
                'priority': 'critical',
                'max_results': 8
            },
            'libpng': {
                'keywords': [
                    'libpng buffer overflow',
                    'libpng integer overflow',
                    'png buffer overflow',
                    'png integer overflow'
                ],
                'vulnerability_types': ['buffer overflow', 'integer overflow'],
                'min_cvss': 7.5,
                'priority': 'high',
                'max_results': 6
            },
            'zlib': {
                'keywords': [
                    'zlib buffer overflow',
                    'zlib integer overflow',
                    'zlib compression vulnerability'
                ],
                'vulnerability_types': ['buffer overflow', 'integer overflow'],
                'min_cvss': 7.5,
                'priority': 'high',
                'max_results': 6
            },
            'curl': {
                'keywords': [
                    'curl buffer overflow',
                    'curl integer overflow',
                    'libcurl vulnerability',
                    'curl use after free'
                ],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'use after free'],
                'min_cvss': 7.5,
                'priority': 'high',
                'max_results': 6
            },
            'libxml2': {
                'keywords': [
                    'libxml2 buffer overflow',
                    'libxml2 integer overflow',
                    'xml parsing vulnerability',
                    'libxml2 use after free'
                ],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'use after free'],
                'min_cvss': 7.5,
                'priority': 'high',
                'max_results': 6
            },
            'sqlite': {
                'keywords': [
                    'sqlite buffer overflow',
                    'sqlite integer overflow',
                    'sqlite injection',
                    'sqlite vulnerability'
                ],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'sql injection'],
                'min_cvss': 7.5,
                'priority': 'high',
                'max_results': 6
            },
            'ffmpeg': {
                'keywords': [
                    'ffmpeg buffer overflow',
                    'ffmpeg integer overflow',
                    'ffmpeg use after free',
                    'ffmpeg media vulnerability'
                ],
                'vulnerability_types': ['buffer overflow', 'integer overflow', 'use after free'],
                'min_cvss': 7.5,
                'priority': 'high',
                'max_results': 6
            }
        }
        
        # Expanded vulnerability patterns
        self.vulnerability_patterns = {
            'buffer_overflow': {
                'keywords': [
                    'buffer overflow cvss:7.5+',
                    'stack overflow cvss:7.5+',
                    'heap overflow cvss:7.5+',
                    'out of bounds cvss:7.5+'
                ],
                'cwe': ['CWE-119', 'CWE-120', 'CWE-122', 'CWE-124', 'CWE-125'],
                'severity': 'critical',
                'max_results': 12
            },
            'integer_overflow': {
                'keywords': [
                    'integer overflow cvss:7.5+',
                    'arithmetic overflow cvss:7.5+',
                    'size_t overflow cvss:7.5+',
                    'integer underflow cvss:7.5+'
                ],
                'cwe': ['CWE-190', 'CWE-191'],
                'severity': 'high',
                'max_results': 12
            },
            'use_after_free': {
                'keywords': [
                    'use after free cvss:7.5+',
                    'use-after-free cvss:7.5+',
                    'dangling pointer cvss:7.5+',
                    'double free cvss:7.5+'
                ],
                'cwe': ['CWE-416', 'CWE-415', 'CWE-825'],
                'severity': 'critical',
                'max_results': 10
            },
            'format_string': {
                'keywords': [
                    'format string cvss:7.5+',
                    'printf vulnerability cvss:7.5+',
                    'sprintf vulnerability cvss:7.5+'
                ],
                'cwe': ['CWE-134'],
                'severity': 'high',
                'max_results': 8
            },
            'deserialization': {
                'keywords': [
                    'deserialization cvss:7.5+',
                    'unmarshal vulnerability cvss:7.5+',
                    'gadget chain cvss:7.5+'
                ],
                'cwe': ['CWE-502'],
                'severity': 'critical',
                'max_results': 10
            }
        }
    
    def query_nvd_api(self, query: str, start_index: int = 0, results_per_page: int = 5) -> Optional[Dict]:
        """Query NVD API with rate limiting"""
        try:
            params = {
                'keywordSearch': query,
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            
            response = requests.get(self.nvd_api_base, params=params, timeout=30)
            response.raise_for_status()
            
            # Rate limiting - 10 requests per minute
            time.sleep(6)  # Wait 6 seconds between requests
            
            return response.json()
        except Exception as e:
            logger.error(f"Failed to query NVD API: {e}")
            return None
    
    def search_project_cves(self, project: str, project_config: Dict) -> List[Dict]:
        """Search for CVEs related to a specific project"""
        logger.info(f"Searching for CVEs in project: {project} (max: {project_config['max_results']})")
        
        cves = []
        
        for keyword in project_config['keywords']:
            logger.info(f"Searching with keyword: {keyword}")
            
            # Get first page of results
            result = self.query_nvd_api(keyword, 0, project_config['max_results'])
            if not result:
                continue
            
            vulnerabilities = result.get('vulnerabilities', [])
            
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
                                'priority': project_config['priority'],
                                'cwe': self._extract_cwe(cve)
                            }
                            cves.append(cve_info)
                            
                            # Stop if we have enough results
                            if len(cves) >= project_config['max_results']:
                                break
            
            # Stop if we have enough results
            if len(cves) >= project_config['max_results']:
                break
        
        logger.info(f"Found {len(cves)} CVEs for {project}")
        return cves[:project_config['max_results']]
    
    def search_vulnerability_patterns(self, pattern_name: str, pattern_config: Dict) -> List[Dict]:
        """Search for CVEs matching specific vulnerability patterns"""
        logger.info(f"Searching for vulnerability pattern: {pattern_name} (max: {pattern_config['max_results']})")
        
        cves = []
        
        for keyword in pattern_config['keywords']:
            logger.info(f"Searching with pattern keyword: {keyword}")
            
            # Get first page of results
            result = self.query_nvd_api(keyword, 0, pattern_config['max_results'])
            if not result:
                continue
            
            vulnerabilities = result.get('vulnerabilities', [])
            
            for vuln in vulnerabilities:
                cve = vuln.get('cve', {})
                cve_id = cve.get('id')
                
                # Check CVSS score
                metrics = cve.get('metrics', {})
                cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] or metrics.get('cvssMetricV30', [{}])[0]
                
                if cvss_v3:
                    cvss_score = cvss_v3.get('cvssData', {}).get('baseScore', 0)
                    if cvss_score >= 7.5:  # Minimum threshold
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
                        
                        # Stop if we have enough results
                        if len(cves) >= pattern_config['max_results']:
                            break
            
            # Stop if we have enough results
            if len(cves) >= pattern_config['max_results']:
                break
        
        logger.info(f"Found {len(cves)} CVEs for pattern {pattern_name}")
        return cves[:pattern_config['max_results']]
    
    def _extract_cwe(self, cve: Dict) -> List[str]:
        """Extract CWE identifiers from CVE"""
        cwes = []
        if 'weaknesses' in cve:
            for weakness in cve['weaknesses']:
                if 'description' in weakness:
                    for desc in weakness['description']:
                        if 'value' in desc and desc['value'].startswith('CWE-'):
                            cwes.append(desc['value'])
        return cwes
    
    def discover_expanded_cves(self) -> Dict[str, List[Dict]]:
        """Discover expanded set of high-quality CVEs"""
        logger.info("Starting expanded CVE discovery...")
        
        discovered_cves = {
            'project_cves': {},
            'pattern_cves': {},
            'summary': {
                'total_discovered': 0,
                'by_project': {},
                'by_pattern': {},
                'discovery_date': datetime.now().isoformat(),
                'discovery_mode': 'expanded'
            }
        }
        
        # Search by project
        logger.info("Searching by project...")
        for project, config in self.target_projects.items():
            logger.info(f"Discovering CVEs for project: {project}")
            project_cves = self.search_project_cves(project, config)
            
            discovered_cves['project_cves'][project] = project_cves
            discovered_cves['summary']['by_project'][project] = len(project_cves)
            
            logger.info(f"Discovered {len(project_cves)} CVEs for {project}")
        
        # Search by vulnerability patterns
        logger.info("Searching by vulnerability patterns...")
        for pattern_name, pattern_config in self.vulnerability_patterns.items():
            logger.info(f"Discovering CVEs for pattern: {pattern_name}")
            pattern_cves = self.search_vulnerability_patterns(pattern_name, pattern_config)
            
            discovered_cves['pattern_cves'][pattern_name] = pattern_cves
            discovered_cves['summary']['by_pattern'][pattern_name] = len(pattern_cves)
            
            logger.info(f"Discovered {len(pattern_cves)} CVEs for pattern {pattern_name}")
        
        # Calculate totals
        total_project_cves = sum(len(cves) for cves in discovered_cves['project_cves'].values())
        total_pattern_cves = sum(len(cves) for cves in discovered_cves['pattern_cves'].values())
        discovered_cves['summary']['total_discovered'] = total_project_cves + total_pattern_cves
        
        logger.info(f"Expanded discovery complete. Total CVEs: {discovered_cves['summary']['total_discovered']}")
        
        return discovered_cves
    
    def save_discovery_results(self, results: Dict, filename: str = None):
        """Save discovery results to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"expanded_cve_discovery_results_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Discovery results saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save discovery results: {e}")
    
    def generate_discovery_report(self, results: Dict) -> str:
        """Generate a comprehensive discovery report"""
        report = f"""# Expanded CVE Discovery Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Mode: Expanded Discovery (Target: 50-100 CVEs)

## Summary
- **Total CVEs Discovered**: {results['summary']['total_discovered']}
- **Projects Analyzed**: {len(results['summary']['by_project'])}
- **Vulnerability Patterns**: {len(results['summary']['by_pattern'])}
- **Discovery Mode**: {results['summary']['discovery_mode']}

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

## Discovery Strategy
- **Projects**: 8 high-priority projects (OpenSSL, Log4j, libpng, zlib, curl, libxml2, SQLite, FFmpeg)
- **Patterns**: 5 critical vulnerability types (buffer overflow, integer overflow, use-after-free, format string, deserialization)
- **CVSS Threshold**: 7.5+ for high-quality vulnerabilities
- **Results Per Search**: Limited to ensure quality over quantity

## Next Steps
1. **Review Discovered CVEs**: Assess quality and relevance
2. **Prioritize for Processing**: Select best candidates for code extraction
3. **Repository Analysis**: Clone repos and extract vulnerable/fixed code
4. **Validation Pipeline**: Implement symbolic execution and fuzzing
5. **Dataset Construction**: Build structured dataset with metadata

## Target Achievement
- **Current**: {results['summary']['total_discovered']} CVEs
- **Target**: 50-100 CVEs
- **Progress**: {results['summary']['total_discovered']/50*100:.1f}% of minimum target
- **Status**: {'On Track' if results['summary']['total_discovered'] >= 25 else 'Needs More Discovery'}

## Notes
- Focus on CVEs with CVSS 7.5+ for high-quality dataset
- Prioritize CVEs with available source code and known fixes
- Some CVEs may require manual review for relevance
- Next phase: Code extraction and validation
"""
        
        return report
    
    def save_discovery_report(self, report: str, filename: str = None):
        """Save discovery report to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"expanded_cve_discovery_report_{timestamp}.md"
        
        try:
            with open(filename, 'w') as f:
                f.write(report)
            logger.info(f"Discovery report saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save discovery report: {e}")

def main():
    """Main function"""
    discovery = ExpandedCVEDiscovery()
    
    # Discover expanded set of CVEs
    logger.info("Starting expanded CVE discovery...")
    start_time = time.time()
    
    results = discovery.discover_expanded_cves()
    
    end_time = time.time()
    discovery_time = end_time - start_time
    
    logger.info(f"Expanded discovery completed in {discovery_time:.1f} seconds")
    
    # Save results
    discovery.save_discovery_results(results)
    
    # Generate and save report
    report = discovery.generate_discovery_report(results)
    discovery.save_discovery_report(report)
    
    logger.info("Expanded discovery process complete!")

if __name__ == "__main__":
    main()
