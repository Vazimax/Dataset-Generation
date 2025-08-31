#!/usr/bin/env python3
"""
Fast CVE Discovery Script

This script provides a faster, more efficient way to discover high-quality CVEs
by limiting results and implementing better rate limiting.
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

class FastCVEDiscovery:
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Focus on highest priority projects only
        self.target_projects = {
            'openssl': {
                'keywords': ['openssl buffer overflow', 'openssl integer overflow'],
                'vulnerability_types': ['buffer overflow', 'integer overflow'],
                'min_cvss': 8.0,  # Higher threshold for faster results
                'priority': 'critical',
                'max_results': 5  # Limit results per project
            },
            'log4j': {
                'keywords': ['log4j deserialization', 'log4j rce'],
                'vulnerability_types': ['deserialization', 'remote code execution'],
                'min_cvss': 8.0,
                'priority': 'critical',
                'max_results': 5
            }
        }
        
        # High-impact vulnerability patterns only
        self.vulnerability_patterns = {
            'buffer_overflow': {
                'keywords': ['buffer overflow cvss:8.0+', 'stack overflow cvss:8.0+'],
                'cwe': ['CWE-119', 'CWE-120', 'CWE-122'],
                'severity': 'critical',
                'max_results': 10
            },
            'integer_overflow': {
                'keywords': ['integer overflow cvss:8.0+', 'arithmetic overflow cvss:8.0+'],
                'cwe': ['CWE-190', 'CWE-191'],
                'severity': 'high',
                'max_results': 10
            }
        }
    
    def query_nvd_api(self, query: str, start_index: int = 0, results_per_page: int = 5) -> Optional[Dict]:
        """Query NVD API with minimal results and faster rate limiting"""
        try:
            params = {
                'keywordSearch': query,
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            
            response = requests.get(self.nvd_api_base, params=params, timeout=30)
            response.raise_for_status()
            
            # Faster rate limiting - 10 requests per minute instead of 5
            time.sleep(6)  # Wait 6 seconds between requests
            
            return response.json()
        except Exception as e:
            logger.error(f"Failed to query NVD API: {e}")
            return None
    
    def search_project_cves_fast(self, project: str, project_config: Dict) -> List[Dict]:
        """Search for CVEs related to a specific project with limited results"""
        logger.info(f"Searching for CVEs in project: {project} (max: {project_config['max_results']})")
        
        cves = []
        
        # Search using project keywords with limited results
        for keyword in project_config['keywords']:
            logger.info(f"Searching with keyword: {keyword}")
            
            # Only get first page of results
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
                                'priority': project_config['priority']
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
    
    def search_vulnerability_patterns_fast(self, pattern_name: str, pattern_config: Dict) -> List[Dict]:
        """Search for CVEs matching specific vulnerability patterns with limited results"""
        logger.info(f"Searching for vulnerability pattern: {pattern_name} (max: {pattern_config['max_results']})")
        
        cves = []
        
        for keyword in pattern_config['keywords']:
            logger.info(f"Searching with pattern keyword: {keyword}")
            
            # Only get first page of results
            result = self.query_nvd_api(keyword, 0, pattern_config['max_results'])
            if not result:
                continue
            
            vulnerabilities = result.get('vulnerabilities', [])
            
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
                        
                        # Stop if we have enough results
                        if len(cves) >= pattern_config['max_results']:
                            break
            
            # Stop if we have enough results
            if len(cves) >= pattern_config['max_results']:
                break
        
        logger.info(f"Found {len(cves)} CVEs for pattern {pattern_name}")
        return cves[:pattern_config['max_results']]
    
    def discover_high_quality_cves_fast(self) -> Dict[str, List[Dict]]:
        """Discover high-quality CVEs quickly with limited results"""
        logger.info("Starting fast CVE discovery...")
        
        discovered_cves = {
            'project_cves': {},
            'pattern_cves': {},
            'summary': {
                'total_discovered': 0,
                'by_project': {},
                'by_pattern': {},
                'discovery_date': datetime.now().isoformat(),
                'discovery_time': 'fast_mode'
            }
        }
        
        # Search by project (limited results)
        logger.info("Searching by project...")
        for project, config in self.target_projects.items():
            logger.info(f"Discovering CVEs for project: {project}")
            project_cves = self.search_project_cves_fast(project, config)
            
            discovered_cves['project_cves'][project] = project_cves
            discovered_cves['summary']['by_project'][project] = len(project_cves)
            
            logger.info(f"Discovered {len(project_cves)} CVEs for {project}")
        
        # Search by vulnerability patterns (limited results)
        logger.info("Searching by vulnerability patterns...")
        for pattern_name, pattern_config in self.vulnerability_patterns.items():
            logger.info(f"Discovering CVEs for pattern: {pattern_name}")
            pattern_cves = self.search_vulnerability_patterns_fast(pattern_name, pattern_config)
            
            discovered_cves['pattern_cves'][pattern_name] = pattern_cves
            discovered_cves['summary']['by_pattern'][pattern_name] = len(pattern_cves)
            
            logger.info(f"Discovered {len(pattern_cves)} CVEs for pattern {pattern_name}")
        
        # Calculate totals
        total_project_cves = sum(len(cves) for cves in discovered_cves['project_cves'].values())
        total_pattern_cves = sum(len(cves) for cves in discovered_cves['pattern_cves'].values())
        discovered_cves['summary']['total_discovered'] = total_project_cves + total_pattern_cves
        
        logger.info(f"Fast discovery complete. Total CVEs: {discovered_cves['summary']['total_discovered']}")
        
        return discovered_cves
    
    def save_discovery_results(self, results: Dict, filename: str = None):
        """Save discovery results to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"fast_cve_discovery_results_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Discovery results saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save discovery results: {e}")
    
    def generate_discovery_report(self, results: Dict) -> str:
        """Generate a human-readable discovery report"""
        report = f"""# Fast CVE Discovery Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Mode: Fast Discovery (Limited Results)

## Summary
- **Total CVEs Discovered**: {results['summary']['total_discovered']}
- **Projects Analyzed**: {len(results['summary']['by_project'])}
- **Vulnerability Patterns**: {len(results['summary']['by_pattern'])}
- **Discovery Time**: {results['summary']['discovery_time']}

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
                for cve in cves[:3]:  # Top 3
                    report += f"- **{cve['cve_id']}** (CVSS: {cve['cvss_score']}) - {cve['description'][:100]}...\n"
        
        report += "\n## Top CVEs by Pattern\n"
        for pattern, cves in results['pattern_cves'].items():
            if cves:
                report += f"\n### {pattern.replace('_', ' ').title()}\n"
                for cve in cves[:3]:  # Top 3
                    report += f"- **{cve['cve_id']}** (CVSS: {cve['cvss_score']}) - {cve['description'][:100]}...\n"
        
        report += f"""

## Fast Discovery Benefits
- **Speed**: Limited to top results per search
- **Efficiency**: Focuses on highest CVSS scores
- **Targeted**: Uses specific vulnerability keywords
- **Time**: Completes in ~2-3 minutes instead of 15+ minutes

## Next Steps
1. Review discovered CVEs for quality and relevance
2. Prioritize CVEs based on CVSS score and exploitability
3. Begin repository analysis for selected CVEs
4. Extract vulnerable and fixed code
5. Validate vulnerabilities through testing

## Notes
- Results are limited to ensure fast discovery
- Focus on CVEs with CVSS 8.0+ for high-quality dataset
- Some CVEs may require manual review for relevance
- Use full discovery script for comprehensive results
"""
        
        return report
    
    def save_discovery_report(self, report: str, filename: str = None):
        """Save discovery report to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"fast_cve_discovery_report_{timestamp}.md"
        
        try:
            with open(filename, 'w') as f:
                f.write(report)
            logger.info(f"Discovery report saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save discovery report: {e}")

def main():
    """Main function"""
    discovery = FastCVEDiscovery()
    
    # Discover high-quality CVEs quickly
    logger.info("Starting fast CVE discovery...")
    start_time = time.time()
    
    results = discovery.discover_high_quality_cves_fast()
    
    end_time = time.time()
    discovery_time = end_time - start_time
    
    logger.info(f"Fast discovery completed in {discovery_time:.1f} seconds")
    
    # Save results
    discovery.save_discovery_results(results)
    
    # Generate and save report
    report = discovery.generate_discovery_report(results)
    discovery.save_discovery_report(report)
    
    logger.info("Fast discovery process complete!")

if __name__ == "__main__":
    main()
