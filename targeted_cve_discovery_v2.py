#!/usr/bin/env python3
"""
Targeted CVE Discovery V2
Focused discovery of high-quality CVEs from specific projects and vulnerability types.
"""

import requests
import time
import json
import logging
from typing import List, Dict, Optional

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TargetedCVEDiscoveryV2:
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.discovered_cves = []
        self.target_count = 36  # Need 36 more to reach 50
        
    def discover_targeted_cves(self) -> List[Dict]:
        """Discover high-quality CVEs using targeted search strategies"""
        
        # Strategy 1: High CVSS scores from critical projects
        logger.info("🎯 Strategy 1: High CVSS scores from critical projects")
        self._search_high_cvss_cves()
        
        # Strategy 2: Specific CWE types from known vulnerable projects
        logger.info("🎯 Strategy 2: Specific CWE types from vulnerable projects")
        self._search_cwe_specific_cves()
        
        # Strategy 3: Recent high-severity CVEs
        logger.info("🎯 Strategy 3: Recent high-severity CVEs")
        self._search_recent_high_severity_cves()
        
        return self.discovered_cves
    
    def _search_high_cvss_cves(self):
        """Search for CVEs with CVSS >= 9.0 from critical projects"""
        critical_projects = [
            "openssl", "sqlite", "zlib", "curl", "ffmpeg", "libpng", "libjpeg", 
            "libxml2", "libcurl", "openssh", "bind", "apache", "nginx", "mysql",
            "postgresql", "redis", "memcached", "varnish", "haproxy", "squid"
        ]
        
        for project in critical_projects:
            if len(self.discovered_cves) >= self.target_count:
                break
                
            logger.info(f"🔍 Searching {project} for CVSS >= 9.0...")
            
            try:
                params = {
                    "keywordSearch": project,
                    "cvssV3Severity": "CRITICAL",
                    "resultsPerPage": 10
                }
                
                response = requests.get(self.nvd_api_base, params=params)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities:
                        if len(self.discovered_cves) >= self.target_count:
                            break
                            
                        if self._is_high_quality_cve(vuln):
                            self.discovered_cves.append(vuln)
                            cvss_score = vuln.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                            logger.info(f"  ✅ Found {vuln['cve_id']} - CVSS {cvss_score}")
                
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                logger.warning(f"Error searching {project}: {e}")
    
    def _search_cwe_specific_cves(self):
        """Search for specific CWE types from vulnerable projects"""
        cwe_targets = [
            ("CWE-119", "openssl"),      # Buffer Overflow in OpenSSL
            ("CWE-190", "sqlite"),       # Integer Overflow in SQLite
            ("CWE-415", "zlib"),         # Double Free in zlib
            ("CWE-416", "curl"),         # Use After Free in cURL
            ("CWE-134", "libpng"),       # Format String in libpng
            ("CWE-78", "apache"),        # OS Command Injection in Apache
            ("CWE-89", "mysql"),         # SQL Injection in MySQL
            ("CWE-502", "redis"),        # Deserialization in Redis
        ]
        
        for cwe, project in cwe_targets:
            if len(self.discovered_cves) >= self.target_count:
                break
                
            logger.info(f"🔍 Searching {project} for {cwe}...")
            
            try:
                params = {
                    "keywordSearch": project,
                    "cweId": cwe,
                    "cvssV3Severity": "HIGH",
                    "resultsPerPage": 5
                }
                
                response = requests.get(self.nvd_api_base, params=params)
                if response.status_code == 200:
                    data = response.json()
                    vulnerabilities = data.get('vulnerabilities', [])
                    
                    for vuln in vulnerabilities:
                        if len(self.discovered_cves) >= self.target_count:
                            break
                            
                        if self._is_high_quality_cve(vuln):
                            self.discovered_cves.append(vuln)
                            cvss_score = vuln.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                            logger.info(f"  ✅ Found {vuln['cve_id']} - {cwe} - CVSS {cvss_score}")
                
                time.sleep(2)  # Rate limiting
                
            except Exception as e:
                logger.warning(f"Error searching {project} for {cwe}: {e}")
    
    def _search_recent_high_severity_cves(self):
        """Search for recent high-severity CVEs"""
        logger.info("🔍 Searching for recent high-severity CVEs...")
        
        try:
            params = {
                "cvssV3Severity": "CRITICAL",
                "pubStartDate": "2023-01-01T00:00:00:000 UTC-05:00",
                "resultsPerPage": 20
            }
            
            response = requests.get(self.nvd_api_base, params=params)
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get('vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    if len(self.discovered_cves) >= self.target_count:
                        break
                        
                    if self._is_high_quality_cve(vuln):
                        self.discovered_cves.append(vuln)
                        cvss_score = vuln.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
                        logger.info(f"  ✅ Found {vuln['cve_id']} - CVSS {cvss_score}")
            
        except Exception as e:
            logger.warning(f"Error searching recent CVEs: {e}")
    
    def _is_high_quality_cve(self, cve_data: Dict) -> bool:
        """Check if CVE meets our quality criteria"""
        try:
            # Must have CVSS score >= 7.0
            cvss_score = cve_data.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 0)
            if cvss_score < 7.0:
                return False
            
            # Must have description
            description = cve_data.get('descriptions', [{}])[0].get('value', '')
            if not description:
                return False
            
            # Must not already be in our list
            if any(cve['cve_id'] == cve_data['cve_id'] for cve in self.discovered_cves):
                return False
            
            # Must be from target projects
            target_projects = ["openssl", "sqlite", "zlib", "curl", "ffmpeg", "libpng", "libjpeg", 
                             "libxml2", "libcurl", "openssh", "bind", "apache", "nginx", "mysql",
                             "postgresql", "redis", "memcached", "varnish", "haproxy", "squid"]
            
            if not any(project in description.lower() for project in target_projects):
                return False
            
            return True
            
        except Exception as e:
            logger.warning(f"Error checking CVE quality: {e}")
            return False
    
    def save_discovered_cves(self, filename: str = "additional_cves_discovered.json"):
        """Save discovered CVEs to file"""
        with open(filename, 'w') as f:
            json.dump(self.discovered_cves, f, indent=2)
        logger.info(f"💾 Saved {len(self.discovered_cves)} additional CVEs to {filename}")

def main():
    """Main discovery function"""
    logger.info("🚀 TARGETED CVE DISCOVERY V2")
    logger.info("="*50)
    
    discovery = TargetedCVEDiscoveryV2()
    discovered_cves = discovery.discover_targeted_cves()
    
    logger.info(f"\n🎯 DISCOVERY COMPLETE")
    logger.info(f"📊 Total CVEs discovered: {len(discovered_cves)}")
    logger.info(f"🎯 Target: 36 CVEs")
    
    if discovered_cves:
        discovery.save_discovered_cves()
        
        # Show summary
        logger.info("\n📋 DISCOVERED CVEs:")
        for cve in discovered_cves[:10]:  # Show first 10
            cvss_score = cve.get('metrics', {}).get('cvssMetricV31', [{}])[0].get('cvssData', {}).get('baseScore', 'N/A')
            logger.info(f"  🔥 {cve['cve_id']} - CVSS {cvss_score}")
    
    logger.info("\n🚀 Ready for code extraction!")

if __name__ == "__main__":
    main()
