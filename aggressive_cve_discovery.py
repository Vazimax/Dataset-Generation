#!/usr/bin/env python3
"""
Aggressive CVE Discovery Script
Targets high-severity, weaponizable CVEs to reach 50 critical CVEs.
"""

import requests
import time
import json
import logging
from typing import List, Dict, Optional

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class AggressiveCVEDiscovery:
    def __init__(self):
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.discovered_cves = []
        self.target_count = 40  # Need 40 more to reach 50
        
    def discover_high_severity_cves(self) -> List[Dict]:
        """Discover high-severity CVEs from critical projects"""
        
        # Target projects with high weaponizable vulnerability rates
        target_projects = [
            "openssl", "sqlite", "zlib", "curl", "ffmpeg", "libpng", "libjpeg", 
            "libxml2", "libcurl", "openssh", "bind", "apache", "nginx", "mysql",
            "postgresql", "redis", "memcached", "varnish", "haproxy", "squid"
        ]
        
        # Weaponizable CWE patterns
        weaponizable_cwes = [
            "CWE-119",  # Buffer Overflow
            "CWE-120",  # Buffer Copy without Checking Size
            "CWE-125",  # Out-of-bounds Read
            "CWE-190",  # Integer Overflow
            "CWE-191",  # Integer Underflow
            "CWE-415",  # Double Free
            "CWE-416",  # Use After Free
            "CWE-134",  # Use of Externally-Controlled Format String
            "CWE-78",   # OS Command Injection
            "CWE-89",   # SQL Injection
            "CWE-502",  # Deserialization of Untrusted Data
            "CWE-22",   # Path Traversal
            "CWE-362",  # Race Condition
            "CWE-287",  # Improper Authentication
            "CWE-295",  # Improper Certificate Validation
        ]
        
        logger.info(f"🎯 Targeting {len(target_projects)} critical projects")
        logger.info(f"🔍 Searching for {len(weaponizable_cwes)} weaponizable CWE types")
        
        discovered_count = 0
        
        for project in target_projects:
            if discovered_count >= self.target_count:
                break
                
            logger.info(f"\n🔍 Searching {project} for high-severity CVEs...")
            
            for cwe in weaponizable_cwes:
                if discovered_count >= self.target_count:
                    break
                    
                cves = self._search_project_cves(project, cwe)
                if cves:
                    for cve in cves:
                        if self._is_high_quality_cve(cve):
                            self.discovered_cves.append(cve)
                            discovered_count += 1
                            logger.info(f"  ✅ Found {cve['cve_id']} - CVSS {cve.get('cvss_score', 'N/A')}")
                            
                            if discovered_count >= self.target_count:
                                logger.info(f"🎯 Target reached: {discovered_count} CVEs discovered!")
                                break
                
                time.sleep(1)  # Rate limiting
            
            time.sleep(2)  # Project rate limiting
        
        return self.discovered_cves
    
    def _search_project_cves(self, project: str, cwe: str) -> List[Dict]:
        """Search for CVEs in a specific project with specific CWE"""
        try:
            # Search parameters
            params = {
                "keywordSearch": project,
                "cweId": cwe,
                "cvssV3Severity": "HIGH",
                "resultsPerPage": 20
            }
            
            response = requests.get(self.nvd_api_base, params=params)
            if response.status_code == 200:
                data = response.json()
                return data.get('vulnerabilities', [])
            
        except Exception as e:
            logger.warning(f"Error searching {project} with {cwe}: {e}")
        
        return []
    
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
    
    def save_discovered_cves(self, filename: str = "discovered_cves.json"):
        """Save discovered CVEs to file"""
        with open(filename, 'w') as f:
            json.dump(self.discovered_cves, f, indent=2)
        logger.info(f"💾 Saved {len(self.discovered_cves)} discovered CVEs to {filename}")

def main():
    """Main discovery function"""
    logger.info("🚀 AGGRESSIVE CVE DISCOVERY")
    logger.info("="*50)
    
    discovery = AggressiveCVEDiscovery()
    discovered_cves = discovery.discover_high_severity_cves()
    
    logger.info(f"\n🎯 DISCOVERY COMPLETE")
    logger.info(f"📊 Total CVEs discovered: {len(discovered_cves)}")
    logger.info(f"🎯 Target: 40 CVEs")
    
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
