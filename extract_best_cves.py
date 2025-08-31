#!/usr/bin/env python3
"""
Extract Best CVEs Script
Extracts high-quality CVEs from previous discovery results for code extraction.
"""

import json
import os
import logging
from typing import List, Dict

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def extract_best_cves(discovery_file: str = "expanded_cve_discovery_results_20250829_171246.json") -> List[Dict]:
    """Extract the best high-severity CVEs from discovery results"""
    
    if not os.path.exists(discovery_file):
        logger.error(f"Discovery file {discovery_file} not found!")
        return []
    
    try:
        with open(discovery_file, 'r') as f:
            data = json.load(f)
        
        best_cves = []
        target_count = 50  # Our target
        
        # Priority order: Critical > High > Medium
        priority_order = ["critical", "high", "medium"]
        
        for priority in priority_order:
            if len(best_cves) >= target_count:
                break
                
            for project, cves in data.get("project_cves", {}).items():
                if len(best_cves) >= target_count:
                    break
                    
                for cve in cves:
                    if len(best_cves) >= target_count:
                        break
                        
                    # Check if this CVE meets our criteria
                    if (cve.get("priority") == priority and 
                        cve.get("cvss_score", 0) >= 7.0 and
                        cve.get("cve_id") not in [c["cve_id"] for c in best_cves]):
                        
                        best_cves.append(cve)
                        logger.info(f"✅ Added {cve['cve_id']} - {cve.get('severity', 'N/A')} - CVSS {cve.get('cvss_score', 'N/A')}")
        
        logger.info(f"🎯 Extracted {len(best_cves)} high-quality CVEs")
        return best_cves
        
    except Exception as e:
        logger.error(f"Error extracting CVEs: {e}")
        return []

def save_best_cves(cves: List[Dict], filename: str = "best_cves_for_extraction.json"):
    """Save the best CVEs to a file for code extraction"""
    try:
        with open(filename, 'w') as f:
            json.dump(cves, f, indent=2)
        logger.info(f"💾 Saved {len(cves)} CVEs to {filename}")
    except Exception as e:
        logger.error(f"Error saving CVEs: {e}")

def create_extraction_list(cves: List[Dict]) -> List[str]:
    """Create a list of CVE IDs for extraction"""
    return [cve["cve_id"] for cve in cves]

def main():
    """Main extraction function"""
    logger.info("🎯 EXTRACTING BEST CVEs FOR CODE EXTRACTION")
    logger.info("="*60)
    
    # Extract best CVEs
    best_cves = extract_best_cves()
    
    if best_cves:
        # Save to file
        save_best_cves(best_cves)
        
        # Create extraction list
        extraction_list = create_extraction_list(best_cves)
        
        # Show summary
        logger.info("\n📊 EXTRACTION SUMMARY:")
        logger.info(f"🎯 Total CVEs: {len(best_cves)}")
        logger.info(f"📈 Target: 50 CVEs")
        
        # Count by severity
        critical_count = len([c for c in best_cves if c.get("severity") == "CRITICAL"])
        high_count = len([c for c in best_cves if c.get("severity") == "HIGH"])
        medium_count = len([c for c in best_cves if c.get("severity") == "MEDIUM"])
        
        logger.info(f"🔥 Critical: {critical_count}")
        logger.info(f"⚠️  High: {high_count}")
        logger.info(f"⚡ Medium: {medium_count}")
        
        # Show first 10 CVEs
        logger.info("\n📋 TOP 10 CVEs:")
        for i, cve in enumerate(best_cves[:10]):
            logger.info(f"  {i+1:2d}. {cve['cve_id']} - {cve.get('severity', 'N/A')} - CVSS {cve.get('cvss_score', 'N/A')}")
        
        logger.info(f"\n🚀 Ready to extract code for {len(best_cves)} CVEs!")
        
    else:
        logger.error("❌ No CVEs extracted!")

if __name__ == "__main__":
    main()
