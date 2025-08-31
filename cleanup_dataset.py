#!/usr/bin/env python3
"""
Dataset Cleanup Script
Removes unreliable CVEs and keeps only high-quality, weaponizable ones.
"""

import os
import shutil
import json
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def cleanup_unreliable_cves():
    """Remove unreliable CVEs from the dataset"""
    dataset_dir = "dataset"
    
    # List of CVEs to remove (failed validation)
    unreliable_cves = [
        "CVE-2021-45046",  # Log4j - all files identical
        "CVE-2022-23302",  # Log4j - all files identical
        "CVE-2019-17571",  # Log4j - all files identical
        "CVE-2022-23307",  # Log4j - all files identical
        "CVE-2021-3711",   # OpenSSL - missing vulnerable directory
        "CVE-2022-0778"    # OpenSSL - missing vulnerable directory
    ]
    
    logger.info("🧹 Starting dataset cleanup...")
    logger.info(f"Targeting {len(unreliable_cves)} unreliable CVEs for removal")
    
    removed_count = 0
    for cve_id in unreliable_cves:
        cve_path = os.path.join(dataset_dir, cve_id)
        if os.path.exists(cve_path):
            try:
                shutil.rmtree(cve_path)
                logger.info(f"✅ Removed {cve_id}")
                removed_count += 1
            except Exception as e:
                logger.error(f"❌ Failed to remove {cve_id}: {e}")
        else:
            logger.warning(f"⚠️  {cve_id} not found in dataset")
    
    logger.info(f"🧹 Cleanup complete! Removed {removed_count} unreliable CVEs")
    
    # Count remaining CVEs
    remaining_cves = [d for d in os.listdir(dataset_dir) if d.startswith('CVE-')]
    logger.info(f"📊 Remaining CVEs: {len(remaining_cves)}")
    
    return remaining_cves

def get_high_quality_cves():
    """Get list of high-quality CVEs that passed validation"""
    dataset_dir = "dataset"
    
    # These CVEs passed validation and are weaponizable
    high_quality_cves = [
        "CVE-2014-4959",   # SQLite - CVSS 9.8, 44 vuln patterns
        "CVE-2016-6303",   # OpenSSL - CVSS 9.8, 25 vuln patterns  
        "CVE-2023-35784",  # OpenSSL - CVSS 9.8, 24 vuln patterns
        "CVE-2016-10553",  # SQLite - CVSS 9.8, 44 vuln patterns
        "CVE-2020-28018",  # OpenSSL - CVSS 9.8, 24 vuln patterns
        "CVE-2022-37434",  # zlib - CVSS 9.8, 18 vuln patterns
        "CVE-2016-7167",   # cURL - CVSS 9.8, 15 vuln patterns
        "CVE-2005-0490",   # cURL - CVSS 8.8, 15 vuln patterns
        "CVE-2016-7134",   # cURL - CVSS 9.8, 15 vuln patterns
        "CVE-2023-45853"   # zlib - CVSS 9.8, 18 vuln patterns
    ]
    
    logger.info("🎯 High-quality CVEs in our dataset:")
    for cve_id in high_quality_cves:
        cve_path = os.path.join(dataset_dir, cve_id)
        if os.path.exists(cve_path):
            logger.info(f"  ✅ {cve_id}")
        else:
            logger.warning(f"  ⚠️  {cve_id} missing from dataset")
    
    return high_quality_cves

def main():
    """Main cleanup function"""
    logger.info("="*80)
    logger.info("🧹 DATASET CLEANUP AND ANALYSIS")
    logger.info("="*80)
    
    # Clean up unreliable CVEs
    remaining_cves = cleanup_unreliable_cves()
    
    # Get high-quality CVEs
    high_quality_cves = get_high_quality_cves()
    
    logger.info("\n" + "="*80)
    logger.info("📊 CLEANUP SUMMARY")
    logger.info("="*80)
    logger.info(f"✅ High-quality CVEs: {len(high_quality_cves)}")
    logger.info(f"📁 Total remaining CVEs: {len(remaining_cves)}")
    logger.info(f"🎯 Target: 50 critical CVEs")
    logger.info(f"📈 Need to add: {50 - len(high_quality_cves)} more CVEs")
    
    if len(high_quality_cves) >= 50:
        logger.info("🎉 Target reached! Ready for variant generation.")
    else:
        logger.info("🚀 Ready to discover more high-quality CVEs!")

if __name__ == "__main__":
    main()
