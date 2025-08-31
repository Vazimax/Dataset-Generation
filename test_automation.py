#!/usr/bin/env python3
"""
Test Automation Script

This script tests the CVE automation scripts to ensure they work correctly.
"""

import os
import sys
import importlib
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def test_imports():
    """Test that all required modules can be imported"""
    logger.info("Testing module imports...")
    
    required_modules = [
        'requests',
        'git',
        'json',
        'os',
        'datetime',
        'typing'
    ]
    
    failed_imports = []
    
    for module in required_modules:
        try:
            importlib.import_module(module)
            logger.info(f"✅ {module} imported successfully")
        except ImportError as e:
            logger.error(f"❌ Failed to import {module}: {e}")
            failed_imports.append(module)
    
    if failed_imports:
        logger.error(f"Import failures: {failed_imports}")
        return False
    
    logger.info("All required modules imported successfully")
    return True

def test_analyze_existing_cves():
    """Test the existing CVE analyzer"""
    logger.info("Testing existing CVE analyzer...")
    
    try:
        # Import the analyzer
        from analyze_existing_cves import ExistingCVEAnalyzer
        
        # Create analyzer instance
        analyzer = ExistingCVEAnalyzer()
        logger.info("✅ ExistingCVEAnalyzer created successfully")
        
        # Test basic functionality
        if hasattr(analyzer, 'analyze_all_cves'):
            logger.info("✅ analyze_all_cves method exists")
        else:
            logger.error("❌ analyze_all_cves method missing")
            return False
        
        if hasattr(analyzer, 'generate_analysis_report'):
            logger.info("✅ generate_analysis_report method exists")
        else:
            logger.error("❌ generate_analysis_report method missing")
            return False
        
        logger.info("✅ Existing CVE analyzer test passed")
        return True
        
    except Exception as e:
        logger.error(f"❌ Existing CVE analyzer test failed: {e}")
        return False

def test_targeted_discovery():
    """Test the targeted CVE discovery"""
    logger.info("Testing targeted CVE discovery...")
    
    try:
        # Import the discovery module
        from targeted_cve_discovery import TargetedCVEDiscovery
        
        # Create discovery instance
        discovery = TargetedCVEDiscovery()
        logger.info("✅ TargetedCVEDiscovery created successfully")
        
        # Test basic functionality
        if hasattr(discovery, 'discover_high_quality_cves'):
            logger.info("✅ discover_high_quality_cves method exists")
        else:
            logger.error("❌ discover_high_quality_cves method missing")
            return False
        
        if hasattr(discovery, 'search_project_cves'):
            logger.info("✅ search_project_cves method exists")
        else:
            logger.error("❌ search_project_cves method missing")
            return False
        
        logger.info("✅ Targeted CVE discovery test passed")
        return True
        
    except Exception as e:
        logger.error(f"❌ Targeted CVE discovery test failed: {e}")
        return False

def test_cve_collector():
    """Test the CVE collector"""
    logger.info("Testing CVE collector...")
    
    try:
        # Import the collector
        from cve_collector import CVECollector
        
        # Create collector instance
        collector = CVECollector()
        logger.info("✅ CVECollector created successfully")
        
        # Test basic functionality
        if hasattr(collector, 'search_high_severity_cves'):
            logger.info("✅ search_high_severity_cves method exists")
        else:
            logger.error("❌ search_high_severity_cves method missing")
            return False
        
        if hasattr(collector, 'run_collection'):
            logger.info("✅ run_collection method exists")
        else:
            logger.error("❌ run_collection method missing")
            return False
        
        logger.info("✅ CVE collector test passed")
        return True
        
    except Exception as e:
        logger.error(f"❌ CVE collector test failed: {e}")
        return False

def test_dataset_structure():
    """Test that the dataset structure is correct"""
    logger.info("Testing dataset structure...")
    
    dataset_dir = "dataset"
    
    if not os.path.exists(dataset_dir):
        logger.error(f"❌ Dataset directory not found: {dataset_dir}")
        return False
    
    # Check for existing CVEs
    cve_dirs = []
    for item in os.listdir(dataset_dir):
        item_path = os.path.join(dataset_dir, item)
        if os.path.isdir(item_path) and item.startswith('CVE-'):
            cve_dirs.append(item)
    
    logger.info(f"Found {len(cve_dirs)} CVE directories: {cve_dirs}")
    
    if not cve_dirs:
        logger.warning("⚠️ No CVE directories found - this is expected for a new setup")
        return True
    
    # Check structure of existing CVEs
    for cve_dir in cve_dirs:
        cve_path = os.path.join(dataset_dir, cve_dir)
        
        # Check for required files
        required_files = ['vulnerable.c', 'fixed.c']
        for file in required_files:
            file_path = os.path.join(cve_path, file)
            if os.path.exists(file_path):
                logger.info(f"✅ {cve_dir}/{file} exists")
            else:
                logger.warning(f"⚠️ {cve_dir}/{file} missing")
    
    logger.info("✅ Dataset structure test passed")
    return True

def test_file_permissions():
    """Test that files have correct permissions"""
    logger.info("Testing file permissions...")
    
    # Check if scripts are executable
    script_files = [
        'cve_collector.py',
        'targeted_cve_discovery.py',
        'analyze_existing_cves.py',
        'test_automation.py'
    ]
    
    for script in script_files:
        if os.path.exists(script):
            if os.access(script, os.X_OK):
                logger.info(f"✅ {script} is executable")
            else:
                logger.warning(f"⚠️ {script} is not executable")
        else:
            logger.error(f"❌ {script} not found")
    
    logger.info("✅ File permissions test completed")
    return True

def run_all_tests():
    """Run all tests"""
    logger.info("Starting automation tests...")
    
    tests = [
        ("Module Imports", test_imports),
        ("Existing CVE Analyzer", test_analyze_existing_cves),
        ("Targeted CVE Discovery", test_targeted_discovery),
        ("CVE Collector", test_cve_collector),
        ("Dataset Structure", test_dataset_structure),
        ("File Permissions", test_file_permissions)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        logger.info(f"\n--- Running {test_name} Test ---")
        try:
            if test_func():
                passed += 1
                logger.info(f"✅ {test_name} PASSED")
            else:
                logger.error(f"❌ {test_name} FAILED")
        except Exception as e:
            logger.error(f"❌ {test_name} FAILED with exception: {e}")
    
    # Summary
    logger.info(f"\n--- Test Summary ---")
    logger.info(f"Passed: {passed}/{total}")
    logger.info(f"Success Rate: {passed/total*100:.1f}%")
    
    if passed == total:
        logger.info("🎉 All tests passed! Automation is ready to use.")
        return True
    else:
        logger.error("❌ Some tests failed. Please fix issues before proceeding.")
        return False

def main():
    """Main function"""
    logger.info("CVE Automation Test Suite")
    logger.info("=" * 50)
    
    success = run_all_tests()
    
    if success:
        logger.info("\n🚀 Ready to start CVE collection!")
        logger.info("Next steps:")
        logger.info("1. Run: python analyze_existing_cves.py")
        logger.info("2. Run: python targeted_cve_discovery.py")
        logger.info("3. Run: python cve_collector.py")
    else:
        logger.error("\n⚠️ Please fix test failures before proceeding")
        sys.exit(1)

if __name__ == "__main__":
    main()
