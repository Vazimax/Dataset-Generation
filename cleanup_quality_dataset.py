#!/usr/bin/env python3
"""
Dataset Cleanup Script
Removes failed CVEs and keeps only high-quality, truly vulnerable CVEs in C language.
"""

import os
import shutil
import json
import logging
from pathlib import Path
from typing import Set, Dict

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class QualityDatasetCleanup:
    def __init__(self, dataset_dir: str = "dataset", quality_report: str = "quality_filter_report.json"):
        self.dataset_dir = dataset_dir
        self.quality_report = quality_report
        self.quality_cves = []
        self.failed_cves = []
        
    def load_quality_report(self):
        """Load the quality filter report"""
        try:
            with open(self.quality_report, 'r') as f:
                report = json.load(f)
            
            self.quality_cves = report.get('quality_cves', [])
            self.failed_cves = report.get('failed_cves', [])
            
            logger.info(f"📋 Loaded quality report: {len(self.quality_cves)} passed, {len(self.failed_cves)} failed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load quality report: {e}")
            return False
    
    def get_cve_ids_to_keep(self) -> Set[str]:
        """Get the set of CVE IDs that passed quality check"""
        return {cve['cve_id'] for cve in self.quality_cves}
    
    def get_cve_ids_to_remove(self) -> Set[str]:
        """Get the set of CVE IDs that failed quality check"""
        return {cve['cve_id'] for cve in self.failed_cves}
    
    def backup_dataset(self, backup_dir: str = "dataset_backup"):
        """Create a backup of the current dataset"""
        if not os.path.exists(self.dataset_dir):
            logger.error(f"Dataset directory {self.dataset_dir} not found!")
            return False
        
        try:
            if os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)
            
            shutil.copytree(self.dataset_dir, backup_dir)
            logger.info(f"📦 Dataset backed up to {backup_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to backup dataset: {e}")
            return False
    
    def cleanup_failed_cves(self) -> Dict:
        """Remove all failed CVEs from the dataset"""
        if not self.failed_cves:
            logger.info("✅ No failed CVEs to remove")
            return {'removed': 0, 'errors': []}
        
        removed_count = 0
        errors = []
        
        for failed_cve in self.failed_cves:
            cve_id = failed_cve['cve_id']
            cve_dir = os.path.join(self.dataset_dir, cve_id)
            
            if os.path.exists(cve_dir):
                try:
                    shutil.rmtree(cve_dir)
                    removed_count += 1
                    logger.info(f"🗑️  Removed failed CVE: {cve_id}")
                    
                except Exception as e:
                    error_msg = f"Failed to remove {cve_id}: {e}"
                    errors.append(error_msg)
                    logger.error(error_msg)
            else:
                logger.warning(f"CVE directory not found: {cve_id}")
        
        logger.info(f"✅ Cleanup complete: {removed_count} failed CVEs removed")
        return {'removed': removed_count, 'errors': errors}
    
    def verify_cleanup(self) -> Dict:
        """Verify that only quality CVEs remain"""
        if not os.path.exists(self.dataset_dir):
            return {'verified': False, 'remaining_cves': 0, 'issues': ['Dataset directory not found']}
        
        # Get remaining CVE directories
        remaining_cves = [item for item in os.listdir(self.dataset_dir) 
                         if item.startswith("CVE-") and os.path.isdir(os.path.join(self.dataset_dir, item))]
        
        # Get expected quality CVEs
        expected_cves = self.get_cve_ids_to_keep()
        
        # Check for unexpected CVEs
        unexpected_cves = set(remaining_cves) - expected_cves
        missing_cves = expected_cves - set(remaining_cves)
        
        issues = []
        if unexpected_cves:
            issues.append(f"Unexpected CVEs found: {list(unexpected_cves)}")
        
        if missing_cves:
            issues.append(f"Expected CVEs missing: {list(missing_cves)}")
        
        verified = len(issues) == 0 and len(remaining_cves) == len(expected_cves)
        
        return {
            'verified': verified,
            'remaining_cves': len(remaining_cves),
            'expected_cves': len(expected_cves),
            'issues': issues,
            'remaining_cve_list': remaining_cves
        }
    
    def create_cleanup_report(self, cleanup_results: Dict, verification_results: Dict, 
                             output_file: str = "dataset_cleanup_report.json"):
        """Create a detailed cleanup report"""
        report = {
            'cleanup_summary': {
                'total_cves_before': len(self.quality_cves) + len(self.failed_cves),
                'quality_cves_kept': len(self.quality_cves),
                'failed_cves_removed': len(self.failed_cves),
                'cleanup_success': verification_results['verified']
            },
            'cleanup_results': cleanup_results,
            'verification_results': verification_results,
            'quality_cves_kept': self.quality_cves,
            'cleanup_timestamp': str(Path().cwd())
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"📋 Cleanup report saved to {output_file}")
        return report
    
    def print_cleanup_summary(self, cleanup_results: Dict, verification_results: Dict):
        """Print a summary of the cleanup results"""
        print("\n" + "="*80)
        print("🧹 DATASET CLEANUP COMPLETE")
        print("="*80)
        print(f"📊 Dataset before cleanup: {len(self.quality_cves) + len(self.failed_cves)} CVEs")
        print(f"✅ Quality CVEs kept: {len(self.quality_cves)}")
        print(f"🗑️  Failed CVEs removed: {cleanup_results['removed']}")
        print(f"📊 Dataset after cleanup: {verification_results['remaining_cves']} CVEs")
        
        if verification_results['verified']:
            print(f"✅ Cleanup verification: PASSED")
        else:
            print(f"❌ Cleanup verification: FAILED")
            for issue in verification_results['issues']:
                print(f"   ⚠️  {issue}")
        
        print(f"\n🔥 High-Quality CVEs Kept:")
        for i, cve in enumerate(self.quality_cves, 1):
            project = cve['metadata'].get('project', 'Unknown')
            quality_score = cve['quality_score']
            vuln_patterns = cve['diff_check']['vulnerability_patterns']
            print(f"{i:2d}. {cve['cve_id']} - {project}")
            print(f"    Quality Score: {quality_score}/100")
            print(f"    Vulnerability Patterns: {vuln_patterns}")
            print()
        
        print(f"\n🎯 Next Steps:")
        if len(self.quality_cves) >= 50:
            print(f"🎉 SUCCESS! We have {len(self.quality_cves)} high-quality CVEs!")
            print("Ready to move to LLM-guided variant generation!")
        else:
            print(f"📈 We have {len(self.quality_cves)} high-quality CVEs")
            print(f"📊 Need {50 - len(self.quality_cves)} more to reach our target")
            print("💡 Consider LLM-guided variant generation to create variants")
    
    def run_cleanup(self) -> bool:
        """Run the complete cleanup process"""
        logger.info("🧹 Starting dataset cleanup process...")
        
        # Load quality report
        if not self.load_quality_report():
            return False
        
        # Create backup
        if not self.backup_dataset():
            logger.warning("⚠️  Backup failed, but continuing with cleanup...")
        
        # Remove failed CVEs
        cleanup_results = self.cleanup_failed_cves()
        
        # Verify cleanup
        verification_results = self.verify_cleanup()
        
        # Create report
        report = self.create_cleanup_report(cleanup_results, verification_results)
        
        # Print summary
        self.print_cleanup_summary(cleanup_results, verification_results)
        
        return verification_results['verified']

def main():
    """Main function"""
    cleanup_tool = QualityDatasetCleanup()
    
    # Run cleanup
    success = cleanup_tool.run_cleanup()
    
    if success:
        print(f"\n🎉 Dataset cleanup completed successfully!")
        print(f"📊 Clean dataset ready with {len(cleanup_tool.quality_cves)} high-quality CVEs")
    else:
        print(f"\n⚠️  Dataset cleanup completed with issues")
        print("Check the cleanup report for details")

if __name__ == "__main__":
    main()
