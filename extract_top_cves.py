#!/usr/bin/env python3
"""
Extract Top CVEs Script
Extracts the top 50 most critical CVEs from the vulnerability dataset.
"""

import json
import os
import logging
from typing import List, Dict

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TopCVEExtractor:
    def __init__(self, report_file: str = "critical_cves_report.json", target_count: int = 50):
        self.report_file = report_file
        self.target_count = target_count
        self.critical_cves = []
        
    def load_report(self):
        """Load the critical CVEs report"""
        try:
            with open(self.report_file, 'r') as f:
                report = json.load(f)
            self.critical_cves = report.get('critical_cves', [])
            logger.info(f"📋 Loaded {len(self.critical_cves)} critical CVEs from report")
            return True
        except Exception as e:
            logger.error(f"Failed to load report: {e}")
            return False
    
    def get_top_cves(self, count: int = None) -> List[Dict]:
        """Get the top N most critical CVEs"""
        if count is None:
            count = self.target_count
        
        # Sort by weaponization score (descending) and take top N
        sorted_cves = sorted(self.critical_cves, key=lambda x: x['weaponization_score'], reverse=True)
        return sorted_cves[:count]
    
    def create_extraction_list(self, output_file: str = "top_50_cves_for_extraction.json"):
        """Create a list of top CVEs ready for code extraction"""
        top_cves = self.get_top_cves()
        
        extraction_list = []
        for cve in top_cves:
            extraction_item = {
                'cve_id': cve['cve_id'],
                'project': cve['project'],
                'cwe_id': cve['cwe_id'],
                'cwe_name': cve['cwe_name'],
                'weaponization_score': cve['weaponization_score'],
                'vulnerability_patterns': cve['vulnerability_patterns'],
                'is_high_priority_project': cve['is_high_priority_project'],
                'priority': 'critical' if cve['weaponization_score'] >= 8.0 else 'high',
                'description': f"{cve['cwe_name']} vulnerability in {cve['project']} with weaponization score {cve['weaponization_score']:.1f}/10.0"
            }
            extraction_list.append(extraction_item)
        
        # Save extraction list
        with open(output_file, 'w') as f:
            json.dump(extraction_list, f, indent=2)
        
        logger.info(f"📋 Created extraction list with {len(extraction_list)} CVEs: {output_file}")
        return extraction_list
    
    def print_summary(self):
        """Print a summary of the top CVEs"""
        top_cves = self.get_top_cves()
        
        print("\n" + "="*80)
        print("🎯 TOP 50 CRITICAL CVEs FOR EXTRACTION")
        print("="*80)
        print(f"📊 Total critical CVEs available: {len(self.critical_cves)}")
        print(f"🎯 Top CVEs selected: {len(top_cves)}")
        print(f"📈 Coverage: {(len(top_cves) / self.target_count) * 100:.1f}%")
        
        print(f"\n🔥 Top 20 Most Critical CVEs:")
        for i, cve in enumerate(top_cves[:20], 1):
            priority_icon = "🚨" if cve['weaponization_score'] >= 8.0 else "⚠️"
            project_icon = "🔥" if cve['is_high_priority_project'] else "⚪"
            print(f"{i:2d}. {priority_icon} {cve['cve_id']} - {cve['cwe_name']}")
            print(f"    {project_icon} Project: {cve['project']}")
            print(f"    🎯 Score: {cve['weaponization_score']:.1f}/10.0")
            print(f"    📋 Patterns: {len(cve['vulnerability_patterns'])}")
            print()
        
        # Count by CWE type
        cwe_counts = {}
        for cve in top_cves:
            cwe = cve['cwe_id']
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
        
        print(f"\n📋 CWE Distribution in Top CVEs:")
        sorted_cwes = sorted(cwe_counts.items(), key=lambda x: x[1], reverse=True)
        for cwe, count in sorted_cwes[:10]:
            cwe_name = cve['cwe_name'] if cve['cwe_id'] == cwe else "Unknown"
            print(f"  {cwe} - {cwe_name}: {count} CVEs")
        
        # Count by project
        project_counts = {}
        for cve in top_cves:
            project = cve['project']
            project_counts[project] = project_counts.get(project, 0) + 1
        
        print(f"\n🏗️  Project Distribution in Top CVEs:")
        sorted_projects = sorted(project_counts.items(), key=lambda x: x[1], reverse=True)
        for project, count in sorted_projects[:10]:
            priority = "🔥 HIGH" if any(cve['project'] == project and cve['is_high_priority_project'] for cve in top_cves) else "⚪ Normal"
            print(f"  {project}: {count} CVEs {priority}")
    
    def check_existing_dataset(self, dataset_dir: str = "dataset") -> Dict:
        """Check which CVEs already exist in our dataset"""
        existing_cves = set()
        if os.path.exists(dataset_dir):
            for item in os.listdir(dataset_dir):
                if item.startswith("CVE-"):
                    existing_cves.add(item)
        
        top_cves = self.get_top_cves()
        new_cves = []
        existing_cves_found = []
        
        for cve in top_cves:
            if cve['cve_id'] in existing_cves:
                existing_cves_found.append(cve['cve_id'])
            else:
                new_cves.append(cve)
        
        logger.info(f"📊 Found {len(existing_cves_found)} CVEs already in dataset")
        logger.info(f"📊 Found {len(new_cves)} new CVEs to extract")
        
        return {
            'existing': existing_cves_found,
            'new': new_cves,
            'total_existing': len(existing_cves),
            'total_new': len(new_cves)
        }
    
    def create_new_cves_list(self, output_file: str = "new_cves_only.json"):
        """Create a list of only new CVEs not in our existing dataset"""
        dataset_status = self.check_existing_dataset()
        new_cves = dataset_status['new']
        
        # Save new CVEs list
        with open(output_file, 'w') as f:
            json.dump(new_cves, f, indent=2)
        
        logger.info(f"📋 Created new CVEs list with {len(new_cves)} CVEs: {output_file}")
        return new_cves

def main():
    """Main function"""
    extractor = TopCVEExtractor()
    
    # Load report
    if not extractor.load_report():
        return
    
    # Create extraction list
    extraction_list = extractor.create_extraction_list()
    
    # Create new CVEs list
    new_cves = extractor.create_new_cves_list()
    
    # Print summary
    extractor.print_summary()
    
    # Check dataset status
    dataset_status = extractor.check_existing_dataset()
    
    print(f"\n" + "="*80)
    print("📊 DATASET INTEGRATION STATUS")
    print("="*80)
    print(f"🎯 Target: 50 critical CVEs")
    print(f"📊 Current dataset: {dataset_status['total_existing']} CVEs")
    print(f"🆕 New CVEs available: {dataset_status['total_new']} CVEs")
    print(f"📈 Potential total: {dataset_status['total_existing'] + dataset_status['total_new']} CVEs")
    
    if dataset_status['total_existing'] + dataset_status['total_new'] >= 50:
        print(f"\n🎉 SUCCESS! We can reach our target of 50 critical CVEs!")
        print(f"   Current: {dataset_status['total_existing']}")
        print(f"   + New: {dataset_status['total_new']}")
        print(f"   = Total: {dataset_status['total_existing'] + dataset_status['total_new']}")
    else:
        print(f"\n⚠️  We still need {50 - (dataset_status['total_existing'] + dataset_status['total_new'])} more CVEs")
        print("   Consider lowering the weaponization threshold or finding additional sources")

if __name__ == "__main__":
    main()
