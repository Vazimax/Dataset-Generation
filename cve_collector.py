#!/usr/bin/env python3
"""
CVE Dataset Generation Automation Script

This script automates the collection and validation of high-quality, weaponizable CVEs
to create a seed dataset for LLM-guided variant generation.
"""

import os
import json
import requests
import subprocess
import git
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cve_collection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CVECollector:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.nvd_api_base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.collected_cves = []
        self.failed_cves = []
        
        # Ensure dataset directory exists
        os.makedirs(dataset_dir, exist_ok=True)
        
        # Load existing progress
        self.load_progress()
    
    def load_progress(self):
        """Load existing CVE collection progress"""
        progress_file = "collection_progress.json"
        if os.path.exists(progress_file):
            try:
                with open(progress_file, 'r') as f:
                    data = json.load(f)
                    self.collected_cves = data.get('collected_cves', [])
                    self.failed_cves = data.get('failed_cves', [])
                logger.info(f"Loaded progress: {len(self.collected_cves)} collected, {len(self.failed_cves)} failed")
            except Exception as e:
                logger.error(f"Failed to load progress: {e}")
    
    def save_progress(self):
        """Save current collection progress"""
        progress_file = "collection_progress.json"
        data = {
            'collected_cves': self.collected_cves,
            'failed_cves': self.failed_cves,
            'last_updated': datetime.now().isoformat()
        }
        try:
            with open(progress_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info("Progress saved successfully")
        except Exception as e:
            logger.error(f"Failed to save progress: {e}")
    
    def query_nvd_api(self, query: str, start_index: int = 0, results_per_page: int = 20) -> Optional[Dict]:
        """Query NVD API for CVEs"""
        try:
            params = {
                'keywordSearch': query,
                'startIndex': start_index,
                'resultsPerPage': results_per_page
            }
            
            response = requests.get(self.nvd_api_base, params=params, timeout=30)
            response.raise_for_status()
            
            return response.json()
        except Exception as e:
            logger.error(f"Failed to query NVD API: {e}")
            return None
    
    def search_high_severity_cves(self, project: str = None, min_cvss: float = 7.0) -> List[Dict]:
        """Search for high-severity CVEs, optionally filtered by project"""
        cves = []
        
        # Search queries for different vulnerability types
        search_queries = [
            "buffer overflow",
            "integer overflow",
            "use after free",
            "format string",
            "cryptographic weakness",
            "denial of service",
            "infinite loop"
        ]
        
        if project:
            search_queries = [f"{project} {query}" for query in search_queries]
        
        for query in search_queries:
            logger.info(f"Searching for: {query}")
            
            start_index = 0
            while True:
                result = self.query_nvd_api(query, start_index)
                if not result:
                    break
                
                vulnerabilities = result.get('vulnerabilities', [])
                if not vulnerabilities:
                    break
                
                for vuln in vulnerabilities:
                    cve = vuln.get('cve', {})
                    cve_id = cve.get('id')
                    
                    # Skip if already collected
                    if cve_id in [c['cve_id'] for c in self.collected_cves]:
                        continue
                    
                    # Check CVSS score
                    metrics = cve.get('metrics', {})
                    cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] or metrics.get('cvssMetricV30', [{}])[0]
                    
                    if cvss_v3:
                        cvss_score = cvss_v3.get('cvssData', {}).get('baseScore', 0)
                        if cvss_score >= min_cvss:
                            cve_info = {
                                'cve_id': cve_id,
                                'description': cve.get('descriptions', [{}])[0].get('value', ''),
                                'cvss_score': cvss_score,
                                'severity': cvss_v3.get('cvssData', {}).get('baseSeverity', 'UNKNOWN'),
                                'search_query': query,
                                'published_date': cve.get('published', ''),
                                'last_modified': cve.get('lastModified', '')
                            }
                            cves.append(cve_info)
                
                start_index += len(vulnerabilities)
                if len(vulnerabilities) < 20:  # Last page
                    break
        
        # Remove duplicates and sort by CVSS score
        unique_cves = {}
        for cve in cves:
            cve_id = cve['cve_id']
            if cve_id not in unique_cves or cve['cvss_score'] > unique_cves[cve_id]['cvss_score']:
                unique_cves[cve_id] = cve
        
        sorted_cves = sorted(unique_cves.values(), key=lambda x: x['cvss_score'], reverse=True)
        logger.info(f"Found {len(sorted_cves)} unique high-severity CVEs")
        
        return sorted_cves
    
    def analyze_cve_repository(self, cve_info: Dict) -> Optional[Dict]:
        """Analyze CVE repository to find vulnerable and fixed code"""
        cve_id = cve_info['cve_id']
        logger.info(f"Analyzing repository for {cve_id}")
        
        # Try to find repository information
        # This is a simplified approach - in practice, you'd need more sophisticated
        # repository discovery logic
        
        # For now, focus on known projects
        known_projects = {
            'openssl': 'https://github.com/openssl/openssl.git',
            'log4j': 'https://github.com/apache/logging-log4j2.git',
            'libpng': 'https://github.com/glennrp/libpng.git',
            'zlib': 'https://github.com/madler/zlib.git',
            'curl': 'https://github.com/curl/curl.git'
        }
        
        # Try to identify project from CVE description
        description = cve_info['description'].lower()
        project = None
        
        for proj_name, repo_url in known_projects.items():
            if proj_name in description:
                project = proj_name
                break
        
        if not project:
            logger.warning(f"Could not identify project for {cve_id}")
            return None
        
        # Clone repository and analyze
        try:
            repo_dir = f"temp_repos/{project}_{cve_id}"
            os.makedirs(repo_dir, exist_ok=True)
            
            if not os.path.exists(f"{repo_dir}/.git"):
                logger.info(f"Cloning {project} repository...")
                git.Repo.clone_from(known_projects[project], repo_dir)
            
            # This is where you'd implement the actual vulnerability analysis
            # For now, return basic structure
            return {
                'cve_id': cve_id,
                'project': project,
                'repository': known_projects[project],
                'local_path': repo_dir,
                'analysis_status': 'repository_cloned'
            }
            
        except Exception as e:
            logger.error(f"Failed to analyze repository for {cve_id}: {e}")
            return None
    
    def validate_cve(self, cve_info: Dict, repo_info: Dict) -> Dict:
        """Validate CVE by analyzing code and running tests"""
        cve_id = cve_info['cve_id']
        logger.info(f"Validating {cve_id}")
        
        validation_result = {
            'cve_id': cve_id,
            'validation_date': datetime.now().isoformat(),
            'validation_methods': [],
            'status': 'pending',
            'issues': [],
            'recommendations': []
        }
        
        # TODO: Implement actual validation logic
        # 1. Symbolic execution with angr
        # 2. Fuzzing with AFL++
        # 3. Static analysis
        # 4. Manual review checklist
        
        # For now, mark as validated (placeholder)
        validation_result['status'] = 'validated'
        validation_result['validation_methods'] = ['placeholder']
        
        return validation_result
    
    def create_cve_dataset(self, cve_info: Dict, repo_info: Dict, validation_result: Dict):
        """Create the CVE dataset structure"""
        cve_id = cve_info['cve_id']
        cve_dir = os.path.join(self.dataset_dir, cve_id)
        os.makedirs(cve_dir, exist_ok=True)
        
        # Create metadata.json
        metadata = {
            'cve_id': cve_id,
            'project': repo_info.get('project', 'Unknown'),
            'vulnerability_type': self._classify_vulnerability(cve_info['description']),
            'cvss_score': cve_info['cvss_score'],
            'severity': cve_info['severity'],
            'description': cve_info['description'],
            'published_date': cve_info['published_date'],
            'last_modified': cve_info['last_modified'],
            'repository': repo_info.get('repository', ''),
            'validation': validation_result,
            'collection_date': datetime.now().isoformat()
        }
        
        metadata_file = os.path.join(cve_dir, 'metadata.json')
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # TODO: Extract vulnerable and fixed code files
        # For now, create placeholder files
        self._create_placeholder_files(cve_dir, cve_id)
        
        logger.info(f"Created dataset for {cve_id}")
    
    def _classify_vulnerability(self, description: str) -> str:
        """Classify vulnerability type based on description"""
        description_lower = description.lower()
        
        if 'buffer overflow' in description_lower:
            return 'Buffer Overflow'
        elif 'integer overflow' in description_lower:
            return 'Integer Overflow'
        elif 'use after free' in description_lower or 'use-after-free' in description_lower:
            return 'Use After Free'
        elif 'format string' in description_lower:
            return 'Format String'
        elif 'cryptographic' in description_lower or 'crypto' in description_lower:
            return 'Cryptographic Weakness'
        elif 'denial of service' in description_lower or 'dos' in description_lower:
            return 'Denial of Service'
        elif 'infinite loop' in description_lower:
            return 'Infinite Loop'
        else:
            return 'Unknown'
    
    def _create_placeholder_files(self, cve_dir: str, cve_id: str):
        """Create placeholder files for CVE dataset"""
        # Create vulnerable.c placeholder
        vulnerable_content = f"""/*
 * Placeholder file for {cve_id}
 * TODO: Extract actual vulnerable code from repository
 */

#include <stdio.h>
#include <stdlib.h>

// This is a placeholder - replace with actual vulnerable code
int vulnerable_function() {{
    // TODO: Implement actual vulnerable code
    return 0;
}}

int main() {{
    vulnerable_function();
    return 0;
}}
"""
        
        with open(os.path.join(cve_dir, 'vulnerable.c'), 'w') as f:
            f.write(vulnerable_content)
        
        # Create fixed.c placeholder
        fixed_content = f"""/*
 * Placeholder file for {cve_id} (fixed version)
 * TODO: Extract actual fixed code from repository
 */

#include <stdio.h>
#include <stdlib.h>

// This is a placeholder - replace with actual fixed code
int fixed_function() {{
    // TODO: Implement actual fixed code
    return 0;
}}

int main() {{
    fixed_function();
    return 0;
}}
"""
        
        with open(os.path.join(cve_dir, 'fixed.c'), 'w') as f:
            f.write(fixed_content)
        
        # Create validation report
        report_content = f"""# Validation Report for {cve_id}

## Status: Pending Full Validation

This CVE has been collected but requires full validation.

## TODO Items:
1. Extract actual vulnerable code from repository
2. Extract actual fixed code from repository
3. Run symbolic execution with angr
4. Run fuzzing tests with AFL++
5. Perform static analysis
6. Manual security review

## Notes:
- This is a placeholder report
- Replace with actual validation results
"""
        
        with open(os.path.join(cve_dir, 'validation_report.md'), 'w') as f:
            f.write(report_content)
    
    def run_collection(self, target_count: int = 50):
        """Run the main CVE collection process"""
        logger.info(f"Starting CVE collection process. Target: {target_count} CVEs")
        
        # Search for high-severity CVEs
        cves = self.search_high_severity_cves()
        
        collected_count = 0
        for cve_info in cves:
            if collected_count >= target_count:
                break
            
            cve_id = cve_info['cve_id']
            
            # Skip if already collected
            if cve_id in [c['cve_id'] for c in self.collected_cves]:
                continue
            
            logger.info(f"Processing {cve_id} ({collected_count + 1}/{target_count})")
            
            try:
                # Analyze repository
                repo_info = self.analyze_cve_repository(cve_info)
                if not repo_info:
                    self.failed_cves.append({
                        'cve_id': cve_id,
                        'reason': 'repository_analysis_failed',
                        'timestamp': datetime.now().isoformat()
                    })
                    continue
                
                # Validate CVE
                validation_result = self.validate_cve(cve_info, repo_info)
                
                # Create dataset
                self.create_cve_dataset(cve_info, repo_info, validation_result)
                
                # Update progress
                self.collected_cves.append({
                    'cve_id': cve_id,
                    'project': repo_info.get('project', 'Unknown'),
                    'cvss_score': cve_info['cvss_score'],
                    'collection_date': datetime.now().isoformat()
                })
                
                collected_count += 1
                logger.info(f"Successfully collected {cve_id}")
                
                # Save progress periodically
                if collected_count % 10 == 0:
                    self.save_progress()
                
            except Exception as e:
                logger.error(f"Failed to process {cve_id}: {e}")
                self.failed_cves.append({
                    'cve_id': cve_id,
                    'reason': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        # Final progress save
        self.save_progress()
        
        logger.info(f"Collection complete. Collected: {len(self.collected_cves)}, Failed: {len(self.failed_cves)}")
        
        # Generate summary report
        self.generate_summary_report()
    
    def generate_summary_report(self):
        """Generate a summary report of the collection process"""
        report_file = "collection_summary.md"
        
        report_content = f"""# CVE Collection Summary Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Collection Statistics
- **Total Collected**: {len(self.collected_cves)}
- **Total Failed**: {len(self.failed_cves)}
- **Success Rate**: {len(self.collected_cves) / (len(self.collected_cves) + len(self.failed_cves)) * 100:.1f}%

## Collected CVEs
"""
        
        for cve in self.collected_cves:
            report_content += f"- **{cve['cve_id']}** ({cve['project']}) - CVSS: {cve['cvss_score']}\n"
        
        if self.failed_cves:
            report_content += "\n## Failed CVEs\n"
            for cve in self.failed_cves:
                report_content += f"- **{cve['cve_id']}** - Reason: {cve['reason']}\n"
        
        report_content += f"""

## Next Steps
1. Complete validation of collected CVEs
2. Extract actual vulnerable and fixed code
3. Run full validation pipeline (angr, AFL++, static analysis)
4. Prepare for LLM-guided variant generation

## Notes
- This is an automated collection
- Manual review and validation required
- Some CVEs may need additional analysis
"""
        
        with open(report_file, 'w') as f:
            f.write(report_content)
        
        logger.info(f"Summary report generated: {report_file}")

def main():
    """Main function"""
    collector = CVECollector()
    
    # Run collection process
    target_count = 50  # Adjust as needed
    collector.run_collection(target_count)

if __name__ == "__main__":
    main()
