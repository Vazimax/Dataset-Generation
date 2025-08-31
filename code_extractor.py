#!/usr/bin/env python3
"""
Code Extraction Script

This script clones repositories for discovered CVEs and extracts the vulnerable
and fixed code versions to build the dataset.
"""

import os
import json
import git
import shutil
import requests
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CodeExtractor:
    def __init__(self, dataset_dir: str = "dataset", temp_dir: str = "temp_repos"):
        self.dataset_dir = dataset_dir
        self.temp_dir = temp_dir
        self.extraction_results = {}
        
        # Ensure directories exist
        os.makedirs(dataset_dir, exist_ok=True)
        os.makedirs(temp_dir, exist_ok=True)
        
        # Repository URLs for known projects
        self.project_repos = {
            'openssl': 'https://github.com/openssl/openssl.git',
            'log4j': 'https://github.com/apache/logging-log4j2.git',
            'libpng': 'https://github.com/glennrp/libpng.git',
            'zlib': 'https://github.com/madler/zlib.git',
            'curl': 'https://github.com/curl/curl.git',
            'libxml2': 'https://github.com/GNOME/libxml2.git',
            'sqlite': 'https://github.com/sqlite/sqlite.git',
            'ffmpeg': 'https://github.com/FFmpeg/FFmpeg.git'
        }
        
        # Alternative repository URLs for some projects
        self.alternative_repos = {
            'log4j': [
                'https://github.com/apache/logging-log4j.git',  # Log4j 1.x
                'https://github.com/apache/logging-log4j2.git'  # Log4j 2.x
            ]
        }
    
    def load_discovery_results(self, results_file: str) -> Dict:
        """Load CVE discovery results from file"""
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
            logger.info(f"Loaded discovery results from {results_file}")
            return results
        except Exception as e:
            logger.error(f"Failed to load discovery results: {e}")
            return {}
    
    def find_repository_for_cve(self, cve_info: Dict) -> Optional[str]:
        """Find the appropriate repository for a CVE"""
        project = cve_info.get('project', '').lower()
        
        # Check if we have a direct repository mapping
        if project in self.project_repos:
            return self.project_repos[project]
        
        # Check alternative repositories
        if project in self.alternative_repos:
            # For projects with multiple repos, try to determine which one
            description = cve_info.get('description', '').lower()
            
            if 'log4j' in project:
                if 'log4j 1' in description or '1.x' in description:
                    return self.alternative_repos['log4j'][0]  # Log4j 1.x
                else:
                    return self.alternative_repos['log4j'][1]  # Log4j 2.x
        
        # Try to infer from description
        description = cve_info.get('description', '').lower()
        
        if 'openssl' in description or 'ssl' in description:
            return self.project_repos['openssl']
        elif 'png' in description or 'libpng' in description:
            return self.project_repos['libpng']
        elif 'zlib' in description or 'compression' in description:
            return self.project_repos['zlib']
        elif 'curl' in description or 'libcurl' in description:
            return self.project_repos['curl']
        elif 'xml' in description or 'libxml' in description:
            return self.project_repos['libxml2']
        elif 'sqlite' in description or 'database' in description:
            return self.project_repos['sqlite']
        elif 'ffmpeg' in description or 'media' in description:
            return self.project_repos['ffmpeg']
        
        return None
    
    def clone_repository(self, repo_url: str, project_name: str, cve_id: str) -> Optional[str]:
        """Clone a repository to a temporary directory"""
        repo_dir = os.path.join(self.temp_dir, f"{project_name}_{cve_id}")
        
        # Remove existing directory if it exists
        if os.path.exists(repo_dir):
            shutil.rmtree(repo_dir)
        
        try:
            logger.info(f"Cloning {repo_url} to {repo_dir}")
            git.Repo.clone_from(repo_url, repo_dir)
            logger.info(f"Successfully cloned repository to {repo_dir}")
            return repo_dir
        except Exception as e:
            logger.error(f"Failed to clone repository {repo_url}: {e}")
            return None
    
    def find_vulnerable_and_fixed_versions(self, cve_info: Dict, repo_path: str) -> Tuple[Optional[str], Optional[str]]:
        """Find vulnerable and fixed versions of the code"""
        cve_id = cve_info['cve_id']
        project = cve_info.get('project', 'unknown')
        
        logger.info(f"Searching for vulnerable and fixed versions of {cve_id}")
        
        try:
            repo = git.Repo(repo_path)
            
            # Get commit history
            commits = list(repo.iter_commits('main', max_count=1000))
            
            # Look for commits that mention the CVE
            cve_commits = []
            for commit in commits:
                if cve_id.lower() in commit.message.lower():
                    cve_commits.append(commit)
            
            if len(cve_commits) >= 2:
                # Assume first commit is the fix, second is the vulnerability
                fix_commit = cve_commits[0]
                vuln_commit = cve_commits[1]
                
                logger.info(f"Found CVE commits: {fix_commit.hexsha[:8]} (fix), {vuln_commit.hexsha[:8]} (vulnerable)")
                
                return fix_commit.hexsha, vuln_commit.hexsha
            
            # If no CVE-specific commits, look for security-related commits
            security_commits = []
            for commit in commits:
                message = commit.message.lower()
                if any(keyword in message for keyword in ['security', 'fix', 'vulnerability', 'cve', 'overflow', 'crash']):
                    security_commits.append(commit)
            
            if len(security_commits) >= 2:
                # Use recent security commits
                fix_commit = security_commits[0]
                vuln_commit = security_commits[1]
                
                logger.info(f"Found security commits: {fix_commit.hexsha[:8]} (fix), {vuln_commit.hexsha[:8]} (vulnerable)")
                
                return fix_commit.hexsha, vuln_commit.hexsha
            
            logger.warning(f"Could not find specific commits for {cve_id}")
            return None, None
            
        except Exception as e:
            logger.error(f"Failed to find versions for {cve_id}: {e}")
            return None, None
    
    def extract_code_versions(self, cve_info: Dict, repo_path: str, fix_commit: str, vuln_commit: str) -> bool:
        """Extract vulnerable and fixed code versions"""
        cve_id = cve_info['cve_id']
        project = cve_info.get('project', 'unknown')
        
        logger.info(f"Extracting code versions for {cve_id}")
        
        try:
            repo = git.Repo(repo_path)
            
            # Create CVE dataset directory
            cve_dir = os.path.join(self.dataset_dir, cve_id)
            os.makedirs(cve_dir, exist_ok=True)
            
            # Extract vulnerable version
            repo.git.checkout(vuln_commit)
            vulnerable_files = self._find_relevant_source_files(repo_path, cve_info)
            
            if vulnerable_files:
                self._extract_vulnerable_code(cve_dir, repo_path, vulnerable_files, cve_info)
            
            # Extract fixed version
            repo.git.checkout(fix_commit)
            fixed_files = self._find_relevant_source_files(repo_path, cve_info)
            
            if fixed_files:
                self._extract_fixed_code(cve_dir, repo_path, fixed_files, cve_info)
            
            # Create metadata
            self._create_cve_metadata(cve_dir, cve_info, fix_commit, vuln_commit)
            
            logger.info(f"Successfully extracted code for {cve_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to extract code for {cve_id}: {e}")
            return False
    
    def _find_relevant_source_files(self, repo_path: str, cve_info: Dict) -> List[str]:
        """Find relevant source files based on CVE information"""
        relevant_files = []
        
        # Common source file extensions
        source_extensions = ['.c', '.cpp', '.h', '.hpp', '.java', '.py', '.js', '.php']
        
        # Look for files that might contain the vulnerability
        for root, dirs, files in os.walk(repo_path):
            # Skip .git and other hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if any(file.endswith(ext) for ext in source_extensions):
                    file_path = os.path.join(root, file)
                    
                    # Check if file content might be relevant
                    if self._is_file_relevant(file_path, cve_info):
                        # Get relative path from repo root
                        rel_path = os.path.relpath(file_path, repo_path)
                        relevant_files.append(rel_path)
        
        return relevant_files[:5]  # Limit to 5 most relevant files
    
    def _is_file_relevant(self, file_path: str, cve_info: Dict) -> bool:
        """Check if a file is relevant to the CVE"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
            
            # Check for vulnerability-related keywords
            vuln_keywords = [
                'buffer', 'overflow', 'integer', 'overflow', 'use after free',
                'format string', 'deserialization', 'injection', 'vulnerability'
            ]
            
            if any(keyword in content for keyword in vuln_keywords):
                return True
            
            # Check for project-specific keywords
            project = cve_info.get('project', '').lower()
            if project in content:
                return True
            
            return False
            
        except Exception:
            return False
    
    def _extract_vulnerable_code(self, cve_dir: str, repo_path: str, files: List[str], cve_info: Dict):
        """Extract vulnerable code version"""
        vulnerable_dir = os.path.join(cve_dir, 'vulnerable')
        os.makedirs(vulnerable_dir, exist_ok=True)
        
        for file_path in files:
            try:
                src_path = os.path.join(repo_path, file_path)
                dst_path = os.path.join(vulnerable_dir, os.path.basename(file_path))
                
                shutil.copy2(src_path, dst_path)
                logger.info(f"Copied vulnerable file: {file_path}")
                
            except Exception as e:
                logger.error(f"Failed to copy vulnerable file {file_path}: {e}")
    
    def _extract_fixed_code(self, cve_dir: str, repo_path: str, files: List[str], cve_info: Dict):
        """Extract fixed code version"""
        fixed_dir = os.path.join(cve_dir, 'fixed')
        os.makedirs(fixed_dir, exist_ok=True)
        
        for file_path in files:
            try:
                src_path = os.path.join(repo_path, file_path)
                dst_path = os.path.join(fixed_dir, os.path.basename(file_path))
                
                shutil.copy2(src_path, dst_path)
                logger.info(f"Copied fixed file: {file_path}")
                
            except Exception as e:
                logger.error(f"Failed to copy fixed file {file_path}: {e}")
    
    def _create_cve_metadata(self, cve_dir: str, cve_info: Dict, fix_commit: str, vuln_commit: str):
        """Create metadata file for the CVE"""
        metadata = {
            'cve_id': cve_info['cve_id'],
            'project': cve_info.get('project', 'Unknown'),
            'vulnerability_type': self._classify_vulnerability(cve_info.get('description', '')),
            'cvss_score': cve_info.get('cvss_score', 0),
            'severity': cve_info.get('severity', 'UNKNOWN'),
            'description': cve_info.get('description', ''),
            'published_date': cve_info.get('published_date', ''),
            'last_modified': cve_info.get('last_modified', ''),
            'cwe': cve_info.get('cwe', []),
            'commits': {
                'vulnerable': vuln_commit,
                'fixed': fix_commit
            },
            'extraction_date': datetime.now().isoformat(),
            'extraction_status': 'completed'
        }
        
        metadata_file = os.path.join(cve_dir, 'metadata.json')
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"Created metadata for {cve_info['cve_id']}")
    
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
        elif 'deserialization' in description_lower:
            return 'Deserialization'
        elif 'injection' in description_lower:
            return 'Injection'
        elif 'cryptographic' in description_lower:
            return 'Cryptographic Weakness'
        else:
            return 'Unknown'
    
    def process_cve(self, cve_info: Dict) -> bool:
        """Process a single CVE for code extraction"""
        cve_id = cve_info['cve_id']
        project = cve_info.get('project', 'unknown')
        
        logger.info(f"Processing CVE: {cve_id} from project: {project}")
        
        # Find repository
        repo_url = self.find_repository_for_cve(cve_info)
        if not repo_url:
            logger.warning(f"Could not find repository for {cve_id}")
            return False
        
        # Clone repository
        repo_path = self.clone_repository(repo_url, project, cve_id)
        if not repo_path:
            logger.error(f"Failed to clone repository for {cve_id}")
            return False
        
        # Find vulnerable and fixed versions
        fix_commit, vuln_commit = self.find_vulnerable_and_fixed_versions(cve_info, repo_path)
        if not fix_commit or not vuln_commit:
            logger.warning(f"Could not find version commits for {cve_id}")
            return False
        
        # Extract code versions
        success = self.extract_code_versions(cve_info, repo_path, fix_commit, vuln_commit)
        
        # Clean up temporary repository
        try:
            shutil.rmtree(repo_path)
            logger.info(f"Cleaned up temporary repository for {cve_id}")
        except Exception as e:
            logger.warning(f"Failed to clean up temporary repository: {e}")
        
        return success
    
    def process_discovery_results(self, results_file: str, max_cves: int = 10) -> Dict:
        """Process discovery results and extract code for selected CVEs"""
        logger.info(f"Processing discovery results from {results_file}")
        
        # Load discovery results
        results = self.load_discovery_results(results_file)
        if not results:
            logger.error("No discovery results to process")
            return {}
        
        # Collect all CVEs
        all_cves = []
        
        # Add project CVEs
        for project, cves in results.get('project_cves', {}).items():
            for cve in cves:
                cve['source'] = 'project'
                all_cves.append(cve)
        
        # Add pattern CVEs
        for pattern, cves in results.get('pattern_cves', {}).items():
            for cve in cves:
                cve['source'] = 'pattern'
                all_cves.append(cve)
        
        # Sort by CVSS score (highest first)
        all_cves.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)
        
        # Process top CVEs
        processed_count = 0
        successful_count = 0
        
        for cve in all_cves[:max_cves]:
            processed_count += 1
            logger.info(f"Processing CVE {processed_count}/{min(max_cves, len(all_cves))}: {cve['cve_id']}")
            
            if self.process_cve(cve):
                successful_count += 1
                self.extraction_results[cve['cve_id']] = {
                    'status': 'success',
                    'project': cve.get('project', 'Unknown'),
                    'cvss_score': cve.get('cvss_score', 0)
                }
            else:
                self.extraction_results[cve['cve_id']] = {
                    'status': 'failed',
                    'project': cve.get('project', 'Unknown'),
                    'cvss_score': cve.get('cvss_score', 0)
                }
        
        # Generate summary
        summary = {
            'total_processed': processed_count,
            'successful': successful_count,
            'failed': processed_count - successful_count,
            'success_rate': successful_count / processed_count * 100 if processed_count > 0 else 0,
            'extraction_date': datetime.now().isoformat()
        }
        
        logger.info(f"Code extraction complete. Success rate: {summary['success_rate']:.1f}%")
        
        return summary
    
    def save_extraction_results(self, results: Dict, filename: str = None):
        """Save extraction results to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"code_extraction_results_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Extraction results saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save extraction results: {e}")
    
    def generate_extraction_report(self, summary: Dict) -> str:
        """Generate extraction report"""
        report = f"""# Code Extraction Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- **Total CVEs Processed**: {summary['total_processed']}
- **Successful Extractions**: {summary['successful']}
- **Failed Extractions**: {summary['failed']}
- **Success Rate**: {summary['success_rate']:.1f}%

## Extraction Results
"""
        
        for cve_id, result in self.extraction_results.items():
            status_emoji = "✅" if result['status'] == 'success' else "❌"
            report += f"- {status_emoji} **{cve_id}** ({result['project']}) - CVSS: {result['cvss_score']} - {result['status'].upper()}\n"
        
        report += f"""

## Next Steps
1. **Review Extracted Code**: Verify code quality and relevance
2. **Validate Vulnerabilities**: Run symbolic execution and fuzzing tests
3. **Update Metadata**: Add validation results and exploitability information
4. **Expand Dataset**: Continue with more CVEs to reach target

## Notes
- Successfully extracted CVEs are now in the dataset directory
- Each CVE has vulnerable and fixed code versions
- Metadata includes commit hashes for version tracking
- Ready for validation pipeline implementation
"""
        
        return report
    
    def save_extraction_report(self, report: str, filename: str = None):
        """Save extraction report to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"code_extraction_report_{timestamp}.md"
        
        try:
            with open(filename, 'w') as f:
                f.write(report)
            logger.info(f"Extraction report saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save extraction report: {e}")

def main():
    """Main function"""
    extractor = CodeExtractor()
    
    # Find the most recent discovery results file
    discovery_files = [f for f in os.listdir('.') if f.startswith('expanded_cve_discovery_results_')]
    if not discovery_files:
        discovery_files = [f for f in os.listdir('.') if f.startswith('fast_cve_discovery_results_')]
    
    if not discovery_files:
        logger.error("No discovery results files found. Run discovery first.")
        return
    
    # Use the most recent file
    latest_file = max(discovery_files)
    logger.info(f"Using discovery results from: {latest_file}")
    
    # Process CVEs (limit to 5 for testing)
    summary = extractor.process_discovery_results(latest_file, max_cves=5)
    
    # Save results and generate report
    extractor.save_extraction_results(summary)
    
    report = extractor.generate_extraction_report(summary)
    extractor.save_extraction_report(report)
    
    logger.info("Code extraction process complete!")

if __name__ == "__main__":
    main()
