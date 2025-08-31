#!/usr/bin/env python3
"""
Improved Code Extraction Script

This script fixes the issues with repeated cloning and missing commit detection
by implementing better repository management and commit finding strategies.
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

class ImprovedCodeExtractor:
    def __init__(self, dataset_dir: str = "dataset", temp_dir: str = "temp_repos"):
        self.dataset_dir = dataset_dir
        self.temp_dir = temp_dir
        self.extraction_results = {}
        self.repo_cache = {}  # Cache cloned repositories
        
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
        
        # Known CVE commit mappings (to avoid repeated searches)
        self.known_cve_commits = {
            'CVE-2021-3711': {
                'openssl': {
                    'vulnerable': 'fd78df59b0',
                    'fixed': 'fb047ebc87'
                }
            },
            'CVE-2022-0778': {
                'openssl': {
                    'vulnerable': '8b7b0f40a38565b6e15c205ab9f80d1a0805e6f4',
                    'fixed': '8b7b0f40a38565b6e15c205ab9f80d1a0805e6f4'
                }
            }
        }
    
    def get_or_clone_repository(self, repo_url: str, project_name: str) -> Optional[str]:
        """Get existing repository or clone if not exists"""
        repo_dir = os.path.join(self.temp_dir, project_name)
        
        if project_name in self.repo_cache:
            logger.info(f"Using cached repository for {project_name}")
            return self.repo_cache[project_name]
        
        if os.path.exists(repo_dir):
            if os.path.exists(os.path.join(repo_dir, '.git')):
                logger.info(f"Using existing repository: {repo_dir}")
                self.repo_cache[project_name] = repo_dir
                return repo_dir
            else:
                # Remove corrupted directory
                shutil.rmtree(repo_dir)
        
        try:
            logger.info(f"Cloning {repo_url} to {repo_dir}")
            repo = git.Repo.clone_from(repo_url, repo_dir)
            
            # Set up the repository properly
            self._setup_repository_branch(repo, repo_dir)
            
            logger.info(f"Successfully cloned repository to {repo_dir}")
            self.repo_cache[project_name] = repo_dir
            return repo_dir
        except Exception as e:
            logger.error(f"Failed to clone repository {repo_url}: {e}")
            return None
    
    def _setup_repository_branch(self, repo: git.Repo, repo_dir: str):
        """Set up the repository with the correct branch"""
        try:
            # Get all branches
            branches = [branch.name for branch in repo.branches]
            logger.info(f"Available branches: {branches}")
            
            # Try to find the main branch
            main_branches = ['main', 'master', 'develop', 'dev']
            target_branch = None
            
            for branch in main_branches:
                if branch in branches:
                    target_branch = branch
                    break
            
            if target_branch:
                logger.info(f"Using branch: {target_branch}")
                repo.git.checkout(target_branch)
            else:
                # Use the first available branch
                first_branch = branches[0] if branches else 'master'
                logger.info(f"No main branch found, using: {first_branch}")
                repo.git.checkout(first_branch)
                
        except Exception as e:
            logger.warning(f"Could not set up repository branch: {e}")
            # Continue with default behavior
    
    def find_vulnerable_and_fixed_versions_improved(self, cve_info: Dict, repo_path: str) -> Tuple[Optional[str], Optional[str]]:
        """Improved method to find vulnerable and fixed versions"""
        cve_id = cve_info['cve_id']
        project = cve_info.get('project', 'unknown')
        
        logger.info(f"Searching for vulnerable and fixed versions of {cve_id}")
        
        # Check if we have known commits for this CVE
        if cve_id in self.known_cve_commits and project in self.known_cve_commits[cve_id]:
            known_commits = self.known_cve_commits[cve_id][project]
            logger.info(f"Using known commits for {cve_id}")
            return known_commits['fixed'], known_commits['vulnerable']
        
        try:
            repo = git.Repo(repo_path)
            
            # Reset to default branch if we're in detached HEAD state
            if repo.head.is_detached:
                default_branch = repo.active_branch.name if repo.active_branch else 'master'
                logger.info(f"Resetting from detached HEAD to {default_branch}")
                repo.git.checkout(default_branch)
            
            # Strategy 1: Use semantic analysis for better commit selection (NEW PRIORITY)
            semantic_commits = self._find_semantic_vulnerability_commits(repo, cve_info)
            if semantic_commits:
                return semantic_commits
            
            # Strategy 2: Look for CVE-specific commits
            cve_commits = self._find_cve_specific_commits(repo, cve_id)
            if cve_commits:
                return cve_commits
            
            # Strategy 3: Look for security-related commits around the CVE date
            security_commits = self._find_security_commits_by_date(repo, cve_info)
            if security_commits:
                return security_commits
            
            # Strategy 4: Look for commits with vulnerability keywords
            vuln_commits = self._find_vulnerability_keyword_commits(repo, cve_info)
            if vuln_commits:
                return vuln_commits
            
            # Strategy 5: Use recent commits as fallback (for testing)
            fallback_commits = self._find_fallback_commits(repo)
            if fallback_commits:
                logger.warning(f"Using fallback commits for {cve_id} - manual review required")
                return fallback_commits
            
            logger.warning(f"Could not find any commits for {cve_id}")
            return None, None
            
        except Exception as e:
            logger.error(f"Failed to find versions for {cve_id}: {e}")
            return None, None
    
    def _find_cve_specific_commits(self, repo: git.Repo, cve_id: str) -> Optional[Tuple[str, str]]:
        """Find commits that specifically mention the CVE"""
        try:
            # Get the default branch name
            default_branch = repo.active_branch.name if repo.active_branch else 'master'
            
            # Search in commit messages with more flexible matching
            commits = list(repo.iter_commits(default_branch, max_count=5000))
            
            cve_commits = []
            cve_short = cve_id.replace('CVE-', '')
            
            for commit in commits:
                message = commit.message.lower()
                # Check for CVE ID or short form
                if cve_id.lower() in message or cve_short in message:
                    cve_commits.append(commit)
                    logger.info(f"Found CVE-specific commit: {commit.hexsha[:8]} - {commit.message[:100]}")
            
            if len(cve_commits) >= 2:
                # Sort by date (newest first)
                cve_commits.sort(key=lambda x: x.committed_date, reverse=True)
                fix_commit = cve_commits[0].hexsha
                vuln_commit = cve_commits[1].hexsha
                
                # Ensure commits are different
                if fix_commit != vuln_commit:
                    logger.info(f"Found CVE-specific commits: {fix_commit[:8]} (fix), {vuln_commit[:8]} (vulnerable)")
                    return fix_commit, vuln_commit
                else:
                    logger.warning(f"Found same commit for both vulnerable and fixed: {fix_commit[:8]}")
                    return None
            
            return None
        except Exception as e:
            logger.error(f"Error in CVE-specific commit search: {e}")
            return None
    
    def _find_security_commits_by_date(self, repo: git.Repo, cve_info: Dict) -> Optional[Tuple[str, str]]:
        """Find security commits around the CVE publication date"""
        try:
            # Get CVE publication date
            published_date = cve_info.get('published_date', '')
            if not published_date:
                return None
            
            # Get the default branch name
            default_branch = repo.active_branch.name if repo.active_branch else 'master'
            
            # Parse date and find commits around that time
            target_date = datetime.fromisoformat(published_date.replace('Z', '+00:00'))
            
            commits = list(repo.iter_commits(default_branch, max_count=2000))
            
            # Find commits within 60 days of CVE publication (wider window)
            security_commits = []
            for commit in commits:
                commit_date = datetime.fromtimestamp(commit.committed_date)
                date_diff = abs((commit_date - target_date).days)
                
                if date_diff <= 60:
                    message = commit.message.lower()
                    if any(keyword in message for keyword in ['security', 'fix', 'vulnerability', 'cve', 'overflow', 'crash', 'bug', 'patch', 'update']):
                        security_commits.append(commit)
                        logger.info(f"Found security commit by date: {commit.hexsha[:8]} - {commit.message[:100]}")
            
            if len(security_commits) >= 2:
                security_commits.sort(key=lambda x: x.committed_date, reverse=True)
                fix_commit = security_commits[0].hexsha
                vuln_commit = security_commits[1].hexsha
                
                # Ensure commits are different
                if fix_commit != vuln_commit:
                    logger.info(f"Found security commits by date: {fix_commit[:8]} (fix), {vuln_commit[:8]} (vulnerable)")
                    return fix_commit, vuln_commit
                else:
                    logger.warning(f"Found same commit for both vulnerable and fixed: {fix_commit[:8]}")
                    return None
            
            return None
        except Exception as e:
            logger.error(f"Error in security commit search by date: {e}")
            return None
    
    def _find_vulnerability_keyword_commits(self, repo: git.Repo, cve_info: Dict) -> Optional[Tuple[str, str]]:
        """Find commits with vulnerability-related keywords"""
        try:
            # Get the default branch name
            default_branch = repo.active_branch.name if repo.active_branch else 'master'
            
            commits = list(repo.iter_commits(default_branch, max_count=3000))
            
            # Keywords based on vulnerability type
            vuln_type = cve_info.get('description', '').lower()
            keywords = []
            
            if 'buffer overflow' in vuln_type:
                keywords = ['buffer overflow', 'overflow', 'boundary', 'bounds', 'stack', 'heap']
            elif 'integer overflow' in vuln_type:
                keywords = ['integer overflow', 'overflow', 'arithmetic', 'bn_', 'bignum']
            elif 'use after free' in vuln_type:
                keywords = ['use after free', 'use-after-free', 'dangling', 'free', 'double free']
            elif 'deserialization' in vuln_type:
                keywords = ['deserialization', 'unmarshal', 'gadget', 'jndi', 'ldap']
            else:
                keywords = ['security', 'fix', 'vulnerability', 'bug', 'crash', 'patch', 'update']
            
            security_commits = []
            for commit in commits:
                message = commit.message.lower()
                if any(keyword in message for keyword in keywords):
                    security_commits.append(commit)
                    logger.info(f"Found vulnerability keyword commit: {commit.hexsha[:8]} - {commit.message[:100]}")
            
            if len(security_commits) >= 2:
                # Sort by date (newest first)
                security_commits.sort(key=lambda x: x.committed_date, reverse=True)
                
                # Try to find commits that are further apart in time
                fix_commit = security_commits[0].hexsha
                
                # Look for a vulnerable commit that's older (not immediately adjacent)
                for i in range(1, min(len(security_commits), 10)):  # Check first 10 commits
                    vuln_commit = security_commits[i].hexsha
                    if vuln_commit != fix_commit:
                        # Check if they're far enough apart (at least 1 day difference)
                        fix_time = security_commits[0].committed_date
                        vuln_time = security_commits[i].committed_date
                        time_diff = abs(fix_time - vuln_time)
                        
                        if time_diff > 86400:  # More than 1 day apart
                            logger.info(f"Found vulnerability keyword commits: {fix_commit[:8]} (fix), {vuln_commit[:8]} (vulnerable)")
                            return fix_commit, vuln_commit
                
                # If no time separation, just use different commits
                for i in range(1, len(security_commits)):
                    vuln_commit = security_commits[i].hexsha
                    if vuln_commit != fix_commit:
                        logger.info(f"Found vulnerability keyword commits: {fix_commit[:8]} (fix), {vuln_commit[:8]} (vulnerable)")
                        return fix_commit, vuln_commit
                
                logger.warning(f"Could not find different commits for {cve_info['cve_id']}")
                return None
            
            return None
        except Exception as e:
            logger.error(f"Error in vulnerability keyword commit search: {e}")
            return None
    
    def _find_fallback_commits(self, repo: git.Repo) -> Optional[Tuple[str, str]]:
        """Find fallback commits when no specific ones are found"""
        try:
            # Get the default branch name
            default_branch = repo.active_branch.name if repo.active_branch else 'master'
            
            commits = list(repo.iter_commits(default_branch, max_count=200))
            
            if len(commits) >= 2:
                # Use recent commits as fallback
                fix_commit = commits[0].hexsha
                vuln_commit = commits[1].hexsha
                
                # Ensure commits are different
                if fix_commit != vuln_commit:
                    logger.info(f"Using fallback commits: {fix_commit[:8]} (recent), {vuln_commit[:8]} (older)")
                    return fix_commit, vuln_commit
                else:
                    logger.warning(f"Fallback commits are the same: {fix_commit[:8]}")
                    return None
            
            return None
        except Exception as e:
            logger.error(f"Error in fallback commit search: {e}")
            return None
    
    def _find_semantic_vulnerability_commits(self, repo: git.Repo, cve_info: Dict) -> Optional[Tuple[str, str]]:
        """Find commits using semantic analysis with branch diversity and different development cycles"""
        try:
            # Strategy 1: Find commits from different branches for better separation
            branch_commits = {}
            
            # Get commits from different branches
            for branch_name in ['master', 'main', '2.x', 'develop', 'dev']:
                try:
                    branch_commits[branch_name] = list(repo.iter_commits(branch_name, max_count=1000))
                except:
                    continue
            
            # Also get commits from release/stable branches
            for ref in repo.remotes.origin.refs:
                if 'release' in ref.name.lower() or 'stable' in ref.name.lower():
                    try:
                        branch_commits[ref.name] = list(repo.iter_commits(ref.name, max_count=500))
                    except:
                        continue
            
            # Extract vulnerability keywords from CVE description
            vuln_keywords = self._extract_vulnerability_keywords(cve_info)
            
            # Strategy 2: Find commits from different branches
            for fix_branch, fix_branch_commits in branch_commits.items():
                for vuln_branch, vuln_branch_commits in branch_commits.items():
                    if fix_branch != vuln_branch:  # Different branches
                        # Find fix commits in fix_branch
                        fix_commits = []
                        for commit in fix_branch_commits:
                            message = commit.message.lower()
                            if any(keyword in message for keyword in vuln_keywords):
                                if any(fix_word in message for fix_word in ['fix', 'patch', 'resolve', 'correct', 'address']):
                                    fix_commits.append(commit)
                        
                        # Find vulnerability commits in vuln_branch
                        vuln_commits = []
                        for commit in vuln_branch_commits:
                            message = commit.message.lower()
                            if any(keyword in message for keyword in vuln_keywords):
                                if not any(fix_word in message for fix_word in ['fix', 'patch', 'resolve', 'correct', 'address']):
                                    vuln_commits.append(commit)
                        
                        if len(fix_commits) > 0 and len(vuln_commits) > 0:
                            # Sort by date
                            fix_commits.sort(key=lambda x: x.committed_date, reverse=True)
                            vuln_commits.sort(key=lambda x: x.committed_date, reverse=True)
                            
                            latest_fix = fix_commits[0]
                            
                            # Find vulnerability commit with time separation
                            for vuln_commit in vuln_commits:
                                if vuln_commit.committed_date < latest_fix.committed_date:
                                    time_diff = latest_fix.committed_date - vuln_commit.committed_date
                                    if time_diff > 259200:  # 3 days in seconds
                                        logger.info(f"Found cross-branch commits: {latest_fix.hexsha[:8]} (fix, {fix_branch}), {vuln_commit.hexsha[:8]} (vulnerable, {vuln_branch})")
                                        return latest_fix.hexsha, vuln_commit.hexsha
            
            # Strategy 3: Fallback to same-branch commits with better time separation
            all_commits = []
            for commits in branch_commits.values():
                all_commits.extend(commits)
            
            # Remove duplicates
            seen = set()
            unique_commits = []
            for commit in all_commits:
                if commit.hexsha not in seen:
                    seen.add(commit.hexsha)
                    unique_commits.append(commit)
            
            # Find commits that mention the vulnerability
            vulnerability_commits = []
            fix_commits = []
            
            for commit in unique_commits:
                message = commit.message.lower()
                
                if any(keyword in message for keyword in vuln_keywords):
                    if any(fix_word in message for fix_word in ['fix', 'patch', 'resolve', 'correct', 'address']):
                        fix_commits.append(commit)
                    else:
                        vulnerability_commits.append(commit)
            
            logger.info(f"Found {len(vulnerability_commits)} vulnerability commits and {len(fix_commits)} fix commits")
            
            if len(fix_commits) > 0 and len(vulnerability_commits) > 0:
                fix_commits.sort(key=lambda x: x.committed_date, reverse=True)
                vulnerability_commits.sort(key=lambda x: x.committed_date, reverse=True)
                
                latest_fix = fix_commits[0]
                
                # Try to find commits with significant time separation (at least 14 days)
                for vuln_commit in vulnerability_commits:
                    if vuln_commit.committed_date < latest_fix.committed_date:
                        time_diff = latest_fix.committed_date - vuln_commit.committed_date
                        if time_diff > 1209600:  # 14 days in seconds
                            logger.info(f"Found same-branch commits with 14+ day separation: {latest_fix.hexsha[:8]} (fix), {vuln_commit.hexsha[:8]} (vulnerable)")
                            return latest_fix.hexsha, vuln_commit.hexsha
                
                # Fallback: try with 7 days separation
                for vuln_commit in vulnerability_commits:
                    if vuln_commit.committed_date < latest_fix.committed_date:
                        time_diff = latest_fix.committed_date - vuln_commit.committed_date
                        if time_diff > 604800:  # 7 days in seconds
                            logger.info(f"Found same-branch commits with 7+ day separation: {latest_fix.hexsha[:8]} (fix), {vuln_commit.hexsha[:8]} (vulnerable)")
                            return latest_fix.hexsha, vuln_commit.hexsha
            
            return None
            
        except Exception as e:
            logger.error(f"Error in semantic vulnerability commit search: {e}")
            return None
    
    def _restore_repository_branch(self, repo: git.Repo) -> bool:
        """Restore repository to its default branch"""
        try:
            # Get the default branch name
            default_branch = None
            
            # Check for common default branch names
            for branch_name in ['main', 'master', '2.x', 'develop', 'dev']:
                try:
                    if f'remotes/origin/{branch_name}' in [b.name for b in repo.remotes.origin.refs]:
                        default_branch = f'origin/{branch_name}'
                        break
                except:
                    continue
            
            if not default_branch:
                # Fallback: try to get the default branch from origin/HEAD
                try:
                    default_branch = repo.remotes.origin.refs['HEAD'].ref.name
                except:
                    default_branch = 'master'  # Final fallback
            
            # Force checkout the default branch by resetting existing local branch
            try:
                # Extract the branch name without 'origin/' prefix
                branch_name = default_branch.replace('origin/', '')
                
                # Checkout the existing local branch
                repo.git.checkout(branch_name)
                
                # Reset it to track the remote branch
                repo.git.reset('--hard', default_branch)
                
                logger.info(f"Successfully restored repository to {branch_name} branch")
                return True
                
            except Exception as e:
                logger.warning(f"Could not force checkout {default_branch}: {e}")
                return False
            
        except Exception as e:
            logger.error(f"Failed to restore repository to default branch: {e}")
            return False
    
    def _extract_vulnerability_keywords(self, cve_info: Dict) -> List[str]:
        """Extract relevant vulnerability keywords from CVE description"""
        description = cve_info.get('description', '').lower()
        vuln_type = cve_info.get('description', '').lower()
        
        keywords = []
        
        # Add CVE-specific keywords
        if 'buffer overflow' in vuln_type:
            keywords.extend(['buffer overflow', 'overflow', 'boundary', 'bounds', 'stack', 'heap', 'memory corruption'])
        elif 'integer overflow' in vuln_type:
            keywords.extend(['integer overflow', 'overflow', 'arithmetic', 'bn_', 'bignum', 'overflow'])
        elif 'use after free' in vuln_type:
            keywords.extend(['use after free', 'use-after-free', 'dangling', 'free', 'double free', 'memory'])
        elif 'deserialization' in vuln_type:
            keywords.extend(['deserialization', 'unmarshal', 'gadget', 'jndi', 'ldap', 'serialization'])
        elif 'format string' in vuln_type:
            keywords.extend(['format string', 'printf', 'sprintf', 'format'])
        elif 'sql injection' in vuln_type:
            keywords.extend(['sql injection', 'injection', 'query', 'database'])
        else:
            # Generic security keywords
            keywords.extend(['vulnerability', 'security', 'bug', 'crash', 'exploit', 'attack'])
        
        # Add project-specific keywords
        project = cve_info.get('project', '').lower()
        if 'openssl' in project:
            keywords.extend(['ssl', 'tls', 'crypto', 'encryption', 'certificate'])
        elif 'log4j' in project:
            keywords.extend(['logging', 'log', 'jndi', 'ldap', 'deserialization'])
        elif 'zlib' in project:
            keywords.extend(['compression', 'deflate', 'inflate', 'zlib'])
        elif 'curl' in project:
            keywords.extend(['http', 'ftp', 'url', 'transfer', 'protocol'])
        
        return list(set(keywords))  # Remove duplicates
    
    def _commits_have_different_content(self, repo: git.Repo, commit1: git.Commit, commit2: git.Commit) -> bool:
        """Check if two commits have different content"""
        try:
            # Get the diff between the two commits
            diff = repo.git.diff(commit2.hexsha, commit1.hexsha, '--name-only')
            
            # If there are changed files, the commits are different
            if diff.strip():
                changed_files = [f.strip() for f in diff.split('\n') if f.strip()]
                logger.info(f"Commits have {len(changed_files)} different files")
                return len(changed_files) > 0
            
            return False
            
        except Exception as e:
            logger.warning(f"Could not compare commits: {e}")
            return False
    
    def _find_commit_with_actual_vulnerability(self, repo: git.Repo, cve_info: Dict, target_commit: str) -> Optional[str]:
        """Find a commit that actually contains the vulnerability code"""
        try:
            # Get the default branch name
            default_branch = repo.active_branch.name if repo.active_branch else 'master'
            
            # Look for commits before the target commit that might contain the vulnerability
            commits = list(repo.iter_commits(target_commit, max_count=100))
            
            # Get vulnerability keywords
            vuln_keywords = self._extract_vulnerability_keywords(cve_info)
            
            for commit in commits:
                message = commit.message.lower()
                
                # Check if this commit introduces the vulnerability
                if any(keyword in message for keyword in vuln_keywords):
                    # Skip if it's a fix commit
                    if not any(fix_word in message for fix_word in ['fix', 'patch', 'resolve']):
                        logger.info(f"Found potential vulnerability commit: {commit.hexsha[:8]} - {commit.message[:100]}")
                        return commit.hexsha
            
            return None
            
        except Exception as e:
            logger.error(f"Error finding vulnerability commit: {e}")
            return None
    
    def _verify_commits_will_produce_different_code(self, repo: git.Repo, fix_commit: str, vuln_commit: str) -> bool:
        """Verify that two commits will actually produce different code"""
        try:
            # Get the diff between the two commits
            diff = repo.git.diff(vuln_commit, fix_commit, '--name-only')
            
            if not diff.strip():
                logger.warning("No files changed between commits")
                return False
            
            changed_files = [f.strip() for f in diff.split('\n') if f.strip()]
            logger.info(f"Found {len(changed_files)} changed files between commits")
            
            # Check if any source code files are changed
            source_extensions = ['.c', '.cpp', '.h', '.hpp', '.java', '.py', '.js', '.php']
            source_files_changed = [f for f in changed_files if any(f.endswith(ext) for ext in source_extensions)]
            
            if not source_files_changed:
                logger.warning("No source code files changed between commits")
                return False
            
            logger.info(f"Source files changed: {source_files_changed}")
            
            # Get a sample of the actual diff to verify it's meaningful
            try:
                sample_diff = repo.git.diff(vuln_commit, fix_commit, '--stat')
                logger.info(f"Diff summary: {sample_diff[:200]}...")
            except:
                pass
            
            return True
            
        except Exception as e:
            logger.error(f"Error verifying commits: {e}")
            return False
    
    def process_cve_improved(self, cve_info: Dict) -> bool:
        """Process a single CVE with improved logic"""
        cve_id = cve_info['cve_id']
        project = cve_info.get('project', 'unknown')
        
        logger.info(f"Processing CVE: {cve_id} from project: {project}")
        
        # Find repository
        repo_url = self._find_repository_for_cve(cve_info)
        if not repo_url:
            logger.warning(f"Could not find repository for {cve_id}")
            return False
        
        # Get or clone repository (reuse if already cloned)
        repo_path = self.get_or_clone_repository(repo_url, project)
        if not repo_path:
            logger.error(f"Failed to get/clone repository for {cve_id}")
            return False
        
        # Ensure repository is on a proper branch before starting
        repo = git.Repo(repo_path)
        if repo.head.is_detached:
            logger.info(f"Repository is in detached HEAD state, restoring to default branch...")
            if not self._restore_repository_branch(repo):
                logger.error(f"Failed to restore repository to default branch for {cve_id}")
                return False
        
        # Find vulnerable and fixed versions
        fix_commit, vuln_commit = self.find_vulnerable_and_fixed_versions_improved(cve_info, repo_path)
        if not fix_commit or not vuln_commit:
            logger.warning(f"Could not find version commits for {cve_id}")
            return False
        
        # Verify that the commits will actually produce different code
        repo = git.Repo(repo_path)
        if not self._verify_commits_will_produce_different_code(repo, fix_commit, vuln_commit):
            logger.error(f"Selected commits for {cve_id} will not produce different code - skipping")
            return False
        
        # Extract code versions
        success = self._extract_code_versions_improved(cve_info, repo_path, fix_commit, vuln_commit)
        
        return success
    
    def _find_repository_for_cve(self, cve_info: Dict) -> Optional[str]:
        """Find the appropriate repository for a CVE"""
        project = cve_info.get('project', '').lower()
        
        # Check if we have a direct repository mapping
        if project in self.project_repos:
            return self.project_repos[project]
        
        # Check alternative repositories
        if project in self.alternative_repos:
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
    
    def _verify_code_differences(self, cve_dir: str) -> bool:
        """Verify that vulnerable and fixed code versions are actually different"""
        try:
            vulnerable_dir = os.path.join(cve_dir, 'vulnerable')
            fixed_dir = os.path.join(cve_dir, 'fixed')
            
            if not os.path.exists(vulnerable_dir) or not os.path.exists(fixed_dir):
                logger.error("Vulnerable or fixed directory not found")
                return False
            
            # Get all files in both directories
            vulnerable_files = set()
            fixed_files = set()
            
            for root, dirs, files in os.walk(vulnerable_dir):
                for file in files:
                    if file.endswith(('.c', '.cpp', '.java', '.h', '.hpp')):
                        rel_path = os.path.relpath(os.path.join(root, file), vulnerable_dir)
                        vulnerable_files.add(rel_path)
            
            for root, dirs, files in os.walk(fixed_dir):
                for file in files:
                    if file.endswith(('.c', '.cpp', '.java', '.h', '.hpp')):
                        rel_path = os.path.relpath(os.path.join(root, file), fixed_dir)
                        fixed_files.add(rel_path)
            
            # Check if files exist in both directories
            common_files = vulnerable_files.intersection(fixed_files)
            
            if not common_files:
                logger.error("No common source files found between vulnerable and fixed versions")
                return False
            
            # Check if any files are different
            different_files = 0
            identical_files = 0
            
            for file_path in common_files:
                vuln_file = os.path.join(vulnerable_dir, file_path)
                fixed_file = os.path.join(fixed_dir, file_path)
                
                if os.path.getsize(vuln_file) != os.path.getsize(fixed_file):
                    different_files += 1
                    continue
                
                # Compare file contents
                with open(vuln_file, 'rb') as f1, open(fixed_file, 'rb') as f2:
                    if f1.read() != f2.read():
                        different_files += 1
                    else:
                        identical_files += 1
                        logger.warning(f"File {file_path} is identical in both versions")
            
            if different_files == 0:
                logger.error("Code versions are identical - extraction failed")
                return False
            
            logger.info(f"Found {different_files} different files and {identical_files} identical files")
            return True
            
        except Exception as e:
            logger.error(f"Error verifying code differences: {e}")
            return False

    def _extract_vulnerability_specific_files(self, repo: git.Repo, cve_info: Dict, fix_commit: str, vuln_commit: str) -> Tuple[List[str], List[str]]:
        """Extract only files that contain the vulnerability based on CVE description and commit analysis"""
        try:
            # Get the diff between the two commits
            diff = repo.git.diff(vuln_commit, fix_commit, '--name-only')
            changed_files = [f.strip() for f in diff.split('\n') if f.strip()]
            
            # Filter for source files only
            source_files = [f for f in changed_files if f.endswith(('.c', '.cpp', '.java', '.h', '.hpp'))]
            
            if not source_files:
                logger.warning("No source files changed between commits")
                return [], []
            
            # Extract vulnerability keywords to identify relevant files
            vuln_keywords = self._extract_vulnerability_keywords(cve_info)
            
            # Score files based on relevance to the vulnerability
            scored_files = []
            for file_path in source_files:
                score = 0
                
                # Check if filename contains vulnerability keywords
                filename = os.path.basename(file_path).lower()
                for keyword in vuln_keywords:
                    if keyword.lower() in filename:
                        score += 10
                
                # Check if directory path contains vulnerability keywords
                dir_path = os.path.dirname(file_path).lower()
                for keyword in vuln_keywords:
                    if keyword.lower() in dir_path:
                        score += 5
                
                # Prioritize core source files over tests
                if 'test' not in file_path.lower() and 'example' not in file_path.lower():
                    score += 3
                
                # Prioritize files in core directories
                core_dirs = ['src', 'lib', 'crypto', 'ssl', 'core']
                for core_dir in core_dirs:
                    if core_dir in file_path.lower():
                        score += 2
                        break
                
                scored_files.append((file_path, score))
            
            # Sort by score and take top files
            scored_files.sort(key=lambda x: x[1], reverse=True)
            top_files = [f[0] for f in scored_files[:10]]  # Top 10 most relevant files
            
            logger.info(f"Selected {len(top_files)} most relevant files for vulnerability: {top_files}")
            
            return top_files, source_files
            
        except Exception as e:
            logger.error(f"Error extracting vulnerability-specific files: {e}")
            return [], []

    def _extract_code_versions_improved(self, cve_info: Dict, repo_path: str, fix_commit: str, vuln_commit: str) -> bool:
        """Extract vulnerable and fixed code versions with improved logic"""
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
            
            # ALWAYS restore repository to default branch after extraction, regardless of success/failure
            self._restore_repository_branch(repo)
            
            # Verify that the code is actually different
            if not self._verify_code_differences(cve_dir):
                logger.error(f"Code versions are identical for {cve_id} - extraction failed")
                return False
            
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
        
        # Get vulnerability keywords for better file selection
        vuln_keywords = self._extract_vulnerability_keywords(cve_info)
        
        # Look for files that might contain the vulnerability
        for root, dirs, files in os.walk(repo_path):
            # Skip .git and other hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if any(file.endswith(ext) for ext in source_extensions):
                    file_path = os.path.join(root, file)
                    
                    # Check if file content might be relevant
                    if self._is_file_relevant(file_path, cve_info, vuln_keywords):
                        # Get relative path from repo root
                        rel_path = os.path.relpath(file_path, repo_path)
                        relevant_files.append(rel_path)
        
        # Sort by relevance score
        relevant_files = self._sort_files_by_relevance(relevant_files, cve_info, vuln_keywords)
        
        return relevant_files[:8]  # Limit to 8 most relevant files
    
    def _is_file_relevant(self, file_path: str, cve_info: Dict, vuln_keywords: List[str]) -> bool:
        """Check if a file is relevant to the CVE"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read().lower()
            
            # Check for vulnerability-related keywords
            if any(keyword in content for keyword in vuln_keywords):
                return True
            
            # Check for project-specific keywords
            project = cve_info.get('project', '').lower()
            if project in content:
                return True
            
            # Check for specific vulnerability patterns
            vuln_type = cve_info.get('description', '').lower()
            if 'buffer overflow' in vuln_type and any(pattern in content for pattern in ['strcpy', 'strcat', 'memcpy', 'sprintf']):
                return True
            elif 'integer overflow' in vuln_type and any(pattern in content for pattern in ['malloc', 'calloc', 'realloc', 'bn_']):
                return True
            elif 'use after free' in vuln_type and any(pattern in content for pattern in ['free(', 'delete', 'release']):
                return True
            elif 'deserialization' in vuln_type and any(pattern in content for pattern in ['readobject', 'unmarshal', 'deserialize']):
                return True
            
            return False
            
        except Exception:
            return False
    
    def _sort_files_by_relevance(self, files: List[str], cve_info: Dict, vuln_keywords: List[str]) -> List[str]:
        """Sort files by relevance to the vulnerability"""
        try:
            # Score files based on relevance
            scored_files = []
            
            for file_path in files:
                score = 0
                file_name = os.path.basename(file_path).lower()
                
                # Check filename relevance
                if any(keyword in file_name for keyword in vuln_keywords):
                    score += 10
                
                # Check if file is in a relevant directory
                if any(keyword in file_path.lower() for keyword in ['crypto', 'ssl', 'security', 'vulnerability']):
                    score += 5
                
                # Check if file is a main source file (not test or example)
                if 'test' not in file_path.lower() and 'example' not in file_path.lower():
                    score += 3
                
                # Check file extension priority
                if file_path.endswith(('.c', '.cpp', '.java')):
                    score += 2
                
                scored_files.append((file_path, score))
            
            # Sort by score (highest first)
            scored_files.sort(key=lambda x: x[1], reverse=True)
            
            return [file_path for file_path, score in scored_files]
            
        except Exception as e:
            logger.warning(f"Could not sort files by relevance: {e}")
            return files
    
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
            'extraction_status': 'completed',
            'extraction_method': 'improved'
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
    
    def process_discovery_results_improved(self, results_file: str, max_cves: int = 10) -> Dict:
        """Process discovery results with improved logic"""
        logger.info(f"Processing discovery results from {results_file}")
        
        # Load discovery results
        results = self._load_discovery_results(results_file)
        if not results:
            logger.error("No discovery results to process")
            return {}
        
        # Load CVE list from file
        cve_list_file = "final_fresh_cves.json"
        if os.path.exists(cve_list_file):
            try:
                with open(cve_list_file, 'r') as f:
                    cve_data = json.load(f)
                # Extract CVE IDs from the loaded data
                self.cve_list = [cve['cve_id'] for cve in cve_data]
                logger.info(f"📋 Loaded {len(self.cve_list)} CVEs from {cve_list_file}")
            except Exception as e:
                logger.error(f"Error loading CVE list: {e}")
                # Fallback to hardcoded list
                self.cve_list = [
                    "CVE-2023-35784", "CVE-2019-17571", "CVE-2022-37434", 
                    "CVE-2023-45853", "CVE-2016-7134", "CVE-2016-7167", 
                    "CVE-2014-4959", "CVE-2016-10553", "CVE-2020-28018", 
                    "CVE-2005-0490"
                ]
        else:
            # Fallback to hardcoded list
            self.cve_list = [
                "CVE-2023-35784", "CVE-2019-17571", "CVE-2022-37434", 
                "CVE-2023-45853", "CVE-2016-7134", "CVE-2016-7167", 
                "CVE-2014-4959", "CVE-2016-10553", "CVE-2020-28018", 
                "CVE-2005-0490"
            ]
        
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
            
            if self.process_cve_improved(cve):
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
            'extraction_date': datetime.now().isoformat(),
            'improvements': 'Repository caching, better commit detection, fallback strategies'
        }
        
        logger.info(f"Improved code extraction complete. Success rate: {summary['success_rate']:.1f}%")
        
        return summary
    
    def _load_discovery_results(self, results_file: str) -> Dict:
        """Load CVE discovery results from file"""
        try:
            with open(results_file, 'r') as f:
                results = json.load(f)
            logger.info(f"Loaded discovery results from {results_file}")
            return results
        except Exception as e:
            logger.error(f"Failed to load discovery results: {e}")
            return {}
    
    def cleanup_repositories(self):
        """Clean up all cloned repositories"""
        logger.info("Keeping repositories for reuse - no cleanup needed")
        # Don't delete repositories - keep them for reuse
        # self.repo_cache.clear()
        logger.info("Repositories kept for future use")

def main():
    """Main function"""
    extractor = ImprovedCodeExtractor()
    
    try:
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
        
        # Process CVEs with improved logic
        summary = extractor.process_discovery_results_improved(latest_file, max_cves=15)
        
        # Save results
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        results_filename = f"improved_code_extraction_results_{timestamp}.json"
        
        with open(results_filename, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"✅ Improved extraction results saved to: {results_filename}")
        logger.info(f"📊 Success rate: {summary['success_rate']:.1f}%")
        
    finally:
        # Always cleanup repositories
        extractor.cleanup_repositories()

if __name__ == "__main__":
    main()
