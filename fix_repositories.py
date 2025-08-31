#!/usr/bin/env python3
"""
Fix detached HEAD repositories by checking out proper branches.
"""

import os
import subprocess
import logging
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def fix_repository(repo_path):
    """Fix a single repository by checking out the proper branch."""
    try:
        # Change to repository directory
        os.chdir(repo_path)
        
        # Check current status
        result = subprocess.run(['git', 'status', '--porcelain'], 
                              capture_output=True, text=True, check=True)
        
        # Check if HEAD is detached
        result = subprocess.run(['git', 'rev-parse', '--abbrev-ref', 'HEAD'], 
                              capture_output=True, text=True, check=True)
        current_branch = result.stdout.strip()
        
        if current_branch == 'HEAD':
            logger.info(f"Fixing detached HEAD in {repo_path}")
            
            # Get available branches
            result = subprocess.run(['git', 'branch', '-a'], 
                                  capture_output=True, text=True, check=True)
            branches = result.stdout.strip().split('\n')
            
            # Look for default branches
            default_branches = ['main', 'master', 'develop', 'dev']
            target_branch = None
            
            for branch in default_branches:
                if any(f'remotes/origin/{branch}' in b for b in branches):
                    target_branch = branch
                    break
            
            if target_branch:
                # Checkout the target branch
                subprocess.run(['git', 'checkout', target_branch], check=True)
                logger.info(f"Successfully checked out {target_branch} in {repo_path}")
            else:
                logger.warning(f"No default branch found in {repo_path}")
        else:
            logger.info(f"Repository {repo_path} is already on branch: {current_branch}")
            
    except subprocess.CalledProcessError as e:
        logger.error(f"Error fixing repository {repo_path}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error fixing repository {repo_path}: {e}")

def main():
    """Fix all repositories in the temp_repos directory."""
    temp_repos_dir = Path("temp_repos")
    
    if not temp_repos_dir.exists():
        logger.info("No temp_repos directory found")
        return
    
    repositories = [d for d in temp_repos_dir.iterdir() if d.is_dir()]
    
    if not repositories:
        logger.info("No repositories found in temp_repos")
        return
    
    logger.info(f"Found {len(repositories)} repositories to fix")
    
    for repo_path in repositories:
        if (repo_path / '.git').exists():
            logger.info(f"Processing repository: {repo_path.name}")
            fix_repository(repo_path)
        else:
            logger.info(f"Skipping {repo_path.name} - not a git repository")
    
    logger.info("Repository fixing complete")

if __name__ == "__main__":
    main()
