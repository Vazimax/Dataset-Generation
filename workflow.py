#!/usr/bin/env python3
"""
Comprehensive CVE Dataset Generation Workflow

This script orchestrates the entire process from CVE discovery to code extraction,
providing a streamlined workflow to build the dataset.
"""

import os
import json
import time
from datetime import datetime
from typing import Dict, List
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CVEWorkflow:
    def __init__(self):
        self.workflow_status = {
            'start_time': None,
            'current_phase': 'not_started',
            'phases_completed': [],
            'phases_failed': [],
            'total_cves_discovered': 0,
            'total_cves_extracted': 0,
            'workflow_status': 'pending'
        }
        
        # Phase definitions
        self.phases = [
            {
                'name': 'discovery',
                'description': 'Discover high-quality CVEs from target projects',
                'script': 'expanded_cve_discovery.py',
                'output_files': ['expanded_cve_discovery_results_*.json', 'expanded_cve_discovery_report_*.md']
            },
            {
                'name': 'analysis',
                'description': 'Analyze existing and discovered CVEs',
                'script': 'analyze_existing_cves.py',
                'output_files': ['cve_analysis_results_*.json', 'cve_analysis_report_*.md']
            },
            {
                'name': 'extraction',
                'description': 'Extract vulnerable and fixed code from repositories',
                'script': 'code_extractor.py',
                'output_files': ['code_extraction_results_*.json', 'code_extraction_report_*.md']
            }
        ]
    
    def start_workflow(self):
        """Start the comprehensive workflow"""
        logger.info("🚀 Starting Comprehensive CVE Dataset Generation Workflow")
        logger.info("=" * 70)
        
        self.workflow_status['start_time'] = datetime.now().isoformat()
        self.workflow_status['current_phase'] = 'discovery'
        
        # Phase 1: Discovery
        if self._run_discovery_phase():
            self.workflow_status['phases_completed'].append('discovery')
            self.workflow_status['current_phase'] = 'analysis'
            
            # Phase 2: Analysis
            if self._run_analysis_phase():
                self.workflow_status['phases_completed'].append('analysis')
                self.workflow_status['current_phase'] = 'extraction'
                
                # Phase 3: Extraction
                if self._run_extraction_phase():
                    self.workflow_status['phases_completed'].append('extraction')
                    self.workflow_status['workflow_status'] = 'completed'
                else:
                    self.workflow_status['phases_failed'].append('extraction')
                    self.workflow_status['workflow_status'] = 'failed'
            else:
                self.workflow_status['phases_failed'].append('analysis')
                self.workflow_status['workflow_status'] = 'failed'
        else:
            self.workflow_status['phases_failed'].append('discovery')
            self.workflow_status['workflow_status'] = 'failed'
        
        # Generate final workflow report
        self._generate_workflow_report()
        
        logger.info("🏁 Workflow completed!")
        return self.workflow_status['workflow_status'] == 'completed'
    
    def _run_discovery_phase(self) -> bool:
        """Run the CVE discovery phase"""
        logger.info("\n📡 Phase 1: CVE Discovery")
        logger.info("-" * 40)
        
        try:
            logger.info("Running expanded CVE discovery...")
            start_time = time.time()
            
            # Import and run discovery
            from expanded_cve_discovery import ExpandedCVEDiscovery
            discovery = ExpandedCVEDiscovery()
            results = discovery.discover_expanded_cves()
            
            end_time = time.time()
            discovery_time = end_time - start_time
            
            # Save results
            discovery.save_discovery_results(results)
            report = discovery.generate_discovery_report(results)
            discovery.save_discovery_report(report)
            
            # Update workflow status
            self.workflow_status['total_cves_discovered'] = results['summary']['total_discovered']
            
            logger.info(f"✅ Discovery phase completed in {discovery_time:.1f} seconds")
            logger.info(f"📊 Discovered {results['summary']['total_discovered']} CVEs")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Discovery phase failed: {e}")
            return False
    
    def _run_analysis_phase(self) -> bool:
        """Run the CVE analysis phase"""
        logger.info("\n🔍 Phase 2: CVE Analysis")
        logger.info("-" * 40)
        
        try:
            logger.info("Analyzing existing and discovered CVEs...")
            start_time = time.time()
            
            # Import and run analysis
            from analyze_existing_cves import ExistingCVEAnalyzer
            analyzer = ExistingCVEAnalyzer()
            results = analyzer.analyze_all_cves()
            
            end_time = time.time()
            analysis_time = end_time - start_time
            
            # Save results
            analyzer.save_analysis_results()
            report = analyzer.generate_analysis_report()
            analyzer.save_analysis_report(report)
            
            logger.info(f"✅ Analysis phase completed in {analysis_time:.1f} seconds")
            logger.info(f"📊 Analyzed {len(results)} CVEs")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Analysis phase failed: {e}")
            return False
    
    def _run_extraction_phase(self) -> bool:
        """Run the code extraction phase"""
        logger.info("\n💻 Phase 3: Code Extraction")
        logger.info("-" * 40)
        
        try:
            logger.info("Extracting vulnerable and fixed code...")
            start_time = time.time()
            
            # Import and run extraction
            from code_extractor import CodeExtractor
            extractor = CodeExtractor()
            
            # Find the most recent discovery results
            discovery_files = [f for f in os.listdir('.') if f.startswith('expanded_cve_discovery_results_')]
            if not discovery_files:
                discovery_files = [f for f in os.listdir('.') if f.startswith('fast_cve_discovery_results_')]
            
            if not discovery_files:
                logger.error("No discovery results found for extraction")
                return False
            
            latest_file = max(discovery_files)
            logger.info(f"Using discovery results from: {latest_file}")
            
            # Process CVEs (limit to 10 for initial run)
            summary = extractor.process_discovery_results(latest_file, max_cves=10)
            
            end_time = time.time()
            extraction_time = end_time - start_time
            
            # Save results
            extractor.save_extraction_results(summary)
            report = extractor.generate_extraction_report(summary)
            extractor.save_extraction_report(report)
            
            # Update workflow status
            self.workflow_status['total_cves_extracted'] = summary['successful']
            
            logger.info(f"✅ Extraction phase completed in {extraction_time:.1f} seconds")
            logger.info(f"📊 Successfully extracted {summary['successful']} CVEs")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Extraction phase failed: {e}")
            return False
    
    def _generate_workflow_report(self):
        """Generate comprehensive workflow report"""
        logger.info("\n📋 Generating Workflow Report")
        
        end_time = datetime.now()
        start_time = datetime.fromisoformat(self.workflow_status['start_time'])
        total_duration = end_time - start_time
        
        report = f"""# Comprehensive CVE Dataset Generation Workflow Report

Generated: {end_time.strftime('%Y-%m-%d %H:%M:%S')}
Workflow Duration: {total_duration}

## Workflow Status
- **Overall Status**: {self.workflow_status['workflow_status'].upper()}
- **Start Time**: {start_time.strftime('%Y-%m-%d %H:%M:%S')}
- **End Time**: {end_time.strftime('%Y-%m-%d %H:%M:%S')}
- **Total Duration**: {total_duration}

## Phase Results
"""
        
        for phase in self.phases:
            phase_name = phase['name']
            if phase_name in self.workflow_status['phases_completed']:
                report += f"- ✅ **{phase_name.title()}**: Completed successfully\n"
            elif phase_name in self.workflow_status['phases_failed']:
                report += f"- ❌ **{phase_name.title()}**: Failed\n"
            else:
                report += f"- ⏳ **{phase_name.title()}**: Not completed\n"
        
        report += f"""

## Results Summary
- **Total CVEs Discovered**: {self.workflow_status['total_cves_discovered']}
- **Total CVEs Extracted**: {self.workflow_status['total_cves_extracted']}
- **Discovery Success Rate**: {self.workflow_status['total_cves_discovered']/50*100:.1f}% of minimum target (50)
- **Extraction Success Rate**: {self.workflow_status['total_cves_extracted']/max(1, self.workflow_status['total_cves_discovered'])*100:.1f}%

## Dataset Status
"""
        
        if os.path.exists('dataset'):
            cve_dirs = [d for d in os.listdir('dataset') if d.startswith('CVE-')]
            report += f"- **Total CVE Directories**: {len(cve_dirs)}\n"
            report += f"- **Dataset Location**: `dataset/`\n"
            
            if cve_dirs:
                report += "\n### CVE Directories:\n"
                for cve_dir in sorted(cve_dirs):
                    cve_path = os.path.join('dataset', cve_dir)
                    if os.path.exists(cve_path):
                        files = os.listdir(cve_path)
                        report += f"- **{cve_dir}**: {len(files)} files\n"
        else:
            report += "- **Dataset Directory**: Not created\n"
        
        report += f"""

## Next Steps
"""
        
        if self.workflow_status['workflow_status'] == 'completed':
            report += """1. **Review Extracted Code**: Verify quality and relevance
2. **Implement Validation Pipeline**: Set up angr and AFL++ for vulnerability validation
3. **Expand Dataset**: Continue with more CVEs to reach 50-100 target
4. **LLM Variant Generation**: Begin generating syntactic variants using verified CVEs
5. **Final Validation**: Ensure all variants pass security validation
"""
        else:
            failed_phases = self.workflow_status['phases_failed']
            report += f"""1. **Fix Failed Phases**: Address issues in {', '.join(failed_phases)}
2. **Rerun Workflow**: Execute workflow again after fixes
3. **Debug Issues**: Check logs and error messages for specific problems
"""
        
        report += f"""

## Files Generated
- **Discovery Results**: `expanded_cve_discovery_results_*.json`
- **Discovery Report**: `expanded_cve_discovery_report_*.md`
- **Analysis Results**: `cve_analysis_results_*.json`
- **Analysis Report**: `cve_analysis_report_*.md`
- **Extraction Results**: `code_extraction_results_*.json`
- **Extraction Report**: `code_extraction_report_*.md`
- **Workflow Report**: `workflow_report_*.md`

## Notes
- This workflow provides a foundation for building the CVE dataset
- Success depends on repository availability and code quality
- Some CVEs may require manual intervention for extraction
- Validation pipeline is the next major milestone
"""
        
        # Save workflow report
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_filename = f"workflow_report_{timestamp}.md"
        
        try:
            with open(report_filename, 'w') as f:
                f.write(report)
            logger.info(f"✅ Workflow report saved to: {report_filename}")
        except Exception as e:
            logger.error(f"❌ Failed to save workflow report: {e}")
        
        # Save workflow status
        status_filename = f"workflow_status_{timestamp}.json"
        try:
            with open(status_filename, 'w') as f:
                json.dump(self.workflow_status, f, indent=2)
            logger.info(f"✅ Workflow status saved to: {status_filename}")
        except Exception as e:
            logger.error(f"❌ Failed to save workflow status: {e}")
    
    def get_workflow_summary(self) -> str:
        """Get a brief summary of the workflow status"""
        if not self.workflow_status['start_time']:
            return "Workflow not started"
        
        completed = len(self.workflow_status['phases_completed'])
        failed = len(self.workflow_status['phases_failed'])
        total = len(self.phases)
        
        summary = f"""Workflow Status: {self.workflow_status['workflow_status'].upper()}
Phases: {completed}/{total} completed, {failed} failed
CVEs Discovered: {self.workflow_status['total_cves_discovered']}
CVEs Extracted: {self.workflow_status['total_cves_extracted']}
Current Phase: {self.workflow_status['current_phase']}"""
        
        return summary

def main():
    """Main function"""
    workflow = CVEWorkflow()
    
    logger.info("🎯 CVE Dataset Generation Workflow")
    logger.info("Target: 50-100 high-quality, weaponizable CVEs")
    logger.info("Final Goal: ~700 validated variants for detector testing")
    
    # Run the complete workflow
    success = workflow.start_workflow()
    
    if success:
        logger.info("🎉 Workflow completed successfully!")
        logger.info("\n" + workflow.get_workflow_summary())
    else:
        logger.error("❌ Workflow failed!")
        logger.info("\n" + workflow.get_workflow_summary())
    
    return success

if __name__ == "__main__":
    main()
