#!/usr/bin/env python3
"""
Analyze Existing CVEs Script

This script analyzes the existing CVEs in the dataset to understand their patterns
and extract detailed vulnerability information for better dataset construction.
"""

import os
import json
import re
from typing import Dict, List, Optional
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ExistingCVEAnalyzer:
    def __init__(self, dataset_dir: str = "dataset"):
        self.dataset_dir = dataset_dir
        self.analysis_results = {}
        
    def analyze_cve_directory(self, cve_dir: str) -> Dict:
        """Analyze a single CVE directory"""
        cve_id = os.path.basename(cve_dir)
        logger.info(f"Analyzing {cve_id}")
        
        analysis = {
            'cve_id': cve_id,
            'files': {},
            'vulnerability_patterns': [],
            'code_analysis': {},
            'metadata': {},
            'analysis_status': 'pending'
        }
        
        # Check for metadata.json
        metadata_file = os.path.join(cve_dir, 'metadata.json')
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    analysis['metadata'] = json.load(f)
                logger.info(f"Loaded metadata for {cve_id}")
            except Exception as e:
                logger.error(f"Failed to load metadata for {cve_id}: {e}")
        
        # Analyze source code files
        for filename in os.listdir(cve_dir):
            file_path = os.path.join(cve_dir, filename)
            if os.path.isfile(file_path) and filename.endswith(('.c', '.cpp', '.h', '.hpp')):
                analysis['files'][filename] = self.analyze_source_file(file_path)
        
        # Analyze vulnerability patterns
        analysis['vulnerability_patterns'] = self.identify_vulnerability_patterns(analysis)
        
        # Update analysis status
        analysis['analysis_status'] = 'completed'
        
        return analysis
    
    def analyze_source_file(self, file_path: str) -> Dict:
        """Analyze a single source code file"""
        filename = os.path.basename(file_path)
        logger.info(f"Analyzing source file: {filename}")
        
        analysis = {
            'filename': filename,
            'file_size': os.path.getsize(file_path),
            'lines_of_code': 0,
            'functions': [],
            'vulnerability_indicators': [],
            'complexity_metrics': {}
        }
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
                analysis['lines_of_code'] = len(lines)
                
                # Extract functions
                analysis['functions'] = self.extract_functions(content)
                
                # Look for vulnerability indicators
                analysis['vulnerability_indicators'] = self.find_vulnerability_indicators(content)
                
                # Calculate complexity metrics
                analysis['complexity_metrics'] = self.calculate_complexity_metrics(content)
                
        except Exception as e:
            logger.error(f"Failed to analyze {filename}: {e}")
            analysis['error'] = str(e)
        
        return analysis
    
    def extract_functions(self, content: str) -> List[Dict]:
        """Extract function definitions from C/C++ code"""
        functions = []
        
        # C function pattern
        c_function_pattern = r'(\w+\s+)?(\w+)\s*\([^)]*\)\s*\{'
        c_matches = re.finditer(c_function_pattern, content)
        
        for match in c_matches:
            return_type = match.group(1).strip() if match.group(1) else 'void'
            function_name = match.group(2)
            
            functions.append({
                'name': function_name,
                'return_type': return_type,
                'type': 'c_function'
            })
        
        # C++ method pattern
        cpp_method_pattern = r'(\w+\s+)?(\w+::\w+)\s*\([^)]*\)\s*\{'
        cpp_matches = re.finditer(cpp_method_pattern, content)
        
        for match in cpp_matches:
            return_type = match.group(1).strip() if match.group(1) else 'void'
            method_name = match.group(2)
            
            functions.append({
                'name': method_name,
                'return_type': return_type,
                'type': 'cpp_method'
            })
        
        return functions
    
    def find_vulnerability_indicators(self, content: str) -> List[Dict]:
        """Find potential vulnerability indicators in the code"""
        indicators = []
        
        # Buffer overflow indicators
        buffer_patterns = [
            (r'strcpy\s*\([^,]+,\s*[^)]+\)', 'strcpy_usage', 'Buffer overflow risk'),
            (r'strcat\s*\([^,]+,\s*[^)]+\)', 'strcat_usage', 'Buffer overflow risk'),
            (r'sprintf\s*\([^,]+,\s*[^)]+\)', 'sprintf_usage', 'Format string vulnerability risk'),
            (r'gets\s*\([^)]+\)', 'gets_usage', 'Buffer overflow risk'),
            (r'memcpy\s*\([^,]+,\s*[^,]+,\s*[^)]+\)', 'memcpy_usage', 'Buffer overflow risk'),
            (r'memset\s*\([^,]+,\s*[^,]+,\s*[^)]+\)', 'memset_usage', 'Buffer overflow risk')
        ]
        
        for pattern, indicator_type, description in buffer_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                indicators.append({
                    'type': indicator_type,
                    'description': description,
                    'line': line_num,
                    'code': match.group(0),
                    'severity': 'high'
                })
        
        # Integer overflow indicators
        integer_patterns = [
            (r'(\w+)\s*\*\s*(\w+)', 'multiplication', 'Potential integer overflow'),
            (r'(\w+)\s*\+\s*(\w+)', 'addition', 'Potential integer overflow'),
            (r'(\w+)\s*-\s*(\w+)', 'subtraction', 'Potential integer underflow')
        ]
        
        for pattern, indicator_type, description in integer_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                indicators.append({
                    'type': indicator_type,
                    'description': description,
                    'line': line_num,
                    'code': match.group(0),
                    'severity': 'medium'
                })
        
        # Memory management indicators
        memory_patterns = [
            (r'malloc\s*\([^)]+\)', 'malloc_usage', 'Memory allocation'),
            (r'free\s*\([^)]+\)', 'free_usage', 'Memory deallocation'),
            (r'new\s+\w+', 'new_usage', 'C++ memory allocation'),
            (r'delete\s+\w+', 'delete_usage', 'C++ memory deallocation')
        ]
        
        for pattern, indicator_type, description in memory_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                indicators.append({
                    'type': indicator_type,
                    'description': description,
                    'line': line_num,
                    'code': match.group(0),
                    'severity': 'medium'
                })
        
        # Loop indicators
        loop_patterns = [
            (r'while\s*\([^)]+\)', 'while_loop', 'Potential infinite loop'),
            (r'for\s*\([^)]+\)', 'for_loop', 'Loop structure'),
            (r'do\s*\{[^}]*\}\s*while\s*\([^)]+\)', 'do_while_loop', 'Loop structure')
        ]
        
        for pattern, indicator_type, description in loop_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                line_num = content[:match.start()].count('\n') + 1
                indicators.append({
                    'type': indicator_type,
                    'description': description,
                    'line': line_num,
                    'code': match.group(0),
                    'severity': 'low'
                })
        
        return indicators
    
    def calculate_complexity_metrics(self, content: str) -> Dict:
        """Calculate code complexity metrics"""
        metrics = {
            'cyclomatic_complexity': 0,
            'nesting_depth': 0,
            'function_count': 0,
            'comment_ratio': 0.0
        }
        
        lines = content.split('\n')
        total_lines = len(lines)
        comment_lines = 0
        
        # Count comment lines
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                comment_lines += 1
        
        metrics['comment_ratio'] = comment_lines / total_lines if total_lines > 0 else 0.0
        
        # Count functions
        metrics['function_count'] = len(self.extract_functions(content))
        
        # Calculate cyclomatic complexity (simplified)
        # Count decision points
        decision_patterns = [
            r'\bif\b', r'\belse\b', r'\bwhile\b', r'\bfor\b', r'\bdo\b',
            r'\bcase\b', r'\bcatch\b', r'\b&&\b', r'\b\|\|\b'
        ]
        
        for pattern in decision_patterns:
            matches = re.findall(pattern, content)
            metrics['cyclomatic_complexity'] += len(matches)
        
        # Add base complexity
        metrics['cyclomatic_complexity'] += 1
        
        return metrics
    
    def identify_vulnerability_patterns(self, analysis: Dict) -> List[Dict]:
        """Identify vulnerability patterns based on analysis"""
        patterns = []
        
        # Analyze vulnerability indicators across all files
        all_indicators = []
        for file_analysis in analysis['files'].values():
            all_indicators.extend(file_analysis.get('vulnerability_indicators', []))
        
        # Group indicators by type
        indicator_groups = {}
        for indicator in all_indicators:
            indicator_type = indicator['type']
            if indicator_type not in indicator_groups:
                indicator_groups[indicator_type] = []
            indicator_groups[indicator_type].append(indicator)
        
        # Identify patterns
        for indicator_type, indicators in indicator_groups.items():
            if len(indicators) > 0:
                # Determine pattern severity
                max_severity = max(indicator['severity'] for indicator in indicators)
                
                pattern = {
                    'type': indicator_type,
                    'count': len(indicators),
                    'severity': max_severity,
                    'locations': [indicator['line'] for indicator in indicators],
                    'description': indicators[0]['description']
                }
                
                patterns.append(pattern)
        
        return patterns
    
    def analyze_all_cves(self) -> Dict:
        """Analyze all existing CVEs in the dataset"""
        logger.info("Starting analysis of all existing CVEs...")
        
        if not os.path.exists(self.dataset_dir):
            logger.error(f"Dataset directory not found: {self.dataset_dir}")
            return {}
        
        # Get all CVE directories
        cve_dirs = []
        for item in os.listdir(self.dataset_dir):
            item_path = os.path.join(self.dataset_dir, item)
            if os.path.isdir(item_path) and item.startswith('CVE-'):
                cve_dirs.append(item_path)
        
        logger.info(f"Found {len(cve_dirs)} CVE directories to analyze")
        
        # Analyze each CVE
        for cve_dir in cve_dirs:
            try:
                analysis = self.analyze_cve_directory(cve_dir)
                cve_id = analysis['cve_id']
                self.analysis_results[cve_id] = analysis
                logger.info(f"Completed analysis of {cve_id}")
            except Exception as e:
                logger.error(f"Failed to analyze {cve_dir}: {e}")
        
        return self.analysis_results
    
    def generate_analysis_report(self) -> str:
        """Generate a comprehensive analysis report"""
        if not self.analysis_results:
            return "No analysis results available."
        
        report = f"""# Existing CVE Analysis Report

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
- **Total CVEs Analyzed**: {len(self.analysis_results)}
- **Analysis Status**: Complete

## CVE Analysis Results
"""
        
        for cve_id, analysis in self.analysis_results.items():
            report += f"\n### {cve_id}\n"
            
            # Basic info
            if 'metadata' in analysis and analysis['metadata']:
                metadata = analysis['metadata']
                report += f"- **Project**: {metadata.get('project', 'Unknown')}\n"
                report += f"- **Vulnerability Type**: {metadata.get('vulnerability_type', 'Unknown')}\n"
                report += f"- **CVSS Score**: {metadata.get('cvss_score', 'Unknown')}\n"
            
            # File analysis
            if 'files' in analysis:
                report += f"- **Files**: {len(analysis['files'])}\n"
                for filename, file_analysis in analysis['files'].items():
                    report += f"  - {filename}: {file_analysis.get('lines_of_code', 0)} lines, "
                    report += f"{len(file_analysis.get('functions', []))} functions\n"
            
            # Vulnerability patterns
            if 'vulnerability_patterns' in analysis:
                patterns = analysis['vulnerability_patterns']
                if patterns:
                    report += f"- **Vulnerability Patterns**: {len(patterns)}\n"
                    for pattern in patterns:
                        report += f"  - {pattern['type']}: {pattern['count']} instances ({pattern['severity']} severity)\n"
            
            # Complexity metrics
            if 'files' in analysis:
                total_complexity = 0
                for file_analysis in analysis['files'].values():
                    total_complexity += file_analysis.get('complexity_metrics', {}).get('cyclomatic_complexity', 0)
                if total_complexity > 0:
                    report += f"- **Total Cyclomatic Complexity**: {total_complexity}\n"
        
        # Summary statistics
        report += "\n## Summary Statistics\n"
        
        # Count by vulnerability type
        vuln_types = {}
        for analysis in self.analysis_results.values():
            if 'metadata' in analysis and analysis['metadata']:
                vuln_type = analysis['metadata'].get('vulnerability_type', 'Unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        report += "\n### Vulnerability Types\n"
        for vuln_type, count in vuln_types.items():
            report += f"- **{vuln_type}**: {count}\n"
        
        # Count by project
        projects = {}
        for analysis in self.analysis_results.values():
            if 'metadata' in analysis and analysis['metadata']:
                project = analysis['metadata'].get('project', 'Unknown')
                projects[project] = projects.get(project, 0) + 1
        
        report += "\n### Projects\n"
        for project, count in projects.items():
            report += f"- **{project}**: {count}\n"
        
        report += f"""

## Recommendations
1. **High Priority**: Focus on CVEs with high cyclomatic complexity and multiple vulnerability indicators
2. **Pattern Analysis**: Use identified patterns to guide LLM variant generation
3. **Code Extraction**: Replace placeholder files with actual vulnerable and fixed code
4. **Validation**: Implement full validation pipeline for all collected CVEs

## Next Steps
1. Prioritize CVEs based on analysis results
2. Extract actual source code from repositories
3. Implement validation pipeline
4. Begin LLM-guided variant generation
"""
        
        return report
    
    def save_analysis_results(self, filename: str = None):
        """Save analysis results to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cve_analysis_results_{timestamp}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.analysis_results, f, indent=2)
            logger.info(f"Analysis results saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save analysis results: {e}")
    
    def save_analysis_report(self, report: str, filename: str = None):
        """Save analysis report to file"""
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"cve_analysis_report_{timestamp}.md"
        
        try:
            with open(filename, 'w') as f:
                f.write(report)
            logger.info(f"Analysis report saved to: {filename}")
        except Exception as e:
            logger.error(f"Failed to save analysis report: {e}")

def main():
    """Main function"""
    analyzer = ExistingCVEAnalyzer()
    
    # Analyze all existing CVEs
    logger.info("Starting CVE analysis...")
    results = analyzer.analyze_all_cves()
    
    # Save results
    analyzer.save_analysis_results()
    
    # Generate and save report
    report = analyzer.generate_analysis_report()
    analyzer.save_analysis_report(report)
    
    logger.info("Analysis complete!")

if __name__ == "__main__":
    main()
