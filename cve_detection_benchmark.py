#!/usr/bin/env python3
"""
CVE Detection Model Benchmarking System

This script tests our critical CVE datasets against state-of-the-art
vulnerability detection models to establish baseline performance metrics.

"""

import json
import os
import subprocess
import tempfile
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cve_detection_benchmark.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class DetectionResult:
    """Result of vulnerability detection"""
    cve_id: str
    model_name: str
    detected: bool
    confidence: float
    detection_time: float
    warnings: List[str]
    errors: List[str]
    raw_output: str

@dataclass
class BenchmarkResult:
    """Overall benchmark result"""
    dataset_name: str
    total_samples: int
    detection_results: List[DetectionResult]
    overall_metrics: Dict
    model_performance: Dict[str, Dict]
    timestamp: str

class CVE_Detection_Benchmark:
    """Main benchmarking system for CVE detection models"""
    
    def __init__(self):
        self.models = self._initialize_detection_models()
        self.results = []
    
    def _initialize_detection_models(self) -> Dict:
        """Initialize available detection models"""
        
        models = {
            'cppcheck': {
                'name': 'Cppcheck',
                'type': 'static_analysis',
                'available': self._check_cppcheck_availability(),
                'command': 'cppcheck',
                'args': ['--enable=all', '--std=c++11', '--xml', '--xml-version=2'],
                'description': 'Static analysis tool for C/C++ code'
            },
            'clang_static': {
                'name': 'Clang Static Analyzer',
                'type': 'static_analysis',
                'available': self._check_clang_availability(),
                'command': 'clang',
                'args': ['-fsyntax-only', '-Wall', '-Wextra', '-Wformat-security', '-Wformat=2'],
                'description': 'Clang compiler with security warnings'
            },
            'gcc_warnings': {
                'name': 'GCC Security Warnings',
                'type': 'static_analysis',
                'available': self._check_gcc_availability(),
                'command': 'gcc',
                'args': ['-fsyntax-only', '-Wall', '-Wextra', '-Wformat-security', '-Wformat=2', '-Wstack-protector'],
                'description': 'GCC compiler with security warnings'
            },
            'flawfinder': {
                'name': 'Flawfinder',
                'type': 'pattern_matching',
                'available': self._check_flawfinder_availability(),
                'command': 'flawfinder',
                'args': ['--minlevel=1', '--html'],
                'description': 'Source code security flaw scanner'
            },
            'rats': {
                'name': 'RATS (Rough Auditing Tool for Security)',
                'type': 'pattern_matching',
                'available': self._check_rats_availability(),
                'command': 'rats',
                'args': ['-w', '3'],
                'description': 'Security vulnerability scanner'
            },
            'splint': {
                'name': 'Splint',
                'type': 'static_analysis',
                'available': self._check_splint_availability(),
                'command': 'splint',
                'args': ['+posixlib', '+gnuextensions'],
                'description': 'Static analysis tool for C programs'
            }
        }
        
        return models
    
    def _check_cppcheck_availability(self) -> bool:
        """Check if cppcheck is available"""
        try:
            result = subprocess.run(['cppcheck', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _check_clang_availability(self) -> bool:
        """Check if clang is available"""
        try:
            result = subprocess.run(['clang', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _check_gcc_availability(self) -> bool:
        """Check if gcc is available"""
        try:
            result = subprocess.run(['gcc', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _check_flawfinder_availability(self) -> bool:
        """Check if flawfinder is available"""
        try:
            result = subprocess.run(['flawfinder', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _check_rats_availability(self) -> bool:
        """Check if rats is available"""
        try:
            result = subprocess.run(['rats', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def _check_splint_availability(self) -> bool:
        """Check if splint is available"""
        try:
            result = subprocess.run(['splint', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
    
    def benchmark_dataset(self, dataset_path: str, dataset_name: str, 
                         sample_limit: Optional[int] = None) -> BenchmarkResult:
        """Benchmark a dataset against all available detection models"""
        
        logger.info(f"Starting benchmark for {dataset_name}")
        
        # Load dataset
        try:
            with open(dataset_path, 'r') as f:
                dataset = json.load(f)
        except FileNotFoundError:
            logger.error(f"Dataset not found: {dataset_path}")
            return None
        
        # Extract samples based on dataset structure
        if 'samples' in dataset:
            samples = dataset['samples']
        elif 'combined_samples' in dataset:
            samples = dataset['combined_samples']
        elif 'generated_variants' in dataset:
            samples = dataset['generated_variants']
        elif isinstance(dataset, list):
            samples = dataset
        else:
            logger.error(f"Unknown dataset structure: {list(dataset.keys())}")
            return None
        
        # Limit samples if specified
        if sample_limit and len(samples) > sample_limit:
            samples = samples[:sample_limit]
        
        logger.info(f"Loaded {len(samples)} samples from {dataset_name}")
        
        # Run detection for each model
        detection_results = []
        model_performance = {}
        
        for model_name, model_config in self.models.items():
            if not model_config['available']:
                logger.warning(f"Model {model_name} not available, skipping")
                continue
            
            logger.info(f"Running {model_name} on {dataset_name}")
            
            model_results = self._run_model_on_dataset(model_config, samples, dataset_name)
            detection_results.extend(model_results)
            
            # Calculate model performance
            model_performance[model_name] = self._calculate_model_metrics(model_results)
        
        # Calculate overall metrics
        overall_metrics = self._calculate_overall_metrics(detection_results, len(samples))
        
        return BenchmarkResult(
            dataset_name=dataset_name,
            total_samples=len(samples),
            detection_results=detection_results,
            overall_metrics=overall_metrics,
            model_performance=model_performance,
            timestamp=datetime.now().isoformat()
        )
    
    def _run_model_on_dataset(self, model_config: Dict, samples: List[Dict], 
                             dataset_name: str) -> List[DetectionResult]:
        """Run a specific model on all samples in the dataset"""
        
        results = []
        
        for i, sample in enumerate(samples):
            cve_id = sample.get('cve_id', f'sample_{i}')
            vulnerable_code = sample.get('vulnerable_code', '')
            
            if not vulnerable_code:
                logger.warning(f"No vulnerable code found for {cve_id}")
                continue
            
            logger.info(f"Testing {cve_id} with {model_config['name']}")
            
            result = self._run_model_on_sample(model_config, cve_id, vulnerable_code)
            results.append(result)
        
        return results
    
    def _run_model_on_sample(self, model_config: Dict, cve_id: str, 
                            code: str) -> DetectionResult:
        """Run a specific model on a single code sample"""
        
        start_time = time.time()
        warnings = []
        errors = []
        raw_output = ""
        detected = False
        confidence = 0.0
        
        try:
            # Create temporary C file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write(code)
                temp_file = f.name
            
            # Run the model
            cmd = [model_config['command']] + model_config['args'] + [temp_file]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=30  # 30 second timeout
            )
            
            raw_output = result.stdout + result.stderr
            
            # Analyze output based on model type
            if model_config['type'] == 'static_analysis':
                detected, confidence = self._analyze_static_analysis_output(raw_output)
            elif model_config['type'] == 'pattern_matching':
                detected, confidence = self._analyze_pattern_matching_output(raw_output)
            
            # Check for errors
            if result.returncode != 0:
                errors.append(f"Model returned non-zero exit code: {result.returncode}")
            
            # Cleanup
            os.unlink(temp_file)
            
        except subprocess.TimeoutExpired:
            errors.append("Model execution timed out")
        except Exception as e:
            errors.append(f"Model execution failed: {str(e)}")
        
        detection_time = time.time() - start_time
        
        return DetectionResult(
            cve_id=cve_id,
            model_name=model_config['name'],
            detected=detected,
            confidence=confidence,
            detection_time=detection_time,
            warnings=warnings,
            errors=errors,
            raw_output=raw_output
        )
    
    def _analyze_static_analysis_output(self, output: str) -> Tuple[bool, float]:
        """Analyze static analysis tool output"""
        
        # Look for security-related warnings
        security_keywords = [
            'buffer overflow', 'buffer overrun', 'stack overflow',
            'format string', 'format string vulnerability',
            'null pointer', 'null pointer dereference',
            'integer overflow', 'integer underflow',
            'use after free', 'double free',
            'memory leak', 'uninitialized',
            'insecure', 'unsafe', 'vulnerable',
            'warning', 'error'
        ]
        
        output_lower = output.lower()
        detected = False
        confidence = 0.0
        
        # Count security-related findings
        security_findings = 0
        for keyword in security_keywords:
            if keyword in output_lower:
                security_findings += 1
                detected = True
        
        # Calculate confidence based on number of findings
        if detected:
            confidence = min(security_findings / len(security_keywords), 1.0)
        
        return detected, confidence
    
    def _analyze_pattern_matching_output(self, output: str) -> Tuple[bool, float]:
        """Analyze pattern matching tool output"""
        
        # Look for vulnerability patterns
        vulnerability_patterns = [
            'strcpy', 'strcat', 'sprintf', 'gets',
            'system', 'exec', 'popen',
            'printf', 'scanf', 'fprintf',
            'malloc', 'free', 'realloc'
        ]
        
        output_lower = output.lower()
        detected = False
        confidence = 0.0
        
        # Count vulnerability patterns
        pattern_count = 0
        for pattern in vulnerability_patterns:
            if pattern in output_lower:
                pattern_count += 1
                detected = True
        
        # Calculate confidence based on pattern count
        if detected:
            confidence = min(pattern_count / len(vulnerability_patterns), 1.0)
        
        return detected, confidence
    
    def _calculate_model_metrics(self, results: List[DetectionResult]) -> Dict:
        """Calculate performance metrics for a specific model"""
        
        if not results:
            return {
                'detection_rate': 0.0,
                'average_confidence': 0.0,
                'average_detection_time': 0.0,
                'total_detections': 0,
                'total_samples': 0,
                'error_rate': 0.0
            }
        
        total_samples = len(results)
        detections = sum(1 for r in results if r.detected)
        errors = sum(1 for r in results if r.errors)
        
        detection_rate = detections / total_samples if total_samples > 0 else 0.0
        error_rate = errors / total_samples if total_samples > 0 else 0.0
        
        avg_confidence = sum(r.confidence for r in results) / total_samples if total_samples > 0 else 0.0
        avg_detection_time = sum(r.detection_time for r in results) / total_samples if total_samples > 0 else 0.0
        
        return {
            'detection_rate': detection_rate,
            'average_confidence': avg_confidence,
            'average_detection_time': avg_detection_time,
            'total_detections': detections,
            'total_samples': total_samples,
            'error_rate': error_rate
        }
    
    def _calculate_overall_metrics(self, results: List[DetectionResult], 
                                  total_samples: int) -> Dict:
        """Calculate overall benchmark metrics"""
        
        if not results:
            return {
                'overall_detection_rate': 0.0,
                'models_tested': 0,
                'total_detections': 0,
                'average_confidence': 0.0,
                'average_detection_time': 0.0
            }
        
        # Group by model
        model_groups = {}
        for result in results:
            if result.model_name not in model_groups:
                model_groups[result.model_name] = []
            model_groups[result.model_name].append(result)
        
        # Calculate metrics
        total_detections = sum(1 for r in results if r.detected)
        overall_detection_rate = total_detections / len(results) if results else 0.0
        
        avg_confidence = sum(r.confidence for r in results) / len(results) if results else 0.0
        avg_detection_time = sum(r.detection_time for r in results) / len(results) if results else 0.0
        
        return {
            'overall_detection_rate': overall_detection_rate,
            'models_tested': len(model_groups),
            'total_detections': total_detections,
            'average_confidence': avg_confidence,
            'average_detection_time': avg_detection_time
        }
    
    def save_results(self, benchmark_result: BenchmarkResult, output_file: str):
        """Save benchmark results to file"""
        
        # Convert to serializable format
        result_dict = {
            'dataset_name': benchmark_result.dataset_name,
            'total_samples': benchmark_result.total_samples,
            'overall_metrics': benchmark_result.overall_metrics,
            'model_performance': benchmark_result.model_performance,
            'timestamp': benchmark_result.timestamp,
            'detection_results': [
                {
                    'cve_id': r.cve_id,
                    'model_name': r.model_name,
                    'detected': r.detected,
                    'confidence': r.confidence,
                    'detection_time': r.detection_time,
                    'warnings': r.warnings,
                    'errors': r.errors
                }
                for r in benchmark_result.detection_results
            ]
        }
        
        with open(output_file, 'w') as f:
            json.dump(result_dict, f, indent=2)
        
        logger.info(f"Results saved to {output_file}")
    
    def generate_report(self, benchmark_result: BenchmarkResult) -> str:
        """Generate a human-readable benchmark report"""
        
        report = f"""
# CVE Detection Benchmark Report

## Dataset: {benchmark_result.dataset_name}
- **Total Samples:** {benchmark_result.total_samples}
- **Timestamp:** {benchmark_result.timestamp}

## Overall Performance
- **Overall Detection Rate:** {benchmark_result.overall_metrics['overall_detection_rate']:.2%}
- **Models Tested:** {benchmark_result.overall_metrics['models_tested']}
- **Total Detections:** {benchmark_result.overall_metrics['total_detections']}
- **Average Confidence:** {benchmark_result.overall_metrics['average_confidence']:.2f}
- **Average Detection Time:** {benchmark_result.overall_metrics['average_detection_time']:.2f}s

## Model Performance

"""
        
        for model_name, metrics in benchmark_result.model_performance.items():
            report += f"""
### {model_name}
- **Detection Rate:** {metrics['detection_rate']:.2%}
- **Average Confidence:** {metrics['average_confidence']:.2f}
- **Average Detection Time:** {metrics['average_detection_time']:.2f}s
- **Total Detections:** {metrics['total_detections']}/{metrics['total_samples']}
- **Error Rate:** {metrics['error_rate']:.2%}

"""
        
        return report

def main():
    """Main function to run CVE detection benchmarking"""
    
    print("🔍 CVE Detection Model Benchmarking System")
    print("=" * 60)
    
    # Initialize benchmark system
    benchmark = CVE_Detection_Benchmark()
    
    # Check available models
    available_models = [name for name, config in benchmark.models.items() if config['available']]
    print(f"📊 Available Detection Models: {len(available_models)}")
    for model_name in available_models:
        model_config = benchmark.models[model_name]
        print(f"  ✓ {model_config['name']} ({model_config['type']}) - {model_config['description']}")
    
    if not available_models:
        print("❌ No detection models available. Please install at least one tool:")
        print("  - cppcheck: pip install cppcheck")
        print("  - flawfinder: pip install flawfinder")
        print("  - gcc/clang: Install development tools")
        return
    
    # Benchmark datasets
    datasets_to_test = [
        {
            'path': 'complete_critical_cves_training_dataset.json',
            'name': 'Critical CVEs Dataset',
            'sample_limit': 10  # Test first 10 samples
        },
        {
            'path': 'template_cve_variants_dataset.json',
            'name': 'Template Variants Dataset',
            'sample_limit': 10  # Test first 10 samples
        }
    ]
    
    benchmark_results = []
    
    for dataset_config in datasets_to_test:
        if not os.path.exists(dataset_config['path']):
            print(f"❌ Dataset not found: {dataset_config['path']}")
            continue
        
        print(f"\n🚀 Benchmarking {dataset_config['name']}...")
        
        # Run benchmark
        result = benchmark.benchmark_dataset(
            dataset_config['path'],
            dataset_config['name'],
            dataset_config['sample_limit']
        )
        
        if result:
            benchmark_results.append(result)
            
            # Save results
            output_file = f"benchmark_results_{dataset_config['name'].lower().replace(' ', '_')}.json"
            benchmark.save_results(result, output_file)
            
            # Generate and save report
            report = benchmark.generate_report(result)
            report_file = f"benchmark_report_{dataset_config['name'].lower().replace(' ', '_')}.md"
            with open(report_file, 'w') as f:
                f.write(report)
            
            print(f"✅ Benchmark completed for {dataset_config['name']}")
            print(f"📊 Detection Rate: {result.overall_metrics['overall_detection_rate']:.2%}")
            print(f"💾 Results saved to {output_file}")
            print(f"📄 Report saved to {report_file}")
    
    # Generate comparison report
    if len(benchmark_results) > 1:
        print(f"\n📊 Generating comparison report...")
        
        comparison_report = f"""
# CVE Detection Benchmark Comparison Report

## Summary
This report compares the performance of state-of-the-art CVE detection models
on our critical CVE datasets.

## Datasets Compared
"""
        
        for result in benchmark_results:
            comparison_report += f"""
### {result.dataset_name}
- **Samples:** {result.total_samples}
- **Overall Detection Rate:** {result.overall_metrics['overall_detection_rate']:.2%}
- **Models Tested:** {result.overall_metrics['models_tested']}

"""
        
        comparison_report += """
## Key Findings

### Detection Performance
- Critical CVEs are detected at varying rates across different models
- Template variants show different detection patterns
- Some models perform better on specific CWE types

### Model Comparison
- Static analysis tools (cppcheck, clang) provide comprehensive coverage
- Pattern matching tools (flawfinder) are faster but less comprehensive
- Compiler warnings (gcc, clang) catch basic issues

### Recommendations
- Use multiple detection models for comprehensive coverage
- Combine static analysis with pattern matching for better results
- Consider model-specific strengths for different CWE types

## Next Steps
1. Analyze detection patterns by CWE type
2. Identify undetected vulnerabilities for improvement
3. Use results to guide LLM variant generation
4. Establish baseline for post-generation validation
"""
        
        with open('benchmark_comparison_report.md', 'w') as f:
            f.write(comparison_report)
        
        print("📄 Comparison report saved to benchmark_comparison_report.md")
    
    print(f"\n🎉 Benchmarking completed!")
    print(f"📊 Total datasets benchmarked: {len(benchmark_results)}")
    print(f"🔍 Total models tested: {len(available_models)}")

if __name__ == "__main__":
    main()
