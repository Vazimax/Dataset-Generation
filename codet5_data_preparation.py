#!/usr/bin/env python3
"""
CodeT5 Data Preparation for Vulnerability Variant Generation

This script prepares our 363 critical CVEs for CodeT5 fine-tuning,
creating training data in the format required for transformer models.

Author: AI Assistant
Date: 2024
"""

import json
import os
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('codet5_data_preparation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class CodeT5TrainingSample:
    """CodeT5 training sample"""
    input_text: str
    target_text: str
    cve_id: str
    cwe_id: str
    severity: str
    vulnerability_type: str
    original_code: str
    fixed_code: str
    variant_code: Optional[str] = None

@dataclass
class CodeT5Dataset:
    """CodeT5 dataset structure"""
    samples: List[CodeT5TrainingSample]
    metadata: Dict
    statistics: Dict

class CodeT5DataPreparation:
    """Prepare data for CodeT5 training"""
    
    def __init__(self):
        self.training_samples = []
        self.dataset_metadata = {}
        self.statistics = {}
    
    def load_cve_dataset(self, dataset_path: str) -> Dict:
        """Load the critical CVE dataset"""
        
        logger.info(f"📂 Loading CVE dataset from {dataset_path}")
        
        try:
            with open(dataset_path, 'r') as f:
                dataset = json.load(f)
            
            logger.info(f"✅ Loaded dataset with {len(dataset.get('samples', []))} samples")
            return dataset
            
        except FileNotFoundError:
            logger.error(f"❌ Dataset file not found: {dataset_path}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON decode error: {str(e)}")
            return {}
        except Exception as e:
            logger.error(f"❌ Error loading dataset: {str(e)}")
            return {}
    
    def create_training_prompts(self, vulnerable_code: str, fixed_code: str, 
                              cve_id: str, cwe_id: str) -> List[Tuple[str, str]]:
        """Create training prompts for CodeT5"""
        
        prompts = []
        
        # Prompt 1: Vulnerability to Fix
        input_1 = f"Fix vulnerability in CVE-{cve_id} (CWE-{cwe_id}):\n{vulnerable_code}"
        target_1 = fixed_code
        prompts.append((input_1, target_1))
        
        # Prompt 2: Code Improvement
        input_2 = f"Improve this vulnerable code (CVE-{cve_id}):\n{vulnerable_code}"
        target_2 = fixed_code
        prompts.append((input_2, target_2))
        
        # Prompt 3: Security Fix
        input_3 = f"Apply security fix for CWE-{cwe_id}:\n{vulnerable_code}"
        target_3 = fixed_code
        prompts.append((input_3, target_3))
        
        # Prompt 4: Vulnerability Description
        vulnerability_desc = self._get_vulnerability_description(cwe_id)
        input_4 = f"Fix {vulnerability_desc} in:\n{vulnerable_code}"
        target_4 = fixed_code
        prompts.append((input_4, target_4))
        
        return prompts
    
    def _get_vulnerability_description(self, cwe_id: str) -> str:
        """Get vulnerability description for CWE"""
        
        descriptions = {
            'CWE-119': 'buffer overflow vulnerability',
            'CWE-787': 'out-of-bounds write vulnerability',
            'CWE-78': 'command injection vulnerability',
            'CWE-134': 'format string vulnerability',
            'CWE-190': 'integer overflow vulnerability',
            'CWE-476': 'NULL pointer dereference vulnerability',
            'CWE-416': 'use-after-free vulnerability',
            'CWE-20': 'input validation vulnerability',
            'CWE-79': 'cross-site scripting vulnerability',
            'CWE-89': 'SQL injection vulnerability'
        }
        
        return descriptions.get(cwe_id, 'security vulnerability')
    
    def create_variant_prompts(self, vulnerable_code: str, cve_id: str, 
                             cwe_id: str) -> List[Tuple[str, str]]:
        """Create prompts for generating variants"""
        
        prompts = []
        
        # Prompt 1: Generate Variant
        input_1 = f"Generate a variant of this vulnerable code (CVE-{cve_id}):\n{vulnerable_code}"
        target_1 = self._generate_simple_variant(vulnerable_code)
        prompts.append((input_1, target_1))
        
        # Prompt 2: Obfuscate Code
        input_2 = f"Obfuscate this vulnerable code while preserving the vulnerability:\n{vulnerable_code}"
        target_2 = self._generate_obfuscated_variant(vulnerable_code)
        prompts.append((input_2, target_2))
        
        # Prompt 3: Restructure Code
        input_3 = f"Restructure this code while maintaining the vulnerability:\n{vulnerable_code}"
        target_3 = self._generate_restructured_variant(vulnerable_code)
        prompts.append((input_3, target_3))
        
        return prompts
    
    def _generate_simple_variant(self, code: str) -> str:
        """Generate a simple variant by renaming variables"""
        
        # Simple variable renaming
        replacements = {
            'buf': 'buffer',
            'len': 'length',
            'str': 'string',
            'ptr': 'pointer',
            'data': 'payload',
            'size': 'capacity',
            'input': 'user_input',
            'output': 'result'
        }
        
        variant = code
        for old, new in replacements.items():
            variant = re.sub(r'\b' + old + r'\b', new, variant)
        
        return variant
    
    def _generate_obfuscated_variant(self, code: str) -> str:
        """Generate an obfuscated variant"""
        
        # Add misleading comments and variable names
        variant = code
        
        # Add misleading comments
        variant = variant.replace('//', '// This is safe code that validates input properly')
        
        # Rename variables to look safe
        variant = re.sub(r'\bbuf\b', 'safe_buffer', variant)
        variant = re.sub(r'\bstrcpy\b', 'secure_copy', variant)
        variant = re.sub(r'\bsprintf\b', 'safe_format', variant)
        
        return variant
    
    def _generate_restructured_variant(self, code: str) -> str:
        """Generate a restructured variant"""
        
        # Split into multiple functions
        variant = code
        
        # Add function wrapper
        if 'int main(' in variant:
            variant = variant.replace('int main(', 'int safe_main(')
            variant = 'int main() {\n    return safe_main();\n}\n\n' + variant
        
        return variant
    
    def prepare_training_data(self, dataset: Dict) -> List[CodeT5TrainingSample]:
        """Prepare training data from CVE dataset"""
        
        logger.info("🔄 Preparing training data...")
        
        samples = dataset.get('samples', [])
        training_samples = []
        
        for i, sample in enumerate(samples):
            cve_id = sample.get('cve_id', f'sample_{i}')
            cwe_id = sample.get('cwe_id', 'CWE-119')
            severity = sample.get('severity', 'HIGH')
            vulnerable_code = sample.get('vulnerable_code', '')
            fixed_code = sample.get('fixed_code', '')
            
            if not vulnerable_code or not fixed_code:
                logger.warning(f"Skipping {cve_id} - missing code")
                continue
            
            # Create vulnerability-to-fix training samples
            fix_prompts = self.create_training_prompts(vulnerable_code, fixed_code, cve_id, cwe_id)
            
            for input_text, target_text in fix_prompts:
                training_sample = CodeT5TrainingSample(
                    input_text=input_text,
                    target_text=target_text,
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    severity=severity,
                    vulnerability_type=cwe_id,
                    original_code=vulnerable_code,
                    fixed_code=fixed_code
                )
                training_samples.append(training_sample)
            
            # Create variant generation training samples
            variant_prompts = self.create_variant_prompts(vulnerable_code, cve_id, cwe_id)
            
            for input_text, target_text in variant_prompts:
                training_sample = CodeT5TrainingSample(
                    input_text=input_text,
                    target_text=target_text,
                    cve_id=cve_id,
                    cwe_id=cwe_id,
                    severity=severity,
                    vulnerability_type=cwe_id,
                    original_code=vulnerable_code,
                    fixed_code=fixed_code,
                    variant_code=target_text
                )
                training_samples.append(training_sample)
            
            if (i + 1) % 50 == 0:
                logger.info(f"Processed {i + 1}/{len(samples)} samples")
        
        logger.info(f"✅ Created {len(training_samples)} training samples")
        return training_samples
    
    def calculate_statistics(self, training_samples: List[CodeT5TrainingSample]) -> Dict:
        """Calculate dataset statistics"""
        
        logger.info("📊 Calculating dataset statistics...")
        
        total_samples = len(training_samples)
        
        # Count by CWE
        cwe_counts = {}
        severity_counts = {}
        input_lengths = []
        target_lengths = []
        
        for sample in training_samples:
            # CWE counts
            cwe_counts[sample.cwe_id] = cwe_counts.get(sample.cwe_id, 0) + 1
            
            # Severity counts
            severity_counts[sample.severity] = severity_counts.get(sample.severity, 0) + 1
            
            # Length statistics
            input_lengths.append(len(sample.input_text))
            target_lengths.append(len(sample.target_text))
        
        statistics = {
            'total_samples': total_samples,
            'unique_cves': len(set(sample.cve_id for sample in training_samples)),
            'cwe_distribution': cwe_counts,
            'severity_distribution': severity_counts,
            'input_length_stats': {
                'min': min(input_lengths),
                'max': max(input_lengths),
                'avg': sum(input_lengths) / len(input_lengths)
            },
            'target_length_stats': {
                'min': min(target_lengths),
                'max': max(target_lengths),
                'avg': sum(target_lengths) / len(target_lengths)
            }
        }
        
        return statistics
    
    def save_training_data(self, training_samples: List[CodeT5TrainingSample], 
                          output_dir: str) -> bool:
        """Save training data in various formats"""
        
        logger.info(f"💾 Saving training data to {output_dir}")
        
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            # Save as JSON
            json_data = []
            for sample in training_samples:
                json_data.append({
                    'input_text': sample.input_text,
                    'target_text': sample.target_text,
                    'cve_id': sample.cve_id,
                    'cwe_id': sample.cwe_id,
                    'severity': sample.severity,
                    'vulnerability_type': sample.vulnerability_type,
                    'original_code': sample.original_code,
                    'fixed_code': sample.fixed_code,
                    'variant_code': sample.variant_code
                })
            
            with open(f"{output_dir}/codet5_training_data.json", 'w') as f:
                json.dump(json_data, f, indent=2)
            
            # Save as text files for easy loading
            with open(f"{output_dir}/inputs.txt", 'w') as f:
                for sample in training_samples:
                    f.write(sample.input_text + "\n")
            
            with open(f"{output_dir}/targets.txt", 'w') as f:
                for sample in training_samples:
                    f.write(sample.target_text + "\n")
            
            # Save metadata
            metadata = {
                'total_samples': len(training_samples),
                'creation_date': datetime.now().isoformat(),
                'description': 'CodeT5 training data for vulnerability variant generation',
                'statistics': self.statistics
            }
            
            with open(f"{output_dir}/metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logger.info(f"✅ Training data saved successfully")
            return True
            
        except Exception as e:
            logger.error(f"❌ Error saving training data: {str(e)}")
            return False
    
    def create_dataset_splits(self, training_samples: List[CodeT5TrainingSample], 
                             train_ratio: float = 0.8, val_ratio: float = 0.1) -> Tuple[List, List, List]:
        """Create train/validation/test splits"""
        
        logger.info("📊 Creating dataset splits...")
        
        total_samples = len(training_samples)
        train_size = int(total_samples * train_ratio)
        val_size = int(total_samples * val_ratio)
        
        train_samples = training_samples[:train_size]
        val_samples = training_samples[train_size:train_size + val_size]
        test_samples = training_samples[train_size + val_size:]
        
        logger.info(f"✅ Dataset splits created:")
        logger.info(f"  - Training: {len(train_samples)} samples")
        logger.info(f"  - Validation: {len(val_samples)} samples")
        logger.info(f"  - Test: {len(test_samples)} samples")
        
        return train_samples, val_samples, test_samples
    
    def prepare_complete_dataset(self, dataset_path: str, output_dir: str) -> bool:
        """Complete dataset preparation pipeline"""
        
        logger.info("🚀 Starting complete dataset preparation...")
        
        # Load dataset
        dataset = self.load_cve_dataset(dataset_path)
        if not dataset:
            return False
        
        # Prepare training data
        training_samples = self.prepare_training_data(dataset)
        if not training_samples:
            logger.error("❌ No training samples created")
            return False
        
        # Calculate statistics
        self.statistics = self.calculate_statistics(training_samples)
        
        # Create dataset splits
        train_samples, val_samples, test_samples = self.create_dataset_splits(training_samples)
        
        # Save all splits
        self.save_training_data(train_samples, f"{output_dir}/train")
        self.save_training_data(val_samples, f"{output_dir}/validation")
        self.save_training_data(test_samples, f"{output_dir}/test")
        
        # Save complete dataset
        self.save_training_data(training_samples, f"{output_dir}/complete")
        
        logger.info("✅ Complete dataset preparation finished")
        return True

def main():
    """Main function for data preparation"""
    
    print("📊 CodeT5 Data Preparation for Vulnerability Variant Generation")
    print("=" * 70)
    
    # Initialize data preparation system
    data_prep = CodeT5DataPreparation()
    
    # Dataset paths
    dataset_path = 'complete_critical_cves_training_dataset.json'
    output_dir = './data/codet5_training'
    
    # Check if dataset exists
    if not os.path.exists(dataset_path):
        print(f"❌ Dataset not found: {dataset_path}")
        print("Please ensure the critical CVE dataset is available.")
        return
    
    # Run complete dataset preparation
    success = data_prep.prepare_complete_dataset(dataset_path, output_dir)
    
    if success:
        print(f"\n🎉 Data preparation completed successfully!")
        print(f"📁 Training data saved to: {output_dir}")
        print(f"📊 Total samples: {data_prep.statistics.get('total_samples', 0)}")
        print(f"🔢 Unique CVEs: {data_prep.statistics.get('unique_cves', 0)}")
        
        print(f"\n📈 CWE Distribution:")
        for cwe, count in data_prep.statistics.get('cwe_distribution', {}).items():
            print(f"  - {cwe}: {count} samples")
        
        print(f"\n🎯 Next Steps:")
        print(f"  - Training data ready for CodeT5 fine-tuning")
        print(f"  - Dataset splits created (train/validation/test)")
        print(f"  - Ready for model training")
    else:
        print(f"\n❌ Data preparation failed. Check the logs for details.")

if __name__ == "__main__":
    main()
