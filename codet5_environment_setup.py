#!/usr/bin/env python3
"""
CodeT5 Environment Setup and Data Preparation

This script sets up the CodeT5 environment, installs dependencies,
and prepares the 363 CVEs for fine-tuning.

Author: AI Assistant
Date: 2024
"""

import os
import subprocess
import json
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import tempfile

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('codet5_environment_setup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class CodeT5Environment:
    """CodeT5 environment configuration"""
    model_name: str
    tokenizer_name: str
    max_length: int
    batch_size: int
    learning_rate: float
    num_epochs: int
    warmup_steps: int
    output_dir: str

class CodeT5EnvironmentSetup:
    """Setup CodeT5 environment and prepare data"""
    
    def __init__(self):
        self.environment = self._initialize_environment()
        self.dependencies = self._initialize_dependencies()
        self.setup_results = {}
    
    def _initialize_environment(self) -> CodeT5Environment:
        """Initialize CodeT5 environment configuration"""
        
        return CodeT5Environment(
            model_name="Salesforce/codet5-base",
            tokenizer_name="Salesforce/codet5-base",
            max_length=512,
            batch_size=8,
            learning_rate=5e-5,
            num_epochs=3,
            warmup_steps=100,
            output_dir="./codet5-vulnerability-model"
        )
    
    def _initialize_dependencies(self) -> Dict[str, str]:
        """Initialize required dependencies"""
        
        return {
            'transformers': '4.35.0',
            'torch': '2.1.0',
            'datasets': '2.14.0',
            'accelerate': '0.24.0',
            'evaluate': '0.4.0',
            'wandb': '0.16.0',
            'numpy': '1.24.0',
            'pandas': '2.0.0',
            'scikit-learn': '1.3.0',
            'tqdm': '4.66.0',
            'matplotlib': '3.7.0',
            'seaborn': '0.12.0'
        }
    
    def install_dependencies(self) -> Dict[str, bool]:
        """Install required dependencies"""
        
        logger.info("📦 Installing CodeT5 dependencies...")
        installation_results = {}
        
        for package, version in self.dependencies.items():
            logger.info(f"Installing {package}=={version}")
            
            try:
                # Install with specific version
                result = subprocess.run(
                    ['pip', 'install', f'{package}=={version}'],
                    capture_output=True, text=True, timeout=300
                )
                
                installation_results[package] = result.returncode == 0
                
                if result.returncode == 0:
                    logger.info(f"✅ {package} installed successfully")
                else:
                    logger.warning(f"⚠️ {package} installation failed: {result.stderr}")
                    
            except subprocess.TimeoutExpired:
                logger.error(f"❌ {package} installation timed out")
                installation_results[package] = False
            except Exception as e:
                logger.error(f"❌ {package} installation error: {str(e)}")
                installation_results[package] = False
        
        return installation_results
    
    def verify_installation(self) -> Dict[str, bool]:
        """Verify that all dependencies are properly installed"""
        
        logger.info("🔍 Verifying CodeT5 installation...")
        verification_results = {}
        
        # Test imports
        import_tests = {
            'transformers': 'from transformers import T5ForConditionalGeneration, T5Tokenizer',
            'torch': 'import torch',
            'datasets': 'import datasets',
            'accelerate': 'import accelerate',
            'evaluate': 'import evaluate',
            'wandb': 'import wandb',
            'numpy': 'import numpy',
            'pandas': 'import pandas',
            'sklearn': 'import sklearn',
            'tqdm': 'import tqdm',
            'matplotlib': 'import matplotlib',
            'seaborn': 'import seaborn'
        }
        
        for package, import_statement in import_tests.items():
            try:
                exec(import_statement)
                verification_results[package] = True
                logger.info(f"✅ {package} import successful")
            except ImportError as e:
                verification_results[package] = False
                logger.error(f"❌ {package} import failed: {str(e)}")
            except Exception as e:
                verification_results[package] = False
                logger.error(f"❌ {package} verification error: {str(e)}")
        
        return verification_results
    
    def test_codet5_model(self) -> bool:
        """Test CodeT5 model loading and basic functionality"""
        
        logger.info("🧪 Testing CodeT5 model...")
        
        try:
            from transformers import T5ForConditionalGeneration, T5Tokenizer
            
            # Load model and tokenizer
            logger.info("Loading CodeT5 model and tokenizer...")
            model = T5ForConditionalGeneration.from_pretrained(self.environment.model_name)
            tokenizer = T5Tokenizer.from_pretrained(self.environment.tokenizer_name)
            
            # Test basic functionality
            test_code = "int main() { return 0; }"
            inputs = tokenizer(test_code, return_tensors="pt", max_length=512, truncation=True)
            
            # Test generation
            with torch.no_grad():
                outputs = model.generate(
                    inputs.input_ids,
                    max_length=100,
                    num_return_sequences=1,
                    temperature=0.7,
                    do_sample=True
                )
            
            generated_text = tokenizer.decode(outputs[0], skip_special_tokens=True)
            logger.info(f"✅ CodeT5 model test successful. Generated: {generated_text[:50]}...")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ CodeT5 model test failed: {str(e)}")
            return False
    
    def create_output_directories(self) -> bool:
        """Create necessary output directories"""
        
        logger.info("📁 Creating output directories...")
        
        directories = [
            self.environment.output_dir,
            f"{self.environment.output_dir}/checkpoints",
            f"{self.environment.output_dir}/logs",
            f"{self.environment.output_dir}/generated_variants",
            f"{self.environment.output_dir}/evaluation_results",
            "./data/codet5_training",
            "./data/codet5_validation",
            "./data/codet5_test"
        ]
        
        try:
            for directory in directories:
                os.makedirs(directory, exist_ok=True)
                logger.info(f"✅ Created directory: {directory}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Directory creation failed: {str(e)}")
            return False
    
    def setup_environment(self) -> Dict[str, bool]:
        """Complete environment setup"""
        
        logger.info("🚀 Starting CodeT5 environment setup...")
        
        setup_results = {}
        
        # Install dependencies
        logger.info("Step 1: Installing dependencies...")
        installation_results = self.install_dependencies()
        setup_results['dependencies_installed'] = all(installation_results.values())
        
        # Verify installation
        logger.info("Step 2: Verifying installation...")
        verification_results = self.verify_installation()
        setup_results['installation_verified'] = all(verification_results.values())
        
        # Test CodeT5 model
        logger.info("Step 3: Testing CodeT5 model...")
        setup_results['model_tested'] = self.test_codet5_model()
        
        # Create directories
        logger.info("Step 4: Creating output directories...")
        setup_results['directories_created'] = self.create_output_directories()
        
        # Overall success
        setup_results['overall_success'] = all(setup_results.values())
        
        return setup_results
    
    def generate_setup_report(self) -> str:
        """Generate setup report"""
        
        report = f"""
# CodeT5 Environment Setup Report

## Setup Summary
- **Setup Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Model:** {self.environment.model_name}
- **Tokenizer:** {self.environment.tokenizer_name}
- **Max Length:** {self.environment.max_length}
- **Batch Size:** {self.environment.batch_size}
- **Learning Rate:** {self.environment.learning_rate}
- **Epochs:** {self.environment.num_epochs}
- **Output Directory:** {self.environment.output_dir}

## Setup Results
- **Dependencies Installed:** {self.setup_results.get('dependencies_installed', False)}
- **Installation Verified:** {self.setup_results.get('installation_verified', False)}
- **Model Tested:** {self.setup_results.get('model_tested', False)}
- **Directories Created:** {self.setup_results.get('directories_created', False)}
- **Overall Success:** {self.setup_results.get('overall_success', False)}

## Dependencies
"""
        
        for package, version in self.dependencies.items():
            report += f"- **{package}:** {version}\n"
        
        return report

def main():
    """Main function to setup CodeT5 environment"""
    
    print("🤖 CodeT5 Environment Setup")
    print("=" * 50)
    
    # Initialize setup system
    setup_system = CodeT5EnvironmentSetup()
    
    # Run setup
    setup_results = setup_system.setup_environment()
    
    # Print results
    print("\n📊 Setup Results:")
    for step, result in setup_results.items():
        status = "✅ SUCCESS" if result else "❌ FAILED"
        print(f"  {step}: {status}")
    
    # Generate and save report
    report = setup_system.generate_setup_report()
    with open('codet5_environment_setup_report.md', 'w') as f:
        f.write(report)
    
    print(f"\n📄 Setup report saved to: codet5_environment_setup_report.md")
    
    # Print next steps
    if setup_results.get('overall_success', False):
        print(f"\n🎯 Next Steps:")
        print(f"  - Environment setup complete")
        print(f"  - Ready for data preparation")
        print(f"  - Ready for CodeT5 fine-tuning")
    else:
        print(f"\n⚠️ Setup incomplete. Check the setup report for details.")

if __name__ == "__main__":
    main()
