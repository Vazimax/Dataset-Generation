#!/usr/bin/env python3
"""
Simplified CodeT5 Setup for Vulnerability Variant Generation

This script sets up a minimal but functional CodeT5 environment
for generating vulnerability variants from our 363 CVEs.

"""

import os
import subprocess
import json
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('codet5_simplified_setup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class SimplifiedCodeT5Config:
    """Simplified CodeT5 configuration"""
    model_name: str = "Salesforce/codet5-base"
    tokenizer_name: str = "Salesforce/codet5-base"
    max_length: int = 512
    batch_size: int = 4
    learning_rate: float = 5e-5
    num_epochs: int = 3
    output_dir: str = "./codet5-vulnerability-model"

class SimplifiedCodeT5Setup:
    """Simplified CodeT5 setup focusing on essential components"""
    
    def __init__(self):
        self.config = SimplifiedCodeT5Config()
        self.essential_dependencies = {
            'transformers': '4.35.0',
            'torch': '2.1.0',
            'sentencepiece': '0.2.1',
            'numpy': '1.24.0',
            'tqdm': '4.66.0'
        }
        self.setup_results = {}
    
    def install_essential_dependencies(self) -> Dict[str, bool]:
        """Install only essential dependencies"""
        
        logger.info("📦 Installing essential CodeT5 dependencies...")
        installation_results = {}
        
        for package, version in self.essential_dependencies.items():
            logger.info(f"Installing {package}=={version}")
            
            try:
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
    
    def verify_essential_installation(self) -> Dict[str, bool]:
        """Verify essential dependencies"""
        
        logger.info("🔍 Verifying essential CodeT5 installation...")
        verification_results = {}
        
        # Test essential imports
        essential_tests = {
            'transformers': 'from transformers import T5ForConditionalGeneration, T5Tokenizer',
            'torch': 'import torch',
            'sentencepiece': 'import sentencepiece',
            'numpy': 'import numpy',
            'tqdm': 'import tqdm'
        }
        
        for package, import_statement in essential_tests.items():
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
            import torch
            
            # Load model and tokenizer
            logger.info("Loading CodeT5 model and tokenizer...")
            model = T5ForConditionalGeneration.from_pretrained(self.config.model_name)
            tokenizer = T5Tokenizer.from_pretrained(self.config.tokenizer_name)
            
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
            self.config.output_dir,
            f"{self.config.output_dir}/checkpoints",
            f"{self.config.output_dir}/logs",
            f"{self.config.output_dir}/generated_variants",
            f"{self.config.output_dir}/evaluation_results",
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
        """Complete simplified environment setup"""
        
        logger.info("🚀 Starting simplified CodeT5 environment setup...")
        
        setup_results = {}
        
        # Install essential dependencies
        logger.info("Step 1: Installing essential dependencies...")
        installation_results = self.install_essential_dependencies()
        setup_results['dependencies_installed'] = all(installation_results.values())
        
        # Verify installation
        logger.info("Step 2: Verifying installation...")
        verification_results = self.verify_essential_installation()
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
# Simplified CodeT5 Environment Setup Report

## Setup Summary
- **Setup Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Model:** {self.config.model_name}
- **Tokenizer:** {self.config.tokenizer_name}
- **Max Length:** {self.config.max_length}
- **Batch Size:** {self.config.batch_size}
- **Learning Rate:** {self.config.learning_rate}
- **Epochs:** {self.config.num_epochs}
- **Output Directory:** {self.config.output_dir}

## Setup Results
- **Dependencies Installed:** {self.setup_results.get('dependencies_installed', False)}
- **Installation Verified:** {self.setup_results.get('installation_verified', False)}
- **Model Tested:** {self.setup_results.get('model_tested', False)}
- **Directories Created:** {self.setup_results.get('directories_created', False)}
- **Overall Success:** {self.setup_results.get('overall_success', False)}

## Essential Dependencies
"""
        
        for package, version in self.essential_dependencies.items():
            report += f"- **{package}:** {version}\n"
        
        return report

def main():
    """Main function to setup simplified CodeT5 environment"""
    
    print("🤖 Simplified CodeT5 Environment Setup")
    print("=" * 50)
    
    # Initialize setup system
    setup_system = SimplifiedCodeT5Setup()
    
    # Run setup
    setup_results = setup_system.setup_environment()
    
    # Print results
    print("\n📊 Setup Results:")
    for step, result in setup_results.items():
        status = "✅ SUCCESS" if result else "❌ FAILED"
        print(f"  {step}: {status}")
    
    # Generate and save report
    report = setup_system.generate_setup_report()
    with open('codet5_simplified_setup_report.md', 'w') as f:
        f.write(report)
    
    print(f"\n📄 Setup report saved to: codet5_simplified_setup_report.md")
    
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
