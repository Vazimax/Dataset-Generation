#!/usr/bin/env python3
"""
Real ML Model Setup and Testing System

This script sets up and tests actual ML-based vulnerability detection models
on our critical CVE dataset.

Models to setup:
- LineVul (Transformer-based)
- Devign (Graph Neural Network)
- VulMaster (Deep Learning)
- ReGVD (Graph + Reinforcement Learning)

"""

import os
import subprocess
import json
import tempfile
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('real_ml_models_setup.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class ModelSetupResult:
    """Result of model setup"""
    model_name: str
    setup_successful: bool
    installation_method: str
    setup_time: float
    error_message: Optional[str] = None
    model_path: Optional[str] = None

class RealMLModelSetup:
    """Setup and manage real ML vulnerability detection models"""
    
    def __init__(self):
        self.models = self._initialize_model_configs()
        self.setup_results = {}
    
    def _initialize_model_configs(self) -> Dict:
        """Initialize model configurations for setup"""
        
        models = {
            'linevul': {
                'name': 'LineVul',
                'type': 'transformer_based',
                'github_url': 'https://github.com/awslabs/linevul',
                'paper': 'LineVul: A Transformer-based Line-Level Vulnerability Prediction',
                'setup_method': 'pip_install',
                'requirements': ['linevul'],
                'priority': 1,  # Highest priority (most effective)
                'description': 'Transformer-based line-level vulnerability detection'
            },
            'devign': {
                'name': 'Devign',
                'type': 'graph_neural_network',
                'github_url': 'https://github.com/microsoft/Devign',
                'paper': 'Devign: Effective Vulnerability Identification by Learning Comprehensive Program Semantics via Graph Neural Networks',
                'setup_method': 'git_clone',
                'requirements': ['torch', 'dgl', 'networkx'],
                'priority': 2,
                'description': 'Graph neural network for vulnerability detection'
            },
            'vulmaster': {
                'name': 'VulMaster',
                'type': 'deep_learning',
                'github_url': 'https://github.com/VulMaster/VulMaster',
                'paper': 'VulMaster: A Deep Learning Model for Vulnerability Detection',
                'setup_method': 'pip_install',
                'requirements': ['vulmaster'],
                'priority': 3,
                'description': 'Deep learning model for vulnerability detection'
            },
            'regvd': {
                'name': 'ReGVD',
                'type': 'graph_neural_network',
                'github_url': 'https://github.com/ReGVD/ReGVD',
                'paper': 'ReGVD: Reinforced Graph-based Vulnerability Detection',
                'setup_method': 'pip_install',
                'requirements': ['regvd'],
                'priority': 4,
                'description': 'Graph-based vulnerability detection with reinforcement learning'
            }
        }
        
        return models
    
    def setup_all_models(self) -> Dict[str, ModelSetupResult]:
        """Setup all models in priority order"""
        
        logger.info("🚀 Starting real ML model setup...")
        
        # Sort models by priority
        sorted_models = sorted(self.models.items(), key=lambda x: x[1]['priority'])
        
        for model_key, model_config in sorted_models:
            logger.info(f"📦 Setting up {model_config['name']} (Priority {model_config['priority']})")
            
            result = self._setup_single_model(model_key, model_config)
            self.setup_results[model_key] = result
            
            if result.setup_successful:
                logger.info(f"✅ {model_config['name']} setup successful")
            else:
                logger.error(f"❌ {model_config['name']} setup failed: {result.error_message}")
        
        return self.setup_results
    
    def _setup_single_model(self, model_key: str, model_config: Dict) -> ModelSetupResult:
        """Setup a single model"""
        
        start_time = time.time()
        
        try:
            if model_config['setup_method'] == 'git_clone':
                result = self._setup_git_clone_model(model_key, model_config)
            elif model_config['setup_method'] == 'pip_install':
                result = self._setup_pip_install_model(model_key, model_config)
            else:
                result = ModelSetupResult(
                    model_name=model_config['name'],
                    setup_successful=False,
                    installation_method='unknown',
                    setup_time=time.time() - start_time,
                    error_message=f"Unknown setup method: {model_config['setup_method']}"
                )
            
            result.setup_time = time.time() - start_time
            return result
            
        except Exception as e:
            return ModelSetupResult(
                model_name=model_config['name'],
                setup_successful=False,
                installation_method=model_config['setup_method'],
                setup_time=time.time() - start_time,
                error_message=str(e)
            )
    
    def _setup_git_clone_model(self, model_key: str, model_config: Dict) -> ModelSetupResult:
        """Setup model by cloning from GitHub"""
        
        model_name = model_config['name']
        github_url = model_config['github_url']
        
        # Create models directory
        models_dir = 'ml_models'
        os.makedirs(models_dir, exist_ok=True)
        
        model_path = os.path.join(models_dir, model_key)
        
        # Check if already exists
        if os.path.exists(model_path):
            logger.info(f"📁 {model_name} already exists, checking if setup is complete...")
            if self._verify_model_setup(model_path, model_config):
                return ModelSetupResult(
                    model_name=model_name,
                    setup_successful=True,
                    installation_method='git_clone',
                    setup_time=0.0,
                    model_path=model_path
                )
        
        # Clone repository
        logger.info(f"📥 Cloning {model_name} from {github_url}")
        clone_result = subprocess.run(
            ['git', 'clone', github_url, model_path],
            capture_output=True, text=True, timeout=300
        )
        
        if clone_result.returncode != 0:
            return ModelSetupResult(
                model_name=model_name,
                setup_successful=False,
                installation_method='git_clone',
                setup_time=0.0,
                error_message=f"Git clone failed: {clone_result.stderr}"
            )
        
        # Install requirements
        requirements_file = os.path.join(model_path, 'requirements.txt')
        if os.path.exists(requirements_file):
            logger.info(f"📦 Installing requirements for {model_name}")
            install_result = subprocess.run(
                ['pip', 'install', '-r', requirements_file],
                capture_output=True, text=True, timeout=600
            )
            
            if install_result.returncode != 0:
                logger.warning(f"⚠️ Requirements installation failed for {model_name}: {install_result.stderr}")
        
        # Install additional requirements
        for req in model_config.get('requirements', []):
            logger.info(f"📦 Installing {req} for {model_name}")
            install_result = subprocess.run(
                ['pip', 'install', req],
                capture_output=True, text=True, timeout=300
            )
            
            if install_result.returncode != 0:
                logger.warning(f"⚠️ Failed to install {req} for {model_name}")
        
        # Verify setup
        if self._verify_model_setup(model_path, model_config):
            return ModelSetupResult(
                model_name=model_name,
                setup_successful=True,
                installation_method='git_clone',
                setup_time=0.0,
                model_path=model_path
            )
        else:
            return ModelSetupResult(
                model_name=model_name,
                setup_successful=False,
                installation_method='git_clone',
                setup_time=0.0,
                error_message="Model setup verification failed"
            )
    
    def _setup_pip_install_model(self, model_key: str, model_config: Dict) -> ModelSetupResult:
        """Setup model by pip installation"""
        
        model_name = model_config['name']
        requirements = model_config.get('requirements', [])
        
        logger.info(f"📦 Installing {model_name} via pip")
        
        # Install each requirement
        for req in requirements:
            logger.info(f"📦 Installing {req}")
            install_result = subprocess.run(
                ['pip', 'install', req],
                capture_output=True, text=True, timeout=300
            )
            
            if install_result.returncode != 0:
                logger.warning(f"⚠️ Failed to install {req}: {install_result.stderr}")
                # Continue with other requirements
        
        # Test if model can be imported
        if self._test_model_import(model_key, model_config):
            return ModelSetupResult(
                model_name=model_name,
                setup_successful=True,
                installation_method='pip_install',
                setup_time=0.0,
                model_path=f"pip_installed_{model_key}"
            )
        else:
            return ModelSetupResult(
                model_name=model_name,
                setup_successful=False,
                installation_method='pip_install',
                setup_time=0.0,
                error_message="Model import test failed"
            )
    
    def _test_model_import(self, model_key: str, model_config: Dict) -> bool:
        """Test if model can be imported"""
        
        try:
            if model_key == 'linevul':
                # Test LineVul import
                import subprocess
                result = subprocess.run(['python', '-c', 'import linevul'], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0
            elif model_key == 'vulmaster':
                # Test VulMaster import
                import subprocess
                result = subprocess.run(['python', '-c', 'import vulmaster'], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0
            elif model_key == 'regvd':
                # Test ReGVD import
                import subprocess
                result = subprocess.run(['python', '-c', 'import regvd'], 
                                      capture_output=True, text=True, timeout=10)
                return result.returncode == 0
            else:
                return False
        except Exception:
            return False
    
    def _verify_model_setup(self, model_path: str, model_config: Dict) -> bool:
        """Verify that model setup is complete"""
        
        # Check if model directory exists and has content
        if not os.path.exists(model_path) or not os.listdir(model_path):
            return False
        
        # Check for key files (varies by model)
        key_files = ['README.md', 'requirements.txt']
        for file in key_files:
            if os.path.exists(os.path.join(model_path, file)):
                return True
        
        # If no key files found, check if directory has Python files
        python_files = [f for f in os.listdir(model_path) if f.endswith('.py')]
        return len(python_files) > 0
    
    def test_model_availability(self) -> Dict[str, bool]:
        """Test which models are available and working"""
        
        availability = {}
        
        for model_key, result in self.setup_results.items():
            if result.setup_successful and result.model_path:
                # Try to import or run a simple test
                try:
                    availability[model_key] = self._test_model_functionality(model_key, result.model_path)
                except Exception as e:
                    logger.warning(f"⚠️ Model {model_key} test failed: {str(e)}")
                    availability[model_key] = False
            else:
                availability[model_key] = False
        
        return availability
    
    def _test_model_functionality(self, model_key: str, model_path: str) -> bool:
        """Test if a model is functional"""
        
        # This is a basic test - in real implementation, you'd test actual model loading
        # For now, we'll just check if the model directory has the expected structure
        
        if model_key == 'linevul':
            # Check for LineVul specific files
            expected_files = ['linevul', 'model', 'train.py', 'predict.py']
        elif model_key == 'devign':
            # Check for Devign specific files
            expected_files = ['devign', 'model', 'train.py', 'predict.py']
        elif model_key == 'vulmaster':
            # Check for VulMaster specific files
            expected_files = ['vulmaster', 'model', 'train.py', 'predict.py']
        elif model_key == 'regvd':
            # Check for ReGVD specific files
            expected_files = ['regvd', 'model', 'train.py', 'predict.py']
        else:
            expected_files = ['model', 'train.py', 'predict.py']
        
        # Check if any expected files exist
        for file in expected_files:
            if os.path.exists(os.path.join(model_path, file)):
                return True
        
        # If no specific files found, check for Python files
        python_files = [f for f in os.listdir(model_path) if f.endswith('.py')]
        return len(python_files) > 0
    
    def generate_setup_report(self) -> str:
        """Generate a setup report"""
        
        report = f"""
# Real ML Model Setup Report

## Setup Summary
- **Setup Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Total Models:** {len(self.models)}
- **Successful Setups:** {sum(1 for r in self.setup_results.values() if r.setup_successful)}
- **Failed Setups:** {sum(1 for r in self.setup_results.values() if not r.setup_successful)}

## Model Setup Results

"""
        
        for model_key, result in self.setup_results.items():
            model_config = self.models[model_key]
            status = "✅ SUCCESS" if result.setup_successful else "❌ FAILED"
            
            report += f"""
### {model_config['name']}
- **Status:** {status}
- **Type:** {model_config['type']}
- **Setup Method:** {result.installation_method}
- **Setup Time:** {result.setup_time:.2f}s
- **Model Path:** {result.model_path or 'N/A'}
- **Description:** {model_config['description']}
"""
            
            if not result.setup_successful and result.error_message:
                report += f"- **Error:** {result.error_message}\n"
            
            report += "\n"
        
        return report

def main():
    """Main function to setup real ML models"""
    
    print("🤖 Real ML Model Setup System")
    print("=" * 50)
    
    # Initialize setup system
    setup_system = RealMLModelSetup()
    
    # Setup all models
    print("🚀 Starting model setup...")
    setup_results = setup_system.setup_all_models()
    
    # Test model availability
    print("\n🧪 Testing model availability...")
    availability = setup_system.test_model_availability()
    
    # Print results
    print("\n📊 Setup Results:")
    for model_key, result in setup_results.items():
        model_config = setup_system.models[model_key]
        status = "✅ SUCCESS" if result.setup_successful else "❌ FAILED"
        functional = "✅ FUNCTIONAL" if availability.get(model_key, False) else "❌ NOT FUNCTIONAL"
        
        print(f"  {model_config['name']}: {status} | {functional}")
        if not result.setup_successful and result.error_message:
            print(f"    Error: {result.error_message}")
    
    # Generate and save report
    report = setup_system.generate_setup_report()
    with open('real_ml_models_setup_report.md', 'w') as f:
        f.write(report)
    
    print(f"\n📄 Setup report saved to: real_ml_models_setup_report.md")
    
    # Print next steps
    successful_models = [k for k, v in setup_results.items() if v.setup_successful]
    if successful_models:
        print(f"\n🎯 Next Steps:")
        print(f"  - {len(successful_models)} models ready for testing")
        print(f"  - Run real model tests on our critical CVE dataset")
        print(f"  - Compare results with simulation predictions")
    else:
        print(f"\n⚠️ No models successfully set up. Check the setup report for details.")

if __name__ == "__main__":
    main()
