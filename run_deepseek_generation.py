#!/usr/bin/env python3
"""
Run DeepSeek Variant Generation

This script runs the actual DeepSeek Coder variant generation process
with a small sample of CVEs for testing and validation.

"""

import json
import os
from deepseek_variant_generator import (
    GenerationConfig, DeepSeekVariantGenerator, VariantBatchProcessor
)

def run_small_sample_generation():
    """Run variant generation on a small sample of CVEs"""
    
    print("🚀 Starting DeepSeek Variant Generation...")
    
    # Get API key
    api_key = input("Enter your DeepSeek API key: ").strip()
    if not api_key:
        print("❌ API key is required")
        return
    
    # Load the critical CVE dataset
    try:
        with open('complete_critical_cves_training_dataset.json', 'r') as f:
            dataset = json.load(f)
        
        samples = dataset.get('samples', [])
        if not samples:
            print("❌ No samples found in dataset")
            return
        
        print(f"📊 Loaded {len(samples)} critical CVEs")
        
    except FileNotFoundError:
        print("❌ complete_critical_cves_training_dataset.json not found")
        return
    
    # Configuration
    config = GenerationConfig(api_key=api_key)
    
    # Initialize generator and processor
    generator = DeepSeekVariantGenerator(config)
    processor = VariantBatchProcessor(generator)
    
    # Process a small sample first (top 5 CVEs by weaponization score)
    print("\n🎯 Processing top 5 CVEs by weaponization score...")
    
    # Sort by weaponization score (highest first)
    sorted_samples = sorted(samples, key=lambda x: x['weaponization_score'], reverse=True)
    sample_batch = sorted_samples[:5]
    
    print("Selected CVEs:")
    for i, cve in enumerate(sample_batch, 1):
        print(f"  {i}. {cve['cve_id']} - Score: {cve['weaponization_score']} - CWE: {cve['cwe_id']}")
    
    # Process the sample batch
    try:
        batch_results = processor.process_cve_batch(sample_batch)
        
        print(f"\n✅ Sample generation completed!")
        print(f"📊 Results:")
        print(f"  - CVEs processed: {len(batch_results)}")
        print(f"  - Total variants generated: {processor.stats['total_variants']}")
        print(f"  - Successful generations: {processor.stats['successful_generations']}")
        print(f"  - Failed generations: {processor.stats['failed_generations']}")
        print(f"  - Validation failures: {processor.stats['validation_failures']}")
        
        # Calculate success rate
        total_attempts = processor.stats['successful_generations'] + processor.stats['failed_generations'] + processor.stats['validation_failures']
        if total_attempts > 0:
            success_rate = (processor.stats['successful_generations'] / total_attempts) * 100
            print(f"  - Success rate: {success_rate:.1f}%")
        
        # Save results
        output_file = 'deepseek_sample_variants.json'
        with open(output_file, 'w') as f:
            json.dump(batch_results, f, indent=2)
        
        print(f"\n💾 Results saved to {output_file}")
        
        # Show detailed results
        print(f"\n📋 Detailed Results:")
        for cve in batch_results:
            variant_count = cve.get('variant_count', 0)
            print(f"  - {cve['cve_id']}: {variant_count} variants")
            
            for variant in cve.get('variants', []):
                print(f"    * {variant['variant_id']}: Score {variant['validation_score']:.2f}")
        
        # Ask if user wants to continue with full generation
        print(f"\n🤔 Would you like to continue with full generation of all {len(samples)} CVEs?")
        print("⚠️  This will take a significant amount of time and API calls.")
        
        continue_full = input("Continue with full generation? (y/N): ").strip().lower()
        
        if continue_full == 'y':
            run_full_generation(generator, processor, samples)
        else:
            print("✅ Sample generation completed. Full generation skipped.")
    
    except Exception as e:
        print(f"❌ Sample generation failed: {str(e)}")
        return

def run_full_generation(generator, processor, samples):
    """Run full generation on all CVEs"""
    
    print(f"\n🚀 Starting full generation of {len(samples)} CVEs...")
    
    # Process CVEs in batches
    batch_size = 10  # Process 10 CVEs at a time
    all_results = []
    
    for i in range(0, len(samples), batch_size):
        batch = samples[i:i + batch_size]
        batch_num = i//batch_size + 1
        total_batches = (len(samples) + batch_size - 1)//batch_size
        
        print(f"\n📦 Processing batch {batch_num}/{total_batches} ({len(batch)} CVEs)")
        
        try:
            batch_results = processor.process_cve_batch(batch)
            all_results.extend(batch_results)
            
            # Save intermediate results
            intermediate_file = f'deepseek_variants_batch_{batch_num}.json'
            with open(intermediate_file, 'w') as f:
                json.dump(batch_results, f, indent=2)
            
            print(f"✅ Batch {batch_num} completed. Stats: {processor.stats}")
            
        except Exception as e:
            print(f"❌ Batch {batch_num} failed: {str(e)}")
            continue
    
    # Save final results
    final_dataset = {
        'metadata': {
            'generation_timestamp': processor.stats.get('generation_timestamp', 'unknown'),
            'generation_method': 'deepseek_coder_refactoring',
            'source_dataset': 'complete_critical_cves_training_dataset.json',
            'total_original_cves': len(samples),
            'total_variants_generated': processor.stats['total_variants'],
            'generation_stats': processor.stats
        },
        'cves_with_variants': all_results
    }
    
    final_file = 'deepseek_variants_final_dataset.json'
    with open(final_file, 'w') as f:
        json.dump(final_dataset, f, indent=2)
    
    # Print final statistics
    print(f"\n🎉 FULL GENERATION COMPLETE!")
    print(f"📊 Final Statistics:")
    print(f"  - Total CVEs processed: {processor.stats['total_processed']}")
    print(f"  - Successful generations: {processor.stats['successful_generations']}")
    print(f"  - Failed generations: {processor.stats['failed_generations']}")
    print(f"  - Validation failures: {processor.stats['validation_failures']}")
    print(f"  - Total variants generated: {processor.stats['total_variants']}")
    
    # Calculate success rate
    total_attempts = processor.stats['successful_generations'] + processor.stats['failed_generations'] + processor.stats['validation_failures']
    if total_attempts > 0:
        success_rate = (processor.stats['successful_generations'] / total_attempts) * 100
        print(f"  - Success rate: {success_rate:.1f}%")
    
    print(f"\n💾 Final dataset saved to {final_file}")
    print(f"📁 Intermediate batch files also saved for backup")

def main():
    """Main function"""
    
    print("🔧 DeepSeek Coder Variant Generation")
    print("=" * 50)
    
    # Check if dataset exists
    if not os.path.exists('complete_critical_cves_training_dataset.json'):
        print("❌ complete_critical_cves_training_dataset.json not found")
        print("Please ensure the critical CVE dataset is available.")
        return
    
    # Check if OpenAI library is available
    try:
        import openai
        print("✅ OpenAI library found")
    except ImportError:
        print("❌ OpenAI library not found")
        print("Please install: pip install openai")
        return
    
    # Run the generation process
    run_small_sample_generation()

if __name__ == "__main__":
    main()
