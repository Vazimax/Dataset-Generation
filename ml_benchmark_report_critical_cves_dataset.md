
# ML-Based Vulnerability Detection Benchmark Report

## Dataset: Critical CVEs Dataset
- **Total Samples:** 20
- **Timestamp:** 2025-09-02T15:43:09.350568

## Overall Performance
- **Overall Detection Rate:** 28.75%
- **Models Tested:** 4
- **Total Detections:** 23
- **Average Confidence:** 0.31
- **Average Detection Time:** 0.01s

## Model Performance


### LineVul
- **Type:** transformer_based
- **Description:** Transformer-based line-level vulnerability detection
- **Detection Rate:** 65.00%
- **Average Confidence:** 0.64
- **Average Detection Time:** 0.04s
- **Total Detections:** 13/20
- **Error Rate:** 0.00%


### Devign
- **Type:** graph_neural_network
- **Description:** Graph neural network for vulnerability detection
- **Detection Rate:** 10.00%
- **Average Confidence:** 0.29
- **Average Detection Time:** 0.00s
- **Total Detections:** 2/20
- **Error Rate:** 0.00%


### VulMaster
- **Type:** deep_learning
- **Description:** Deep learning model for vulnerability detection
- **Detection Rate:** 40.00%
- **Average Confidence:** 0.26
- **Average Detection Time:** 0.00s
- **Total Detections:** 8/20
- **Error Rate:** 0.00%


### ReGVD
- **Type:** graph_neural_network
- **Description:** Graph-based vulnerability detection with reinforcement learning
- **Detection Rate:** 0.00%
- **Average Confidence:** 0.06
- **Average Detection Time:** 0.00s
- **Total Detections:** 0/20
- **Error Rate:** 0.00%

