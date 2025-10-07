
Title: Weaponizable Vulnerability Variant Generation with CodeT5

We present a practical pipeline to synthesize compile-valid CVE variants with CodeT5 using compile-in-the-loop filtering and evaluate them against cppcheck and ML detectors (CodeBERT, Devign-proxy). On 40 variants across CWE-119/134/190/416/476, CodeBERT flags 75.0% and a Devign proxy 55.0%, with strong detection on UAF/NULL-deref and mixed performance on buffer/format/int overflows. Results suggest syntax-level obfuscation is insufficient; future work targets grammar-constrained decoding, semantic-preservation checks, and compiled-only training at scale, plus true Devign (GNN) evaluation.
