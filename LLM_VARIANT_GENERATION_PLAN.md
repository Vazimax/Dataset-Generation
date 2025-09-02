Phase 1: Seed Dataset Preparation & Verification

Select CVEs from Your Dataset:
Goal: Choose a manageable subset (e.g., 20-50) from your 363 critical CVEs to serve as high-quality seeds.
Criteria for Selection:
Clear Vulnerability Type: Prioritize entries with well-defined, common C/C++ vulnerability patterns (Buffer Overflows, Integer Overflows leading to Buffer Overflows, Use-After-Free, Double Free, Infinite Loops). The dataset's cwe_name column is useful here.
Code Quality: Ensure the vulnerable_code and fixed_code snippets are reasonably complete and readable (not heavily truncated or filled with <S2SV_...> placeholders). If placeholders are common, prioritize CVEs where you can easily find the real code via the commit_link.
Diversity: Aim for a spread across different projects and CWE types relevant to your final goal.
Action: Filter your CSV (e.g., using Python/Pandas) to select entries meeting these criteria.
Deep Manual Verification (of the selected seeds):
Goal: Confirm the accuracy and exploitability of your selected seed CVEs.
Process (for each selected CVE):
Check Commit Link: Visit the URL in the commit_link field (e.g., https://github.com/.../commit/...).
Analyze Diff: Examine the actual code changes in the commit. Verify that the change corresponds to fixing the vulnerability described by the cve_id and cwe_name.
Cross-Reference Code Snippets: Compare the vulnerable_code and fixed_code in the CSV with the actual code in the commit. Are they accurate representations?
Assess Exploitability: Based on the vulnerability type and the fix, can you reason about a potential exploitation path? Does it align with the "critical" and "weaponizable" tags?
Document Findings: Keep a log of which seeds passed/failed verification and why. Discard any that fail this step.
Outcome: You should end up with a small set (e.g., 15-40) of thoroughly verified, critical, and weaponizable CVE entries. These are your Golden Seeds.
Prepare Seed Data for Prompting:
Goal: Structure your verified seeds for easy use in LLM prompts.
Action: For each Golden Seed, create a structured format (e.g., JSON) containing:
cve_id
cwe_name / cwe_id
Clean, actual vulnerable_code_snippet (extracted from the verified commit or cleaned from the CSV).
Clean, actual fixed_code_snippet.
A brief, clear description of the vulnerability pattern (e.g., "Buffer overflow due to lack of bounds check before memcpy").
The specific transformation goal related to that pattern (e.g., "Convert array indexing to pointer arithmetic while preserving the buffer overflow").


Phase 2: Variant Generation with DeepSeek-Coder

Set Up DeepSeek-Coder:
Ensure you have access (API, local deployment). The 33B or 6.7B versions are suitable.
Develop Prompt Templates:
Goal: Create precise prompts that guide the LLM to generate syntactic variants preserving the vulnerability.
Template Structure:


1
2
3
4
5
Generate a syntactically different but semantically identical version of the following C code snippet. The new version MUST preserve the exact vulnerability described: {vulnerability_pattern_description}.

Original Vulnerable Code:
```c
{vulnerable_code_snippet}
Specific Transformation Instruction: {transformation_goal}.
Critical Requirements:
The core vulnerability ({cwe_name}) MUST remain exploitable in the generated variant.
Do NOT fix the vulnerability.
Provide ONLY the modified C code snippet.
Ensure the generated code is syntactically correct C.
Modified Code:
```
Example using a Seed:


1
2
3
4
5
6
7
8
9
10
11
12
Generate a syntactically different but semantically identical version of the following C code snippet. The new version MUST preserve the exact vulnerability described: Buffer overflow due to lack of bounds check before `memcpy`.

Original Vulnerable Code:
```c
int process_data(char *input, size_t len) {
    char buffer[100];
    if (len < 1000) { // Flawed check
        memcpy(buffer, input, len); // Vulnerable line
        buffer[len] = '\0';
    }
    return 0;
}
Specific Transformation Instruction: Convert the if condition check to use a goto statement and change the memcpy call to a manual for loop for copying data.
Critical Requirements:
The core vulnerability (CWE-121: Buffer Overflow) MUST remain exploitable in the generated variant.
Do NOT fix the vulnerability.
Provide ONLY the modified C code snippet.
Ensure the generated code is syntactically correct C.
Modified Code:
```
Generate Variants:
Goal: Create a large pool of candidate variants.
Process:
For each Golden Seed, use its structured data to populate the prompt template.
Send the prompt to DeepSeek-Coder.
Collect the output (the candidate variant code).
Repeat for each seed, potentially multiple times per seed with slightly varied prompts or transformation goals, aiming to generate several thousand candidates (e.g., 3000-5000).


Phase 3: Rigorous Validation of Generated Variants

Set Up Validation Tools:
Ensure angr (for symbolic execution to check for specific vulnerability conditions) and AFL++ (for fuzzing to demonstrate crashes/exploitability) are installed and configured.
Validation Pipeline:
Goal: Filter the generated candidates down to proven, weaponizable variants.
Process (for each candidate variant):
Static Sanity Check (Optional but fast): A quick syntactic check (e.g., with a C compiler -fsyntax-only) to discard obvious garbage.
Symbolic Execution (angr):
Set up the analysis to identify if the specific vulnerability condition still holds (e.g., can an unconstrained len still lead to a write beyond the buffer boundary?).
Run angr. Does it confirm the presence of the intended vulnerability pattern?
Fail: If angr indicates the vulnerability pattern is fixed or significantly altered, discard the variant.
Pass: Proceed to fuzzing.
Fuzzing (AFL++):
Integrate the candidate variant code into a simple harness that allows AFL++ to provide input (e.g., feed data into the function corresponding to the vulnerable one).
Run AFL++ for a defined short period (e.g., 5-15 minutes).
Fail: If AFL++ does not find a crash or timeout related to the vulnerability (e.g., segfault, out-of-bounds access consistent with the CWE), discard the variant.
Pass: The variant has demonstrated both the presence of the vulnerability pattern and a degree of exploitability (it can be made to crash). Keep it.
(Optional) Manual Review: For borderline cases or a small subset of validated variants, manual inspection can provide final confirmation.
Outcome: This pipeline is expected to filter out a large percentage (70-80%+) of the generated candidates. The ones that pass are your high-confidence, weaponizable variants.
Build Final Dataset:
Collect all variants that successfully pass the validation pipeline.
Continue generating and validating until you reach your target of approximately 700 validated variants.
Store these validated variants, potentially keeping track of which Golden Seed they originated from and the specific transformation applied.


Phase 4: Utilization (Testing Detectors)

Test Against Detectors:
Use your final dataset of ~700 validated weaponizable variants to test existing vulnerability detection models (e.g., Devign, LineVul, CodeQL).
Measure their detection accuracy (True Positives, False Negatives) on this challenging set.
Analyze the results to identify specific syntactic patterns or transformation types that cause detectors to fail, providing insights for improving detection robustness.
This plan emphasizes quality and verification at each step, using your large initial dataset efficiently to find good seeds, leveraging LLMs for generation, and relying on strict automated validation to ensure the final dataset's credibility and effectiveness.