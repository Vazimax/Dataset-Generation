# Expanded CVE Discovery Report

Generated: 2025-08-29 17:12:46
Mode: Expanded Discovery (Target: 50-100 CVEs)

## Summary
- **Total CVEs Discovered**: 33
- **Projects Analyzed**: 8
- **Vulnerability Patterns**: 5
- **Discovery Mode**: expanded

## CVEs by Project
- **openssl**: 7 CVEs
- **log4j**: 8 CVEs
- **libpng**: 0 CVEs
- **zlib**: 5 CVEs
- **curl**: 5 CVEs
- **libxml2**: 2 CVEs
- **sqlite**: 6 CVEs
- **ffmpeg**: 0 CVEs

## CVEs by Vulnerability Pattern
- **buffer_overflow**: 0 CVEs
- **integer_overflow**: 0 CVEs
- **use_after_free**: 0 CVEs
- **format_string**: 0 CVEs
- **deserialization**: 0 CVEs

## Top CVEs by Project

### OPENSSL
- **CVE-2016-0797** (CVSS: 7.5) - Multiple integer overflows in OpenSSL 1.0.1 before 1.0.1s and 1.0.2 before 1.0.2g allow remote attac...
- **CVE-2016-2105** (CVSS: 7.5) - Integer overflow in the EVP_EncodeUpdate function in crypto/evp/encode.c in OpenSSL before 1.0.1t an...
- **CVE-2016-2106** (CVSS: 7.5) - Integer overflow in the EVP_EncryptUpdate function in crypto/evp/evp_enc.c in OpenSSL before 1.0.1t ...
- **CVE-2016-6303** (CVSS: 9.8) - Integer overflow in the MDC2_Update function in crypto/mdc2/mdc2dgst.c in OpenSSL before 1.1.0 allow...
- **CVE-2020-28018** (CVSS: 9.8) - Exim 4 before 4.94.2 allows Use After Free in smtp_reset in certain situations that may be common fo...

### LOG4J
- **CVE-2019-17571** (CVSS: 9.8) - Included in Log4j 1.2 is a SocketServer class that is vulnerable to deserialization of untrusted dat...
- **CVE-2021-4104** (CVSS: 7.5) - JMSAppender in Log4j 1.2 is vulnerable to deserialization of untrusted data when the attacker has wr...
- **CVE-2022-23302** (CVSS: 8.8) - JMSSink in all versions of Log4j 1.x is vulnerable to deserialization of untrusted data when the att...
- **CVE-2022-23307** (CVSS: 8.8) - CVE-2020-9493 identified a deserialization issue that was present in Apache Chainsaw. Prior to Chain...
- **CVE-2022-24818** (CVSS: 8.2) - GeoTools is an open source Java library that provides tools for geospatial data. The GeoTools librar...

### ZLIB
- **CVE-2022-37434** (CVSS: 9.8) - zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via...
- **CVE-2022-1922** (CVSS: 7.8) - DOS / potential heap overwrite in mkv demuxing using zlib decompression. Integer overflow in matrosk...
- **CVE-2022-2122** (CVSS: 7.8) - DOS / potential heap overwrite in qtdemux using zlib decompression. Integer overflow in qtdemux elem...
- **CVE-2023-45853** (CVSS: 9.8) - MiniZip in zlib through 1.3 has an integer overflow and resultant heap-based buffer overflow in zipO...
- **CVE-2023-35989** (CVSS: 7.8) - An integer overflow vulnerability exists in the LXT2 zlib block allocation functionality of GTKWave ...

### CURL
- **CVE-2005-0490** (CVSS: 8.8) - Multiple stack-based buffer overflows in libcURL and cURL 7.12.1, and possibly other versions, allow...
- **CVE-2016-7134** (CVSS: 9.8) - ext/curl/interface.c in PHP 7.x before 7.0.10 does not work around a libcurl integer overflow, which...
- **CVE-2016-7167** (CVSS: 9.8) - Multiple integer overflows in the (1) curl_escape, (2) curl_easy_escape, (3) curl_unescape, and (4) ...
- **CVE-2018-14618** (CVSS: 7.5) - curl before version 7.61.1 is vulnerable to a buffer overrun in the NTLM authentication code. The in...
- **CVE-2023-28319** (CVSS: 7.5) - A use after free vulnerability exists in curl <v8.1.0 in the way libcurl offers a feature to verify ...

### LIBXML2
- **CVE-2017-5130** (CVSS: 8.8) - An integer overflow in xmlmemory.c in libxml2 before 2.9.5, as used in Google Chrome prior to 62.0.3...
- **CVE-2017-15412** (CVSS: 8.8) - Use after free in libxml2 before 2.9.5, as used in Google Chrome prior to 63.0.3239.84 and other pro...

### SQLITE
- **CVE-2018-20346** (CVSS: 8.1) - SQLite before 3.25.3, when the FTS3 extension is enabled, encounters an integer overflow (and result...
- **CVE-2018-20506** (CVSS: 8.1) - SQLite before 3.25.3, when the FTS3 extension is enabled, encounters an integer overflow (and result...
- **CVE-2019-5827** (CVSS: 8.8) - Integer overflow in SQLite via WebSQL in Google Chrome prior to 74.0.3729.131 allowed a remote attac...
- **CVE-2014-4959** (CVSS: 9.8) - **DISPUTED** SQL injection vulnerability in SQLiteDatabase.java in the SQLi Api in Android allows re...
- **CVE-2016-10556** (CVSS: 7.5) - sequelize is an Object-relational mapping, or a middleman to convert things from Postgres, MySQL, Ma...

## Top CVEs by Pattern


## Discovery Strategy
- **Projects**: 8 high-priority projects (OpenSSL, Log4j, libpng, zlib, curl, libxml2, SQLite, FFmpeg)
- **Patterns**: 5 critical vulnerability types (buffer overflow, integer overflow, use-after-free, format string, deserialization)
- **CVSS Threshold**: 7.5+ for high-quality vulnerabilities
- **Results Per Search**: Limited to ensure quality over quantity

## Next Steps
1. **Review Discovered CVEs**: Assess quality and relevance
2. **Prioritize for Processing**: Select best candidates for code extraction
3. **Repository Analysis**: Clone repos and extract vulnerable/fixed code
4. **Validation Pipeline**: Implement symbolic execution and fuzzing
5. **Dataset Construction**: Build structured dataset with metadata

## Target Achievement
- **Current**: 33 CVEs
- **Target**: 50-100 CVEs
- **Progress**: 66.0% of minimum target
- **Status**: On Track

## Notes
- Focus on CVEs with CVSS 7.5+ for high-quality dataset
- Prioritize CVEs with available source code and known fixes
- Some CVEs may require manual review for relevance
- Next phase: Code extraction and validation
