# Methodology (COMP3010 – Maha Almasoudi)

This document explains the forensic workflow used to analyse the BOTSv3 dataset in Splunk.

## 1. Data Ingestion
- Installed Splunk Enterprise locally
- Created index `botsv3`
- Ingested all BOTSv3 log files (AWS, Windows, hardware, S3 access logs)

## 2. Identifying Relevant Sourcetypes
Key sourcetypes used:
- aws:cloudtrail → IAM, S3 ACLs, API events
- aws:s3:accesslogs → S3 PUT/GET objects
- hardware → processor & device telemetry
- WinHostMon → operating system inventory

## 3. Log Structure Analysis
`spath` and `rex` used to extract fields such as:
- userIdentity.userName  
- requestParameters.bucketName  
- filename via regex  

## 4. Investigative Strategy
Each quiz question aligns with a forensic objective:
- Identify responsible IAM users
- Detect misconfigured ACLs
- Confirm S3 bucket exploitation
- Track anomalous Windows host

Queries were validated using:
- eventName filters  
- keyword matching  
- stats aggregation  
- deduplication  

## 5. Evidence Preservation
- Screenshots captured from Splunk
- Query files exported as `.spl`
- All findings documented in the academic report
