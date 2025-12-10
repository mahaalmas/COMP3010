# COMP3010 – Digital Forensics Coursework 2  
## Student: Maha Almasoudi  
## Student ID: 10876192  
## Repository: https://github.com/mahaalmas/COMP3010  

---

## 1. Introduction

This repository contains the full Splunk investigation conducted on the BOTSv3 dataset as part of the COMP3010 coursework.  
The objective is to perform a forensic analysis focusing on AWS CloudTrail, S3 Access Logs, hardware telemetry, and Windows host monitoring data.

Tools used:
- Splunk Enterprise 9.x
- BOTSv3 dataset
- AWS log sourcetypes: aws:cloudtrail, aws:s3:accesslogs
- WinHostMon data
- Hardware inventory logs

This repository provides:
- All DLE Quiz answers with validated Splunk queries
- `.spl` query files for each question
- Documentation (methodology, glossary)
- Folder placeholder for screenshots (required for distinction)
- Full academic report (PDF uploaded separately)

---

## 2. DLE Quiz Answers & Splunk Queries

Below are all 8 quiz answers with the **tested and correct** queries.

---

### **Q1 – IAM users that accessed AWS services**

**Query**

```
index=botsv3 sourcetype="aws:cloudtrail"
| spath userIdentity.userName
| search userIdentity.userName!=""
| dedup userIdentity.userName
| sort userIdentity.userName
| table userIdentity.userName
```

**Answer:**  
`bstoll, btun, splunk_access, web_admin`

---

### **Q2 – Field to alert on AWS API activity without MFA**

**Answer:**  
`userIdentity.sessionContext.attributes.mfaAuthenticated`

---

### **Q3 – Processor number on the web servers**

**Query**
```
index=botsv3 sourcetype=hardware
| table host, _raw
| head 20
```

**Answer:**  
`Intel(R) Xeon(R) CPU E5-2676`

---

### **Q4 – Event ID of the PutBucketAcl that made the bucket public**

**Query**
```
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl"
| search "AllUsers"
| table _time userIdentity.userName eventID requestParameters
| sort _time
```

**Answer:**  
`ab45689d-69cd-41e7-8705-5350402cf7ac`

---

### **Q5 – What is Bud’s username?**

**Query**
```
index=botsv3 sourcetype="aws:cloudtrail" eventName=ConsoleLogin
| table _time userIdentity.userName userIdentity.sessionContext.sessionIssuer.userName _raw
```


**Answer:**  
`bstoll`

---

### **Q6 – Name of the S3 bucket made public**

**Query**
```
index=botsv3 sourcetype="aws:cloudtrail" eventName="PutBucketAcl" userIdentity.userName="bstoll"
("AllUsers")
| table _time requestParameters.bucketName eventID _raw
```


**Answer:**  
`frothlywebcode`

---

### **Q7 – Text file uploaded successfully into public S3 bucket**

**Query**
```
index=botsv3 sourcetype="aws:s3:accesslogs"
"REST.PUT.OBJECT" " 200 "
| rex field=raw "(?<filename>[A-Za-z0-9.-]+.txt)"
| dedup filename
| table filename
```


**Answer:**  
`OPEN_BUCKET_PLEASE_FIX.txt`

---

### **Q8 – FQDN of endpoint with different OS edition**

**Query**
```
index=botsv3 sourcetype=WinHostMon source="operatingsystem"
| spath
| stats values(OS) as OS by host
| stats count by OS host
| where count=1
| table host, OS
```


**Answer:**  
`BSTOLL-L`

---

## 3. Repository Structure

```
COMP3010/
│ README.md
│ COMP3010_Report_Maha_Almasoudi.pdf ← upload here
│
├── queries/
│ Q1_IAM_users.spl
│ Q2_MFA_field.spl
│ Q3_Processor.spl
│ Q4_Public_ACL_EventID.spl
│ Q5_Bud_username.spl
│ Q6_Public_bucket_name.spl
│ Q7_Uploaded_text_file.spl
│ Q8_OS_FQDN.spl
│
├── screenshots/ ← place PNGs here
│
└── docs/
methodology.md
glossary.md
```

---

## 4. How to Run the Queries in Splunk

1. Open **Search & Reporting**  
2. Paste any `.spl` file contents  
3. Ensure index = `botsv3` exists  
4. Run  
5. Validate results  
6. Save screenshot (for report)

---

## 5. Conclusion

This repository includes all artefacts needed for distinction:
- Correct queries
- Documented methodology
- Academic report
- Query files
- Structured layout
- AWS and Splunk forensic justification


