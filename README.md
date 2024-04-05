# Power BI Desktop Top Techniques Calculator
This document walks through the steps to add the [Top Techniques Calculator](https://top-attack-techniques.mitre-engenuity.org/calculator) functionality to Power BI Desktop.
  * [MITRE Engenuity Center for Threat Informed Defense Top Techniques Calculator Project Site](https://mitre-engenuity.org/cybersecurity/center-for-threat-informed-defense/our-work/top-attack-techniques/)
  * [Microsoft Blog on Top Techniques Calculator](https://www.microsoft.com/en-us/security/blog/2022/05/11/center-for-threat-informed-defense-microsoft-and-industry-partners-streamline-mitre-attck-matrix-evaluation-for-defenders/)
  * [Top Techniques Calculator GitHub Repo](https://github.com/center-for-threat-informed-defense/top-attack-techniques)

### Import the data sources to the model
1. Download the following files: 
  * [Top Techniques Calculator Excel Workbook](https://github.com/center-for-threat-informed-defense/top-attack-techniques/raw/main/Calculator.xlsx)
  * The most recent [MITRE ATT&CK Enteprise Dataset](https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack) (14.1 at time of writing)
  * [NIST SP 800-53r5 to ATT&CK 14.1 Mapping](https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/nist_800_53/attack-14.1/nist_800_53-rev5/enterprise/nist_800_53-rev5_attack-14.1-enterprise.json)
  * [AWS to ATT&CK 9.0 Mapping](https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/aws/attack-9.0/aws-09.21.2021/enterprise/aws-09.21.2021_attack-9.0-enterprise.json)
  * [Azure to ATT&CK 8.2 Mapping](https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/azure/attack-8.2/azure-06.29.2021/enterprise/azure-06.29.2021_attack-8.2-enterprise.json)
  * [GCP to ATT&CK 10 Mapping](https://raw.githubusercontent.com/center-for-threat-informed-defense/mappings-explorer/main/mappings/gcp/attack-10.0/gcp-06.28.2022/enterprise/gcp-06.28.2022_attack-10.0-enterprise.json)
  * [CIS Controls to ATT&CK 8.2 Mapping](https://www.cisecurity.org/-/media/project/cisecurity/cisecurity/data/media/files/uploads/2022/cis-controls-v8-to-enterprise-attck-v82-master-mapping--5262021.xlsx)
3. Import the Top Techniques Calculator data into the Power BI data model
  * The following columns must be added:
    * Technique (ID), Num. TID Before, Num. TID After, Prevalence Scores, Num. CAR, Num. Sigma, Num. ES SIEM, Num. Splunk, Num. CIS Controls, Num. 800-53 (r5),
4. Import the ATT&CK Enterprise Dataset
  * The following steps were taken to import enterprise-attack-14.1.json in STIX 2.1 format
    * Expand the columns to display the values under objects.external_references. 
    * Filter the "objects.external_references" column to include only rows that begin with T and do not begin with TA.
    * Expand the following columns so you can see the values: 
        * objects.x_mitre_permissions_required
        * objects.x_mitre_data_sources
        * objects.x_mitre_defense_bypassed
        * objects.kill_chain_phases
        * objects.x_mitre_platforms
        * objects.x_mitre_domains
    * Filter the "objects.name" column to include only rows that do not end with "Mitigation"
    
5. Import the Top Techniques Calculator Workbook
    * Import the "Methodology" sheet and use the first row as headers

6. Import the NIST 800-53r5, AWS, Azure, and GCP mappings. Make sure you can see the values in the following columns:
    * metadata.mapping_framework
    * mapping_objects.comments
    * mapping_objects.attack_object_id
    * mapping_objects.attack_object_name
    * mapping_objects.capability_description
    * mapping_objects.score_category
    * mapping_objects.score_value

7. Import the CIS Controls to ATT&CK mapping
    * Import the v8-ATT&CK Low Mit & (Sub-)Tech sheet and use the first row as headers

### Create the Sort Order Tables
1. Create the asset_sort_order_table and set the asset category column to sort by the order column
```
asset_sort_order_table = DATATABLE("order",INTEGER,"asset category",STRING,{{1,"Devices"},{2,"Network"},{3,"Applications"},{4,"Data"},{5,"Users"}})
```
2. Create the attack_tactic_sort_order_table  and set the tactic and display columns to sort by the order column
```
attack_tactic_sort_order_table = DATATABLE("order",INTEGER,"tactic",STRING,"display",STRING,{{1,"reconnaissance","Reconnaissance"},{2,"resource-development","Resource Development"},{3,"initial-access","Initial Access"},{4,"execution","Execution"},{5,"persistence","Persistence"},{6,"privilege-escalation","Privilege Escalation"},{7,"defense-evasion","Defense Evasion"},{8,"credential-access","Credential Access"},{9,"discovery","Discovery"},{10,"lateral-movement","Lateral Movement"},{11,"collection","Collection"},{12,"command-and-control","Command and Control"},{13,"exfiltration","Exfiltration"},{14,"impact","Impact"}})
```
3. Create the security_function_sort_order_table  and set the security function column to sort by the order column
```
security_function_sort_order_table = DATATABLE("order",INTEGER,"security function",STRING,{{1,"Identify"},{2,"Protect"},{3,"Detect"},{4,"Respond"},{5,"Recover"}})
```

### Create the Monitoring Coverage Slicer Tables
These tables facilitate selecting the level of monitoring coverage to inform the calculation. For each table, we'll also make sure the the values are displayed in order using the "Sory by column" option in the Column Tools tab of the ribbon menu.
1. Create the process_coverage_table and set the weight column to sort by the order column
```
process_coverage_table = DATATABLE("order", INTEGER, "weight", STRING, {{1,"None"}, {2,"Low"}, {3,"Medium"}, {4,"High"}})
```
2. Create the network_coverage_table and set the weight column to sort by the order column
```
network_coverage_table = DATATABLE("order", INTEGER, "weight", STRING, {{1,"None"}, {2,"Low"}, {3,"Medium"}, {4,"High"}})
```
3. Create the file_coverage_table and set the weight column to sort by the order column
```
file_coverage_table = DATATABLE("order", INTEGER, "weight", STRING, {{1,"None"}, {2,"Low"}, {3,"Medium"}, {4,"High"}})
```
4. Create the cloud_coverage_table and set the weight column to sort by the order column
```
cloud_coverage_table = DATATABLE("order", INTEGER, "weight", STRING, {{1,"None"}, {2,"Low"}, {3,"Medium"}, {4,"High"}})
```
5. Create the hardware_coverage_table and set the weight column to sort by the order column
```
hardware_coverage_table = DATATABLE("order", INTEGER, "weight", STRING, {{1,"None"}, {2,"Low"}, {3,"Medium"}, {4,"High"}})
```

### Create the relationships
Create the following relationships: 
* enterprise-attack-14 1 (objects.external_references.external_id) to aws-09 21 2021_attack-9 0-enterprise (mapping_objects.attack_object_id)
    * cardinality: many to many
    * cross filter direction: both

* enterprise-attack-14 1 (objects.external_references.external_id) to azure-06 29 2021_attack-8 2-enterprise (mapping_objects.attack_object_id)
    * cardinality: many to many
    * cross filter direction: both

* enterprise-attack-14 1 (objects.external_references.external_id) to gcp-06 28 2022_attack-10 0-enterprise (mapping_objects.attack_object_id)
    * cardinality: many to many
    * cross filter direction: both

* enterprise-attack-14 1 (objects.external_references.external_id) to nist_800_53-rev5_attack-14 1-enterprise (mapping_objects.attack_object_id)
    * cardinality: many to many
    * cross filter direction: both

* enterprise-attack-14 1 (objects.external_references.external_id) to v8-ATT&CK Low Mit & (Sub-)Tech (Combined ATT&CK (Sub-)Technique ID)
    * cardinality: many to many
    * cross filter direction: both

* enterprise-attack-14 1 (objects.external_references.external_id) to attack_tactic_sort_order_table (tactic)
    * cardinality: many to one
    * cross filter direction: single

* v8-ATT&CK Low Mit & (Sub-)Tech (Asset Type) to asset_sort_order_table(asset category)
    * cardinality: many to one
    * cross filter direction: single

* v8-ATT&CK Low Mit & (Sub-)Tech (Security Function) to security_function_sort_order_table(security function)
    * cardinality: many to one
    * cross filter direction: single

### Create the Unmodified Att&ck Score calculated column
1. In the Table View, select the enterprise-attack-14-1 table.
2. In the Column tools tab of the ribbon menu, click New column
3. Enter the following DAX expression: 
```
Unmodified Att&ck Score = 

VAR actionability_mitigations_lower_cutoff = 0
VAR actionability_mitigations_upper_cutoff = 55
VAR actionability_detections_lower_cutoff = 0
VAR actionability_detections_upper_cutoff = 100
VAR actionability_mitigations_to_detections_ratio = 2
VAR actionability_w_miti1 = 1
VAR actionability_w_detect1 = actionability_w_miti1 / actionability_mitigations_to_detections_ratio * (actionability_detections_upper_cutoff - actionability_detections_lower_cutoff) / (actionability_mitigations_upper_cutoff - actionability_mitigations_lower_cutoff)
VAR actionability_w_miti = actionability_w_miti1 / (actionability_w_detect1 + actionability_w_miti1)
VAR actionability_w_detect = actionability_w_detect1 / (actionability_w_detect1 + actionability_w_miti1)

VAR chokepoint_before_lower_cutoff = 0
VAR chokepoint_before_upper_cutoff = 10
VAR chokepoint_after_lower_cutoff = 0
VAR chokepoint_after_upper_cutoff = 10
VAR chokepoint_before_to_after_ratio = 1
VAR chokepoint_w_before1 = 1
VAR chokepoint_w_after1 = chokepoint_w_before1 / chokepoint_before_to_after_ratio * (chokepoint_after_upper_cutoff - chokepoint_after_lower_cutoff) / (chokepoint_before_upper_cutoff - chokepoint_before_lower_cutoff)
VAR chokepoint_w_before = chokepoint_w_before1 / (chokepoint_w_after1 + chokepoint_w_before1)
VAR chokepoint_w_after = chokepoint_w_after1 / (chokepoint_w_after1 + chokepoint_w_before1)

VAR ransomware_utility_tat_lower_cutoff = 0
VAR ransomware_utility_tat_upper_cutoff = 3
VAR ransomware_utility_count_lower_cutoff = 0
VAR ransomware_utility_count_upper_cutoff = 21
VAR ransomware_utility_tat_to_count_ratio = 3
VAR ransomware_utility_w_tat1 = 1
VAR ransomware_utility_w_count1 = ransomware_utility_w_tat1 / ransomware_utility_tat_to_count_ratio * (ransomware_utility_count_upper_cutoff - ransomware_utility_count_lower_cutoff) / (ransomware_utility_tat_upper_cutoff - ransomware_utility_tat_lower_cutoff)
VAR ransomware_utility_w_tat = ransomware_utility_w_tat1 / (ransomware_utility_w_tat1 + ransomware_utility_w_count1)
VAR ransomware_utility_w_count = ransomware_utility_w_count1 / (ransomware_utility_w_tat1 + ransomware_utility_w_count1)

VAR ransomware_polynomial_w_count1 = 1
VAR ransomware_polynomial_w_tat1 = 0
VAR ransomware_polynomial_w_counttat1 = 1
VAR ransomware_polynomial_w_countcount1 = 0
VAR ransomware_polynomial_w_count = ransomware_polynomial_w_count1 / (ransomware_polynomial_w_count1 + ransomware_polynomial_w_tat1 + ransomware_polynomial_w_counttat1 + ransomware_polynomial_w_countcount1)
VAR ransomware_polynomial_w_tat = ransomware_polynomial_w_tat1 / (ransomware_polynomial_w_count1 + ransomware_polynomial_w_tat1 + ransomware_polynomial_w_counttat1 + ransomware_polynomial_w_countcount1)
VAR ransomware_polynomial_w_counttat = ransomware_polynomial_w_counttat1 / (ransomware_polynomial_w_count1 + ransomware_polynomial_w_tat1 + ransomware_polynomial_w_counttat1 + ransomware_polynomial_w_countcount1)
VAR ransomware_polynomial_w_countcount = ransomware_polynomial_w_countcount1 / (ransomware_polynomial_w_count1 + ransomware_polynomial_w_tat1 + ransomware_polynomial_w_counttat1 + ransomware_polynomial_w_countcount1)


VAR before_utility = IF(
    (RELATED('Methodology'[Num. TID Before]) - chokepoint_before_lower_cutoff)/(chokepoint_before_upper_cutoff - chokepoint_before_lower_cutoff) > 1,
    1,
    IF((RELATED('Methodology'[Num. TID Before]) - chokepoint_before_lower_cutoff)/(chokepoint_before_upper_cutoff - chokepoint_before_lower_cutoff) < 0,
    0,
    (RELATED('Methodology'[Num. TID Before]) - chokepoint_before_lower_cutoff)/(chokepoint_before_upper_cutoff - chokepoint_before_lower_cutoff)
    ))

VAR after_utility = IF(
    (RELATED('Methodology'[Num. TID After]) - chokepoint_after_lower_cutoff)/(chokepoint_after_upper_cutoff - chokepoint_after_lower_cutoff) > 1,
    1,
    IF((RELATED('Methodology'[Num. TID After]) - chokepoint_after_lower_cutoff)/(chokepoint_after_upper_cutoff - chokepoint_after_lower_cutoff) < 0,
    0,
    (RELATED('Methodology'[Num. TID After]) - chokepoint_after_lower_cutoff)/(chokepoint_after_upper_cutoff - chokepoint_after_lower_cutoff)
    ))

VAR chokepoint_score = chokepoint_w_before * before_utility + chokepoint_w_after * after_utility

VAR mitigations_utility = IF(
    (((RELATED('Methodology'[Num. 800-53 (r5)]) + RELATED('Methodology'[Num. CIS Controls])) - actionability_mitigations_lower_cutoff) / (actionability_mitigations_upper_cutoff - actionability_mitigations_lower_cutoff)) > 1,
    1,
    IF(((RELATED('Methodology'[Num. 800-53 (r5)]) + RELATED('Methodology'[Num. CIS Controls])) - actionability_mitigations_lower_cutoff) / (actionability_mitigations_upper_cutoff - actionability_mitigations_lower_cutoff) < 0,
    0,
    (((RELATED('Methodology'[Num. 800-53 (r5)]) + RELATED('Methodology'[Num. CIS Controls])) - actionability_mitigations_lower_cutoff) / (actionability_mitigations_upper_cutoff - actionability_mitigations_lower_cutoff))
    ))

VAR detections_utility = IF(
    ((RELATED('Methodology'[Total Detections]) - actionability_detections_lower_cutoff) / (actionability_detections_upper_cutoff - actionability_detections_lower_cutoff)) > 1,
    1,
    IF((RELATED('Methodology'[Total Detections]) - actionability_detections_lower_cutoff) / (actionability_detections_upper_cutoff - actionability_detections_lower_cutoff) < 0,
    0,
    ((RELATED('Methodology'[Total Detections]) - actionability_detections_lower_cutoff) / (actionability_detections_upper_cutoff - actionability_detections_lower_cutoff))
    ))

VAR actionability_score = actionability_w_miti * mitigations_utility + actionability_w_detect * detections_utility

RETURN RELATED('Methodology'[Prevalence Scores]) + chokepoint_score + actionability_score
```

### Add the monitoring coverage slicers
1. In the report view, add a slicer. 
2. Add 'process_coverage_table'[weight] to the field for the slicer
3. Repeat this process, adding new slicers for each of the monitoring coverage tables (network, file, cloud, and hardware)

### Add the Total Top Score Measure
1. Select the enterprise-attack-14 1 table
2. In the Table tools tab of the ribbon menu, select New measure
3. Enter the following DAX expression: 
```
Total Top Score = 
SUMX(
'enterprise-attack-14 1[1]',
VAR process_weight = 
(IF(
	CONTAINSSTRING([objects.x_mitre_data_sources],"Process") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Command") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Script") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"WMI") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Module") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Pipe") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Service"),
	(SWITCH(SELECTEDVALUE(process_coverage_table[weight], "None"),
"None", 0.198,
"Low", 0.132,
"Medium", 0.066,
"High", 0 
)),
	0)) 
VAR network_weight = 
(IF(
	CONTAINSSTRING([objects.x_mitre_data_sources],"Network") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Firewall"),
	(SWITCH(SELECTEDVALUE(network_coverage_table[weight], "None"),
"None", 0.198,
"Low", 0.132,
"Medium", 0.066,
"High", 0 
)),
	0)) 
VAR file_weight = 
(IF(
	CONTAINSSTRING([objects.x_mitre_data_sources],"File") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Group") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Logon") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Schedule") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"User") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Registry") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Active") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Application"),
	SWITCH(SELECTEDVALUE(file_coverage_table[weight], "None"),
"None", 0.198,
"Low", 0.132,
"Medium", 0.066,
"High", 0 
),
	0))
VAR cloud_weight = 
(IF(
	CONTAINSSTRING([objects.x_mitre_data_sources],"Cloud") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Cluster") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Container") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Image") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Instance") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Pod") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Snapshot") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Volume"),
	SWITCH(SELECTEDVALUE(cloud_coverage_table[weight], "None"),
"None", 0.198,
"Low", 0.132,
"Medium", 0.066,
"High", 0 
),
	0))
VAR hardware_weight = 
(IF(
	CONTAINSSTRING([objects.x_mitre_data_sources],"Drive") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Firmware") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Host") ||
	CONTAINSSTRING([objects.x_mitre_data_sources],"Kernel"),
	SWITCH(SELECTEDVALUE(hardware_coverage_table[weight], "None"),
"None", 0.198,
"Low", 0.132,
"Medium", 0.066,
"High", 0 
),
	0))
VAR weight_sum = process_weight + network_weight + file_weight + cloud_weight + hardware_weight
RETURN
    ([Unmodified Att&ck Score]) * (1 + weight_sum)
)

```

### Build your report
You can now use the existing relationships and models to build your report. Select the estimated monitoring coverage for each area based on the specific asset or protect surface. Consider starting by adding a table to your report with Total Top Score and the controls or capabilties from the mapped frameworks. 

Also consider other data sources mapped to ATT&CK, such as the [CIS Benchmarks for Windows 10 Enterprise 21H1 v1.11.0](https://workbench.cisecurity.org/files/3453/download) or the [CIS Benchmarks for Red Hat Enterprise Linux 7 v3.1.1](https://workbench.cisecurity.org/files/3407/download)
