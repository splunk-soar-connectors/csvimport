[comment]: # "Auto-generated SOAR connector documentation"
# CSV Import

Publisher: Splunk  
Connector Version: 1\.0\.1  
Product Vendor: Splunk  
Product Name: CSV Import  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 5\.0\.0  

Ingest CSV files into Phantom

### Supported Actions  
[ingest csv](#action-ingest-csv) - Read contents of a CSV and create artifact  
[csv from artifacts](#action-csv-from-artifacts) - Create the csv in the vault from the artifacts of container  

## action: 'ingest csv'
Read contents of a CSV and create artifact

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault\_id** |  required  | The vault\_id for the csv | string |  `sha1`  `vault id` 
**container\_id** |  required  | Create artifacts on given container ID | numeric | 
**cef\_column\_headers** |  required  | Comma separated list of the CEF columns \(e\.g\. ip,port,type,comment\) | string | 
**artifact\_name** |  required  | Name for the artifact \(e\.g\. IP Artifact\) | string | 
**artifact\_label** |  optional  | Label for the artifact \(e\.g\. IP\_test\) | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.artifact\_label | string | 
action\_result\.parameter\.artifact\_name | string | 
action\_result\.parameter\.cef\_column\_headers | string | 
action\_result\.parameter\.container\_id | numeric | 
action\_result\.parameter\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.data\.\*\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'csv from artifacts'
Create the csv in the vault from the artifacts of container

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container\_id** |  required  | The container\_id for the artifacts | numeric | 
**limit** |  optional  | The number of artifacts to retrieve | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.container\_id | numeric | 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.vault\_id | string |  `sha1`  `vault id` 
action\_result\.data\.\*\.file\_name | string | 
action\_result\.summary | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 