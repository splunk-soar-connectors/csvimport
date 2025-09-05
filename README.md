# CSV Import

Publisher: Splunk <br>
Connector Version: 1.1.1 <br>
Product Vendor: Splunk <br>
Product Name: CSV Import <br>
Minimum Product Version: 6.1.0

Ingest CSV files into Phantom

### Supported Actions

[ingest csv](#action-ingest-csv) - Read contents of a CSV and create artifact <br>
[csv from artifacts](#action-csv-from-artifacts) - Create the csv in the vault from the artifacts of container

## action: 'ingest csv'

Read contents of a CSV and create artifact

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**vault_id** | required | The vault_id for the csv | string | `sha1` `vault id` |
**container_id** | required | Create artifacts on given container ID | numeric | |
**cef_column_headers** | required | Comma separated list of the CEF columns (e.g. ip,port,type,comment) | string | |
**artifact_name** | required | Name for the artifact (e.g. IP Artifact) | string | |
**artifact_label** | optional | Label for the artifact (e.g. IP_test) | string | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.artifact_label | string | | events |
action_result.parameter.artifact_name | string | | artifact |
action_result.parameter.cef_column_headers | string | | header_1 header_2 |
action_result.parameter.container_id | numeric | | 123 |
action_result.parameter.vault_id | string | `sha1` `vault id` | 285ed37b6be7b4bf1583b59150b22e9a741caede |
action_result.data.\*.vault_id | string | `sha1` `vault id` | b90e6c7ab7f77d058efd444279b81c4c6a9cf4ce |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

## action: 'csv from artifacts'

Create the csv in the vault from the artifacts of container

Type: **generic** <br>
Read only: **True**

#### Action Parameters

PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**container_id** | required | The container_id for the artifacts | numeric | |
**limit** | optional | The number of artifacts to retrieve | numeric | |

#### Action Output

DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string | | success failed |
action_result.parameter.container_id | numeric | | 123 |
action_result.parameter.limit | numeric | | 1000 |
action_result.data.\*.vault_id | string | `sha1` `vault id` | b90e6c7ab7f77d058efd444279b81c4c6a9cf4ce |
action_result.data.\*.file_name | string | | test.csv |
action_result.summary | string | | |
action_result.message | string | | |
summary.total_objects | numeric | | |
summary.total_objects_successful | numeric | | |

______________________________________________________________________

Auto-generated Splunk SOAR Connector documentation.

Copyright 2025 Splunk Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and limitations under the License.
