# File: csvimport_consts.py
# Copyright (c) 2021 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#

CSVIMPORT_INVALID_INT = "Please provide a valid integer value in the {param}"
CSVIMPORT_ERR_NEGATIVE_INT_PARAM = "Please provide a valid non-negative integer value in the {param}"
CSVIMPORT_ERR_INVALID_PARAM = "Please provide a non-zero positive integer in the {param}"
CSVIMPORT_ERR_SPECIFY_IP_HOSTNAME = "Accessing 127.0.0.1 is not allowed. Please specify the actual IP " \
                                  "or hostname used by the Phantom instance in the Asset config"
TIMEOUT = 120
