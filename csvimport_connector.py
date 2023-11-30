# File: csvimport_connector.py
# Copyright (c) 2022-2023 Splunk Inc.
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

import csv
import json
import os
import sys
from datetime import datetime

# Phantom App imports
import phantom.app as phantom
import phantom.rules as phantomrules
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault
from phantom_common import paths

from csvimport_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class CsvImportConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(CsvImportConnector, self).__init__()

        self._state = None

        # Variable to hold a base_url in case the app makes REST calls
        # Do note that the app json defines the asset config, so please
        # modify this as you deem fit.
        self._base_url = None
        self._auth_token = None

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code
        # Handle valid responses from ipinfo.io
        if status_code == 200:
            return RetVal(phantom.APP_SUCCESS, response.text)

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                                                                      error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))),
                          None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
            r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        content_type = r.headers.get('Content-Type', '')
        if content_type.__contains__('json') or content_type.__contains__('javascript'):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if content_type == 'html':
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_response(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
            r.headers, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, method="get", **kwargs):
        # **kwargs can be any additional parameters that requests.request accepts

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint
        self.save_progress("Connecting to endpoint: {}".format(url))
        try:
            r = request_func(
                url,
                verify=False,
                **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))),
                          resp_json)

        return self._process_response(r, action_result)

    def _get_file_info_from_vault(self, action_result, vault_id, file_type=None):
        file_info = {
            'id': vault_id
        }

        try:
            info = phantomrules.vault_info(vault_id=vault_id)[2][0]
        except IndexError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "No file with vault ID found"), None)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error retrieving file from vault: {0}".format(str(e))),
                          None)
        file_info['path'] = info['path']
        file_info['name'] = info['name']
        if not file_type:
            file_type = info['name'].split('.')[-1]
        file_info['type'] = file_type

        return RetVal(phantom.APP_SUCCESS, file_info)

    def _handle_create_csv(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, container_id = self._validate_integer(action_result, param["container_id"], 'Container ID', False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        ret_val, page_size = self._validate_integer(action_result, param.get('limit', 1000), 'Limit', False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, response = self._make_rest_call('/rest/artifact?_filter_container_id={0}&page_size={1}'.format(
            container_id, page_size), action_result)
        if phantom.is_fail(ret_val):
            self.debug_print("Error while fetching artifact from the container")
            return action_result.get_status()
        fieldnames = set()
        for i in response['data']:
            for key, val in list(i.items()):
                if isinstance(val, dict) and key != 'cef_types':
                    temp = i.pop(key)
                    i.update(temp)
            for j in list(i.keys()):
                fieldnames.add(j)
        curr_time = datetime.now().strftime("%Y_%m_%d_%I_%M_%S")
        filename = "csv_output_" + curr_time + ".csv"

        if hasattr(Vault, 'get_vault_tmp_dir'):
            vault_tmp_dir = Vault.get_vault_tmp_dir()
        else:
            vault_tmp_dir = os.path.join(paths.PHANTOM_VAULT, "tmp")

        file_loc = vault_tmp_dir + '/' + filename

        with open(file_loc, 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=list(fieldnames))
            writer.writeheader()
            for row in response['data']:
                writer.writerow(row)
        vault_ret_dict = phantomrules.vault_add(container=container_id,
                                                file_location=file_loc,
                                                file_name=filename)
        if vault_ret_dict[0]:
            vault_details = {
                phantom.APP_JSON_VAULT_ID: vault_ret_dict[2],
                'file_name': filename
            }
            action_result.add_data(vault_details)
            self.debug_print("Successfully Created CSV")
            return action_result.set_status(phantom.APP_SUCCESS, "Successfully Created CSV")

        return action_result.set_status(phantom.APP_ERROR, 'Error adding file to vault: {0}'.format(vault_ret_dict))

    def _handle_ingest_csv(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, container_id = self._validate_integer(action_result, param["container_id"], 'Container ID', False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        vault_id = param['vault_id']
        artifact_name = param['artifact_name']
        artifact_label = param.get('artifact_label', 'events')
        cef_names = param['cef_column_headers']

        if cef_names:
            cef_names = [x.strip() for x in cef_names.split(',')]
            cef_names = list(filter(None, cef_names))
        num_columns = len(cef_names)

        # Make sure container exists first, provide a better error message than waiting for save_artifacts to fail
        ret_val, message, _ = self.get_container_info(container_id)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Unable to find container: {}".format(message))

        # run_automation = param.get('run_automation', True)
        if vault_id:
            ret_val, file_info = self._get_file_info_from_vault(action_result, vault_id)
            if phantom.is_fail(ret_val):
                return ret_val
            self.debug_print("File Info", file_info)
            self.save_progress("****File Info : {0}".format(file_info))
            csv_vault_path = file_info['path']
            with open(csv_vault_path, "r") as csvf:
                artifacts_list = []
                try:
                    reader = csv.reader(csvf)
                    for row in reader:
                        cef = {}
                        for i in range(num_columns):
                            cef[cef_names[i]] = row[i]
                        artifact_json = {
                            "container_id": container_id,
                            "cef": cef,
                            "label": artifact_label,
                            "name": artifact_name,
                            "severity": "high",
                            "type": artifact_label
                        }
                        artifacts_list.append(artifact_json)
                    if artifacts_list:
                        create_artifacts_status, create_artifacts_msg, _ = self.save_artifacts(artifacts_list)
                        if phantom.is_fail(create_artifacts_status):
                            self.debug_print("Error saving artifacts: {}".format(create_artifacts_msg))
                            return action_result.set_status(phantom.APP_ERROR, "Error saving artifacts: {}".format(create_artifacts_msg))

                except Exception:
                    return action_result.set_status(
                        phantom.APP_ERROR, "Error while performing file operation. File:{0}".format(csv_vault_path))
        data = {'vault_id': vault_id}
        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS, 'Successfully Ingested CSV')

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, CSVIMPORT_INVALID_INT.format(param=key)), None

                parameter = int(parameter)
            except Exception:
                return action_result.set_status(phantom.APP_ERROR, CSVIMPORT_INVALID_INT.format(param=key)), None

            if parameter < 0:
                return action_result.set_status(phantom.APP_ERROR, CSVIMPORT_ERR_NEGATIVE_INT_PARAM.format(param=key)), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(phantom.APP_ERROR, CSVIMPORT_ERR_INVALID_PARAM.format(param=key)), None

        return phantom.APP_SUCCESS, parameter

    def _get_error_message_from_exception(self, e):
        """ This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        err_code = ERR_CODE_UNAVAILABLE
        err_msg = ERR_MSG_UNAVAILABLE
        try:
            if hasattr(e, 'args'):
                if len(e.args) > 1:
                    err_code = e.args[0]
                    err_msg = e.args[1]
                elif len(e.args) == 1:
                    err_msg = e.args[0]
        except Exception:
            pass

        return "Error Code: {0}. Error Message: {1}".format(err_code, err_msg)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'ingest_csv':
            ret_val = self._handle_ingest_csv(param)
        if action_id == 'create_csv':
            ret_val = self._handle_create_csv(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        self._base_url = CsvImportConnector._get_phantom_base_url()

        return phantom.APP_SUCCESS

    def finalize(self):

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':
    # import sys
    import pudb

    pudb.set_trace()

    if len(sys.argv) < 2:
        print("No test json specified as input")
        sys.exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CsvImportConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
