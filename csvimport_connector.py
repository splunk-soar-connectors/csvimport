# File: csvimport_connector.py
# Copyright (c) 2018-2021 Splunk Inc.
#
# SPLUNK CONFIDENTIAL - Use or disclosure of this material in whole or in part
# without a valid written license from Splunk Inc. is PROHIBITED.

import csv
import json
import sys

# Phantom App imports
import phantom.app as phantom
import phantom.rules as phantomrules
import requests
from bs4 import BeautifulSoup
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector

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
        if 'json' or 'javascript' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML response, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
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

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint
        headers = {"ph-auth-token": self._auth_token}
        self.save_progress("Connecting to endpoint: {}".format(url))
        try:
            r = request_func(
                url,
                headers=headers,
                verify=config.get('verify_server_cert', False),
                **kwargs)
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".format(str(e))),
                          resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Connecting to endpoint")
        # make rest call
        ret_val, response = self._make_rest_call('/rest/version', action_result)

        if phantom.is_fail(ret_val):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # for now the return is commented out, but after implementation, return from here
            self.save_progress("Test Connectivity Failed.")
            return action_result.get_status()

        # Return success
        self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

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
        ret_val, page_size = self._validate_integer(action_result, param.get('page_size', 1000), 'Page Size', False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        ret_val, response = self._make_rest_call('/rest/artifact?_filter_container_id={0}&page_size={1}'.format(
            container_id, page_size), action_result)
        fieldnames = set()
        for i in response['data']:
            for key, val in list(i.items()):
                if isinstance(val, dict) and key != 'cef_types':
                    temp = i.pop(key)
                    i.update(temp)
            for j in list(i.keys()):
                fieldnames.add(j)
        with open('/opt/phantom/vault/tmp/csv_output.csv', 'w') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=list(fieldnames))
            writer.writeheader()
            for row in response['data']:
                writer.writerow(row)
        phantomrules.vault_add(container=container_id,
                               file_location="/opt/phantom/vault/tmp/csv_output.csv",
                               file_name="csv_output.csv")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_ingest_csv(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        ret_val, container_id = self._validate_integer(action_result, param["container_id"], 'Container ID', False)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        vault_id = param['vault_id']
        artifact_name = param['artifact_name']
        artifact_label = param.get('artifact_label')
        cef_names = param['cef_column_headers']

        if cef_names:
            cef_names = [x.strip() for x in cef_names.split(',')]
            cef_names = list(filter(None, cef_names))
        if not artifact_label:
            artifact_label = "events"
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
                reader = csv.reader(csvf)
                for row in reader:
                    cef = {}
                    for i in range(num_columns):
                        cef[cef_names[i]] = row[i]
                    phantomrules.add_artifact(
                        container=container_id, raw_data={}, cef_data=cef, label=artifact_label,
                        name=artifact_name, severity='high',
                        identifier=None,
                        artifact_type=artifact_label)
                    # self.save_progress("****JSON : {0}".format(artifact_json))

        return action_result.set_status(phantom.APP_SUCCESS)

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

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'ingest_csv':
            ret_val = self._handle_ingest_csv(param)
        if action_id == 'create_csv':
            ret_val = self._handle_create_csv(param)
        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)

        return ret_val

    def initialize(self):

        # Load the state in initialize, use it to store data
        # that needs to be accessed across actions
        self._state = self.load_state()

        # get the asset config
        config = self.get_config()

        """
        # Access values in asset config by the name

        # Required values can be accessed directly
        required_config_name = config['required_config_name']

        # Optional values should use the .get() function
        optional_config_name = config.get('optional_config_name')
        """

        self._base_url = config.get('base_url')
        self._auth_token = config.get('auth_token')

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
