#!/usr/bin/env python3


"""
    Checkmk special agent for Alyvix Server
    Copyright (C) 2021 Francesco Melchiori
    <https://www.francescomelchiori.com/>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see
    <http://www.gnu.org/licenses/>.
"""


import sys
import argparse
import time
import json
import urllib.request


class AlyvixServerMeasure:
    def __init__(self,
                 timestamp_epoch,  # e.g. 1619000540323290112
                 hostname,  # e.g. "alyvixserver"
                 domain_username,  # e.g. "CO\\AlyvixUser05"
                 test_case_alias,  # e.g. "visittrentino"
                 test_case_exit,  # e.g. "true"
                 test_case_state,  # e.g. 0
                 transaction_alias,  # e.g. "vt_home_ready"
                 transaction_performance_ms,  # e.g. 4689
                 transaction_exit,  # e.g. "true"
                 transaction_state,  # e.g. 0
                 test_case_name=None,  # e.g. "visittrentino"
                 test_case_arguments=None,  # e.g. null
                 test_case_execution_code=None,  # e.g. "pb02Al05vino1619000538"
                 test_case_duration_ms=None,  # e.g. 13998
                 transaction_name=None,  # e.g. "vt_home_ready"
                 transaction_group=None,  # e.g. null
                 transaction_detection_type=None,  # e.g. "appear"
                 transaction_timeout_ms=None,  # e.g. 10000
                 transaction_warning_ms=None,  # e.g. null
                 transaction_critical_ms=None,  # e.g. null
                 transaction_accuracy_ms=None,  # e.g. 82
                 transaction_record_text=None,  # e.g. ""
                 transaction_record_extract=None,  # e.g. ""
                 transaction_resolution_width=None,  # e.g. 1280
                 transaction_resolution_height=None,  # e.g. 800
                 transaction_scaling_factor=None):  # e.g. 100
        self.timestamp_epoch = timestamp_epoch
        self.hostname = hostname
        self.domain_username = domain_username
        self.test_case_alias = test_case_alias
        self.test_case_exit = test_case_exit
        self.test_case_state = test_case_state
        self.transaction_alias = transaction_alias
        self.transaction_performance_ms = transaction_performance_ms
        self.transaction_exit = transaction_exit
        self.transaction_state = transaction_state
        self.test_case_name = test_case_name
        self.test_case_arguments = test_case_arguments
        self.test_case_execution_code = test_case_execution_code
        self.test_case_duration_ms = test_case_duration_ms
        self.transaction_name = transaction_name
        self.transaction_group = transaction_group
        self.transaction_detection_type = transaction_detection_type
        self.transaction_timeout_ms = transaction_timeout_ms
        self.transaction_warning_ms = transaction_warning_ms
        self.transaction_critical_ms = transaction_critical_ms
        self.transaction_accuracy_ms = transaction_accuracy_ms
        self.transaction_record_text = transaction_record_text
        self.transaction_record_extract = transaction_record_extract
        self.transaction_resolution_width = transaction_resolution_width
        self.transaction_resolution_height = transaction_resolution_height
        self.transaction_scaling_factor = transaction_scaling_factor


class AlyvixServerCheckmkMeasure(AlyvixServerMeasure):
    def __repr__(self, testcase=False):
        if testcase:
            checkmk_agent_measure_output = ''
            checkmk_agent_separator = ' | '
            checkmk_agent_newline = '\n'
            # checkmk_agent_measure_output += '{0}{1}'.format(time.ctime(self.timestamp_epoch/pow(10, 9)),
            #                                                 checkmk_agent_separator)
            # checkmk_agent_measure_output += '{0}{1}'.format(self.hostname,
            #                                                 checkmk_agent_separator)
            # checkmk_agent_measure_output += '{0}{1}'.format(self.domain_username,
            #                                                 checkmk_agent_separator)
            # checkmk_agent_measure_output += '{0}{1}'.format(self.test_case_alias,
            #                                                 checkmk_agent_separator)
            checkmk_agent_measure_output += '{0}{1}'.format(self.test_case_exit,
                                                            checkmk_agent_separator)
            checkmk_agent_measure_output += '{0}{1}'.format(self.test_case_state,
                                                            checkmk_agent_newline)
            return checkmk_agent_measure_output
        else:
            checkmk_agent_measure_output = ''
            checkmk_agent_separator = ' | '
            checkmk_agent_newline = '\n'
            checkmk_agent_measure_output += '{0}{1}'.format(time.ctime(self.timestamp_epoch/pow(10, 9)),
                                                            checkmk_agent_separator)
            checkmk_agent_measure_output += '{0}{1}'.format(self.hostname,
                                                            checkmk_agent_separator)
            checkmk_agent_measure_output += '{0}{1}'.format(self.domain_username,
                                                            checkmk_agent_separator)
            checkmk_agent_measure_output += '{0}{1}'.format(self.test_case_alias,
                                                            checkmk_agent_separator)
            checkmk_agent_measure_output += '{0}{1}'.format(self.transaction_alias,
                                                            checkmk_agent_separator)
            checkmk_agent_measure_output += '{0}{1}'.format(self.transaction_performance_ms,
                                                            checkmk_agent_separator)
            checkmk_agent_measure_output += '{0}{1}'.format(self.transaction_exit,
                                                            checkmk_agent_separator)
            checkmk_agent_measure_output += '{0}{1}'.format(self.transaction_state,
                                                            checkmk_agent_newline)
            return checkmk_agent_measure_output


class AlyvixServerCheckmkAgent:
    def __init__(self, alyvix_server_https_url, test_case_alias):
        self.alyvix_server_https_url = alyvix_server_https_url
        self.test_case_alias = test_case_alias
        self.alyvix_server_response = {}
        self.get_alyvix_server_data()
        self.alyvix_server_measure_response = None
        self.alyvix_server_checkmk_measure = None
        self.alyvix_server_checkmk_measures = []
        self.alyvix_server_checkmk_testcase = None
        self.build_alyvix_server_checkmk_measures()

    def __repr__(self):
        checkmk_agent_output = '<<<alyvix>>>\n'
        for self.alyvix_server_checkmk_measure in self.alyvix_server_checkmk_measures:
            checkmk_agent_output += self.alyvix_server_checkmk_measure.__repr__()
        checkmk_agent_output += self.alyvix_server_checkmk_testcase.__repr__(testcase=True)
        return checkmk_agent_output

    def get_alyvix_server_data(self):
        alyvix_server_request = \
            '{0}/v0/testcases/{1}/'.format(self.alyvix_server_https_url, self.test_case_alias)
        self.alyvix_server_response = json.load(urllib.request.urlopen(
            alyvix_server_request))
        return self.alyvix_server_response

    def build_alyvix_server_checkmk_measure(self):
        self.alyvix_server_checkmk_measure = AlyvixServerCheckmkMeasure(
            timestamp_epoch=self.alyvix_server_measure_response['timestamp_epoch'],
            hostname=self.alyvix_server_measure_response['hostname'],
            domain_username=self.alyvix_server_measure_response['domain_username'],
            test_case_alias=self.alyvix_server_measure_response['test_case_alias'],
            test_case_exit=self.alyvix_server_measure_response['test_case_exit'],
            test_case_state=self.alyvix_server_measure_response['test_case_state'],
            transaction_alias=self.alyvix_server_measure_response['transaction_alias'],
            transaction_performance_ms=self.alyvix_server_measure_response['transaction_performance_ms'],
            transaction_exit=self.alyvix_server_measure_response['transaction_exit'],
            test_case_name=self.alyvix_server_measure_response['test_case_name'],
            test_case_arguments=self.alyvix_server_measure_response['test_case_arguments'],
            test_case_execution_code=self.alyvix_server_measure_response['test_case_execution_code'],
            test_case_duration_ms=self.alyvix_server_measure_response['test_case_duration_ms'],
            transaction_name=self.alyvix_server_measure_response['transaction_name'],
            transaction_group=self.alyvix_server_measure_response['transaction_group'],
            transaction_detection_type=self.alyvix_server_measure_response['transaction_detection_type'],
            transaction_timeout_ms=self.alyvix_server_measure_response['transaction_timeout_ms'],
            transaction_warning_ms=self.alyvix_server_measure_response['transaction_warning_ms'],
            transaction_critical_ms=self.alyvix_server_measure_response['transaction_critical_ms'],
            transaction_accuracy_ms=self.alyvix_server_measure_response['transaction_accuracy_ms'],
            transaction_state=self.alyvix_server_measure_response['transaction_state'],
            transaction_record_text=self.alyvix_server_measure_response['transaction_record_text'],
            transaction_record_extract=self.alyvix_server_measure_response['transaction_record_extract'],
            transaction_resolution_width=self.alyvix_server_measure_response['transaction_resolution_width'],
            transaction_resolution_height=self.alyvix_server_measure_response['transaction_resolution_height'],
            transaction_scaling_factor=self.alyvix_server_measure_response['transaction_scaling_factor'])
        return self.alyvix_server_checkmk_measure

    def build_alyvix_server_checkmk_measures(self):
        for self.alyvix_server_measure_response in self.alyvix_server_response['measures']:
            if not self.alyvix_server_checkmk_testcase:
                self.alyvix_server_checkmk_testcase = self.build_alyvix_server_checkmk_measure()
            self.alyvix_server_checkmk_measures.append(self.build_alyvix_server_checkmk_measure())
        return self.alyvix_server_checkmk_measures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--alyvix_server_https_url',
                        help='set the HTTPS URL to Alyvix Server (e.g. https://alyvixserver.co.lan)')
    parser.add_argument('-t', '--test_case_alias',
                        help='set the Alyvix test case alias (e.g. visittrentino)')
    cli_args = sys.argv[1:]
    if cli_args:
        args = parser.parse_args()
        alyvix_server_https_url = args.alyvix_server_https_url if args.alyvix_server_https_url else False
        test_case_alias = args.test_case_alias if args.test_case_alias else False
        if alyvix_server_https_url and test_case_alias:
            alyvix_server_checkmk_agent = AlyvixServerCheckmkAgent(alyvix_server_https_url,
                                                                   test_case_alias)
            print(alyvix_server_checkmk_agent)
        else:
            # test_alyvix_server_checkmk_measure = AlyvixServerCheckmkMeasure(1619000540323290112,
            #                                                                 'alyvixserver',
            #                                                                 'CO\\AlyvixUser',
            #                                                                 'visittrentino',
            #                                                                 True,
            #                                                                 0,
            #                                                                 'vt_home_ready',
            #                                                                 4689,
            #                                                                 True,
            #                                                                 0)
            # print(test_alyvix_server_checkmk_measure)
            pass


if __name__ == '__main__':
    main()
