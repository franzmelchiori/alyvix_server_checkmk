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
import ssl
import urllib.request


ERROR_LEVEL = {0: 'OK',
               1: 'WARNING',
               2: 'CRITICAL',
               3: 'UNKNOWN'}


class AlyvixServerMeasure:
    def __init__(self,
                 timestamp_epoch,  # 1619000540323290112
                 hostname,  # "alyvixserver"
                 domain_username,  # "CO\\AlyvixUser05"
                 test_case_alias,  # "visittrentino"
                 test_case_duration_ms,  # 13998
                 test_case_exit,  # "true"
                 test_case_state,  # 0
                 transaction_alias,  # "vt_home_ready"
                 transaction_performance_ms,  # 4689
                 transaction_exit,  # "true"
                 transaction_state,  # 0
                 test_case_name=None,  # "visittrentino"
                 test_case_arguments=None,  # "text"
                 test_case_execution_code=None,  # "pb02Al05vino1619000538"
                 transaction_name=None,  # "vt_home_ready"
                 transaction_group=None,  # "text"
                 transaction_detection_type=None,  # "appear"
                 transaction_timeout_ms=None,  # 10000
                 transaction_warning_ms=None,  # null
                 transaction_critical_ms=None,  # null
                 transaction_accuracy_ms=None,  # 82
                 transaction_record_text=None,  # "text"
                 transaction_record_extract=None,  # "text"
                 transaction_resolution_width=None,  # 1280
                 transaction_resolution_height=None,  # 800
                 transaction_scaling_factor=None):  # 100
        self.timestamp_epoch = timestamp_epoch
        self.hostname = hostname
        self.domain_username = domain_username
        self.test_case_alias = test_case_alias
        self.test_case_duration_ms = test_case_duration_ms
        self.test_case_exit = test_case_exit
        self.test_case_state = test_case_state
        self.transaction_alias = transaction_alias
        self.transaction_performance_ms = transaction_performance_ms
        self.transaction_exit = transaction_exit
        self.transaction_state = transaction_state
        self.test_case_name = test_case_name
        self.test_case_arguments = test_case_arguments
        self.test_case_execution_code = test_case_execution_code
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
    def __repr__(self):
        return self.output_measure()

    def output_measure(self):
        checkmk_agent_measure_output = ''
        checkmk_agent_separator = ' | '
        checkmk_agent_newline = '\n'
        checkmk_agent_measure_output += '{0}{1}'.format(
            ERROR_LEVEL[self.transaction_state], checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            time.ctime(self.timestamp_epoch/pow(10, 9)),
            checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.hostname, checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.domain_username, checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.test_case_alias, checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.transaction_alias, checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.transaction_performance_ms, checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.transaction_exit, checkmk_agent_newline)
        return checkmk_agent_measure_output

    def output_testcase(self):
        checkmk_agent_measure_output = ''
        checkmk_agent_separator = ' | '
        checkmk_agent_newline = '\n'
        checkmk_agent_measure_output += '{0}{1}'.format(
            ERROR_LEVEL[self.test_case_state], checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            time.ctime(self.timestamp_epoch/pow(10, 9)),
            checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.hostname, checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.domain_username, checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.test_case_alias, checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.test_case_duration_ms, checkmk_agent_separator)
        checkmk_agent_measure_output += '{0}{1}'.format(
            self.test_case_exit, checkmk_agent_newline)
        return checkmk_agent_measure_output


class AlyvixServerCheckmkAgent:
    def __init__(self,
                 alyvix_server_https_url,
                 test_case_alias,
                 development_environment=False):
        self.alyvix_server_https_url = alyvix_server_https_url
        self.test_case_alias = test_case_alias
        self.development_environment = development_environment
        self.alyvix_server_response = {}
        self.get_alyvix_server_data()
        self.alyvix_server_measure_response = None
        self.alyvix_server_checkmk_measure = None
        self.alyvix_server_checkmk_measures = []
        self.alyvix_server_checkmk_testcase = None
        self.build_alyvix_server_checkmk_measures()

    def __repr__(self):
        checkmk_agent_output =\
            '<<<alyvix>>>\n' +\
            ''.join([self.alyvix_server_checkmk_measure.output_measure()
                     for self.alyvix_server_checkmk_measure
                     in self.alyvix_server_checkmk_measures]) +\
            self.alyvix_server_checkmk_testcase.output_testcase()
        return checkmk_agent_output

    def get_alyvix_server_data(self):
        if self.development_environment:
            self.alyvix_server_response = json.load(
                open('alyvix_server_response.json'))
        else:
            alyvix_server_request = '{0}/v0/testcases/{1}/'.format(
                self.alyvix_server_https_url, self.test_case_alias)
            self.alyvix_server_response = json.load(
                urllib.request.urlopen(alyvix_server_request))
        return self.alyvix_server_response

    def build_alyvix_server_checkmk_measure(self):
        self.alyvix_server_checkmk_measure = AlyvixServerCheckmkMeasure(
            timestamp_epoch=self.alyvix_server_measure_response[
                'timestamp_epoch'],
            hostname=self.alyvix_server_measure_response[
                'hostname'],
            domain_username=self.alyvix_server_measure_response[
                'domain_username'],
            test_case_alias=self.alyvix_server_measure_response[
                'test_case_alias'],
            test_case_duration_ms=self.alyvix_server_measure_response[
                'test_case_duration_ms'],
            test_case_exit=self.alyvix_server_measure_response[
                'test_case_exit'],
            test_case_state=self.alyvix_server_measure_response[
                'test_case_state'],
            transaction_alias=self.alyvix_server_measure_response[
                'transaction_alias'],
            transaction_performance_ms=self.alyvix_server_measure_response[
                'transaction_performance_ms'],
            transaction_exit=self.alyvix_server_measure_response[
                'transaction_exit'],
            transaction_state=self.alyvix_server_measure_response[
                'transaction_state'],
            test_case_name=self.alyvix_server_measure_response[
                'test_case_name'],
            test_case_arguments=self.alyvix_server_measure_response[
                'test_case_arguments'],
            test_case_execution_code=self.alyvix_server_measure_response[
                'test_case_execution_code'],
            transaction_name=self.alyvix_server_measure_response[
                'transaction_name'],
            transaction_group=self.alyvix_server_measure_response[
                'transaction_group'],
            transaction_detection_type=self.alyvix_server_measure_response[
                'transaction_detection_type'],
            transaction_timeout_ms=self.alyvix_server_measure_response[
                'transaction_timeout_ms'],
            transaction_warning_ms=self.alyvix_server_measure_response[
                'transaction_warning_ms'],
            transaction_critical_ms=self.alyvix_server_measure_response[
                'transaction_critical_ms'],
            transaction_accuracy_ms=self.alyvix_server_measure_response[
                'transaction_accuracy_ms'],
            transaction_record_text=self.alyvix_server_measure_response[
                'transaction_record_text'],
            transaction_record_extract=self.alyvix_server_measure_response[
                'transaction_record_extract'],
            transaction_resolution_width=self.alyvix_server_measure_response[
                'transaction_resolution_width'],
            transaction_resolution_height=self.alyvix_server_measure_response[
                'transaction_resolution_height'],
            transaction_scaling_factor=self.alyvix_server_measure_response[
                'transaction_scaling_factor'])
        return self.alyvix_server_checkmk_measure

    def build_alyvix_server_checkmk_measures(self):
        self.alyvix_server_checkmk_measures = [
            self.build_alyvix_server_checkmk_measure() for
            self.alyvix_server_measure_response in
            self.alyvix_server_response['measures']]
        self.alyvix_server_checkmk_testcase = \
            self.alyvix_server_checkmk_measures[0]
        return self.alyvix_server_checkmk_measures


def main():
    parser = argparse.ArgumentParser(
        description='This Checkmk special agent uses the RESTful web'
                    'API of the Alyvix Server to gather transaction'
                    'measurements about a given ongoing Alyvix test'
                    'case.')
    parser.add_argument(
        '-d', '--development_environment', action='store_true',
        help='get static Alyvix Server sample data from file for'
             'development purposes')
    parser.add_argument(
        '-a', '--alyvix_server_https_url',
        help='set the HTTPS URL to Alyvix Server (e.g.'
             'https://alyvixserver.co.lan)')
    parser.add_argument(
        '-t', '--test_case_alias',
        help='set the Alyvix test case alias (e.g. visittrentino)')
    cli_args = sys.argv[1:]
    if cli_args:
        args = parser.parse_args()
        development_environment = args.development_environment \
            if args.development_environment else False
        alyvix_server_https_url = args.alyvix_server_https_url \
            if args.alyvix_server_https_url else False
        test_case_alias = args.test_case_alias \
            if args.test_case_alias else False
        if development_environment:
            alyvix_server_checkmk_agent = AlyvixServerCheckmkAgent(
                '', '', True)
            print(alyvix_server_checkmk_agent)
            pass
        else:
            if alyvix_server_https_url and test_case_alias:
                alyvix_server_checkmk_agent = AlyvixServerCheckmkAgent(
                    alyvix_server_https_url, test_case_alias)
                print(alyvix_server_checkmk_agent)
            else:
                pass


if __name__ == '__main__':
    main()
