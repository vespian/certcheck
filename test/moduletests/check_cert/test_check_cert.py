#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
# Copyright (c) 2013 Spotify AB
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.


# Make it a bit more like python3:
from __future__ import absolute_import
from __future__ import division
from __future__ import nested_scopes
from __future__ import print_function
from __future__ import with_statement

# Global imports:
from collections import namedtuple
from datetime import datetime, timedelta
from pymisc.script import RecoverableException, FatalException
import fileinput
import mock
import os
import subprocess
import sys
major, minor, micro, releaselevel, serial = sys.version_info
if major == 2 and minor < 7:
    import unittest2 as unittest
else:
    import unittest

# To perform local imports first we need to fix PYTHONPATH:
pwd = os.path.abspath(os.path.dirname(__file__))
sys.path.append(os.path.abspath(pwd + '/../../modules/'))

# Local imports:
import file_paths as paths
import check_cert


@mock.patch('logging.warn')
@mock.patch('logging.info')
@mock.patch('logging.error')
@mock.patch('check_cert.ScriptLock', autospec=True)
@mock.patch('check_cert.ScriptStatus', autospec=True)
@mock.patch('check_cert.ScriptConfiguration', autospec=True)
class TestCheckCert(unittest.TestCase):
    @staticmethod
    def _create_test_cert(days, path, is_der=False):
        openssl_cmd = ["/usr/bin/openssl", "req", "-x509", "-nodes",
                       "-newkey", "rsa:1024",
                       "-subj", "/C=SE/ST=Stockholm/L=Stockholm/CN=www.example.com"]

        openssl_cmd.extend(["-days", str(days)])
        openssl_cmd.extend(["-out", path])

        if is_der:
            openssl_cmd.extend(["-outform", "DER"])
            openssl_cmd.extend(["-keyout", path + ".key"])
        else:
            openssl_cmd.extend(["-keyout", path])

        child = subprocess.Popen(openssl_cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
        child_stdout, child_stderr = child.communicate()
        if child.returncode != 0:
            print("Failed to execute opensssl command:\n\t{0}\n".format(
                ' '.join(openssl_cmd)))
            print("Stdout+Stderr:\n{0}".format(child_stdout))
            sys.exit(1)
        else:
            print("Created test certificate {0}".format(os.path.basename(path)))

    def _script_conf_factory(self, **kwargs):
        """
        Provide fake configuration data objects.
        """
        good_configuration = {"warn_treshold": 30,
                              "critical_treshold": 15,
                              "nrpe_enabled": True,
                              "riemann_enabled": True,
                              "riemann_hosts": {
                                  'static': ['1.2.3.4:1:udp',
                                             '2.3.4.5:5555:tcp', ]
                                  },
                              "riemann_tags": ["abc", "def"],
                              "riemann_ttl": 60,
                              "repo_host": "git.foo.net",
                              "repo_port": 22,
                              "repo_url": "/foo-puppet",
                              "repo_masterbranch": "refs/heads/foo",
                              "repo_localdir": "/tmp/foo",
                              "repo_user": "foo",
                              "repo_pubkey": "./foo",
                              "lockfile": "./fake_lock.pid",
                              "ignored_certs": {
                                  '42b270cbd03eaa8c16c386e66f910195f769f8b1':
                                  "certificate used during unit-tests"
                                  }
                              }

        def func(key):
            config = good_configuration.copy()
            config.update(kwargs)
            self.assertIn(key, config)
            return config[key]

        return func

    @staticmethod
    def _certpath2namedtuple(path):
        with open(path, 'rb') as fh:
            cert = namedtuple("FileTuple", ['path', 'content'])
            cert.path = path
            cert.content = fh.read()
            return cert

    @classmethod
    def setUpClass(cls):
        # Prepare the test certificate tree:
        cls._create_test_cert(-3, paths.EXPIRED_3_DAYS)
        cls._create_test_cert(6, paths.EXPIRE_6_DAYS)
        cls._create_test_cert(21, paths.EXPIRE_21_DAYS)
        cls._create_test_cert(41, paths.EXPIRE_41_DAYS)
        cls._create_test_cert(41, paths.EXPIRE_41_DAYS_DER, is_der=True,)
        cls._create_test_cert(41, paths.TRUSTED_EXPIRE_41_CERT)

        # Simulate a sample certificate that has non-standard header
        for line in fileinput.input(paths.TRUSTED_EXPIRE_41_CERT, inplace=True):
            print(line.replace('-----BEGIN CERTIFICATE-----',
                               '-----BEGIN TRUSTED CERTIFICATE-----'), end="")

    def test_cert_expiration_parsing(self, ScriptConfigurationMock, ScriptStatusMock,
                                     *unused):
        IGNORED_CERTS = ['42b270cbd03eaa8c16c386e66f910195f769f8b1']

        # -3 days is in fact -4 days, 23:59:58.817181
        # so we compensate and round up
        # additionally, openssl uses utc dates
        now = datetime.utcnow() - timedelta(days=1)

        # Test an expired certificate:
        cert = self._certpath2namedtuple(paths.EXPIRED_3_DAYS)
        expiry_time = check_cert.get_cert_expiration(cert, IGNORED_CERTS) - now
        self.assertEqual(expiry_time.days, -3)

        # Test an ignored certificate:
        cert = self._certpath2namedtuple(paths.IGNORED_CERT)
        expiry_time = check_cert.get_cert_expiration(cert, IGNORED_CERTS)
        self.assertEqual(expiry_time, None)

        # Test a good certificate:
        cert = self._certpath2namedtuple(paths.EXPIRE_21_DAYS)
        expiry_time = check_cert.get_cert_expiration(cert, IGNORED_CERTS) - now
        self.assertEqual(expiry_time.days, 21)

        # Test a DER certificate:
        cert = self._certpath2namedtuple(paths.EXPIRE_41_DAYS_DER)
        expiry_time = check_cert.get_cert_expiration(cert, IGNORED_CERTS)
        self.assertIs(expiry_time, None)

        # Test a broken certificate:
        cert = self._certpath2namedtuple(paths.BROKEN_CERT)
        expiry_time = check_cert.get_cert_expiration(cert, IGNORED_CERTS)
        self.assertIs(expiry_time, None)

        # Test a "TRUSTED" certificate:
        cert = self._certpath2namedtuple(paths.TRUSTED_EXPIRE_41_CERT)
        expiry_time = check_cert.get_cert_expiration(cert, IGNORED_CERTS) - now
        self.assertEqual(expiry_time.days, 41)

    @mock.patch('sys.exit')
    def test_command_line_parsing(self, SysExitMock, *unused):
        old_args = sys.argv

        # General parsing:
        sys.argv = ['./check_cert', '-v', '-s', '-d', '-c', './check_cert.json']
        parsed_cmdline = check_cert.parse_command_line()
        self.assertEqual(parsed_cmdline, {'std_err': True,
                                          'config_file': './check_cert.json',
                                          'verbose': True,
                                          'dont_send': True,
                                          })

        # Config file should be a mandatory argument:
        sys.argv = ['./check_cert', ]
        # Suppres warnings from argparse
        with mock.patch('sys.stderr'):
            parsed_cmdline = check_cert.parse_command_line()
        SysExitMock.assert_called_once_with(2)

        # Test default values:
        sys.argv = ['./check_cert', '-c', './check_cert.json']
        parsed_cmdline = check_cert.parse_command_line()
        self.assertEqual(parsed_cmdline, {'std_err': False,
                                          'config_file': './check_cert.json',
                                          'verbose': False,
                                          'dont_send': False,
                                          })

        sys.argv = old_args

    @mock.patch('sys.exit')
    @mock.patch('check_cert.CertStore')
    def test_script_init(self, CertStoreMock, SysExitMock,
                         ScriptConfigurationMock, ScriptStatusMock,
                         ScriptLockMock, *unused):
        """
        Test if script initializes its dependencies properly
        """

        ScriptConfigurationMock.get_val.side_effect = self._script_conf_factory()

        check_cert.main(config_file='./check_cert.conf')

        proper_init_call = dict(riemann_enabled=True,
                                riemann_ttl=60,
                                riemann_service_name='check_cert',
                                riemann_hosts_config={
                                    'static': ['1.2.3.4:1:udp',
                                               '2.3.4.5:5555:tcp', ]
                                    },
                                riemann_tags=['abc', 'def'],
                                nrpe_enabled=True,
                                debug=False)
        ScriptConfigurationMock.load_config.assert_called_once_with('./check_cert.conf')
        ScriptLockMock.init.assert_called_once_with("./fake_lock.pid")
        ScriptLockMock.aqquire.assert_called_once_with()
        ScriptStatusMock.initialize.assert_called_once_with(**proper_init_call)

        proper_init_call = dict(host="git.foo.net",
                                port=22,
                                pubkey="./foo",
                                username="foo",
                                repo_localdir="/tmp/foo",
                                repo_url="/foo-puppet",
                                repo_masterbranch="refs/heads/foo",)

        CertStoreMock.initialize.assert_called_once_with(**proper_init_call)

    @mock.patch('sys.exit')
    @mock.patch('check_cert.get_cert_expiration')
    @mock.patch('check_cert.CertStore')
    def test_sanity_checking(self, CertStoreMock, CertExpirationMock,
                             SysExitMock, ScriptConfigurationMock, ScriptStatusMock,
                             *unused):

        def terminate_script(exit_status):
            raise SystemExit(exit_status)
        SysExitMock.side_effect = terminate_script

        # Test if ScriptStatus gets properly initialized
        # and whether warn > crit condition is
        # checked as well
        ScriptConfigurationMock.get_val.side_effect = \
            self._script_conf_factory(warn_treshold=7, critical_treshold=15)

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertEqual(e.exception.code, 1)

        # this time test only the negative warn threshold:
        check_cert.ScriptConfiguration.get_val.side_effect = \
            self._script_conf_factory(warn_treshold=-30)
        ScriptStatusMock.notify_immediate.reset_mock()
        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertTrue(ScriptStatusMock.notify_immediate.called)
        self.assertEqual(e.exception.code, 1)

        # this time test only the crit threshold == 0 condition check:
        check_cert.ScriptConfiguration.get_val.side_effect = \
            self._script_conf_factory(critical_treshold=-1)

        ScriptStatusMock.notify_immediate.reset_mock()
        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertTrue(ScriptStatusMock.notify_immediate.called)
        self.assertEqual(e.exception.code, 1)

    @mock.patch('check_cert.sys.exit')
    @mock.patch('check_cert.get_cert_expiration')
    @mock.patch('check_cert.CertStore')
    def test_certificate_testing(self, CertStoreMock, CertExpirationMock,
                                 SysExitMock, ScriptConfigurationMock,
                                 ScriptStatusMock, ScriptLockMock, *unused):

        # A bit of a workaround, but we cannot simply call sys.exit
        def terminate_script(exit_status):
            raise SystemExit(exit_status)
        SysExitMock.side_effect = terminate_script

        # Provide fake data for the script:
        fake_cert_tuple = namedtuple("FileTuple", ['path', 'content'])
        fake_cert_tuple.path = 'some_cert'
        fake_cert_tuple.content = 'some content'

        def fake_cert(cert_extensions):
            return iter([fake_cert_tuple])
        CertStoreMock.lookup_certs.side_effect = fake_cert

        ScriptConfigurationMock.get_val.side_effect = self._script_conf_factory()

        # test if an expired cert is properly handled:
        def fake_cert_expiration(cert, ignored_certs):
            self.assertEqual(cert, fake_cert_tuple)
            return datetime.utcnow() - timedelta(days=4)
        CertExpirationMock.side_effect = fake_cert_expiration
        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertEqual(e.exception.code, 0)
        self.assertTrue(ScriptStatusMock.update.called)
        self.assertEqual(ScriptStatusMock.update.call_args[0][0], 'critical')
        self.assertTrue(ScriptStatusMock.notify_agregated.called)
        self.assertFalse(ScriptStatusMock.notify_immediate.called)
        ScriptStatusMock.reset_mock()

        # test if soon to expire (<critical) cert is properly handled:
        def fake_cert_expiration(cert, ignored_certs):
            self.assertEqual(cert, fake_cert_tuple)
            return datetime.utcnow() + timedelta(days=7)
        CertExpirationMock.side_effect = fake_cert_expiration
        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertEqual(e.exception.code, 0)
        self.assertFalse(ScriptStatusMock.notify_immediate.called)
        self.assertTrue(ScriptStatusMock.notify_agregated.called)
        self.assertEqual(ScriptStatusMock.update.call_args[0][0], 'critical')
        ScriptStatusMock.reset_mock()

        # test if not so soon to expire (<warning) cert is properly handled:
        def fake_cert_expiration(cert, ignored_certs):
            self.assertEqual(cert, fake_cert_tuple)
            return datetime.utcnow() + timedelta(days=21)
        CertExpirationMock.side_effect = fake_cert_expiration
        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertEqual(e.exception.code, 0)
        self.assertFalse(ScriptStatusMock.notify_immediate.called)
        self.assertTrue(ScriptStatusMock.notify_agregated.called)
        self.assertEqual(ScriptStatusMock.update.call_args[0][0], 'warn')
        ScriptStatusMock.reset_mock()

        # test if a good certificate is properly handled:
        def fake_cert_expiration(cert, ignored_certs):
            self.assertEqual(cert, fake_cert_tuple)
            return datetime.utcnow() + timedelta(days=40)
        CertExpirationMock.side_effect = fake_cert_expiration
        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertEqual(e.exception.code, 0)
        self.assertFalse(ScriptStatusMock.notify_immediate.called)
        self.assertTrue(ScriptStatusMock.notify_agregated.called)
        # All certs were ok, so a 'default' message should be send to Rieman
        self.assertFalse(ScriptStatusMock.update.called)
        ScriptStatusMock.reset_mock()

        # test if a certificate that expires today is properly handled:
        def fake_cert_expiration(cert, ignored_certs):
            self.assertEqual(cert, fake_cert_tuple)
            return datetime.utcnow()
        CertExpirationMock.side_effect = fake_cert_expiration
        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertEqual(e.exception.code, 0)
        self.assertFalse(ScriptStatusMock.notify_immediate.called)
        self.assertTrue(ScriptStatusMock.notify_agregated.called)
        self.assertEqual(ScriptStatusMock.update.call_args[0][0], 'critical')
        ScriptStatusMock.reset_mock()

        # test if a certificate that is malformed/invalid is properly handled:
        def fake_cert_expiration(cert, ignored_certs):
            self.assertEqual(cert, fake_cert_tuple)
            return None
        CertExpirationMock.side_effect = fake_cert_expiration
        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertEqual(e.exception.code, 0)
        self.assertFalse(ScriptStatusMock.notify_immediate.called)
        self.assertTrue(ScriptStatusMock.notify_agregated.called)
        self.assertEqual(ScriptStatusMock.update.call_args[0][0], 'unknown')
        ScriptStatusMock.reset_mock()

    @mock.patch('check_cert.sys.exit')
    @mock.patch('check_cert.get_cert_expiration')
    @mock.patch('check_cert.CertStore')
    def test_exception_handling(self, CertStoreMock, CertExpirationMock,
                                 SysExitMock, ScriptConfigurationMock,
                                 ScriptStatusMock, ScriptLockMock,
                                 LoggingErrorMock, LoggingInfoMock,
                                 LoggingWarnMock):

        # A bit of a workaround, but we cannot simply call sys.exit
        def terminate_script(exit_status):
            raise SystemExit(exit_status)
        SysExitMock.side_effect = terminate_script

        #Provide some sane configuration:
        ScriptConfigurationMock.get_val.side_effect = self._script_conf_factory()

        # Test an exception from which we can recover:
        def throw_test_exception(cert_extensions):
            raise RecoverableException("this is just a test exception")
        CertStoreMock.lookup_certs.side_effect = throw_test_exception

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertEqual(e.exception.code, 1)
        self.assertTrue(LoggingErrorMock.called)
        self.assertTrue(ScriptStatusMock.notify_immediate.called)
        self.assertEqual(ScriptStatusMock.notify_immediate.call_args[0][0], 'unknown')
        ScriptStatusMock.reset_mock()

        # Test an fatal exception
        def throw_test_exception(cert_extensions):
            raise FatalException("this is just a test exception")
        CertStoreMock.lookup_certs.side_effect = throw_test_exception

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')
        self.assertEqual(e.exception.code, 1)
        self.assertTrue(LoggingErrorMock.called)
        self.assertFalse(ScriptStatusMock.notify_immediate.called)
        ScriptStatusMock.reset_mock()


if __name__ == '__main__':
    unittest.main()
