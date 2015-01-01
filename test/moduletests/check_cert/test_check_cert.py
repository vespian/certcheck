#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (c) 2014 Pawel Rozlach
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
class TestCertificateParsing(unittest.TestCase):
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

    def setUp(self):
        # -3 days is in fact -4 days, 23:59:58.817181
        # so we compensate and round up
        # additionally, openssl uses utc dates
        self.now = datetime.utcnow() - timedelta(days=1)

    def test_expired_cert(self, *unused):
        # Test an expired certificate:
        cert = self._certpath2namedtuple(paths.EXPIRED_3_DAYS)
        expiry_time = check_cert.get_cert_expiration(cert) - self.now
        self.assertEqual(expiry_time.days, -3)

    def test_ok_cert(self, *unused):
        # Test a good certificate:
        cert = self._certpath2namedtuple(paths.EXPIRE_21_DAYS)
        expiry_time = check_cert.get_cert_expiration(cert) - self.now
        self.assertEqual(expiry_time.days, 21)

    def test_der_cert(self, *unused):
        # Test a DER certificate:
        cert = self._certpath2namedtuple(paths.EXPIRE_41_DAYS_DER)
        with self.assertRaises(RecoverableException):
            check_cert.get_cert_expiration(cert)

    def test_broken_cert(self, *unused):
        # Test a broken certificate:
        cert = self._certpath2namedtuple(paths.BROKEN_CERT)
        with self.assertRaises(RecoverableException):
            check_cert.get_cert_expiration(cert)

    def test_trusted_cert(self, *unused):
        # Test a "TRUSTED" certificate:
        cert = self._certpath2namedtuple(paths.TRUSTED_EXPIRE_41_CERT)
        expiry_time = check_cert.get_cert_expiration(cert) - self.now
        self.assertEqual(expiry_time.days, 41)


@mock.patch('sys.exit')
class TestCommandLineParsing(unittest.TestCase):
    def setUp(self):
        self._old_args = sys.argv

    def tearDown(self):
        sys.argv = self._old_args

    def test_proper_command_line_parsing(self, *unused):
        # General parsing:
        sys.argv = ['./check_cert', '-v', '-s', '-d', '-c', './check_cert.json']
        parsed_cmdline = check_cert.parse_command_line()
        self.assertEqual(parsed_cmdline, {'std_err': True,
                                          'config_file': './check_cert.json',
                                          'verbose': True,
                                          'dont_send': True,
                                          })

    def test_config_file_missing_from_commandline(self, SysExitMock):
        sys.argv = ['./check_cert', ]
        # Suppres warnings from argparse
        with mock.patch('sys.stderr'):
            check_cert.parse_command_line()
        SysExitMock.assert_called_once_with(2)

    def test_default_command_line_args(self, *unused):
        # Test default values:
        sys.argv = ['./check_cert', '-c', './check_cert.json']
        parsed_cmdline = check_cert.parse_command_line()
        self.assertEqual(parsed_cmdline, {'std_err': False,
                                          'config_file': './check_cert.json',
                                          'verbose': False,
                                          'dont_send': False,
                                          })


class TestCheckCert(unittest.TestCase):
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
                                  'a69d081221a9caf21b1c18907c800528d6f414d2':
                                  "sample/path/ignored_cert.pem"
                                  }
                              }

        config = good_configuration.copy()
        config.update(kwargs)

        def get_val(key):
            self.assertIn(key, config)
            return config[key]

        def get_config():
            return config

        return get_val, get_config

    @staticmethod
    def _fake_cert_git_repo(cert_extensions):
        fake_cert_tuple = namedtuple("FileTuple", ['path', 'content'])
        fake_cert_tuple.path = 'sample/path/sample_cert.pem'
        fake_cert_tuple.content = 'some content'
        return iter([fake_cert_tuple])

    @staticmethod
    def _ignored_cert_git_repo(cert_extensions):
        ignored_cert_tuple = namedtuple("FileTuple", ['path', 'content'])
        ignored_cert_tuple.path = 'sample/path/ignored_cert.pem'
        ignored_cert_tuple.content = 'some ignored content'
        return iter([ignored_cert_tuple])

    @staticmethod
    def _unsupported_cert_git_repo(cert_extensions):
        unsupported_cert_tuple = namedtuple("FileTuple", ['path', 'content'])
        unsupported_cert_tuple.path = 'sample/path/unsupported_cert.der'
        unsupported_cert_tuple.content = 'some unsupported content'
        return iter([unsupported_cert_tuple])

    def setUp(self):
        self.mocks = {}
        for patched in ['check_cert.ScriptConfiguration',
                        'check_cert.ScriptStatus',
                        'check_cert.ScriptLock',
                        'logging.error',
                        'logging.info',
                        'logging.warn',
                        'sys.exit',
                        'check_cert.CertStore',
                        'check_cert.get_cert_expiration']:
            patcher = mock.patch(patched)
            self.mocks[patched] = patcher.start()
            self.addCleanup(patcher.stop)

        # Hack, hack, hack - we terminate script after a call to
        # notify_immediate with a non-standard exit code hoping
        # that it will be uniq enough to differentiate other
        # errors
        def terminate_script(*unused):
            raise SystemExit(-216)
        self.mocks['check_cert.ScriptStatus'].notify_immediate.side_effect = \
            terminate_script

        def terminate_script(exit_status):
            raise SystemExit(exit_status)
        self.mocks['sys.exit'].side_effect = terminate_script

        # Fake configuration for the script:
        self.mocks['check_cert.ScriptConfiguration'].get_val.side_effect, \
            self.mocks['check_cert.ScriptConfiguration'].get_config.side_effect = \
            self._script_conf_factory()

        self.mocks['check_cert.CertStore'].lookup_certs.side_effect = \
            self._fake_cert_git_repo

    def test_script_init(self):
        """
        Test if script initializes its dependencies properly
        """

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, 0)

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
        self.mocks['check_cert.ScriptConfiguration'].load_config.assert_called_once_with(
            './check_cert.conf')
        self.mocks['check_cert.ScriptLock'].init.assert_called_once_with(
            "./fake_lock.pid")
        self.mocks['check_cert.ScriptLock'].aqquire.assert_called_once_with()
        self.mocks['check_cert.ScriptStatus'].initialize.assert_called_once_with(
            **proper_init_call)

        proper_init_call = dict(host="git.foo.net",
                                port=22,
                                pubkey="./foo",
                                username="foo",
                                repo_localdir="/tmp/foo",
                                repo_url="/foo-puppet",
                                repo_masterbranch="refs/heads/foo",)

        self.mocks['check_cert.CertStore'].initialize.assert_called_once_with(
            **proper_init_call)

    def test_warn_gt_crit(self):
        self.mocks['check_cert.ScriptConfiguration'].get_val.side_effect, \
            self.mocks['check_cert.ScriptConfiguration'].get_config.side_effect = \
            self._script_conf_factory(warn_treshold=7,
                                      critical_treshold=15)

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, -216)
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertEqual(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.call_args[0][0],
            'unknown')

    def test_negative_warn_thresh(self):
        self.mocks['check_cert.ScriptConfiguration'].get_val.side_effect, \
            self.mocks['check_cert.ScriptConfiguration'].get_config.side_effect = \
            self._script_conf_factory(warn_treshold=-30)

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, -216)
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertEqual(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.call_args[0][0],
            'unknown')

    def test_crit_is_zero(self):
        self.mocks['check_cert.ScriptConfiguration'].get_val.side_effect, \
            self.mocks['check_cert.ScriptConfiguration'].get_config.side_effect = \
            self._script_conf_factory(critical_treshold=-1)

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, -216)
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertEqual(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.call_args[0][0],
            'unknown')

    def test_unsuported_cert_detection(self):
        self.mocks['check_cert.CertStore'].lookup_certs.side_effect = \
            self._unsupported_cert_git_repo

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, 0)
        self.assertFalse(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_agregated.called)
        self.assertEqual(
            self.mocks['check_cert.ScriptStatus'].update.call_args[0][0], 'unknown')

    def test_ignored_cert_detection(self):
        # simulate a git repo with an ignored cert:
        self.mocks['check_cert.CertStore'].lookup_certs.side_effect = \
            self._ignored_cert_git_repo

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, 0)
        self.assertFalse(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_agregated.called)
        # All certs were ok, so a 'default' message should be send to
        # monitoring
        self.assertFalse(self.mocks['check_cert.ScriptStatus'].update.called)

    def test_expired_cert_detection(self):

        def fake_cert_expiration(cert):
            return datetime.utcnow() - timedelta(days=4)
        self.mocks['check_cert.get_cert_expiration'].side_effect = \
            fake_cert_expiration

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, 0)
        self.assertTrue(self.mocks['check_cert.ScriptStatus'].update.called)
        self.assertEqual(
            self.mocks['check_cert.ScriptStatus'].update.call_args[0][0],
            'critical')
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_agregated.called)
        self.assertFalse(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)

    def test_soon_to_expire_crit_cert_detection(self):
        def fake_cert_expiration(cert):
            return datetime.utcnow() + timedelta(days=7)
        self.mocks['check_cert.get_cert_expiration'].side_effect = fake_cert_expiration

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, 0)
        self.assertFalse(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_agregated.called)
        self.assertEqual(
            self.mocks['check_cert.ScriptStatus'].update.call_args[0][0], 'critical')

    def test_soon_to_expire_warn_cert_detection(self):
        def fake_cert_expiration(cert):
            return datetime.utcnow() + timedelta(days=21)
        self.mocks['check_cert.get_cert_expiration'].side_effect = fake_cert_expiration

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, 0)
        self.assertFalse(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_agregated.called)
        self.assertEqual(
            self.mocks['check_cert.ScriptStatus'].update.call_args[0][0], 'warn')

    def test_ok_cert_detection(self):
        def fake_cert_expiration(cert):
            return datetime.utcnow() + timedelta(days=40)
        self.mocks['check_cert.get_cert_expiration'].side_effect = fake_cert_expiration

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, 0)
        self.assertFalse(self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertTrue(self.mocks['check_cert.ScriptStatus'].notify_agregated.called)
        # All certs were ok, so a 'default' message should be send to Rieman
        self.assertFalse(self.mocks['check_cert.ScriptStatus'].update.called)

    def test_expire_today_cert_detection(self):
        def fake_cert_expiration(cert):
            return datetime.utcnow()
        self.mocks['check_cert.get_cert_expiration'].side_effect = fake_cert_expiration

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, 0)
        self.assertFalse(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_agregated.called)
        self.assertEqual(
            self.mocks['check_cert.ScriptStatus'].update.call_args[0][0], 'critical')

    def test_malformed_cert_detection(self):
        def fake_cert_expiration(cert):
            raise RecoverableException()
        self.mocks['check_cert.get_cert_expiration'].side_effect = fake_cert_expiration

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, 0)
        self.assertFalse(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_agregated.called)
        self.assertEqual(
            self.mocks['check_cert.ScriptStatus'].update.call_args[0][0],
            'unknown')

    def test_recoverable_exception_handling(self):
        # Test an exception from which we can recover:
        def throw_test_exception(cert_extensions):
            raise RecoverableException("this is just a test exception")
        self.mocks['check_cert.CertStore'].lookup_certs.side_effect = throw_test_exception

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, -216)
        self.assertTrue(
            self.mocks['logging.error'].called)
        self.assertTrue(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.called)
        self.assertEqual(
            self.mocks['check_cert.ScriptStatus'].notify_immediate.call_args[0][0],
            'unknown')

    def test_fatal_exception_handling(self):
        # Test a fatal exception
        def throw_test_exception(cert_extensions):
            raise FatalException("this is just a test exception")
        self.mocks['check_cert.CertStore'].lookup_certs.side_effect = throw_test_exception

        with self.assertRaises(SystemExit) as e:
            check_cert.main(config_file='./check_cert.conf')

        self.assertEqual(e.exception.code, 1)
        self.assertTrue(self.mocks['logging.error'].called)
        self.assertFalse(self.mocks['check_cert.ScriptStatus'].notify_immediate.called)

if __name__ == '__main__':
    unittest.main()
