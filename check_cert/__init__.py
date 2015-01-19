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
from __future__ import division
from __future__ import nested_scopes
from __future__ import print_function
from __future__ import with_statement

# Imports:
from OpenSSL.crypto import FILETYPE_PEM
from OpenSSL.crypto import load_certificate
from collections import namedtuple
from datetime import datetime, timedelta
from dulwich.client import SSHGitClient, SubprocessWrapper, TraditionalGitClient
from dulwich.errors import GitProtocolError
from dulwich.protocol import Protocol
from dulwich.repo import Repo
from pymisc.monitoring import ScriptStatus
from pymisc.script import RecoverableException, ScriptConfiguration, ScriptLock
import argparse
import hashlib
import logging
import logging.handlers as lh
import os
import re
import subprocess
import sys

# Constants:
LOCKFILE_LOCATION = './'+os.path.basename(__file__)+'.lock'
CONFIGFILE_LOCATION = './'+os.path.basename(__file__)+'.conf'
SERVICE_NAME = 'check_cert'
CERTIFICATE_EXTENSIONS = ['der', 'crt', 'pem', 'cer', 'p12', 'pfx', ]


class PubkeySSHGitClient(SSHGitClient):
    """
    Connect to GIT repos using pubkey authentication.

    This simple class extends SSHGitClient class with pubkey authentication.
    In the base class it is not supported, and using password authentication
    for a script is insecure.
    """
    def __init__(self, host, pubkey, port=None, username=None, *args, **kwargs):
        """
        Initialize the class with authdata and call superclass constructor.

        Please see SSHGitClient's class constructor for a documentation of
        arguments not mentioned here.

        Args:
            host: host to connect to
            pubkey: file path of the publickey to use
            port: SSH port to connect to
            username: username to use while connecting
        """
        self.host = host
        self.port = port
        self.pubkey = pubkey
        self.username = username
        TraditionalGitClient.__init__(self, *args, **kwargs)
        self.alternative_paths = {}

    def _connect(self, cmd, path):
        """
        Override connection establishment in SSHGitClient class so that pubkey
        is used.
        """
        # FIXME: This has no way to deal with passphrases..
        # FIXME: can we rely on ssh being in PATH here ?
        args = ['ssh', '-x', '-oStrictHostKeyChecking=no']
        if not (os.path.exists(self.pubkey) and os.access(self.pubkey, os.R_OK)):
            raise GitProtocolError("Public key file is missing or incaccesible")
        args.extend(['-i', self.pubkey])
        if self.port is not None:
            args.extend(['-p', str(self.port)])
        if self.username is not None:
            host = '{0}@{1}'.format(self.username, self.host)
        else:
            host = self.host
        args.append(host)
        args.extend(["{0} '{1}'".format(self._get_cmd_path(cmd), path)])
        proc = subprocess.Popen(args,
                                stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE)
        con = SubprocessWrapper(proc)
        logging.info("Connected to repo {0}:{1} via ssh, cmd: {2}".format(
                     self.host, self.port if self.port else 22, cmd))
        return (Protocol(con.read,
                         con.write,
                         report_activity=self._report_activity
                         ),
                con.can_read)


class LocalMirrorRepo(Repo):
    """
    Common GIT repo object extened with file searching capabilities.
    """
    def lookup_files(self, determine_wants, root_sha=None, repo_path=''):
        """
        Search the repo for files described by the determine_wants function.

        The search is done recursively, with each iteration scanning just one
        repo directory. In case a directory is found the root_sha and repo_path
        parameters are provided for a next iteration of the function.

        Args:
            determine_wants: the function used to determine whether the file is
                of interest. It operates on the file paths in a repo and must
                return True for objects that match, False otherwise.
            root_sha: sha of the tree object that search should be started from
            repo_path: repo path of the tree object pointed by root_sha

        Returns:
            The result is a list of the named tuples containing file paths and
            their contents, accumulated by all recursive calls:
        """
        file_list = []
        if root_sha is None:
            commit = self.get_object(self.head())
            root_sha = commit.tree
        logging.debug("Root sha is {0}".format(root_sha))
        try:
            root = self.get_object(root_sha)
        except KeyError:
            msg = "Skipping object from submodule: {0}, dir: {1}".format(root_sha, repo_path)
            logging.warning(msg)
            return file_list
        if repo_path:
            # Extreme verbosity
            logging.debug("Scanning repo directory {0}".format(repo_path))
        else:
            logging.info("Scanning repo root directory")

        for item in root.iteritems():
            full_path = os.path.join(repo_path, item.path)
            if item.mode & 0b0100000000000000:
                # A directory:
                subentries = self.lookup_files(determine_wants=determine_wants,
                                               root_sha=item.sha,
                                               repo_path=full_path)
                file_list.extend(subentries)
            if item.mode & 0b1000000000000000:
                # A file, lets check if user wants it:
                if determine_wants(item.path):
                    logging.info("Matching file found: {0}".format(full_path))
                    buf = namedtuple("FileTuple", ['path', 'sha'])
                    buf.path = full_path
                    buf.content = self.get_object(item.sha).data
                    file_list.append(buf)
        return file_list


class CertStore(object):
    """
    Provide local clone of a remote repo plus some extra functionality.

    Class is meant to be an abstraction of the GIT repos complexity, allowing
    easy extraction of certificates.
    """
    _remote = None
    _local = None

    @classmethod
    def initialize(cls, host, port, pubkey, username, repo_localdir, repo_url,
                   repo_masterbranch):
        """
        Initialize CertStore object.

        Args:
            host: host to connect to
            pubkey: file path of the publickey to use
            port: SSH port to connect to
            username: username to use while connecting
            repo_localdir: path to use for local repo storage
            repo_url: url of the repo to fetch
            repo_masterbranch: git branch to fetch and scan
        """
        if cls._remote is None:
            cls._remote = PubkeySSHGitClient(host=host,
                                             pubkey=pubkey,
                                             username=username,
                                             port=port,
                                             thin_packs=False,  # Not supported by
                                                                # dulwich properly
                                             )
        if not os.path.exists(os.path.join(repo_localdir, "objects")):
            if not os.path.exists(repo_localdir):
                os.mkdir(repo_localdir, 0700)
            cls._local = LocalMirrorRepo.init_bare(repo_localdir)
        else:
            cls._local = LocalMirrorRepo(repo_localdir)

        # We are only interested in 'production' branch, not the topic branches
        # all the commits linked to the master will be downloaded as well of
        # course
        def wants_master_only(refs):
            return [sha for (ref, sha) in refs.iteritems()
                    if ref == repo_masterbranch]
        refs = cls._remote.fetch(path=repo_url, target=cls._local,
                                 determine_wants=wants_master_only)
        cls._local["HEAD"] = refs[repo_masterbranch]

    @classmethod
    def lookup_certs(cls, cert_suffixes):
        """
        Find all the certificates in the locally cached repository.

        The classification whether file is a certificate or not is made basing
        on the file suffix.

        Args:
            cert_suffixes: list of valid certificate suffixes
        """
        if cls._local is None:
            raise RecoverableException("Local repo mirror has not been " +
                                       "initialized yet")

        def wants_all_certs(path):
            if len(path) >= 5 and path[-4] == '.' and \
                    path[-3:] in cert_suffixes:
                return True
            else:
                return False
        certs = cls._local.lookup_files(determine_wants=wants_all_certs)
        logging.info("{0} certificates found".format(len(certs)))
        return certs


def parse_command_line():
    """
    Convert command line arguments into script runtime configuration.
    """
    parser = argparse.ArgumentParser(
        description='Certificate checking tool',
        epilog="Author: vespian a t wp.pl",
        add_help=True,)
    parser.add_argument(
        '--version',
        action='version',
        version='0.3.0')
    parser.add_argument(
        "-c", "--config-file",
        action='store',
        required=True,
        help="Location of the configuration file")
    parser.add_argument(
        "-v", "--verbose",
        action='store_true',
        required=False,
        help="Provide extra logging messages.")
    parser.add_argument(
        "-s", "--std-err",
        action='store_true',
        required=False,
        help="Log to stderr instead of syslog")
    parser.add_argument(
        "-d", "--dont-send",
        action='store_true',
        required=False,
        help="Do not send data to Riemann [use for debugging]")

    args = parser.parse_args()
    return {'std_err': args.std_err,
            'verbose': args.verbose,
            'config_file': args.config_file,
            'dont_send': args.dont_send,
            }


def get_cert_expiration(certificate):
    """
    Extract the certificate expiration date from a certificate blob.

    Args:
        certificate: a named tuple object, containing path and content attributes

    Returns:
        None if certificate was invalid or expiry date could not be extracted,
        datetime object otherwise.
    """
    try:
        # Many bad things can happen here, but still - we can recover! :)
        # Workaround for -----BEGIN TRUSTED CERTIFICATE-----
        if certificate.content.find('TRUSTED ') > -1:
            logging.info("'TRUSTED' string has been removed from " +
                         "certificate {0}".format(certificate.path))
            certificate.content = certificate.content.replace('TRUSTED ',
                                                              '')
        cert_data = load_certificate(FILETYPE_PEM, certificate.content)
        expiry_date = cert_data.get_notAfter()
        # Return datetime object:
        return datetime.strptime(expiry_date, '%Y%m%d%H%M%SZ')
    except Exception:
        raise RecoverableException()


def _verify_conf(conf_hash):
    """
    Check if script configuration is sane.

    This function takes care of checking if the script configuration is
    logically correct.

    Args:
        conf_hash: A hash containing whole configuration, as defined in config
            file.

    Returns:
        A list of errors/issues found in the configuration, or an empty list
        if the configuration is OK.
    """

    msg = []

    try:
        warn_treshold = conf_hash['warn_treshold']
        critical_treshold = conf_hash['critical_treshold']
        repo_host = conf_hash['repo_host']
        repo_url = conf_hash['repo_url']
        repo_masterbranch = conf_hash['repo_masterbranch']
        repo_localdir = conf_hash['repo_localdir']
        repo_user = conf_hash['repo_user']
        repo_pubkey = conf_hash['repo_pubkey']
        lockfile = conf_hash['lockfile']
    except KeyError as e:
        msg.append('Mandatory parameter is missing: {0}'.format(str(e)))

    # Verify thresholds:
    if warn_treshold <= 0:
        msg.append('Certificate expiration warn threshold should be > 0.')
    if critical_treshold <= 0:
        msg.append('Certificate expiration critical threshold should be > 0.')
    if critical_treshold >= warn_treshold:
        msg.append('Warninig threshold should be greater than critical treshold.')

    # repo_host
    if not re.match(r'^(([a-z0-9]\-*[a-z0-9]*){1,63}\.?){1,255}$', repo_host):
        msg.append('Repo host {0} is not a valid domain name.'.format(repo_host))

    # FIXME - add verification of other command line parameters

    return msg


def main(config_file, std_err=False, verbose=True, dont_send=False):
    """
    Main function of the script

    Args:
        config_file: file path of the config file to load
        std_err: whether print logging output to stderr
        verbose: whether to provide verbose logging messages
        dont_send: whether to sent data to monitoring system or just do a dry
                   run
    """
    try:
        # Configure logging:
        fmt = logging.Formatter('%(filename)s[%(process)d] %(levelname)s: ' +
                                '%(message)s')
        logger = logging.getLogger()
        if verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        if std_err:
            handler = logging.StreamHandler()
        else:
            handler = lh.SysLogHandler(address='/dev/log',
                                       facility=lh.SysLogHandler.LOG_USER)
        handler.setFormatter(fmt)
        logger.addHandler(handler)

        logger.info("check_cert is starting, command line arguments:" +
                    "config_file={0}, ".format(config_file) +
                    "std_err={0}, ".format(std_err) +
                    "verbose={0}, ".format(verbose)
                    )

        # FIXME - Remember to correctly configure syslog, otherwise rsyslog will
        # discard messages
        ScriptConfiguration.load_config(config_file)

        logger.debug("Loaded configuration: " +
                     str(ScriptConfiguration.get_config())
                     )

        # Provide some sane defaults:
        try:
            repo_port = ScriptConfiguration.get_val("repo_port")
        except KeyError:
            repo_port = 22

        try:
            ignored_certs = ScriptConfiguration.get_val("ignored_certs")
        except KeyError:
            ignored_certs = {}

        logger.debug("Remote repo is: {0}@{1}{3}->{4}, tcp port {2}".format(
                     ScriptConfiguration.get_val("repo_user"),
                     ScriptConfiguration.get_val("repo_host"),
                     repo_port,
                     ScriptConfiguration.get_val("repo_url"),
                     ScriptConfiguration.get_val("repo_masterbranch")) +
                     ", local repository dir is {0}".format(
                     ScriptConfiguration.get_val('repo_localdir')) +
                     ", repository key is {0}".format(
                     ScriptConfiguration.get_val('repo_pubkey')) +
                     ", warn_thresh is {0}".format(
                     ScriptConfiguration.get_val('warn_treshold')) +
                     ", crit_thresh is {0}".format(
                     ScriptConfiguration.get_val('critical_treshold'))
                     )

        # Initialize Riemann/NRPE reporting:
        if ScriptConfiguration.get_val("riemann_enabled") is True:
            ScriptStatus.initialize(
                riemann_enabled=True,
                riemann_hosts_config=ScriptConfiguration.get_val("riemann_hosts"),
                riemann_tags=ScriptConfiguration.get_val("riemann_tags"),
                riemann_ttl=ScriptConfiguration.get_val("riemann_ttl"),
                riemann_service_name=SERVICE_NAME,
                nrpe_enabled=ScriptConfiguration.get_val("nrpe_enabled"),
                debug=dont_send,)
        else:
            ScriptStatus.initialize(
                nrpe_enabled=ScriptConfiguration.get_val("nrpe_enabled"),
                debug=dont_send,)

        # Now, let's verify the configuration:
        # FIXME - ScriptStatus might have been already initialized with
        # incorrect config and in effect ScriptStatus.notify_immediate will
        # not reach monitoring system
        conf_issues = _verify_conf(ScriptConfiguration.get_config())
        if conf_issues:
            logging.debug("Configuration problems:\n\t" +
                          '\n\t'.join(conf_issues))
            ScriptStatus.notify_immediate('unknown',
                                          "Configuration file contains errors: " +
                                          ' '.join(conf_issues))

        # Make sure that we are the only ones running on the server:
        ScriptLock.init(ScriptConfiguration.get_val('lockfile'))
        ScriptLock.aqquire()

        # Initialize our repo mirror:
        CertStore.initialize(host=ScriptConfiguration.get_val("repo_host"),
                             port=repo_port,
                             pubkey=ScriptConfiguration.get_val('repo_pubkey'),
                             username=ScriptConfiguration.get_val("repo_user"),
                             repo_localdir=ScriptConfiguration.get_val(
                                 'repo_localdir'),
                             repo_url=ScriptConfiguration.get_val("repo_url"),
                             repo_masterbranch=ScriptConfiguration.get_val(
                                 "repo_masterbranch"),
                             )

        unparsable_certs = {"number": 0, "paths": []}

        for cert in CertStore.lookup_certs(CERTIFICATE_EXTENSIONS):
            # Check whether the cert needs to be included in checks at all:
            cert_hash = hashlib.sha1(cert.content).hexdigest()
            if cert_hash in ignored_certs:
                # This cert should be ignored
                logging.info("certificate {0} (sha1sum: {1})".format(
                             cert.path, cert_hash) + " has been ignored.")
                continue

            # Check if certifice type is supported:
            if cert.path[-3:] not in ['pem', 'crt', 'cer']:
                ScriptStatus.update('unknown',
                                    "Certificate {0} ".format(cert.path) +
                                    "is not supported by the check script, " +
                                    "please add it to ignore list or upgrade " +
                                    "the script.")
                continue

            # Check the expiry date:
            try:
                cert_expiration = get_cert_expiration(cert)
            except RecoverableException:
                unparsable_certs["number"] += 1
                unparsable_certs["paths"].append(cert.path)
                continue

            # -3 days is in fact -4 days, 23:59:58.817181
            # so we compensate and round up
            # additionally, openssl uses utc dates
            now = datetime.utcnow() - timedelta(days=1)
            time_left = cert_expiration - now  # timedelta object
            if time_left.days < 0:
                ScriptStatus.update('critical',
                                    "Certificate {0} expired {1} days ago.".format(
                                        cert.path, abs(time_left.days)))
            elif time_left.days == 0:
                ScriptStatus.update('critical',
                                    "Certificate {0} expires today.".format(
                                        cert.path))
            elif time_left.days < ScriptConfiguration.get_val("critical_treshold"):
                ScriptStatus.update('critical',
                                    "Certificate {0} is about to expire in"
                                    "{0} days.".format(cert.path, time_left.days))
            elif time_left.days < ScriptConfiguration.get_val("warn_treshold"):
                ScriptStatus.update('warn',
                                    "Certificate {0} is about to expire in"
                                    "{0} days.".format(cert.path, time_left.days))
            else:
                logger.info("{0} expires in {1} days - OK!".format(
                    cert.path, time_left.days))

        # We do not want to pollute output in case when there are too many broken
        # certs in the report.
        if unparsable_certs["number"] > 0:
            if unparsable_certs["number"] <= 2:
                ScriptStatus.update('unknown',
                                    'Script cannot parse certificates: '
                                    ','.join(unparsable_certs["paths"]))
            else:
                ScriptStatus.update('unknown', 'Script cannot parse {0} '.format(
                                    unparsable_certs["number"]) +
                                    "certificates, please check with verbose out on")

        ScriptStatus.notify_agregated()
        ScriptLock.release()
        sys.exit(0)

    except RecoverableException as e:
        msg = str(e)
        logging.error(msg)
        ScriptStatus.notify_immediate('unknown', msg)
        sys.exit(1)
    except AssertionError as e:
        # Unittest require it:
        raise
    except Exception as e:
        msg = "Exception occured: {0}, msg: {1}".format(e.__class__.__name__, str(e))
        logging.error(msg)
        logging.exception(e)
        sys.exit(1)
