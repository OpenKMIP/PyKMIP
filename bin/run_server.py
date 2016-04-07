#!/usr/bin/env python

# Copyright (c) 2016 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import optparse
import sys

from kmip.services import server


def build_argument_parser():
    parser = optparse.OptionParser(
        usage="%prog [options]",
        description="Run the PyKMIP software server.")

    parser.add_option(
        "-n",
        "--hostname",
        action="store",
        type="str",
        default="127.0.0.1",
        dest="hostname",
        help=(
            "The host address the server will be bound to. A string "
            "representing either a hostname in Internet domain notation or "
            "an IPv4 address. Defaults to '127.0.0.1'."
        ),
    )
    parser.add_option(
        "-p",
        "--port",
        action="store",
        type="int",
        default=5696,
        dest="port",
        help=(
            "The port number the server will be bound to. An integer "
            "representing a port number. Recommended to be 5696 according to "
            "the KMIP specification. Defaults to 5696."
        ),
    )
    parser.add_option(
        "-c",
        "--certificate_path",
        action="store",
        type="str",
        default=None,
        dest="certificate_path",
        help=(
            "A string representing a path to a PEM-encoded server "
            "certificate file. Defaults to None."
        ),
    )
    parser.add_option(
        "-k",
        "--key_path",
        action="store",
        type="str",
        default=None,
        dest="key_path",
        help=(
            "A string representing a path to a PEM-encoded server "
            "certificate key file. Defaults to None."
        ),
    )
    parser.add_option(
        "-a",
        "--ca_path",
        action="store",
        type="str",
        default=None,
        dest="ca_path",
        help=(
            "A string representing a path to a PEM-encoded certificate "
            "authority certificate file. Defaults to None."
        ),
    )
    parser.add_option(
        "-s",
        "--auth_suite",
        action="store",
        type="str",
        default="Basic",
        dest="auth_suite",
        help=(
            "A string representing the type of authentication suite to use "
            "when establishing TLS connections. Defaults to 'Basic'."
        ),
    )
    parser.add_option(
        "-f",
        "--config_path",
        action="store",
        type="str",
        default=None,
        dest="config_path",
        help=(
            "A string representing a path to a server configuration file. "
            "Defaults to None."
        ),
    )
    parser.add_option(
        "-l",
        "--log_path",
        action="store",
        type="str",
        default=None,
        dest="log_path",
        help=(
            "A string representing a path to a log file. Defaults to None."
        ),
    )

    return parser


if __name__ == '__main__':
    # Build argument parser and parser command-line arguments.
    parser = build_argument_parser()
    opts, args = parser.parse_args(sys.argv[1:])

    kwargs = {}
    if opts.hostname:
        kwargs['hostname'] = opts.hostname
    if opts.port:
        kwargs['port'] = opts.port
    if opts.certificate_path:
        kwargs['certificate_path'] = opts.certificate_path
    if opts.key_path:
        kwargs['key_path'] = opts.key_path
    if opts.ca_path:
        kwargs['ca_path'] = opts.ca_path
    if opts.auth_suite:
        kwargs['auth_suite'] = opts.auth_suite
    if opts.config_path:
        kwargs['config_path'] = opts.config_path
    if opts.log_path:
        kwargs['log_path'] = opts.log_path

    # Create and start the server.
    s = server.KmipServer(**kwargs)
    with s:
        s.serve()
