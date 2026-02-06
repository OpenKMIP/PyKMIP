# Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
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

import logging
import multiprocessing
import os
import signal
import time

from kmip.core import policy as operation_policy

def get_json_files(p):
    """
    Scan the provided policy directory for all JSON policy files.
    """
    f = [os.path.join(p, x) for x in os.listdir(p) if x.endswith(".json")]
    return sorted(f)

class PolicyDirectoryMonitor(multiprocessing.Process):
    """
    A file monitor that tracks modifications made within the policy directory.
    """

    def __init__(self, policy_directory, policy_store, live_monitoring=True):
        """
        Set up the file monitor with the policy directory to track.

        Args:
            policy_directory (string): The system path of the policy directory
                that should be monitored. Required.
            policy_store (DictProxy): A dictionary proxy created by the server
                multiprocessing resource manager. Used to store and share the
                policy information across server processes and threads.
                Required.
            live_monitoring (boolean): A boolean indicating whether or not
                live monitoring should continue indefinitely. Optional,
                defaults to True.
        """
        super(PolicyDirectoryMonitor, self).__init__()

        self.halt_trigger = multiprocessing.Event()
        self.policy_directory = policy_directory
        self.live_monitoring = live_monitoring

        self.file_timestamps = None
        self.policy_cache = None
        self.policy_files = None
        self.policy_map = None
        self.policy_store = policy_store

        self.reserved_policies = ['default', 'public']

        def interrupt_handler(trigger, frame):
            self.stop()
        signal.signal(signal.SIGINT, interrupt_handler)
        signal.signal(signal.SIGTERM, interrupt_handler)

        self.logger = logging.getLogger("kmip.server.monitor")
        self.initialize_tracking_structures()

    def stop(self):
        self.halt_trigger.set()

    def scan_policies(self):
        """
        Scan the policy directory for policy data.
        """
        policy_files = get_json_files(self.policy_directory)
        for f in set(policy_files) - set(self.policy_files):
            self.file_timestamps[f] = 0
        for f in set(self.policy_files) - set(policy_files):
            self.logger.info("Removing policies for file: {}".format(f))
            self.file_timestamps.pop(f, None)
            for p in self.policy_cache.keys():
                self.disassociate_policy_and_file(p, f)
            for p in [k for k, v in self.policy_map.items() if v == f]:
                self.restore_or_delete_policy(p)
        self.policy_files = policy_files

        for f in sorted(self.file_timestamps.keys()):
            t = os.path.getmtime(f)
            if t > self.file_timestamps[f]:
                self.logger.info("Loading policies for file: {}".format(f))
                self.file_timestamps[f] = t
                old_p = [k for k, v in self.policy_map.items() if v == f]
                try:
                    new_p = operation_policy.read_policy_from_file(f)
                except ValueError:
                    self.logger.error("Failure loading file: {}".format(f))
                    self.logger.debug("", exc_info=True)
                    continue
                for p in new_p.keys():
                    self.logger.info("Loading policy: {}".format(p))
                    if p in self.reserved_policies:
                        self.logger.warning(
                            "Policy '{}' overwrites a reserved policy and "
                            "will be thrown out.".format(p)
                        )
                        continue
                    if p in sorted(self.policy_store.keys()):
                        self.logger.debug(
                            "Policy '{}' overwrites an existing "
                            "policy.".format(p)
                        )
                        if f != self.policy_map.get(p):
                            self.policy_cache.get(p).append(
                                (
                                    time.time(),
                                    self.policy_map.get(p),
                                    self.policy_store.get(p)
                                )
                            )
                    else:
                        self.policy_cache[p] = []
                    self.policy_store[p] = new_p.get(p)
                    self.policy_map[p] = f
                for p in set(old_p) - set(new_p.keys()):
                    self.disassociate_policy_and_file(p, f)
                    self.restore_or_delete_policy(p)

    def run(self):
        """
        Start monitoring operation policy files.
        """
        self.initialize_tracking_structures()

        if self.live_monitoring:
            self.logger.info("Starting up the operation policy file monitor.")
            while not self.halt_trigger.is_set():
                time.sleep(1)
                self.scan_policies()
            self.logger.info("Stopping the operation policy file monitor.")
        else:
            self.scan_policies()

    def initialize_tracking_structures(self):
        self.file_timestamps = {}
        self.policy_cache = {}
        self.policy_files = []
        self.policy_map = {}

        for k in self.policy_store.keys():
            if k not in self.reserved_policies:
                self.policy_store.pop(k, None)

    def disassociate_policy_and_file(self, policy, file_name):
        c = self.policy_cache.get(policy, [])
        for i in [c.index(e) for e in c if e[1] == file_name][::-1]:
            c.pop(i)

    def restore_or_delete_policy(self, policy):
        c = self.policy_cache.get(policy, [])
        if len(c) == 0:
            self.logger.info("Removing policy: {}".format(policy))
            self.policy_store.pop(policy, None)
            self.policy_map.pop(policy, None)
            self.policy_cache.pop(policy, None)
        else:
            e = c.pop()
            self.policy_store[policy] = e[2]
            self.policy_map[policy] = e[1]
