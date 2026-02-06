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
import mock
import multiprocessing
import os
import shutil
import signal
import tempfile
import testtools

from kmip.core import enums
from kmip.services.server import monitor

class TestMonitorUtilities(testtools.TestCase):

    def setUp(self):
        super(TestMonitorUtilities, self).setUp()

        self.tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp_dir)

    def test_get_json_files(self):
        """
        Test that all files ending in .json can be collected from a directory.
        """
        with open(os.path.join(self.tmp_dir, "policy_1.json"), "w") as f:
            f.write('{"policy_1": {}}\n')
        with open(os.path.join(self.tmp_dir, "policy_2.json"), "w") as f:
            f.write('{"policy_2": {}}\n')
        with open(os.path.join(self.tmp_dir, "policy_3.txt"), "w") as f:
            f.write('{"policy_3": {}}\n')

        result = monitor.get_json_files(self.tmp_dir)

        self.assertIsInstance(result, list)
        self.assertEqual(2, len(result))
        self.assertIn(os.path.join(self.tmp_dir, "policy_1.json"), result)
        self.assertIn(os.path.join(self.tmp_dir, "policy_2.json"), result)

POLICY_1 = """
{
    "policy_A": {
        "groups": {
            "group_A": {
                "SYMMETRIC_KEY": {
                    "GET": "ALLOW_ALL",
                    "DESTROY": "ALLOW_ALL"
                }
            }
        }
    }
}
"""
POLICY_2 = """
{
    "policy_B": {
        "groups": {
            "group_B": {
                "SYMMETRIC_KEY": {
                    "GET": "ALLOW_ALL",
                    "LOCATE": "ALLOW_ALL",
                    "DESTROY": "ALLOW_ALL"
                }
            }
        }
    },
    "policy_C": {
        "groups": {
            "group_C": {
                "SYMMETRIC_KEY": {
                    "GET": "ALLOW_ALL",
                    "DESTROY": "DISALLOW_ALL"
                }
            }
        }
    }
}
"""
POLICY_3 = """
{
    "policy_B": {
        "groups": {
            "group_B": {
                "SYMMETRIC_KEY": {
                    "GET": "DISALLOW_ALL",
                    "LOCATE": "DISALLOW_ALL",
                    "DESTROY": "DISALLOW_ALL"
                }
            }
        }
    }
}
"""
POLICY_4 = """
{
    "default": {
        "groups": {
            "group_B": {
                "SYMMETRIC_KEY": {
                    "GET": "DISALLOW_ALL",
                    "LOCATE": "DISALLOW_ALL",
                    "DESTROY": "DISALLOW_ALL"
                }
            }
        }
    }
}
"""
POLICY_5 = """
{
    "policy_B": {
        "groups": {
            "group_B": {
                "SYMMETRIC_KEY": {
                    "GET": "ALLOW_ALL",
                    "LOCATE": "ALLOW_ALL",
                    "DESTROY": "ALLOW_ALL"
                }
            }
        }
    },
    "policy_D": {
        "groups": {
            "group_D": {
                "SYMMETRIC_KEY": {
                    "GET": "ALLOW_ALL",
                    "DESTROY": "DISALLOW_ALL"
                }
            }
        }
    }
}
"""
POLICY_6 = """
{
    "policy_A": {
        "groups": {
            "group_A": {
                "SYMMETRIC_KEY": {
                    "GET": "ALLOW_ALL",
                    "DESTROY": "ALLOW_ALL"
                }
            }
        }
    },
    "policy_E": {
        "groups": {
            "group_E": {
                "SYMMETRIC_KEY": {
                    "GET": "ALLOW_ALL",
                    "CHECK": "ALLOW_OWNER",
                    "DESTROY": "ALLOW_ALL"
                }
            }
        }
    }
}
"""
POLICY_7 = """
{
    "policy_D": {
        "groups": {
            "group_D": {
                "SYMMETRIC_KEY": {
                    "GET": "DISALLOW_ALL",
                    "LOCATE": "DISALLOW_ALL",
                    "DESTROY": "DISALLOW_ALL"
                }
            }
        }
    }
}
"""

def write_file(path, file_name, content):
    with open(os.path.join(path, file_name), "w") as f:
        f.write("{}\n".format(content))

def side_effects(effects):
    for effect in effects:
        if isinstance(effect, bool):
            yield effect
        else:
            effect()
            yield False

def build_write_effect(path, file_name, content):
    def side_effect():
        write_file(path, file_name, content)
    return side_effect

def build_delete_effect(path, file_name):
    def side_effect():
        os.remove(os.path.join(path, file_name))
    return side_effect

class TestPolicyDirectoryMonitor(testtools.TestCase):

    def setUp(self):
        super(TestPolicyDirectoryMonitor, self).setUp()

        self.tmp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp_dir)

    def test_init(self):
        """
        Test that the PolicyDirectoryMonitor can be instantiated without error.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )

        self.assertIsInstance(
            m.halt_trigger,
            multiprocessing.synchronize.Event
        )
        self.assertEqual(self.tmp_dir, m.policy_directory)
        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())
        self.assertEqual(['default', 'public'], m.reserved_policies)
        self.assertIsInstance(m.logger, logging.Logger)

    def test_signal_handler(self):
        """
        Test that the signal handler for SIGINT and SIGTERM correctly stops
        the monitor.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.stop = mock.MagicMock()
        handler = signal.getsignal(signal.SIGINT)

        m.stop.assert_not_called()
        handler(None, None)
        m.stop.assert_called()

    def test_stop(self):
        """
        Test that the PolicyDirectoryMonitor processes stop calls correctly.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )

        self.assertFalse(m.halt_trigger.is_set())

        m.stop()

        self.assertTrue(m.halt_trigger.is_set())

    def test_run(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = [False, True]

        write_file(self.tmp_dir, "policy_1.json", POLICY_1)
        write_file(self.tmp_dir, "policy_2.json", POLICY_2)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(2, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))

        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))
        self.assertEqual(path, m.policy_map.get("policy_C", None))

        self.assertEqual(
            {
                "policy_A": [],
                "policy_B": [],
                "policy_C": []
            },
            m.policy_cache
        )

        self.assertEqual(3, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_C": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_C", None)
        )

    def test_run_with_policy_overloading(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when one policy overloads another existing policy.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = [False, True]

        write_file(self.tmp_dir, "policy_1.json", POLICY_1)
        write_file(self.tmp_dir, "policy_2.json", POLICY_2)
        write_file(self.tmp_dir, "policy_3.json", POLICY_3)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_3.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.debug.assert_any_call(
            "Policy 'policy_B' overwrites an existing policy."
        )
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(3, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))

        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_C", None))

        path = os.path.join(self.tmp_dir, "policy_3.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))

        cache = m.policy_cache.get("policy_A")
        self.assertEqual(0, len(cache))
        cache = m.policy_cache.get("policy_B")
        self.assertEqual(1, len(cache))
        self.assertEqual(
            os.path.join(self.tmp_dir, "policy_2.json"),
            cache[0][1]
        )
        self.assertEqual(
            {
                'groups': {
                    'group_B': {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET:
                                enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE:
                                enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY:
                                enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            cache[0][2]
        )

        self.assertEqual(3, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.DISALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.DISALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_C": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_C", None)
        )

    def test_run_with_policy_load_failure(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when one policy can't be loaded properly.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = [False, True]

        write_file(self.tmp_dir, "policy_1.json", POLICY_1)
        write_file(self.tmp_dir, "policy_2.json", "not a JSON blob")

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.error.assert_any_call(
            "Failure loading file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.debug.assert_called()
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(2, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))

        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)

        self.assertEqual(
            {
                "policy_A": []
            },
            m.policy_cache
        )

        self.assertEqual(1, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )

    def test_run_with_policy_load_failure_and_fix(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when one policy can't be loaded properly and is
        then fixed while tracking is active.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = side_effects(
            [
                False,
                build_write_effect(
                    self.tmp_dir,
                    "policy_2.json",
                    "invalid JSON"
                ),
                False,
                build_write_effect(self.tmp_dir, "policy_2.json", POLICY_2),
                False,
                True
            ]
        )

        write_file(self.tmp_dir, "policy_1.json", POLICY_1)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.error.assert_any_call(
            "Failure loading file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.debug.assert_called()
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(2, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))

        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))
        self.assertEqual(path, m.policy_map.get("policy_C", None))

        self.assertEqual(
            {
                "policy_A": [],
                "policy_B": [],
                "policy_C": []
            },
            m.policy_cache
        )

        self.assertEqual(3, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_C": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_C", None)
        )

    def test_run_with_policy_overloading_reserved(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when one policy can't be loaded properly.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = [False, True]

        write_file(self.tmp_dir, "policy_3.json", POLICY_3)
        write_file(self.tmp_dir, "policy_4.json", POLICY_4)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_3.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_4.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: default")
        m.logger.warning.assert_any_call(
            "Policy 'default' overwrites a reserved policy and will be "
            "thrown out."
        )
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(2, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_3.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))

        path = os.path.join(self.tmp_dir, "policy_4.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)

        self.assertEqual(
            {
                "policy_B": []
            },
            m.policy_cache
        )

        self.assertEqual(1, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.DISALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.DISALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )

    def test_run_with_edit_modifying_existing_file(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when an existing policy file is modified while
        tracking is active.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = side_effects(
            [
                False,
                build_write_effect(self.tmp_dir, "policy_2.json", POLICY_5),
                True
            ]
        )

        write_file(self.tmp_dir, "policy_1.json", POLICY_1)
        write_file(self.tmp_dir, "policy_2.json", POLICY_2)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_D")
        m.logger.info.assert_any_call("Removing policy: policy_C")
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(2, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))

        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))
        self.assertEqual(path, m.policy_map.get("policy_D", None))

        self.assertEqual(
            {
                "policy_A": [],
                "policy_B": [],
                "policy_D": []
            },
            m.policy_cache
        )

        self.assertEqual(3, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_D": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_D", None)
        )

    def test_run_with_edit_adding_to_existing_file(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when an existing policy file is added to while
        tracking is active.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = side_effects(
            [
                False,
                build_write_effect(self.tmp_dir, "policy_1.json", POLICY_6),
                True
            ]
        )

        write_file(self.tmp_dir, "policy_1.json", POLICY_1)
        write_file(self.tmp_dir, "policy_2.json", POLICY_2)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call("Loading policy: policy_E")
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(2, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))
        self.assertEqual(path, m.policy_map.get("policy_E", None))

        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))
        self.assertEqual(path, m.policy_map.get("policy_C", None))

        self.assertEqual(
            {
                "policy_A": [],
                "policy_B": [],
                "policy_C": [],
                "policy_E": []
            },
            m.policy_cache
        )

        self.assertEqual(4, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_C": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_C", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_E": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.CHECK: enums.Policy.ALLOW_OWNER,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_E", None)
        )

    def test_run_with_edit_deleting_from_existing_file(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when an existing policy file has content removed
        while tracking is active.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = side_effects(
            [
                False,
                build_write_effect(self.tmp_dir, "policy_1.json", POLICY_1),
                True
            ]
        )

        write_file(self.tmp_dir, "policy_1.json", POLICY_6)
        write_file(self.tmp_dir, "policy_2.json", POLICY_2)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call("Loading policy: policy_E")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call("Removing policy: policy_E")
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(2, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))

        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))
        self.assertEqual(path, m.policy_map.get("policy_C", None))

        self.assertEqual(
            {
                "policy_A": [],
                "policy_B": [],
                "policy_C": []
            },
            m.policy_cache
        )

        self.assertEqual(3, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_C": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_C", None)
        )

    def test_run_with_deleting_existing_file(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when an existing policy file is removed while
        tracking is active.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = side_effects(
            [
                False,
                build_delete_effect(self.tmp_dir, "policy_1.json"),
                True
            ]
        )

        write_file(self.tmp_dir, "policy_1.json", POLICY_6)
        write_file(self.tmp_dir, "policy_2.json", POLICY_2)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call("Loading policy: policy_E")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.info.assert_any_call(
            "Removing policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Removing policy: policy_A")
        m.logger.info.assert_any_call("Removing policy: policy_E")
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(1, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(2, len(m.policy_map.keys()))
        self.assertEqual(path, m.policy_map.get("policy_B", None))
        self.assertEqual(path, m.policy_map.get("policy_C", None))

        self.assertEqual(
            {
                "policy_B": [],
                "policy_C": []
            },
            m.policy_cache
        )

        self.assertEqual(2, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_C": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_C", None)
        )

    def test_run_with_adding_new_file(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when a new policy file is added while tracking is
        active.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = side_effects(
            [
                False,
                build_write_effect(self.tmp_dir, "policy_2.json", POLICY_2),
                True
            ]
        )

        write_file(self.tmp_dir, "policy_1.json", POLICY_1)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.debug.assert_not_called()
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(2, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))

        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))
        self.assertEqual(path, m.policy_map.get("policy_C", None))

        self.assertEqual(
            {
                "policy_A": [],
                "policy_B": [],
                "policy_C": []
            },
            m.policy_cache
        )

        self.assertEqual(3, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_C": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_C", None)
        )

    def test_run_with_adding_new_file_overloading(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when new policy files are added overwritting
        existing policies while tracking is active.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = side_effects(
            [
                False,
                build_write_effect(self.tmp_dir, "policy_3.json", POLICY_2),
                build_write_effect(self.tmp_dir, "policy_4.json", POLICY_3),
                True
            ]
        )

        write_file(self.tmp_dir, "policy_1.json", POLICY_1)
        write_file(self.tmp_dir, "policy_2.json", POLICY_2)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_3.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.debug.assert_any_call(
            "Policy 'policy_B' overwrites an existing policy."
        )
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.debug.assert_any_call(
            "Policy 'policy_C' overwrites an existing policy."
        )

        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_4.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.debug.assert_any_call(
            "Policy 'policy_B' overwrites an existing policy."
        )

        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(4, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))

        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)

        path = os.path.join(self.tmp_dir, "policy_3.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_C", None))

        path = os.path.join(self.tmp_dir, "policy_4.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))

        self.assertEqual([], m.policy_cache.get("policy_A"))
        cache = m.policy_cache.get("policy_B")
        self.assertEqual(2, len(cache))
        self.assertEqual(
            os.path.join(self.tmp_dir, "policy_2.json"),
            cache[0][1]
        )
        self.assertEqual(
            {
                'groups': {
                    'group_B': {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET:
                                enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE:
                                enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY:
                                enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            cache[0][2]
        )
        self.assertEqual(
            os.path.join(self.tmp_dir, "policy_3.json"),
            cache[1][1]
        )
        self.assertEqual(
            {
                'groups': {
                    'group_B': {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET:
                                enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE:
                                enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY:
                                enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            cache[1][2]
        )
        cache = m.policy_cache.get("policy_C")
        self.assertEqual(1, len(cache))
        self.assertEqual(
            os.path.join(self.tmp_dir, "policy_2.json"),
            cache[0][1]
        )
        self.assertEqual(
            {
                'groups': {
                    'group_C': {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET:
                                enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY:
                                enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            cache[0][2]
        )

        self.assertEqual(3, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.DISALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.DISALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_C": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_C", None)
        )

    def test_run_with_adding_new_file_editing_overloading(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly, even when new policy files are added overwritting
        existing policies while tracking is active.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = side_effects(
            [
                False,
                build_write_effect(self.tmp_dir, "policy_3.json", POLICY_2),
                build_write_effect(self.tmp_dir, "policy_4.json", POLICY_3),
                build_delete_effect(self.tmp_dir, "policy_2.json"),
                build_write_effect(self.tmp_dir, "policy_4.json", POLICY_7),
                True
            ]
        )

        write_file(self.tmp_dir, "policy_1.json", POLICY_1)
        write_file(self.tmp_dir, "policy_2.json", POLICY_2)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Starting up the operation policy file monitor."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_3.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.debug.assert_any_call(
            "Policy 'policy_B' overwrites an existing policy."
        )
        m.logger.info.assert_any_call("Loading policy: policy_C")
        m.logger.debug.assert_any_call(
            "Policy 'policy_C' overwrites an existing policy."
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_4.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.debug.assert_any_call(
            "Policy 'policy_B' overwrites an existing policy."
        )
        m.logger.info.assert_any_call(
            "Removing policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_4.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_D")
        m.logger.info.assert_any_call(
            "Stopping the operation policy file monitor."
        )

        self.assertEqual(3, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))

        path = os.path.join(self.tmp_dir, "policy_3.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))
        self.assertEqual(path, m.policy_map.get("policy_C", None))

        path = os.path.join(self.tmp_dir, "policy_4.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_D", None))

        self.assertEqual([], m.policy_cache.get("policy_A"))
        self.assertEqual([], m.policy_cache.get("policy_B"))
        self.assertEqual([], m.policy_cache.get("policy_C"))

        self.assertEqual(4, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_C": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_C", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_D": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.DISALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.DISALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_D", None)
        )

    def test_run_without_live_monitoring(self):
        """
        Test that the PolicyDirectoryMonitor can load policy files and track
        them properly even when operating in a one-shot scanning mode.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict(),
            live_monitoring=False
        )
        m.logger = mock.MagicMock(logging.Logger)
        m.halt_trigger = mock.MagicMock(multiprocessing.synchronize.Event)
        m.halt_trigger.is_set.side_effect = [False, True]

        write_file(self.tmp_dir, "policy_1.json", POLICY_1)
        write_file(self.tmp_dir, "policy_2.json", POLICY_2)

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual([], m.policy_store.keys())

        m.run()

        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_1.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_A")
        m.logger.info.assert_any_call(
            "Loading policies for file: {}".format(
                os.path.join(self.tmp_dir, "policy_2.json")
            )
        )
        m.logger.info.assert_any_call("Loading policy: policy_B")
        m.logger.info.assert_any_call("Loading policy: policy_C")

        self.assertEqual(2, len(m.policy_files))
        path = os.path.join(self.tmp_dir, "policy_1.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_A", None))

        path = os.path.join(self.tmp_dir, "policy_2.json")
        self.assertEqual(
            os.path.getmtime(path),
            m.file_timestamps.get(path, None)
        )
        self.assertIn(path, m.policy_files)
        self.assertEqual(path, m.policy_map.get("policy_B", None))
        self.assertEqual(path, m.policy_map.get("policy_C", None))

        self.assertEqual(
            {
                "policy_A": [],
                "policy_B": [],
                "policy_C": []
            },
            m.policy_cache
        )

        self.assertEqual(3, len(m.policy_store.keys()))
        self.assertEqual(
            {
                "groups": {
                    "group_A": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_A", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_B": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.LOCATE: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.ALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_B", None)
        )
        self.assertEqual(
            {
                "groups": {
                    "group_C": {
                        enums.ObjectType.SYMMETRIC_KEY: {
                            enums.Operation.GET: enums.Policy.ALLOW_ALL,
                            enums.Operation.DESTROY: enums.Policy.DISALLOW_ALL
                        }
                    }
                }
            },
            m.policy_store.get("policy_C", None)
        )

    def test_initialize_tracking_structures(self):
        """
        Test that the PolicyDirectoryMonitor can correctly initialize/reset the
        various tracking structures used for file monitoring.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )

        m.file_timestamps["a"] = 1234
        m.policy_cache["a"] = (123.12, "b", {"c": 2})
        m.policy_files = ["a", "b"]
        m.policy_map["a"] = "b"
        m.policy_store["a"] = {"c": 2}
        m.policy_store["default"] = {"c": 3}

        m.initialize_tracking_structures()

        self.assertEqual({}, m.file_timestamps)
        self.assertEqual({}, m.policy_cache)
        self.assertEqual([], m.policy_files)
        self.assertEqual({}, m.policy_map)
        self.assertEqual(["default"], m.policy_store.keys())
        self.assertEqual({"c": 3}, m.policy_store.get("default"))

    def test_disassociate_policy_and_file(self):
        """
        Test that the PolicyDirectoryMonitor can correctly unlink a policy and
        a policy file in its tracking structures.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )

        m.policy_cache = {
            "policy_A": [
                (
                    1480043060.870089,
                    os.path.join(self.tmp_dir, "policy_1.json"),
                    {}
                ),
                (
                    1480043062.02171,
                    os.path.join(self.tmp_dir, "policy_2.json"),
                    {}
                ),
                (
                    1480043062.645776,
                    os.path.join(self.tmp_dir, "policy_1.json"),
                    {}
                ),
                (
                    1480043063.453713,
                    os.path.join(self.tmp_dir, "policy_3.json"),
                    {}
                )
            ],
            "policy_B": [
                (
                    1480043123.65311,
                    os.path.join(self.tmp_dir, "policy_1.json"),
                    {}
                )
            ]
        }

        m.disassociate_policy_and_file(
            "policy_A",
            os.path.join(self.tmp_dir, "policy_1.json")
        )

        self.assertEqual(
            [
                (
                    1480043062.02171,
                    os.path.join(self.tmp_dir, "policy_2.json"),
                    {}
                ),
                (
                    1480043063.453713,
                    os.path.join(self.tmp_dir, "policy_3.json"),
                    {}
                )
            ],
            m.policy_cache.get("policy_A", [])
        )
        self.assertEqual(
            [
                (
                    1480043123.65311,
                    os.path.join(self.tmp_dir, "policy_1.json"),
                    {}
                )
            ],
            m.policy_cache.get("policy_B", [])
        )

    def test_restore_or_delete_policy_restore(self):
        """
        Test that the PolicyDirectoryMonitor can correctly restore policy data
        upon a policy file change.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)

        m.policy_cache = {
            "policy_A": [
                (
                    1480043060.870089,
                    os.path.join(self.tmp_dir, "policy_1.json"),
                    {'{"policy_1"}'}
                ),
                (
                    1480043062.02171,
                    os.path.join(self.tmp_dir, "policy_2.json"),
                    {'{"policy_2"}'}
                ),
                (
                    1480043063.453713,
                    os.path.join(self.tmp_dir, "policy_3.json"),
                    {'{"policy_3"}'}
                )
            ]
        }
        m.policy_store["policy_A"] = {'{"policy_4"}'}
        m.policy_map["policy_A"] = os.path.join(self.tmp_dir, "policy_4.json")

        m.restore_or_delete_policy("policy_A")

        m.logger.info.assert_not_called()
        self.assertEqual(
            [
                (
                    1480043060.870089,
                    os.path.join(self.tmp_dir, "policy_1.json"),
                    {'{"policy_1"}'}
                ),
                (
                    1480043062.02171,
                    os.path.join(self.tmp_dir, "policy_2.json"),
                    {'{"policy_2"}'}
                )
            ],
            m.policy_cache.get("policy_A", [])
        )
        self.assertEqual(
            {'{"policy_3"}'},
            m.policy_store.get("policy_A", {})
        )
        self.assertEqual(
            os.path.join(self.tmp_dir, "policy_3.json"),
            m.policy_map.get("policy_A", None)
        )

    def test_restore_or_delete_policy_delete(self):
        """
        Test that the PolicyDirectoryMonitor can correctly delete policy data
        upon a policy file change.
        """
        m = monitor.PolicyDirectoryMonitor(
            self.tmp_dir,
            multiprocessing.Manager().dict()
        )
        m.logger = mock.MagicMock(logging.Logger)

        m.policy_cache = {
            "policy_A": []
        }
        m.policy_store["policy_A"] = {'{"policy_4"}'}
        m.policy_map["policy_A"] = os.path.join(self.tmp_dir, "policy_4.json")

        m.restore_or_delete_policy("policy_A")

        m.logger.info.assert_called_once_with("Removing policy: policy_A")
        self.assertNotIn("policy_A", m.policy_cache.keys())
        self.assertNotIn("policy_A", m.policy_store.keys())
        self.assertNotIn("policy_A", m.policy_map.keys())
