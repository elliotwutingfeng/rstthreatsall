"""Extract all unique domains and their latest last seen timestamp
from all historical versions of random100_ioc_domain_latest.json

MIT License

Copyright (c) 2023 Wu Tingfeng <wutingfeng@outlook.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import enum
import json
import logging
import multiprocessing
import os
import socket
import subprocess
import unittest

domain_feed_path = f"feeds{os.sep}full{os.sep}random100_ioc_domain_latest.json"
ip_feed_path = f"feeds{os.sep}full{os.sep}random100_ioc_ip_latest.json"
url_feed_path = f"feeds{os.sep}full{os.sep}random100_ioc_url_latest.json"

os.chdir("rstthreats")


def extract_ioc_records(feed_path: str) -> list[dict]:
    """Extract IOC records from all historical versions of
    file at `feed_path`

    Args:
        commit_ids (list[str]): Git commit ids where file at `feed_path` is present

    Returns:
        list[dict]: IOC records
    """
    res = subprocess.check_output(
        [
            "git",
            "rev-list",
            "--all",
            "--objects",
            "--",
            feed_path,
        ]
    )
    commit_ids = [
        line.strip() for line in res.decode().split("\n") if line and len(line.split(" ")) == 1
    ]
    ioc_records: list[dict] = []
    for idx, commit_id in enumerate(commit_ids):
        try:
            commit_data = json.loads(
                "["  # Malformed JSON workaround
                + subprocess.check_output(
                    [
                        "git",
                        "cat-file",
                        "-p",
                        f"{commit_id}:{feed_path}",
                    ]
                )
                .decode()
                .replace("} {", "},{")  # Malformed JSON workaround
                .replace("\n", "")  # Malformed JSON workaround
                .replace("}{", "},{")  # Malformed JSON workaround
                + "]"  # Malformed JSON workaround
            )
        except Exception as e:
            logging.warning("Commit %d : ID %s | %s", idx, commit_id, e)
        else:
            ioc_records += commit_data
    return ioc_records


def get_domain_and_last_seen(ioc_records: list[dict]) -> list[tuple[str, str]]:
    """Search IOC records for all unique domains and their last seen timestamps
    sorted by domain name and then by timestamp in ascending order

    Args:
        ioc_records (list[dict]): IOC records

    Returns:
        list[tuple[str, str]]: All unique domains and their last seen timestamps
    """
    return sorted(
        set((h["domain"].strip(), h["lseen"]) for h in ioc_records), key=lambda x: (x[0], x[1])
    ) + [("", "")]


def get_ip_and_last_seen(ioc_records: list[dict]) -> list[tuple[str, str]]:
    """Search IOC records for all unique IPs and their last seen timestamps
    sorted by IP and then by timestamp in ascending order

    Args:
        ioc_records (list[dict]): IOC records

    Returns:
        list[tuple[str, str]]: All unique IPs and their last seen timestamps
    """
    return sorted(
        set((h["ip"]["v4"].strip(), h["lseen"]) for h in ioc_records),
        key=lambda x: (socket.inet_aton(x[0]), x[1]),
    ) + [("", "")]


def get_url_and_last_seen(ioc_records: list[dict]) -> list[tuple[str, str]]:
    """Search IOC records for all unique URLs and their last seen timestamps
    sorted by URL and then by timestamp in ascending order

    Args:
        ioc_records (list[dict]): IOC records

    Returns:
        list[tuple[str, str]]: All unique URLs and their last seen timestamps
    """
    return sorted(
        set((h["url"].strip(), h["lseen"]) for h in ioc_records), key=lambda x: (x[0], x[1])
    ) + [("", "")]


def get_ioc_and_latest_last_seen(ioc_and_last_seen: list[tuple[str, str]]) -> list[str]:
    """For each ioc-timestamp pair, drop duplicates except for tuple with latest timestamp,
    store result as string of format "{ioc} # {timestamp}"

    Args:
        ioc_and_last_seen (list[tuple[str, str]]): All unique iocs and their last seen timestamps

    Returns:
        list[str]: Each unique ioc and its latest last seen timestamp in format "{ioc} # {timestamp}"
    """
    ioc_and_latest_last_seen: list[str] = []

    current = None
    for i, entry in enumerate(ioc_and_last_seen):
        if current is not None and current[0] != entry[0]:
            ioc_and_latest_last_seen.append(f"{current[0]} # {current[1]}")
        current = entry

    return ioc_and_latest_last_seen


class TestMethods(unittest.TestCase):
    """Run `python -m coverage run -m unittest -f extract.py && python -m coverage html`"""

    def setUp(self):
        self.ioc_record_sample_size = 500

        self.domain_feed_path = domain_feed_path
        self.ip_feed_path = ip_feed_path
        self.url_feed_path = url_feed_path

        self.domain_ioc_records = extract_ioc_records(self.domain_feed_path)[
            : self.ioc_record_sample_size
        ]
        self.ip_ioc_records = extract_ioc_records(self.ip_feed_path)[: self.ioc_record_sample_size]
        self.url_ioc_records = extract_ioc_records(self.url_feed_path)[
            : self.ioc_record_sample_size
        ]

        self.domain_and_last_seen = get_domain_and_last_seen(self.domain_ioc_records)
        self.ip_and_last_seen = get_ip_and_last_seen(self.ip_ioc_records)
        self.url_and_last_seen = get_url_and_last_seen(self.url_ioc_records)

        self.domain_and_latest_last_seen = get_ioc_and_latest_last_seen(self.domain_and_last_seen)
        self.ip_and_latest_last_seen = get_ioc_and_latest_last_seen(self.ip_and_last_seen)
        self.url_and_latest_last_seen = get_ioc_and_latest_last_seen(self.url_and_last_seen)

    def test_extract_ioc_records(self):

        self.assertTrue(len(self.domain_ioc_records) == self.ioc_record_sample_size)
        self.assertTrue(len(self.ip_ioc_records) == self.ioc_record_sample_size)
        self.assertTrue(len(self.url_ioc_records) == self.ioc_record_sample_size)

    def test_get_ioc_and_last_seen(self):
        self.assertTrue(len(self.domain_and_last_seen) == self.ioc_record_sample_size + 1)
        self.assertTrue(len(self.ip_and_last_seen) == self.ioc_record_sample_size + 1)
        self.assertTrue(len(self.url_and_last_seen) == self.ioc_record_sample_size + 1)

    def test_get_ioc_and_latest_last_seen(self):
        self.assertTrue(len(get_ioc_and_latest_last_seen([("", "")])) == 0)
        self.assertTrue(len(get_ioc_and_latest_last_seen([("example.com", "1"), ("", "")])) == 1)
        self.assertTrue(
            len(
                get_ioc_and_latest_last_seen([("example.com", "1"), ("example.com", "2"), ("", "")])
            )
            == 1
        )
        self.assertTrue(
            len(
                get_ioc_and_latest_last_seen(
                    [("example.com", "1"), ("example.com", "2"), ("example.org", "1"), ("", "")]
                )
            )
            == 2
        )
        self.assertTrue(
            len(
                get_ioc_and_latest_last_seen([("example.com", "1"), ("example.org", "1"), ("", "")])
            )
            == 2
        )
        self.assertTrue(
            len(
                get_ioc_and_latest_last_seen(
                    [("example.com", "1"), ("example.org", "1"), ("example.org", "2"), ("", "")]
                )
            )
            == 2
        )


if __name__ == "__main__":

    class Task(enum.Enum):
        DOMAIN = 1
        IP = 2
        URL = 3

    def extract_iocs(task: Task):
        if task is Task.DOMAIN:
            domain_ioc_records = extract_ioc_records(domain_feed_path)
            domain_and_last_seen = get_domain_and_last_seen(domain_ioc_records)
            domain_and_latest_last_seen = get_ioc_and_latest_last_seen(domain_and_last_seen)
            with open(f"..{os.sep}random100_ioc_domain_latest_all.txt", "w") as f:
                f.write("\n".join(domain_and_latest_last_seen))
        if task is Task.IP:
            ip_ioc_records = extract_ioc_records(ip_feed_path)
            ip_and_last_seen = get_ip_and_last_seen(ip_ioc_records)
            ip_and_latest_last_seen = get_ioc_and_latest_last_seen(ip_and_last_seen)
            with open(f"..{os.sep}random100_ioc_ip_latest_all.txt", "w") as f:
                f.write("\n".join(ip_and_latest_last_seen))
        if task is Task.URL:
            url_ioc_records = extract_ioc_records(url_feed_path)
            url_and_last_seen = get_url_and_last_seen(url_ioc_records)
            url_and_latest_last_seen = get_ioc_and_latest_last_seen(url_and_last_seen)
            with open(f"..{os.sep}random100_ioc_url_latest_all.txt", "w") as f:
                f.write("\n".join(url_and_latest_last_seen))

    with multiprocessing.Pool(None) as p:
        p.map(extract_iocs, [Task.DOMAIN, Task.IP, Task.URL])
