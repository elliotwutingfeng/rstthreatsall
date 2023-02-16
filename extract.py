"""Extract all IOCs and their latest last seen timestamp
from all historical versions of rstthreats
"""

import enum
import json
import logging
import multiprocessing
import os
import re
import socket
import subprocess
import unittest

domain_feed_path = f"feeds{os.sep}full{os.sep}random100_ioc_domain_latest.json"
ip_feed_path = f"feeds{os.sep}full{os.sep}random100_ioc_ip_latest.json"
url_feed_path = f"feeds{os.sep}full{os.sep}random100_ioc_url_latest.json"

short_feed_path = f"feeds{os.sep}short{os.sep}*"

os.chdir("rstthreats")


class Task(enum.Enum):
    DOMAIN = 1
    IP = 2
    URL = 3


class CommitHistory:
    def get_commit_ids(self, feed_path: str) -> list[str]:
        """Search git repository for all commits where files exist at `feed_path`

        Args:
            feed_path (str): Path to files to be extracted

        Returns:
            list[str]: Git commit ids where files at `feed_path` are present
        """
        # rev-list results are in reverse-chronological order
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
            line for line in res.decode().split("\n") if line and len(line.split(" ")) == 1
        ]
        return commit_ids


class Random100(CommitHistory):
    def extract_ioc_records(self, feed_path: str) -> list[dict]:
        """Extract IOC records from all historical versions of
        files at `feed_path`

        Args:
            commit_ids (list[str]): Git commit ids where files at `feed_path` are present

        Returns:
            list[dict]: IOC records
        """
        commit_ids = self.get_commit_ids(feed_path)
        ioc_records: list[dict] = []
        for idx, commit_id in enumerate(commit_ids):
            try:
                commit_data = json.loads(
                    "["  # NDJSON workaround
                    + subprocess.check_output(
                        [
                            "git",
                            "cat-file",
                            "-p",
                            f"{commit_id}:{feed_path}",
                        ]
                    )
                    .decode()
                    .replace("} {", "},{")  # NDJSON workaround
                    .replace("\n", "")  # NDJSON workaround
                    .replace("}{", "},{")  # NDJSON workaround
                    + "]"  # NDJSON workaround
                )
            except Exception as e:
                logging.info("Commit %d : ID %s | %s", idx, commit_id, e)
            else:
                ioc_records += commit_data
        return ioc_records

    def get_domain_and_last_seen(self, ioc_records: list[dict]) -> list[tuple[str, str]]:
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

    def get_ip_and_last_seen(self, ioc_records: list[dict]) -> list[tuple[str, str]]:
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

    def get_url_and_last_seen(self, ioc_records: list[dict]) -> list[tuple[str, str]]:
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

    def drop_duplicates(self, ioc_and_last_seen: list[tuple[str, str]]) -> list[str]:
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

    def write_random100_list(self, task: Task):
        """Writes consolidated random100 lists to text files

        Args:
            task (Task): IOC type
        """
        if task is Task.DOMAIN:
            domain_ioc_records = self.extract_ioc_records(domain_feed_path)
            domain_and_last_seen = self.get_domain_and_last_seen(domain_ioc_records)
            domain_and_latest_last_seen = self.drop_duplicates(domain_and_last_seen)
            if domain_and_latest_last_seen:
                with open(f"..{os.sep}random100_ioc_domain_latest_all.txt", "w") as f:
                    f.write("\n".join(domain_and_latest_last_seen))
        if task is Task.IP:
            ip_ioc_records = self.extract_ioc_records(ip_feed_path)
            ip_and_last_seen = self.get_ip_and_last_seen(ip_ioc_records)
            ip_and_latest_last_seen = self.drop_duplicates(ip_and_last_seen)
            if ip_and_latest_last_seen:
                with open(f"..{os.sep}random100_ioc_ip_latest_all.txt", "w") as f:
                    f.write("\n".join(ip_and_latest_last_seen))
        if task is Task.URL:
            url_ioc_records = self.extract_ioc_records(url_feed_path)
            url_and_last_seen = self.get_url_and_last_seen(url_ioc_records)
            url_and_latest_last_seen = self.drop_duplicates(url_and_last_seen)
            if url_and_latest_last_seen:
                with open(f"..{os.sep}random100_ioc_url_latest_all.txt", "w") as f:
                    f.write("\n".join(url_and_latest_last_seen))


class TestRandom100(unittest.TestCase):
    def setUp(self):
        self.random100 = Random100()
        self.ioc_record_sample_size = 500

        self.domain_ioc_records = self.random100.extract_ioc_records(domain_feed_path)[
            : self.ioc_record_sample_size
        ]
        self.ip_ioc_records = self.random100.extract_ioc_records(ip_feed_path)[
            : self.ioc_record_sample_size
        ]
        self.url_ioc_records = self.random100.extract_ioc_records(url_feed_path)[
            : self.ioc_record_sample_size
        ]

    def test_extract_ioc_records(self):
        self.assertTrue(len(self.domain_ioc_records) == self.ioc_record_sample_size)
        self.assertTrue(len(self.ip_ioc_records) == self.ioc_record_sample_size)
        self.assertTrue(len(self.url_ioc_records) == self.ioc_record_sample_size)

    def test_get_ioc_and_last_seen(self):
        self.domain_and_last_seen = self.random100.get_domain_and_last_seen(self.domain_ioc_records)
        self.ip_and_last_seen = self.random100.get_ip_and_last_seen(self.ip_ioc_records)
        self.url_and_last_seen = self.random100.get_url_and_last_seen(self.url_ioc_records)

        self.assertTrue(len(self.domain_and_last_seen) == self.ioc_record_sample_size + 1)
        self.assertTrue(len(self.ip_and_last_seen) == self.ioc_record_sample_size + 1)
        self.assertTrue(len(self.url_and_last_seen) == self.ioc_record_sample_size + 1)

    def test_drop_duplicates(self):
        self.assertTrue(len(self.random100.drop_duplicates([("", "")])) == 0)
        self.assertTrue(len(self.random100.drop_duplicates([("example.com", "1"), ("", "")])) == 1)
        self.assertTrue(
            len(
                self.random100.drop_duplicates(
                    [("example.com", "1"), ("example.com", "2"), ("", "")]
                )
            )
            == 1
        )
        self.assertTrue(
            len(
                self.random100.drop_duplicates(
                    [("example.com", "1"), ("example.com", "2"), ("example.org", "1"), ("", "")]
                )
            )
            == 2
        )
        self.assertTrue(
            len(
                self.random100.drop_duplicates(
                    [("example.com", "1"), ("example.org", "1"), ("", "")]
                )
            )
            == 2
        )
        self.assertTrue(
            len(
                self.random100.drop_duplicates(
                    [("example.com", "1"), ("example.org", "1"), ("example.org", "2"), ("", "")]
                )
            )
            == 2
        )


class Short(CommitHistory):
    def extract_short_ioc_records(self, feed_path: str) -> dict[Task, dict]:
        """Extract IOC records from all historical versions of
        files at `feed_path` and categorises them by type `Task`

        Args:
            feed_path (str): Path to files to be extracted

        Returns:
            dict[Task, dict]: IOCs categorised by type `Task`
        """
        commit_ids = self.get_commit_ids(feed_path)

        domain_records: dict = dict()
        ip_records: dict = dict()
        url_records: dict = dict()

        for idx, commit_id in enumerate(commit_ids):
            files_in_commit = subprocess.check_output(["git", "show", commit_id, "--name-only"])
            json_feed_paths_in_commit = [
                line
                for line in files_in_commit.decode().split("\n")
                if line and re.match(f"^feeds{os.sep}short{os.sep}.*json$", line)
            ]
            for json_feed_path in json_feed_paths_in_commit:
                if "ioc_hash" in json_feed_path:
                    continue
                try:
                    commit_data = json.loads(
                        "["  # NDJSON workaround
                        + subprocess.check_output(
                            [
                                "git",
                                "cat-file",
                                "-p",
                                f"{commit_id}:{json_feed_path}",
                            ],
                            stderr=subprocess.DEVNULL,
                        )
                        .decode()
                        .replace("}\n{", "},\n{")  # NDJSON workaround
                        + "]"  #  NDJSON workaround
                    )
                except Exception as e:
                    logging.info("Commit %d : ID %s | %s", idx, commit_id, e)
                else:
                    # duplicate records are always older as `git rev-list is in reverse chronological order`
                    if "ioc_domain" in json_feed_path:
                        for entry in commit_data:
                            if entry["domain"] not in domain_records:
                                domain_records[entry["domain"]] = entry["collect"]
                    if "ioc_ip" in json_feed_path:
                        for entry in commit_data:
                            if entry["ip"]["v4"] not in ip_records:
                                ip_records[entry["ip"]["v4"]] = entry["collect"]
                    if "ioc_url" in json_feed_path:
                        for entry in commit_data:
                            if entry["url"] not in url_records:
                                url_records[entry["url"]] = entry["collect"]

        return {Task.DOMAIN: domain_records, Task.IP: ip_records, Task.URL: url_records}

    def write_short_lists(self):
        """Writes consolidated short lists to text files"""
        records = self.extract_short_ioc_records(short_feed_path)
        domain_records = records[Task.DOMAIN]
        ip_records = records[Task.IP]
        url_records = records[Task.URL]

        domain_and_latest_last_seen = [
            f"{s[0]} # {s[1]}" for s in sorted(domain_records.items(), key=lambda x: x[0])
        ]
        if domain_and_latest_last_seen:
            with open(f"..{os.sep}ioc_domain_short_all.txt", "w") as f:
                f.write("\n".join(domain_and_latest_last_seen))

        ip_and_latest_last_seen = [
            f"{s[0]} # {s[1]}"
            for s in sorted(ip_records.items(), key=lambda x: socket.inet_aton(x[0]))
        ]
        if ip_and_latest_last_seen:
            with open(f"..{os.sep}ioc_ip_short_all.txt", "w") as f:
                f.write("\n".join(ip_and_latest_last_seen))

        url_and_latest_last_seen = [
            f"{s[0]} # {s[1]}" for s in sorted(url_records.items(), key=lambda x: x[0])
        ]
        if url_and_latest_last_seen:
            with open(f"..{os.sep}ioc_url_short_all.txt", "w") as f:
                f.write("\n".join(url_and_latest_last_seen))


class TestShort(unittest.TestCase):
    def setUp(self):
        self.short = Short()
        sample_short_domain_feed_path = f"feeds{os.sep}short{os.sep}ioc_domain_20230208_short.json"
        sample_short_ip_feed_path = f"feeds{os.sep}short{os.sep}ioc_ip_20230208_short.json"
        sample_short_url_feed_path = f"feeds{os.sep}short{os.sep}ioc_url_20230208_short.json"

        self.short_domain_ioc_records = self.short.extract_short_ioc_records(
            sample_short_domain_feed_path
        )
        self.short_ip_ioc_records = self.short.extract_short_ioc_records(sample_short_ip_feed_path)
        self.short_url_ioc_records = self.short.extract_short_ioc_records(
            sample_short_url_feed_path
        )

    def test_extract_short_ioc_records(self):
        print(self.short_domain_ioc_records.keys())
        self.assertTrue(len(self.short_domain_ioc_records[Task.DOMAIN]))
        self.assertTrue(len(self.short_ip_ioc_records[Task.IP]))
        self.assertTrue(len(self.short_url_ioc_records[Task.URL]))


if __name__ == "__main__":

    with multiprocessing.Pool(None) as p:
        random100 = Random100()
        p.map(random100.write_random100_list, [Task.DOMAIN, Task.IP, Task.URL])

    short = Short()
    short.write_short_lists()
