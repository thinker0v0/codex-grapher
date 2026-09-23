import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

from control_plane import backup_archive
from control_plane.backup_archive import (
    ArchiveError, ArchiveLimits, create_archive, extract_archive, inspect_archive,
)


class BackupArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "source"
        self.source.mkdir(mode=0o700)
        (self.source / "nested").mkdir(mode=0o750)
        (self.source / "nested/data").write_bytes(b"immutable data\x00")
        (self.source / "nested/data").chmod(0o640)
        (self.source / "empty").mkdir(mode=0o700)
        self.archive = self.root / "backup.tar"
        self.destination = self.root / "restore"
        self.destination.mkdir(mode=0o700)

    def create(self, **kwargs):
        return create_archive(self.source, self.archive, **kwargs)

    def rewrite(self, mutate):
        with tarfile.open(self.archive, "r:") as archive:
            records = [(member, archive.extractfile(member).read() if member.isfile() else b"")
                       for member in archive]
        records = mutate(records)
        with tarfile.open(self.archive, "w", format=tarfile.USTAR_FORMAT) as archive:
            for member, content in records:
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content) if content else None)

    def assert_invalid(self):
        before = self.archive.read_bytes()
        mode = stat.S_IMODE(self.archive.stat().st_mode)
        with self.assertRaises(ArchiveError):
            inspect_archive(self.archive)
        with self.assertRaises(ArchiveError):
            extract_archive(self.archive, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertEqual(self.archive.read_bytes(), before)
        self.assertEqual(stat.S_IMODE(self.archive.stat().st_mode), mode)

    def test_deterministic_complete_inventory_and_permission_round_trip(self):
        manifest = self.create(metadata={"original_root": "/private/workspace"},
                               role_for_path=lambda name, info: ("bootstrap", "graph"))
        other = self.root / "other.tar"
        create_archive(self.source, other, metadata={"original_root": "/private/workspace"},
                       role_for_path=lambda name, info: ("bootstrap", "graph"))
        self.assertEqual(self.archive.read_bytes(), other.read_bytes())
        before = self.archive.read_bytes()
        with mock.patch("os.chown", side_effect=AssertionError("numeric chown forbidden")):
            restored = extract_archive(self.archive, self.destination)
        self.assertEqual(restored, manifest)
        self.assertEqual([entry["path"] for entry in manifest["entries"]],
                         ["empty", "nested", "nested/data"])
        self.assertEqual((self.destination / "nested/data").read_bytes(), b"immutable data\x00")
        self.assertEqual(stat.S_IMODE((self.destination / "nested/data").stat().st_mode), 0o640)
        self.assertEqual(stat.S_IMODE((self.destination / "nested").stat().st_mode), 0o750)
        self.assertEqual(self.archive.read_bytes(), before)
        self.assertTrue(all(entry["owner_role"] == "bootstrap" for entry in restored["entries"]))

    def test_sgid_directory_round_trip_and_ordinary_modes(self):
        for name, mode in (("state", 0o2700), ("publications", 0o2750), ("ordinary", 0o777)):
            directory = self.source / name
            directory.mkdir()
            directory.chmod(mode)
        manifest = self.create(role_for_path=lambda name, info: ("graph", "worker"))
        self.assertEqual(inspect_archive(self.archive), manifest)
        self.assertEqual(extract_archive(self.archive, self.destination), manifest)
        for name, mode in (("state", 0o2700), ("publications", 0o2750), ("ordinary", 0o777)):
            self.assertEqual(stat.S_IMODE((self.destination / name).stat().st_mode), mode)

    def test_sgid_source_permission_contract_rejects(self):
        cases = [
            ("wrong", "directory", 0o2700, "graph", "worker"),
            ("nested/state", "directory", 0o2700, "graph", "worker"),
            ("state", "file", 0o2700, "graph", "worker"),
            ("publications", "file", 0o2750, "graph", "worker"),
            ("state", "directory", 0o2700, "bootstrap", "worker"),
            ("state", "directory", 0o2700, "graph", "graph"),
            ("publications", "directory", 0o2750, "worker", "worker"),
            ("publications", "directory", 0o2750, "graph", "signer"),
            ("state", "directory", 0o2750, "graph", "worker"),
            ("publications", "directory", 0o2700, "graph", "worker"),
            ("state", "directory", 0o2701, "graph", "worker"),
            ("publications", "directory", 0o2755, "graph", "worker"),
            ("state", "directory", 0o4700, "graph", "worker"),
            ("state", "directory", 0o1700, "graph", "worker"),
            ("state", "directory", 0o6700, "graph", "worker"),
        ]
        for relative, kind, mode, owner, group in cases:
            with self.subTest(path=relative, kind=kind, mode=oct(mode), owner=owner, group=group):
                target = self.source / relative
                if kind == "directory":
                    target.mkdir()
                else:
                    target.write_bytes(b"data")
                target.chmod(mode)
                try:
                    with self.assertRaises(ArchiveError):
                        self.create(role_for_path=lambda name, info: (owner, group))
                    self.assertFalse(self.archive.exists())
                finally:
                    target.rmdir() if kind == "directory" else target.unlink()

    def test_sgid_manifest_permission_contract_rejects(self):
        (self.source / "state").mkdir()
        (self.source / "state").chmod(0o2700)
        for changes in [
            {"path": "wrong"}, {"path": "nested/state"}, {"path": "publications"},
            {"mode": 0o2750}, {"mode": 0o2701}, {"mode": 0o2755},
            {"mode": 0o1700}, {"mode": 0o4700}, {"mode": 0o6700},
            {"mode": True}, {"mode": -1},
            {"type": "file", "sha256": hashlib.sha256(b"").hexdigest()},
            {"owner_role": "bootstrap"}, {"group_role": "graph"},
        ]:
            with self.subTest(changes=changes):
                self.archive.unlink(missing_ok=True)
                self.create(role_for_path=lambda name, info: ("graph", "worker"))

                def mutate(records):
                    member, content = records[0]
                    manifest = json.loads(content)
                    entry = next(item for item in manifest["entries"] if item["path"] == "state")
                    entry.update(changes)
                    manifest["entries"].sort(key=lambda item: item["path"])
                    records[0] = (member, backup_archive._canonical(manifest))
                    return records

                self.rewrite(mutate)
                self.assert_invalid()

    def test_sgid_tar_header_permission_contract_rejects(self):
        for name, kind, mode in [
            ("payload/state", "directory", 0o2700),
            ("payload/publications", "directory", 0o2750),
        ]:
            header = backup_archive._header(name, kind, mode, 0)
            parsed = backup_archive._read_header(io.BytesIO(header.tobuf(format=tarfile.USTAR_FORMAT)))
            self.assertEqual(parsed.mode, mode)
        for name, kind, mode in [
            ("state", "directory", 0o2700),
            ("payload/wrong", "directory", 0o2700),
            ("payload/nested/state", "directory", 0o2700),
            ("payload/state", "file", 0o2700),
            ("payload/publications", "file", 0o2750),
            ("payload/state", "directory", 0o2750),
            ("payload/publications", "directory", 0o2700),
            ("payload/state", "directory", 0o2701),
            ("payload/publications", "directory", 0o2755),
            ("payload/state", "directory", 0o1700),
            ("payload/state", "directory", 0o4700),
            ("payload/state", "directory", 0o6700),
        ]:
            with self.subTest(name=name, kind=kind, mode=oct(mode)):
                header = backup_archive._header(name, kind, mode, 0)
                with self.assertRaises(ArchiveError):
                    backup_archive._read_header(io.BytesIO(header.tobuf(format=tarfile.USTAR_FORMAT)))

    def test_sgid_extraction_rejects_silently_stripped_mode(self):
        (self.source / "state").mkdir()
        (self.source / "state").chmod(0o2700)
        self.create(role_for_path=lambda name, info: ("graph", "worker"))
        real_fchmod = os.fchmod

        def strip_sgid(descriptor, mode):
            real_fchmod(descriptor, mode & ~stat.S_ISGID)

        with mock.patch("os.fchmod", side_effect=strip_sgid):
            with self.assertRaisesRegex(ArchiveError, "did not preserve"):
                extract_archive(self.archive, self.destination)

    def test_exact_recursive_exclusions_skip_credentials_and_special_files(self):
        (self.source / "private").mkdir()
        (self.source / "private/key").write_text("fake-private-key")
        (self.source / "private/link").symlink_to("/etc/passwd")
        os.mkfifo(self.source / "runtime.sock")
        manifest = self.create(excludes=["private", "runtime.sock", "absent"])
        self.assertEqual([entry["path"] for entry in manifest["entries"]],
                         ["empty", "nested", "nested/data"])
        self.assertNotIn(b"fake-private-key", self.archive.read_bytes())

    def test_includes_add_parent_directories(self):
        manifest = self.create(includes=["nested/data"])
        self.assertEqual([entry["path"] for entry in manifest["entries"]], ["nested", "nested/data"])
        with self.assertRaises(ArchiveError):
            create_archive(self.source, self.root / "missing.tar", includes=["missing"])

    def test_source_links_special_files_and_privileged_modes_reject(self):
        bad = self.source / "bad"
        for kind in ["symlink", "hardlink", "fifo", "setuid"]:
            with self.subTest(kind=kind):
                if kind == "symlink":
                    bad.symlink_to("nested/data")
                elif kind == "hardlink":
                    os.link(self.source / "nested/data", bad)
                elif kind == "fifo":
                    os.mkfifo(bad)
                else:
                    bad.write_text("privileged")
                    bad.chmod(0o4755)
                with self.assertRaises(ArchiveError):
                    self.create()
                self.assertFalse(self.archive.exists())
                bad.unlink()

    def test_exclusive_destination_and_source_output_overlap(self):
        self.create()
        before = self.archive.read_bytes()
        with self.assertRaises(ArchiveError):
            self.create()
        self.assertEqual(self.archive.read_bytes(), before)
        with self.assertRaises(ArchiveError):
            create_archive(self.source, self.source / "backup.tar")

    def test_member_corruption_rejected_without_mutating_archive_or_destination(self):
        self.create()
        self.rewrite(lambda records: records[:-1] + [(records[-1][0], b"changed bytes!!")])
        self.assert_invalid()

    def test_extra_duplicate_missing_and_changed_mode_members_reject(self):
        for mutation in ["extra", "duplicate", "missing", "mode", "uid", "symlink", "hardlink", "fifo", "traversal", "absolute"]:
            with self.subTest(mutation=mutation):
                self.archive.unlink(missing_ok=True)
                self.create()

                def mutate(records):
                    if mutation in {"extra", "duplicate"}:
                        records.append(records[-1])
                    elif mutation == "missing":
                        records.pop()
                    else:
                        member = records[-1][0]
                        if mutation == "mode":
                            member.mode ^= 0o001
                        elif mutation == "uid":
                            member.uid = 1234
                        elif mutation in {"symlink", "hardlink", "fifo"}:
                            member.type = {"symlink": tarfile.SYMTYPE, "hardlink": tarfile.LNKTYPE,
                                           "fifo": tarfile.FIFOTYPE}[mutation]
                            member.linkname = "outside"
                        else:
                            member.name = "../outside" if mutation == "traversal" else "/outside"
                    return records

                self.rewrite(mutate)
                self.assert_invalid()

    def test_manifest_duplicates_extras_bad_roles_and_parent_omissions_reject(self):
        for mutation in ["duplicate_json", "unknown_field", "role", "duplicate_path", "missing_parent", "bool_size", "invalid_type"]:
            with self.subTest(mutation=mutation):
                self.archive.unlink(missing_ok=True)
                self.create()

                def mutate(records):
                    member, content = records[0]
                    manifest = json.loads(content)
                    if mutation == "unknown_field":
                        manifest["extra"] = 1
                    elif mutation == "role":
                        manifest["entries"][0]["owner_role"] = "root"
                    elif mutation == "duplicate_path":
                        manifest["entries"].append(manifest["entries"][-1])
                    elif mutation == "missing_parent":
                        manifest["entries"].pop(1)
                    elif mutation == "bool_size":
                        manifest["entries"][-1]["size"] = True
                    elif mutation == "invalid_type":
                        manifest["entries"][-1]["type"] = []
                    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
                    if mutation == "duplicate_json":
                        content = b'{"schema_version":1,' + content[1:]
                    records[0] = (member, content)
                    return records

                self.rewrite(mutate)
                self.assert_invalid()

    def test_truncation_checksum_corruption_and_trailing_archives_reject(self):
        for mutation in ["truncated", "checksum", "trailing", "concatenated"]:
            with self.subTest(mutation=mutation):
                self.archive.unlink(missing_ok=True)
                self.create()
                content = self.archive.read_bytes()
                if mutation == "truncated":
                    content = content[:-512]
                elif mutation == "checksum":
                    content = b"x" + content[1:]
                elif mutation == "trailing":
                    content += b"hidden"
                else:
                    content += content
                self.archive.write_bytes(content)
                self.assert_invalid()

    def test_tight_limits_allow_two_terminator_blocks_and_record_padding(self):
        source = self.root / "tight-source"
        source.mkdir()
        for number in range(8):
            (source / str(number)).write_bytes(b"x")
            (source / str(number)).chmod(0o644)
        metadata = {"pad": "x" * 9379}
        manifest = create_archive(source, self.archive, metadata=metadata)
        limits = ArchiveLimits(max_entries=8, max_file_bytes=1, max_total_bytes=8,
                               max_manifest_bytes=len(backup_archive._canonical(manifest)))
        bounded = self.root / "bounded.tar"
        self.assertEqual(create_archive(source, bounded, metadata=metadata, limits=limits), manifest)
        self.assertEqual(inspect_archive(bounded, limits=limits), manifest)

    def test_limits_and_invalid_paths_fail_before_publication_or_extraction(self):
        for kwargs in [dict(limits=ArchiveLimits(max_file_bytes=2)),
                       dict(limits=ArchiveLimits(max_total_bytes=2)),
                       dict(limits=ArchiveLimits(max_entries=1)),
                       dict(limits=ArchiveLimits(max_manifest_bytes=2)),
                       dict(excludes=["../private"]), dict(includes=["/nested"]),
                       dict(role_for_path=lambda name, info: ("graph", 0))]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ArchiveError):
                    self.create(**kwargs)
                self.assertFalse(self.archive.exists())
        self.create()
        with self.assertRaises(ArchiveError):
            extract_archive(self.archive, self.destination, limits=ArchiveLimits(max_file_bytes=2))
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_nonempty_public_or_linked_destinations_reject(self):
        self.create()
        (self.destination / "existing").write_text("keep")
        with self.assertRaises(ArchiveError):
            extract_archive(self.archive, self.destination)
        (self.destination / "existing").unlink()
        self.destination.chmod(0o755)
        with self.assertRaises(ArchiveError):
            extract_archive(self.archive, self.destination)
        linked = self.root / "linked"
        linked.symlink_to(self.destination, target_is_directory=True)
        with self.assertRaises(ArchiveError):
            extract_archive(self.archive, linked)

    def test_replaced_extraction_ancestor_cannot_write_outside_staging(self):
        self.create()
        outside = self.root / "outside"
        outside.mkdir()
        real_source_open = backup_archive._source_open
        replaced = False

        def replace_parent(root_fd, relative, directory=False):
            nonlocal replaced
            if relative == "nested" and not replaced:
                replaced = True
                (self.destination / "nested").rename(self.destination / "moved")
                (self.destination / "nested").symlink_to(outside, target_is_directory=True)
            return real_source_open(root_fd, relative, directory)

        with mock.patch.object(backup_archive, "_source_open", side_effect=replace_parent):
            with self.assertRaises(ArchiveError):
                extract_archive(self.archive, self.destination)
        self.assertTrue(replaced)
        self.assertEqual(list(outside.iterdir()), [])

    @unittest.skipUnless(os.geteuid() == 0, "requires root to construct hostile-owner fixture")
    def test_private_destination_owned_by_another_user_rejects(self):
        self.create()
        os.chown(self.destination, 65534, 65534)
        self.addCleanup(os.chown, self.destination, 0, 0)
        with self.assertRaises(ArchiveError):
            extract_archive(self.archive, self.destination)
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_source_changes_before_publication_fail_and_leave_no_archive(self):
        real_inspect = inspect_archive

        def inspect_then_modify(path, **kwargs):
            result = real_inspect(path, **kwargs)
            (self.source / "new-file").write_text("raced")
            return result

        with mock.patch.object(backup_archive, "inspect_archive", side_effect=inspect_then_modify):
            with self.assertRaises(ArchiveError):
                self.create()
        self.assertFalse(self.archive.exists())
        self.assertFalse(list(self.root.glob(".backup-*")))

    def test_noncanonical_extension_and_inflated_manifest_headers_reject(self):
        self.create()
        original = self.archive.read_bytes()
        with tarfile.open(self.archive, "r:") as archive:
            header = archive.next()
        header.size = 65 * 1024 * 1024
        self.archive.write_bytes(header.tobuf(format=tarfile.USTAR_FORMAT) + original[512:])
        self.assert_invalid()
        header.type = tarfile.XHDTYPE
        header.size = 1024 * 1024 * 1024
        self.archive.write_bytes(header.tobuf(format=tarfile.USTAR_FORMAT) + original[512:])
        self.assert_invalid()

    def test_extraction_writes_in_bounded_chunks(self):
        data = b"x" * (2 * 1024 * 1024 + 3)
        (self.source / "large").write_bytes(data)
        self.create()
        original = os.write
        lengths = []

        def bounded_write(fd, content):
            lengths.append(len(content))
            return original(fd, content)

        with mock.patch("os.write", side_effect=bounded_write):
            extract_archive(self.archive, self.destination)
        self.assertLessEqual(max(lengths), 1024 * 1024)
        self.assertEqual(hashlib.sha256((self.destination / "large").read_bytes()).digest(),
                         hashlib.sha256(data).digest())


if __name__ == "__main__":
    unittest.main()
