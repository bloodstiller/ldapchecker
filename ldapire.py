#!/usr/bin/env python3
"""LDAP enumeration tool for Active Directory domain reconnaissance."""

from __future__ import annotations

import argparse
import datetime
import getpass
import logging
import re
import socket
import sys
from typing import Optional

from ldap3 import ALL, ANONYMOUS, SUBTREE, Connection, Server
from ldap3.core.exceptions import LDAPException

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

LOG_FILE = "ldap_test.log"

# userAccountControl bitmask definitions
UAC_FLAGS: dict[int, str] = {
    0x00000001: "SCRIPT",
    0x00000002: "ACCOUNTDISABLE",
    0x00000008: "HOMEDIR_REQUIRED",
    0x00000010: "LOCKOUT",
    0x00000020: "PASSWD_NOTREQD",
    0x00000040: "PASSWD_CANT_CHANGE",
    0x00000080: "ENCRYPTED_TEXT_PWD_ALLOWED",
    0x00000100: "TEMP_DUPLICATE_ACCOUNT",
    0x00000200: "NORMAL_ACCOUNT",
    0x00000800: "INTERDOMAIN_TRUST_ACCOUNT",
    0x00001000: "WORKSTATION_TRUST_ACCOUNT",
    0x00002000: "SERVER_TRUST_ACCOUNT",
    0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00020000: "MNS_LOGON_ACCOUNT",
    0x00040000: "SMARTCARD_REQUIRED",
    0x00080000: "TRUSTED_FOR_DELEGATION",
    0x00100000: "NOT_DELEGATED",
    0x00200000: "USE_DES_KEY_ONLY",
    0x00400000: "DONT_REQ_PREAUTH",
    0x00800000: "PASSWORD_EXPIRED",
    0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
    0x04000000: "PARTIAL_SECRETS_ACCOUNT",
}

# UAC flags relevant to attack surface — used for summary warnings
UAC_ATTACK_FLAGS: dict[int, str] = {
    0x00000020: "PASSWD_NOTREQD",
    0x00010000: "DONT_EXPIRE_PASSWORD",
    0x00080000: "TRUSTED_FOR_DELEGATION",
    0x00400000: "DONT_REQ_PREAUTH",
    0x01000000: "TRUSTED_TO_AUTH_FOR_DELEGATION",
}

# Specific UAC bit values used in LDAP filters and checks
UAC_ACCOUNTDISABLE            = 0x00000002
UAC_SERVER_TRUST_ACCOUNT      = 0x00002000  # Domain Controllers
UAC_TRUSTED_FOR_DELEGATION    = 0x00080000  # Unconstrained delegation
UAC_DONT_REQ_PREAUTH          = 0x00400000  # ASREPRoastable
UAC_TRUSTED_TO_AUTH_FOR_DELEG = 0x01000000  # Constrained with protocol transition

# Attributes whose binary values are displayed as raw hex
HEX_DISPLAY_ATTRS = frozenset({
    "msexchmailboxsecuritydescriptor",
    "repluptodatevector",
    "dsasignature",
    "auditingpolicy",
})

# Attributes whose binary values are Exchange/AD GUIDs
GUID_ATTRS = frozenset({"msexchmailboxguid", "msexcharchiveguid"})

# Attributes whose binary values are SIDs
SID_ATTRS = frozenset({"objectsid", "msexchmasteraccountsid"})

# Keywords used when scanning output files for service accounts
SERVICE_ACCOUNT_PATTERNS = ("svc", "service", "srvc", "svc_", "service_")

# Windows FILETIME epoch offset — 100-ns intervals between 1601-01-01 and 1970-01-01
_FILETIME_EPOCH_DIFF = 116_444_736_000_000_000

# Files produced by the enumeration that are scanned for service accounts
ENUMERATION_OUTPUT_FILES = (
    "Users.txt",
    "UsersDetailed.txt",
    "Groups.txt",
    "GroupsDetailed.txt",
    "Objects.txt",
    "ObjectsDetailedLdap.txt",
    "AllObjectDescriptions.txt",
    "KerberoastableAccounts.txt",
    "ASREPRoastableAccounts.txt",
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(filename=LOG_FILE, level=logging.INFO)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_IP_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")


def is_valid_ip(ip: str) -> bool:
    return bool(_IP_RE.match(ip))


# ---------------------------------------------------------------------------
# UAC decoding
# ---------------------------------------------------------------------------


def decode_uac(uac_value: int) -> str:
    """
    Decode a userAccountControl integer into a human-readable flag string.

    Returns the raw integer followed by the set flag names in parentheses,
    e.g. ``66048 (NORMAL_ACCOUNT | DONT_EXPIRE_PASSWORD)``.
    """
    flags = [name for bit, name in UAC_FLAGS.items() if uac_value & bit]
    flag_str = " | ".join(flags) if flags else "UNKNOWN"
    return f"{uac_value} ({flag_str})"


def uac_attack_summary(uac_value: int) -> list[str]:
    """Return a list of attack-relevant flag names set in uac_value."""
    return [name for bit, name in UAC_ATTACK_FLAGS.items() if uac_value & bit]


# ---------------------------------------------------------------------------
# Time conversion
# ---------------------------------------------------------------------------


def filetime_to_str(value: object) -> str:
    """
    Convert a Windows FILETIME to a readable UTC string.

    Accepts either a raw integer (100-ns intervals since 1601-01-01) or a
    datetime.datetime object, which ldap3 may return when schema info is
    available.  Returns "Never" for zero/None values.
    """
    if value is None:
        return "Never"
    if isinstance(value, datetime.datetime):
        return value.strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        ft = int(value)
        if ft == 0:
            return "Never"
        timestamp = (ft - _FILETIME_EPOCH_DIFF) / 10_000_000
        dt = datetime.datetime.utcfromtimestamp(timestamp)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return str(value)


# ---------------------------------------------------------------------------
# Binary-value conversion
# ---------------------------------------------------------------------------


def sid_to_str(sid: bytes) -> str:
    """Convert a binary SID to its canonical S-1-... string form."""
    try:
        if all(b == 0 for b in sid):
            return "<all zeros>"

        revision = sid[0]
        sub_authority_count = sid[1]
        identifier_authority = int.from_bytes(sid[2:8], byteorder="big")
        authority_str = (
            hex(identifier_authority)
            if identifier_authority >= 2**32
            else str(identifier_authority)
        )
        sub_authorities = "-".join(
            str(int.from_bytes(sid[8 + i * 4 : 12 + i * 4], byteorder="little"))
            for i in range(sub_authority_count)
        )
        return f"S-{revision}-{authority_str}-{sub_authorities}"
    except Exception as exc:
        return f"<error converting SID: 0x{sid.hex()} ({exc})>"


def convert_guid(binary_guid: bytes) -> str:
    """Convert a binary GUID to its standard xxxxxxxx-xxxx-... string form."""
    try:
        h = binary_guid.hex()
        return (
            f"{h[6:8]}{h[4:6]}{h[2:4]}{h[0:2]}-"
            f"{h[10:12]}{h[8:10]}-"
            f"{h[14:16]}{h[12:14]}-"
            f"{h[16:20]}-"
            f"{h[20:]}"
        )
    except Exception:
        return f"<invalid GUID format: {binary_guid.hex()}>"


def format_binary_value(attribute_name: str, value: bytes) -> str:
    """Return a human-readable string for a binary LDAP attribute value."""
    if not value or all(b == 0 for b in value):
        return "<all zeros>"

    name_lower = attribute_name.lower()

    if name_lower in SID_ATTRS or name_lower == "objectsid":
        return sid_to_str(value)
    if name_lower == "objectguid" or name_lower in GUID_ATTRS:
        return convert_guid(value)
    if name_lower in HEX_DISPLAY_ATTRS:
        return f"0x{value.hex()}"

    try:
        return value.decode("utf-8", errors="replace")
    except Exception:
        return f"<binary data length={len(value)}>"


def format_attribute_value(attribute_name: str, value: object) -> str:
    """
    Return a display string for any LDAP attribute value.

    Handles binary data, userAccountControl decoding, and falls back to
    str() for all other types.
    """
    if isinstance(value, bytes):
        return format_binary_value(attribute_name, value)
    if attribute_name.lower() == "useraccountcontrol":
        try:
            return decode_uac(int(value))
        except (ValueError, TypeError):
            pass
    return str(value)


# ---------------------------------------------------------------------------
# Network / domain helpers
# ---------------------------------------------------------------------------


def get_host_and_domain_info(dc_ip: str) -> tuple[Optional[str], Optional[str]]:
    """
    Resolve hostname and domain name for a DC IP via DNS.

    Returns:
        (hostname, domain_name) — either element may be None on failure.
    """
    try:
        fqdn = socket.gethostbyaddr(dc_ip)[0]
        parts = fqdn.split(".")
        return parts[0], ".".join(parts[1:])
    except Exception:
        return None, None


def construct_user_string(user: str, dc_ip: str) -> str:
    """
    Build an LDAP bind user string from a bare username and DC IP.

    Leaves the string unchanged if it already contains a domain separator.
    """
    if "\\" in user or "," in user:
        return user
    _, domain = get_host_and_domain_info(dc_ip)
    return f"{domain}\\{user}" if domain else user


# ---------------------------------------------------------------------------
# LDAP connection helpers
# ---------------------------------------------------------------------------


def attempt_connection(
    server: str, use_ssl: bool, user: str, password: str
) -> tuple[Optional[Server], Optional[Connection], bool]:
    """
    Try to open an LDAP(S) connection and verify at least one entry is readable.

    Returns:
        (Server, Connection, success_flag)
    """
    port = 636 if use_ssl else 389
    protocol = "ldaps" if use_ssl else "ldap"
    try:
        s = Server(server, port=port, use_ssl=use_ssl, get_info=ALL)
        if user and password:
            c = Connection(
                s,
                user=construct_user_string(user, server),
                password=password,
                authentication="SIMPLE",
                auto_bind=True,
            )
        else:
            c = Connection(s, auto_bind=True)

        if hasattr(s.info, "other") and "defaultNamingContext" in s.info.other:
            base_dn = s.info.other["defaultNamingContext"][0]
            c.search(base_dn, "(objectClass=*)", attributes=["cn"], size_limit=1)
            if c.entries:
                return s, c, True

        return s, c, False

    except LDAPException as exc:
        log.error("Error connecting to %s://%s:%d: %s", protocol, server, port, exc)
        return None, None, False


def check_anonymous_bind(server_ip: str) -> bool:
    """Return True when the server accepts an anonymous LDAP bind."""
    try:
        s = Server(server_ip, get_info=ALL)
        c = Connection(s, authentication=ANONYMOUS)
        return c.bind()
    except Exception:
        return False


def get_basic_server_info(dc_ip: str) -> None:
    """Print domain/server metadata available without authentication."""
    print("\n" + "-" * 60)
    print(" Server Information")
    print("-" * 60)
    print(f"  • IP Address  : {dc_ip}")

    try:
        s = Server(dc_ip, get_info=ALL)
        Connection(s).bind()

        if not hasattr(s.info, "other"):
            return

        info = s.info.other

        if "defaultNamingContext" in info:
            parts = [
                dc.replace("DC=", "")
                for dc in info["defaultNamingContext"][0].split(",")
                if dc.startswith("DC=")
            ]
            print(f"  • Domain Name : {'.'.join(parts)}")

        if "serverName" in info:
            hostname = info["serverName"][0].split(",")[0].replace("CN=", "")
            print(f"  • Server Name : {hostname}")
        elif "ldapServiceName" in info:
            hostname = (
                info["ldapServiceName"][0].split(":")[1].split("@")[0].replace("$", "")
            )
            print(f"  • Server Name : {hostname}")

        if "forestFunctionality" in info:
            print(f"  • Forest Level: {info['forestFunctionality'][0]}")
        if "domainFunctionality" in info:
            print(f"  • Domain Level: {info['domainFunctionality'][0]}")

    except Exception as exc:
        print("  • Could not retrieve server information")
        log.error("Error getting server info: %s", exc)

    print()


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def print_banner() -> None:
    print("\n" + "=" * 60)
    print(" " * 20 + "LDAP Information Retrieval")
    print(" " * 22 + "Domain Enumeration")
    print("=" * 60 + "\n")


def print_section_header(section: str) -> None:
    print("\n" + "-" * 60)
    print(f" {section}")
    print("-" * 60)


def _get_values_list(entry, attribute: str) -> list:
    """Return the values of an LDAP entry attribute as a plain list."""
    values = entry[attribute].values
    return list(values) if isinstance(values, (list, set)) else [values]


def _get_sam(entry) -> str:
    """Return sAMAccountName from an entry or a safe fallback."""
    if "sAMAccountName" in entry.entry_attributes:
        return str(entry["sAMAccountName"].value)
    return "<unknown>"


def _get_object_type(entry) -> str:
    """Return 'Computer' or 'User' based on objectClass."""
    if "objectClass" in entry.entry_attributes:
        classes = [c.lower() for c in _get_values_list(entry, "objectClass")]
        if "computer" in classes:
            return "Computer"
    return "User"


# ---------------------------------------------------------------------------
# File writers
# ---------------------------------------------------------------------------


def _write_entry_attributes(f, entry) -> None:
    """Write every attribute of a single LDAP entry to an open file handle."""
    f.write(f"DN: {entry.entry_dn}\n")
    for attribute in entry.entry_attributes:
        try:
            values = entry[attribute].values
            value_list = list(values) if isinstance(values, (list, set)) else [values]
            formatted = [format_attribute_value(attribute, v) for v in value_list]

            if len(formatted) == 1:
                f.write(f"{attribute}: {formatted[0]}\n")
            else:
                f.write(f"{attribute}:\n")
                for item in formatted:
                    f.write(f"  {item}\n")
        except Exception as exc:
            f.write(f"{attribute}: <error reading value: {exc}>\n")
    f.write("\n")


def write_entries_to_file(results, filename: str) -> None:
    """Write full attribute details for a collection of LDAP entries."""
    with open(filename, "w", encoding="utf-8", errors="replace") as f:
        for entry in results:
            try:
                _write_entry_attributes(f, entry)
            except Exception as exc:
                f.write(f"<error processing entry: {exc}>\n\n")
    print(f"[+] Results written to {filename}")


def write_detailed_results_to_file(results, filename: str) -> None:
    """
    Write full attribute details and append a hex-conversion summary.

    userAccountControl values are decoded inline via format_attribute_value.
    """
    hex_converted_attrs: set[str] = set()

    with open(filename, "w", encoding="utf-8", errors="replace") as f:
        for entry in results:
            try:
                f.write(f"DN: {entry.entry_dn}\n")
                for attribute in entry.entry_attributes:
                    try:
                        values = entry[attribute].values
                        value_list = (
                            list(values)
                            if isinstance(values, (list, set))
                            else [values]
                        )
                        formatted = []
                        for v in value_list:
                            text = format_attribute_value(attribute, v)
                            formatted.append(text)
                            if isinstance(v, bytes) and text.startswith("0x"):
                                hex_converted_attrs.add(attribute)

                        if len(formatted) == 1:
                            f.write(f"{attribute}: {formatted[0]}\n")
                        else:
                            f.write(f"{attribute}:\n")
                            for item in formatted:
                                f.write(f"  {item}\n")
                    except Exception as exc:
                        f.write(f"{attribute}: <error reading value: {exc}>\n")
                f.write("\n")
            except Exception as exc:
                f.write(f"<error processing entry: {exc}>\n\n")

        if hex_converted_attrs:
            f.write("\n=== CONVERSION SUMMARY ===\n")
            f.write("Attributes rendered as hexadecimal:\n")
            for attr in sorted(hex_converted_attrs):
                f.write(f"- {attr}\n")

    print(f"[+] Detailed results written to {filename}")


def write_basic_names_to_file(
    results, filename: str, name_attribute: str = "sAMAccountName"
) -> None:
    """Write a plain list of account/object names, one per line."""
    with open(filename, "w", encoding="utf-8", errors="replace") as f:
        for entry in results:
            try:
                if name_attribute in entry.entry_attributes:
                    name = entry[name_attribute].value
                    if name:
                        f.write(f"{name}\n")
            except Exception as exc:
                f.write(f"<error processing entry: {exc}>\n")
    print(f"[+] Basic names written to {filename}")


def write_all_descriptions_to_file(results_list, filename: str) -> None:
    """Extract description fields from all LDAP objects into one file."""
    with open(filename, "w", encoding="utf-8", errors="replace") as f:
        for results in results_list:
            for entry in results:
                try:
                    if "description" not in entry.entry_attributes:
                        continue

                    f.write(f"DN: {entry.entry_dn}\n")

                    name = next(
                        (
                            entry[attr].value
                            for attr in ("name", "sAMAccountName", "cn")
                            if attr in entry.entry_attributes
                        ),
                        None,
                    )
                    f.write(f"Name: {name if name else '<no name>'}\n")

                    if "objectClass" in entry.entry_attributes:
                        obj_classes = entry["objectClass"].values
                        if obj_classes:
                            f.write(f"Object Class: {list(obj_classes)[-1]}\n")

                    descriptions = entry["description"].values
                    desc_list = (
                        list(descriptions)
                        if isinstance(descriptions, (list, set))
                        else [descriptions]
                    )
                    if len(desc_list) == 1:
                        f.write(f"Description: {desc_list[0]}\n")
                    else:
                        f.write("Description:\n")
                        for desc in desc_list:
                            f.write(f"  {desc}\n")
                    f.write("\n")
                except Exception as exc:
                    f.write(
                        f"<error processing entry {entry.entry_dn}: {exc}>\n\n"
                    )
    print(f"[+] All descriptions written to {filename}")


# ---------------------------------------------------------------------------
# Service-account search
# ---------------------------------------------------------------------------


def find_service_accounts(output_file: str = "ServiceAccounts.txt") -> None:
    """Scan enumeration output files for likely service-account entries."""
    print_section_header("Searching for Service Accounts")

    found_entries: set[str] = set()
    total_matches = 0

    with open(output_file, "w", encoding="utf-8") as out:
        out.write("=== Potential Service Accounts Found ===\n\n")

        for filename in ENUMERATION_OUTPUT_FILES:
            try:
                with open(filename, "r", encoding="utf-8", errors="ignore") as f:
                    print(f"  Searching {filename}")
                    lines = f.readlines()

                file_had_match = False
                for line_num, line in enumerate(lines, start=1):
                    if not any(
                        p.lower() in line.lower() for p in SERVICE_ACCOUNT_PATTERNS
                    ):
                        continue

                    ctx_start = max(0, line_num - 3)
                    ctx_end = min(len(lines), line_num + 2)
                    entry = (
                        f"\n--- Found in {filename} around line {line_num} ---\n"
                        + "".join(lines[ctx_start:ctx_end])
                        + "\n"
                    )
                    if entry not in found_entries:
                        found_entries.add(entry)
                        total_matches += 1
                        file_had_match = True

                status = "Found matches" if file_had_match else "No matches"
                print(f"  {status} in {filename}")

            except FileNotFoundError:
                print(f"  Skipping {filename} (not found)")

        if found_entries:
            out.writelines(sorted(found_entries))
            out.write("\n=== End of Service Accounts Search ===\n")
            print(f"\n  Written to {output_file} ({total_matches} matches)\n")
        else:
            out.write("No service accounts found.\n")
            print("\n  No service accounts found\n")


# ---------------------------------------------------------------------------
# Attack-surface enumeration
# ---------------------------------------------------------------------------


def find_kerberoastable_accounts(conn: Connection, base_dn: str) -> None:
    """
    Find enabled user accounts with at least one SPN set (Kerberoastable).

    Computer accounts are excluded — their SPNs are expected and not
    directly usable for offline cracking without additional access.
    """
    print_section_header("Kerberoastable Accounts (SPN Enumeration)")

    search_filter = (
        "(&(objectCategory=person)(objectClass=user)"
        "(servicePrincipalName=*)"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_ACCOUNTDISABLE})))"
    )
    attrs = [
        "sAMAccountName",
        "servicePrincipalName",
        "userAccountControl",
        "pwdLastSet",
        "memberOf",
    ]
    conn.search(base_dn, search_filter, attributes=attrs)
    entries = conn.entries
    filename = "KerberoastableAccounts.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=== Kerberoastable Accounts ===\n")
        f.write(
            "Enabled users with SPNs set. Request tickets with GetUserSPNs.py,\n"
            "Rubeus kerberoast, or netexec, then crack offline.\n\n"
        )

        if not entries:
            f.write("None found.\n")
            print("  No Kerberoastable accounts found")
            return

        f.write(f"Found: {len(entries)} account(s)\n\n")
        print(f"  WARNING: Found {len(entries)} Kerberoastable account(s)")

        for entry in entries:
            sam = _get_sam(entry)
            f.write(f"Account     : {sam}\n")

            if "pwdLastSet" in entry.entry_attributes:
                f.write(
                    f"Pwd Last Set: {filetime_to_str(entry['pwdLastSet'].value)}\n"
                )

            if "userAccountControl" in entry.entry_attributes:
                uac = int(entry["userAccountControl"].value)
                attack_flags = uac_attack_summary(uac)
                if attack_flags:
                    f.write(f"UAC Flags   : {', '.join(attack_flags)}\n")

            if "servicePrincipalName" in entry.entry_attributes:
                spns = _get_values_list(entry, "servicePrincipalName")
                f.write(f"SPNs ({len(spns)}):\n")
                for spn in spns:
                    f.write(f"  {spn}\n")

            if "memberOf" in entry.entry_attributes:
                groups = _get_values_list(entry, "memberOf")
                if groups:
                    f.write(f"Member Of ({len(groups)}):\n")
                    for g in groups:
                        f.write(f"  {g}\n")

            f.write("-" * 50 + "\n")

    print(f"  Results written to {filename}")


def find_asreproastable_accounts(conn: Connection, base_dn: str) -> None:
    """
    Find user accounts with DONT_REQ_PREAUTH set (ASREPRoastable).

    These accounts can be targeted without any credentials — an AS-REQ can
    be sent without pre-authentication and the AS-REP ticket cracked offline.
    """
    print_section_header("ASREPRoastable Accounts")

    search_filter = (
        f"(&(objectCategory=person)(objectClass=user)"
        f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_DONT_REQ_PREAUTH}))"
    )
    attrs = ["sAMAccountName", "userAccountControl", "pwdLastSet", "memberOf"]
    conn.search(base_dn, search_filter, attributes=attrs)
    entries = conn.entries
    filename = "ASREPRoastableAccounts.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=== ASREPRoastable Accounts ===\n")
        f.write(
            "DONT_REQ_PREAUTH is set — AS-REP Roasting is possible with no credentials.\n"
            "Exploit with GetNPUsers.py, Rubeus asreproast, or netexec.\n\n"
        )

        if not entries:
            f.write("None found.\n")
            print("  No ASREPRoastable accounts found")
            return

        f.write(f"Found: {len(entries)} account(s)\n\n")
        print(f"  WARNING: Found {len(entries)} ASREPRoastable account(s)")

        for entry in entries:
            sam = _get_sam(entry)
            f.write(f"Account     : {sam}\n")

            if "pwdLastSet" in entry.entry_attributes:
                f.write(
                    f"Pwd Last Set: {filetime_to_str(entry['pwdLastSet'].value)}\n"
                )

            if "userAccountControl" in entry.entry_attributes:
                uac = int(entry["userAccountControl"].value)
                f.write(f"UAC         : {decode_uac(uac)}\n")
                # Flag any additional security-relevant UAC settings
                extra_flags = [
                    name
                    for bit, name in UAC_ATTACK_FLAGS.items()
                    if uac & bit and bit != UAC_DONT_REQ_PREAUTH
                ]
                if extra_flags:
                    f.write(f"Also Set    : {', '.join(extra_flags)}\n")

            if "memberOf" in entry.entry_attributes:
                groups = _get_values_list(entry, "memberOf")
                if groups:
                    f.write(f"Member Of ({len(groups)}):\n")
                    for g in groups:
                        f.write(f"  {g}\n")

            f.write("-" * 50 + "\n")

    print(f"  Results written to {filename}")


def find_delegation_issues(conn: Connection, base_dn: str) -> None:
    """
    Find accounts and computers with dangerous delegation configurations.

    Covers three delegation types:
    - Unconstrained  -- any service, any user; TGTs cached on the host
    - Constrained    -- specific services only; optionally any protocol
    - RBCD           -- target-controlled; msDS-AllowedToActOnBehalfOfOtherIdentity
    """
    print_section_header("Delegation Issues")
    filename = "DelegationIssues.txt"

    with open(filename, "w", encoding="utf-8") as f:
        f.write("=== Delegation Issues ===\n\n")
        _find_unconstrained_delegation(conn, base_dn, f)
        _find_constrained_delegation(conn, base_dn, f)
        _find_rbcd(conn, base_dn, f)

    print(f"  Results written to {filename}")


def _find_unconstrained_delegation(conn: Connection, base_dn: str, f) -> None:
    """
    Find non-DC objects with TRUSTED_FOR_DELEGATION set.

    Domain Controllers always carry this flag and are excluded — they are
    not an anomaly worth flagging separately here.
    """
    search_filter = (
        f"(&(|(objectClass=user)(objectClass=computer))"
        f"(userAccountControl:1.2.840.113556.1.4.803:={UAC_TRUSTED_FOR_DELEGATION})"
        f"(!(userAccountControl:1.2.840.113556.1.4.803:={UAC_SERVER_TRUST_ACCOUNT})))"
    )
    attrs = ["sAMAccountName", "userAccountControl", "objectClass", "pwdLastSet"]
    conn.search(base_dn, search_filter, attributes=attrs)
    entries = conn.entries

    f.write("--- Unconstrained Delegation ---\n")
    f.write(
        "Any user authenticating to these hosts will have their TGT cached.\n"
        "Compromising the host gives access to all cached tickets.\n\n"
    )

    if not entries:
        f.write("None found.\n\n")
        print("  No unconstrained delegation found")
        return

    f.write(f"Found: {len(entries)} target(s)\n\n")
    print(f"  WARNING: Found {len(entries)} unconstrained delegation target(s)")

    for entry in entries:
        f.write(f"  Account : {_get_sam(entry)}\n")
        f.write(f"  Type    : {_get_object_type(entry)}\n")
        if "pwdLastSet" in entry.entry_attributes:
            f.write(f"  Pwd Set : {filetime_to_str(entry['pwdLastSet'].value)}\n")
        f.write("\n")


def _find_constrained_delegation(conn: Connection, base_dn: str, f) -> None:
    """
    Find accounts/computers with msDS-AllowedToDelegateTo populated.

    Also notes whether protocol transition (S4U2Self) is enabled, which
    allows the account to obtain a service ticket for any user regardless
    of whether they authenticated via Kerberos.
    """
    search_filter = (
        "(&(|(objectClass=user)(objectClass=computer))"
        "(msDS-AllowedToDelegateTo=*))"
    )
    attrs = [
        "sAMAccountName",
        "msDS-AllowedToDelegateTo",
        "userAccountControl",
        "objectClass",
        "pwdLastSet",
    ]
    conn.search(base_dn, search_filter, attributes=attrs)
    entries = conn.entries

    f.write("--- Constrained Delegation ---\n")
    f.write(
        "Accounts permitted to impersonate users to specific services.\n"
        "'Protocol Transition: Yes' means TRUSTED_TO_AUTH_FOR_DELEGATION is set,\n"
        "enabling S4U2Self -- the account can impersonate any user without their password.\n\n"
    )

    if not entries:
        f.write("None found.\n\n")
        print("  No constrained delegation found")
        return

    f.write(f"Found: {len(entries)} target(s)\n\n")
    print(f"  WARNING: Found {len(entries)} constrained delegation target(s)")

    for entry in entries:
        protocol_transition = False
        if "userAccountControl" in entry.entry_attributes:
            uac = int(entry["userAccountControl"].value)
            protocol_transition = bool(uac & UAC_TRUSTED_TO_AUTH_FOR_DELEG)

        f.write(f"  Account            : {_get_sam(entry)}\n")
        f.write(f"  Type               : {_get_object_type(entry)}\n")
        f.write(
            f"  Protocol Transition: "
            f"{'Yes -- S4U2Self enabled (any protocol)' if protocol_transition else 'No -- Kerberos only'}\n"
        )

        if "pwdLastSet" in entry.entry_attributes:
            f.write(f"  Pwd Set            : {filetime_to_str(entry['pwdLastSet'].value)}\n")

        if "msDS-AllowedToDelegateTo" in entry.entry_attributes:
            targets = _get_values_list(entry, "msDS-AllowedToDelegateTo")
            f.write(f"  Delegate Targets ({len(targets)}):\n")
            for t in targets:
                f.write(f"    {t}\n")

        f.write("\n")


def _find_rbcd(conn: Connection, base_dn: str, f) -> None:
    """
    Find objects with msDS-AllowedToActOnBehalfOfOtherIdentity set (RBCD).

    The attribute value is a binary security descriptor — parsing the full
    DACL to extract the permitted principals requires impacket or BloodyAD.
    This function records presence and directs the analyst to those tools.
    """
    search_filter = "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)"
    attrs = ["sAMAccountName", "objectClass", "msDS-AllowedToActOnBehalfOfOtherIdentity"]
    conn.search(base_dn, search_filter, attributes=attrs)
    entries = conn.entries

    f.write("--- Resource-Based Constrained Delegation (RBCD) ---\n")
    f.write(
        "These objects allow other principals to act on their behalf.\n"
        "Decode msDS-AllowedToActOnBehalfOfOtherIdentity with impacket or BloodyAD\n"
        "to identify which accounts are granted delegation rights.\n\n"
    )

    if not entries:
        f.write("None found.\n\n")
        print("  No RBCD configurations found")
        return

    f.write(f"Found: {len(entries)} target(s)\n\n")
    print(f"  WARNING: Found {len(entries)} RBCD configuration(s)")

    for entry in entries:
        f.write(f"  Account : {_get_sam(entry)}\n")
        f.write(f"  Type    : {_get_object_type(entry)}\n")
        f.write(
            "  Note    : Binary security descriptor present --\n"
            "            use impacket/BloodyAD to decode permitted principals\n"
        )
        f.write("\n")


# ---------------------------------------------------------------------------
# Main enumeration
# ---------------------------------------------------------------------------


def process_ldap_results(conn: Connection, base_dn: str, server_ip: str) -> None:
    """Run all LDAP queries and write output files."""
    print_banner()

    hostname, domain_name = get_host_and_domain_info(server_ip)
    print_section_header("Target Information")
    print(f"  • IP Address  : {server_ip}")
    if hostname:
        print(f"  • Hostname    : {hostname}")
    if domain_name:
        print(f"  • Domain Name : {domain_name}")
    print()

    # --- Standard object enumeration ---

    print_section_header("Processing Users")
    conn.search(base_dn, "(objectClass=user)", attributes=["*"])
    users = conn.entries
    write_detailed_results_to_file(users, "UsersDetailed.txt")
    write_basic_names_to_file(users, "Users.txt")
    print("  Users.txt / UsersDetailed.txt")

    print_section_header("Processing Groups")
    conn.search(base_dn, "(objectClass=group)", attributes=["*"])
    groups = conn.entries
    write_entries_to_file(groups, "GroupsDetailed.txt")
    write_basic_names_to_file(groups, "Groups.txt")
    print("  Groups.txt / GroupsDetailed.txt")

    print_section_header("Processing Computers")
    conn.search(base_dn, "(objectClass=computer)", attributes=["*"])
    computers = conn.entries
    write_entries_to_file(computers, "ComputersDetailed.txt")
    write_basic_names_to_file(computers, "Computers.txt")
    print("  Computers.txt / ComputersDetailed.txt")

    print_section_header("Processing All Objects")
    conn.search(base_dn, "(objectClass=*)", attributes=["*"])
    all_objects = conn.entries
    write_detailed_results_to_file(all_objects, "ObjectsDetailedLdap.txt")
    write_basic_names_to_file(all_objects, "Objects.txt")
    print("  Objects.txt / ObjectsDetailedLdap.txt")

    print_section_header("Processing Descriptions")
    write_all_descriptions_to_file(
        [users, groups, computers], "AllObjectDescriptions.txt"
    )
    print("  AllObjectDescriptions.txt")

    # --- Attack-surface enumeration ---

    find_kerberoastable_accounts(conn, base_dn)
    find_asreproastable_accounts(conn, base_dn)
    find_delegation_issues(conn, base_dn)
    find_service_accounts()

    # --- Security check ---

    print_section_header("Security Check")
    if check_anonymous_bind(server_ip):
        print("  WARNING: Anonymous Bind is ENABLED")
        print("  This is a security risk and should be disabled\n")
    else:
        print("  Anonymous Bind is DISABLED (recommended)\n")

    print("=" * 60)
    print(" " * 20 + "Enumeration Complete!")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LDAP Active Directory Enumeration")
    parser.add_argument("dc_ip", help="IP address of the Domain Controller")
    parser.add_argument("-u", "--user", help="Username for authentication", default="")
    parser.add_argument(
        "-p", "--password", help="Password for authentication", default=""
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if not is_valid_ip(args.dc_ip):
        print("Invalid IP address format.")
        log.error("Invalid IP address format: %s", args.dc_ip)
        sys.exit(1)

    user = args.user
    password = args.password
    if user and not password:
        password = getpass.getpass("Enter password: ")

    get_basic_server_info(args.dc_ip)

    anon_enabled = check_anonymous_bind(args.dc_ip)

    if not user and not anon_enabled:
        print("-" * 60)
        print(" Access Denied")
        print("-" * 60)
        print("  Anonymous Bind is DISABLED (Secure Configuration)")
        print("  No credentials provided")
        print("  Use: -u USERNAME -p PASSWORD\n")
        sys.exit(1)

    print("-" * 60)
    print(" Connection Attempts")
    print("-" * 60)

    for use_ssl in (True, False):
        protocol = "SSL" if use_ssl else "non-SSL"
        print(f"  Attempting {protocol} connection...")
        log.info("Attempting to connect to %s with %s", args.dc_ip, protocol)

        s, c, success = attempt_connection(args.dc_ip, use_ssl, user, password)

        if success:
            bind_type = "authenticated" if user else "anonymous"
            print(f"  Connected successfully using {bind_type} bind")
            log.info("Connected successfully using %s bind", bind_type)

            base_dn = s.info.other["defaultNamingContext"][0]

            if not user:
                print("\n" + "-" * 60)
                print(" Security Warning")
                print("-" * 60)
                print("  WARNING: Connected using Anonymous Bind")
                print("  This is a security risk and should be disabled\n")

            process_ldap_results(c, base_dn, args.dc_ip)
            return

        if c is not None:
            print("  Connection established but no read access")
            log.warning("Connected but no read access")
        else:
            print(f"  Failed to connect with {protocol}")
            log.warning("Failed to connect with %s", protocol)

    print()
    print("-" * 60)
    print(" Connection Failed")
    print("-" * 60)
    print("  Could not establish LDAP connection")
    print("  • Anonymous bind may be disabled (good security practice)")
    print("  • Credentials may be incorrect")
    print("  • Server may be unreachable")
    print("  • LDAP/LDAPS ports may be filtered\n")
    log.error("All connection attempts failed")
    sys.exit(1)


if __name__ == "__main__":
    main()
