#!/usr/bin/env python3
"""
MAS: Mac Archive Scanner
macOS security analyser for DMG, PKG, and APP bundles.
by thisislola
"""

import argparse
import hashlib
import json
import csv
import io
import plistlib
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional
from urllib.parse import unquote


class Colours:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

    @classmethod
    def disable(cls):
        cls.GREEN = cls.RED = cls.YELLOW = cls.CYAN = cls.BOLD = cls.RESET = ''


class SecurityAnalyser:
    SUPPORTED_EXTENSIONS = {'.dmg', '.pkg', '.app'}

    def __init__(self, verbose: bool = False, show_entitlements: bool = False, no_colour: bool = False):
        self.verbose = verbose
        self.show_entitlements = show_entitlements

        if no_colour or not sys.stdout.isatty():
            Colours.disable()

    def analyse_file(self, filepath: Path) -> Dict:
        if not filepath.exists():
            return {'error': f"File not found: {filepath}"}

        if not self._is_supported(filepath):
            return {
                'error': f"Unsupported file type: {filepath.suffix or 'no extension'}. Only .dmg, .pkg, and .app are supported."
            }

        if filepath.suffix == '.app' and filepath.is_dir():
            return self._analyse_bundle(filepath)

        if not filepath.is_file():
            return {'error': f"Not a file: {filepath}"}

        return self._analyse_installer(filepath)

    def _is_supported(self, filepath: Path) -> bool:
        return filepath.suffix.lower() in self.SUPPORTED_EXTENSIONS

    def _analyse_installer(self, filepath: Path) -> Dict:
        result = {
            'path': str(filepath),
            'name': filepath.name,
            'type': filepath.suffix[1:].upper(),
        }

        stat = filepath.stat()
        result['size'] = stat.st_size
        result['size_human'] = self._human_size(stat.st_size)

        if self.verbose:
            result['created'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
            result['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
            result['hashes'] = self._calculate_hashes(filepath)

        result['security'] = self._get_security_info(filepath)

        return result

    def _analyse_bundle(self, bundle_path: Path) -> Dict:
        result = {
            'path': str(bundle_path),
            'name': bundle_path.name,
            'type': 'APP',
            'bundle': {}
        }

        info_plist = bundle_path / 'Contents' / 'Info.plist'
        if info_plist.exists():
            try:
                with open(info_plist, 'rb') as f:
                    plist = plistlib.load(f)
                    result['bundle']['identifier'] = plist.get('CFBundleIdentifier')
                    result['bundle']['name'] = plist.get('CFBundleName') or plist.get('CFBundleDisplayName')
                    result['bundle']['version'] = plist.get('CFBundleShortVersionString')
                    result['bundle']['build'] = plist.get('CFBundleVersion')
                    result['bundle']['min_os'] = plist.get('LSMinimumSystemVersion')
                    result['bundle']['executable'] = plist.get('CFBundleExecutable')
                    result['bundle']['category'] = plist.get('LSApplicationCategoryType')
            except Exception as e:
                result['bundle']['error'] = str(e)

        # Get security info - try bundle first (preferred), then executable
        # Most modern apps are signed at the bundle level
        result['security'] = self._get_security_info(bundle_path)

        # If no security info from bundle, try the executable
        if not result['security'].get('codesign', {}).get('signed'):
            executable_name = result['bundle'].get('executable')
            if executable_name:
                executable_path = bundle_path / 'Contents' / 'MacOS' / executable_name
                if executable_path.exists():
                    result['executable_path'] = str(executable_path)
                    result['security'] = self._get_security_info(executable_path)

                    if self.verbose:
                        stat = executable_path.stat()
                        result['created'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
                        result['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
                        result['hashes'] = self._calculate_hashes(executable_path)

        return result

    def _get_security_info(self, filepath: Path) -> Dict:
        info = {}

        mdls_data = self._run_cmd(['mdls', '-name', 'kMDItemContentType', '-name', 'kMDItemKind', str(filepath)])
        if mdls_data:
            info['content_type'] = self._parse_mdls(mdls_data, 'kMDItemContentType')
            info['kind'] = self._parse_mdls(mdls_data, 'kMDItemKind')

        info['xattrs'] = self._get_xattrs(filepath)
        info['codesign'] = self._check_codesign(filepath)
        info['notarisation'] = self._check_notarisation(filepath)
        info['gatekeeper'] = self._check_gatekeeper(filepath)

        # Only get entitlements when requested
        if self.show_entitlements:
            entitlements = self._get_entitlements(filepath)
            if entitlements:
                # Check for sandbox entitlement - can be True, 1, or '1'
                sandbox_value = entitlements.get('com.apple.security.app-sandbox', False)
                info['sandboxed'] = bool(sandbox_value) if sandbox_value is not None else False
                info['entitlements'] = entitlements
            else:
                info['sandboxed'] = False

        return info

    def _get_xattrs(self, filepath: Path) -> Dict:
        xattrs = {'list': []}

        output = self._run_cmd(['xattr', '-l', str(filepath)])
        if not output:
            return xattrs

        lines = output.strip().split('\n')
        for line in lines:
            if ':' in line:
                key = line.split(':')[0].strip()
                xattrs['list'].append(key)

                if key == 'com.apple.quarantine':
                    quar_output = self._run_cmd(['xattr', '-p', 'com.apple.quarantine', str(filepath)])
                    if quar_output:
                        xattrs['quarantine'] = self._parse_quarantine(quar_output)

        return xattrs

    def _parse_quarantine(self, quar_data: str) -> Dict:
        # Format: flags|agent|timestamp|bundle_id or url
        parts = quar_data.strip().split(';')

        quarantine = {}
        if len(parts) >= 1:
            quarantine['flags'] = parts[0]
        if len(parts) >= 2:
            quarantine['agent'] = parts[1]
        if len(parts) >= 3 and parts[2]:
            try:
                # Mac timestamp is hex seconds since 2001-01-01
                timestamp = int(parts[2], 16)
                # Convert to Unix timestamp (seconds since 1970-01-01)
                mac_epoch = datetime(2001, 1, 1)
                download_time = mac_epoch.timestamp() + timestamp
                # Format as UTC
                quarantine['downloaded_iso'] = datetime.utcfromtimestamp(download_time).strftime('%Y-%m-%d %H:%M:%S UTC')
            except (ValueError, OverflowError, OSError):
                pass
        if len(parts) >= 4 and parts[3]:
            # Clean up the source - remove extra spaces and decode URL encoding
            source = parts[3].strip()
            # If it's a URL, decode it
            if source:
                try:
                    source = unquote(source)
                except (ValueError, UnicodeDecodeError):
                    pass
                quarantine['source'] = source

        return quarantine

    def _check_codesign(self, filepath: Path) -> Dict:
        output = self._run_cmd(['codesign', '-dv', '--verbose=4', str(filepath)], stderr=True)

        info = {'signed': bool(output)}
        if not output:
            return info

        info['authorities'] = []
        for line in output.split('\n'):
            if 'Authority=' in line:
                info['authorities'].append(line.split('Authority=')[1].strip())
            elif 'Identifier=' in line:
                info['identifier'] = line.split('=')[1].strip()
            elif 'TeamIdentifier=' in line:
                info['team_id'] = line.split('=')[1].strip()

        # First authority is typically the developer/signing certificate
        if info['authorities']:
            info['signed_by'] = info['authorities'][0]

        return info

    def _check_notarisation(self, filepath: Path) -> Dict:
        # Check stapled ticket first
        stapler_output = self._run_cmd(['stapler', 'validate', str(filepath)], stderr=True)
        stapled = stapler_output and 'validated' in stapler_output.lower()

        # Check codesign for notarisation info (more reliable)
        codesign_output = self._run_cmd(['codesign', '-dvvv', str(filepath)], stderr=True)

        notarised = False
        details = []

        if stapled:
            notarised = True
            details.append('Stapled ticket validated')

        if codesign_output:
            # Check for notarisation in codesign output
            for line in codesign_output.split('\n'):
                if 'runtime' in line.lower() or 'notarized' in line.lower():
                    if 'runtime' in line.lower():
                        notarised = True
                        details.append('Hardened Runtime enabled')

        # Also check spctl output which may show notarisation
        spctl_output = self._run_cmd(['spctl', '--assess', '--verbose', str(filepath)], stderr=True)
        if spctl_output and 'notarized' in spctl_output.lower():
            notarised = True
            details.append('Notarisation verified by spctl')

        return {
            'notarised': notarised,
            'details': '; '.join(details) if details else ('Not notarised' if not notarised else None)
        }

    def _check_gatekeeper(self, filepath: Path) -> Dict:
        output = self._run_cmd(['spctl', '--assess', '--type', 'execute', '--verbose', str(filepath)], stderr=True)

        if not output:
            return {'accepted': False}

        accepted = 'accepted' in output.lower()
        return {'accepted': accepted, 'details': output.strip()}

    def _get_entitlements(self, filepath: Path) -> Dict:
        # For --entitlements :-, the XML goes to stdout, not stderr
        try:
            result = subprocess.run(
                ['codesign', '-d', '--entitlements', ':-', str(filepath)],
                capture_output=True,
                text=True,
                timeout=10
            )

            # Try stdout first (where entitlements should be)
            output = result.stdout

            # If stdout is empty, the file might not have entitlements
            if not output or '<?xml' not in output:
                # Check if the command itself failed
                if result.returncode != 0:
                    return {}
                # No entitlements found (not an error, just no entitlements)
                return {}

            xml_start = output.index('<?xml')
            xml_data = output[xml_start:].encode('utf-8')
            entitlements = plistlib.loads(xml_data)

            # Ensure we return a dict, plistlib sometimes returns other types
            if isinstance(entitlements, dict):
                return entitlements
            else:
                return {}

        except (ValueError, plistlib.InvalidFileException, UnicodeDecodeError, subprocess.TimeoutExpired, OSError):
            return {}

    def _calculate_hashes(self, filepath: Path) -> Dict:
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        try:
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5.update(chunk)
                    sha256.update(chunk)
            return {'md5': md5.hexdigest(), 'sha256': sha256.hexdigest()}
        except (OSError, IOError):
            return {}

    def _human_size(self, size: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} PB"

    def _run_cmd(self, cmd: list, stderr: bool = False) -> Optional[str]:
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if stderr and result.stderr:
                return result.stderr
            if result.returncode == 0:
                return result.stdout
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            pass
        return None

    def _parse_mdls(self, output: str, key: str) -> Optional[str]:
        for line in output.split('\n'):
            if key in line and '=' in line:
                value = line.split('=', 1)[1].strip().strip('"')
                return value if value != '(null)' else None
        return None


class OutputFormatter:
    @staticmethod
    def format_text(result: Dict, verbose: bool) -> str:
        if 'error' in result:
            return f"{Colours.RED}ERROR: {result['error']}{Colours.RESET}"

        lines = []
        lines.append("=" * 70)
        lines.append(f"{Colours.BOLD}File: {result['name']}{Colours.RESET}")
        lines.append(f"Path: {result['path']}")
        lines.append(f"Type: {result['type']}")
        lines.append("=" * 70)

        if result.get('type') == 'APP':
            bundle = result.get('bundle', {})
            if bundle:
                lines.append(f"\n{Colours.CYAN}[BUNDLE INFO]{Colours.RESET}")
                if 'name' in bundle and bundle['name']:
                    lines.append(f"  Name:       {bundle['name']}")
                if 'identifier' in bundle:
                    lines.append(f"  Identifier: {bundle['identifier']}")
                if 'version' in bundle:
                    lines.append(f"  Version:    {bundle['version']} (build {bundle.get('build', 'N/A')})")
                if 'min_os' in bundle:
                    lines.append(f"  Min macOS:  {bundle['min_os']}")
                if 'category' in bundle and bundle['category']:
                    lines.append(f"  Category:   {bundle['category']}")

        if 'size' in result:
            lines.append(f"\n{Colours.CYAN}[FILE INFO]{Colours.RESET}")
            lines.append(f"  Size: {result['size_human']} ({result['size']:,} bytes)")

        if verbose and 'created' in result:
            lines.append(f"\n{Colours.CYAN}[TIMESTAMPS]{Colours.RESET}")
            lines.append(f"  Created:  {result['created']}")
            lines.append(f"  Modified: {result['modified']}")

        if verbose and 'hashes' in result and result['hashes']:
            lines.append(f"\n{Colours.CYAN}[HASHES]{Colours.RESET}")
            lines.append(f"  MD5:    {result['hashes']['md5']}")
            lines.append(f"  SHA256: {result['hashes']['sha256']}")

        security = result.get('security', {})
        if security:
            xattrs = security.get('xattrs', {})
            if xattrs.get('list'):
                lines.append(f"\n{Colours.CYAN}[EXTENDED ATTRIBUTES]{Colours.RESET}")
                for attr in xattrs['list']:
                    if attr == 'com.apple.quarantine':
                        lines.append(f"  {Colours.YELLOW}{attr}{Colours.RESET}")
                    else:
                        lines.append(f"  {attr}")

                if 'quarantine' in xattrs:
                    q = xattrs['quarantine']
                    lines.append(f"\n{Colours.YELLOW}[QUARANTINE]{Colours.RESET}")
                    if 'agent' in q:
                        lines.append(f"  Downloaded by: {q['agent']}")
                    if 'downloaded_iso' in q:
                        lines.append(f"  Download time: {q['downloaded_iso']}")
                    if 'source' in q:
                        lines.append(f"  Source:        {q['source']}")

            codesign = security.get('codesign', {})
            if codesign:
                lines.append(f"\n{Colours.CYAN}[CODE SIGNATURE]{Colours.RESET}")
                if codesign.get('signed'):
                    lines.append(f"  Status:     {Colours.GREEN}✓ SIGNED{Colours.RESET}")
                    if 'signed_by' in codesign:
                        lines.append(f"  Signed by:  {codesign['signed_by']}")
                    if 'team_id' in codesign:
                        lines.append(f"  Team ID:    {codesign['team_id']}")
                    if 'identifier' in codesign:
                        lines.append(f"  Identifier: {codesign['identifier']}")
                    if codesign.get('authorities') and len(codesign['authorities']) > 1:
                        lines.append(f"  Certificate chain:")
                        for auth in codesign['authorities']:
                            lines.append(f"    - {auth}")
                else:
                    lines.append(f"  Status: {Colours.RED}✗ NOT SIGNED{Colours.RESET}")

            notarisation = security.get('notarisation', {})
            if notarisation:
                lines.append(f"\n{Colours.CYAN}[NOTARISATION]{Colours.RESET}")
                if notarisation.get('notarised'):
                    lines.append(f"  Status: {Colours.GREEN}✓ NOTARISED{Colours.RESET}")
                    if notarisation.get('details'):
                        lines.append(f"  Details: {notarisation['details']}")
                else:
                    lines.append(f"  Status: {Colours.YELLOW}✗ NOT NOTARISED{Colours.RESET}")
                    if notarisation.get('details'):
                        lines.append(f"  Details: {notarisation['details']}")

            gatekeeper = security.get('gatekeeper', {})
            if gatekeeper:
                lines.append(f"\n{Colours.CYAN}[GATEKEEPER]{Colours.RESET}")
                if gatekeeper.get('accepted'):
                    lines.append(f"  Status: {Colours.GREEN}✓ ACCEPTED{Colours.RESET}")
                else:
                    lines.append(f"  Status: {Colours.RED}✗ REJECTED{Colours.RESET}")
                if gatekeeper.get('details'):
                    lines.append(f"  Details: {gatekeeper['details']}")

            # Show sandbox status
            if 'sandboxed' in security:
                lines.append(f"\n{Colours.CYAN}[APP SANDBOX]{Colours.RESET}")
                if security['sandboxed']:
                    lines.append(f"  Status: {Colours.GREEN}✓ SANDBOXED{Colours.RESET}")
                else:
                    lines.append(f"  Status: {Colours.YELLOW}✗ NOT SANDBOXED{Colours.RESET}")

            entitlements = security.get('entitlements', {})
            if entitlements:
                lines.append(f"\n{Colours.CYAN}[ENTITLEMENTS]{Colours.RESET}")
                for key, value in entitlements.items():
                    lines.append(f"  {key}: {value}")

        lines.append("=" * 70)
        return '\n'.join(lines)

    @staticmethod
    def format_json(results: list) -> str:
        return json.dumps(results, indent=2, default=str)

    @staticmethod
    def format_csv(results: list) -> str:
        if not results:
            return ""

        output = io.StringIO()

        flat_results = []
        for r in results:
            if 'error' in r:
                flat_results.append({'path': r.get('path', ''), 'error': r['error']})
                continue

            flat = {
                'path': r['path'],
                'name': r['name'],
                'type': r['type'],
                'size': r.get('size', ''),
            }

            security = r.get('security', {})
            codesign = security.get('codesign', {})
            flat['signed'] = codesign.get('signed', '')
            flat['notarised'] = security.get('notarisation', {}).get('notarised', '')
            flat['gatekeeper'] = security.get('gatekeeper', {}).get('accepted', '')

            # Only include sandboxed if entitlements were checked
            if 'sandboxed' in security:
                flat['sandboxed'] = security.get('sandboxed', '')

            xattrs = security.get('xattrs', {})
            flat['has_quarantine'] = 'com.apple.quarantine' in xattrs.get('list', [])

            if r.get('type') == 'APP':
                bundle = r.get('bundle', {})
                flat['bundle_id'] = bundle.get('identifier', '')
                flat['version'] = bundle.get('version', '')

            if 'hashes' in r and r['hashes']:
                flat['sha256'] = r['hashes'].get('sha256', '')

            flat_results.append(flat)

        if flat_results:
            # Collect all unique field names across all results
            all_fields = []
            seen = set()
            for result in flat_results:
                for key in result.keys():
                    if key not in seen:
                        all_fields.append(key)
                        seen.add(key)

            writer = csv.DictWriter(output, fieldnames=all_fields)
            writer.writeheader()
            writer.writerows(flat_results)

        return output.getvalue()

    @staticmethod
    def format_html(results: list) -> str:
        # Check if any result has sandboxed info (entitlements were checked)
        has_sandbox = any('sandboxed' in r.get('security', {}) for r in results if 'error' not in r)

        html = ['<!DOCTYPE html>', '<html>', '<head>',
                '<meta charset="UTF-8">',
                '<title>MAS: Mac Archive Scanner</title>',
                '<style>',
                'body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 20px; background: #f5f5f5; }',
                'h1 { color: #333; }',
                '.container { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }',
                'table { border-collapse: collapse; width: 100%; margin: 20px 0; }',
                'th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }',
                'th { background-color: #007AFF; color: white; font-weight: 600; }',
                'tr:nth-child(even) { background-color: #f9f9f9; }',
                '.signed { color: #34C759; font-weight: bold; }',
                '.unsigned { color: #FF3B30; font-weight: bold; }',
                '.warning { color: #FF9500; font-weight: bold; }',
                '</style>',
                '</head>', '<body>', '<div class="container">',
                '<h1>🔐 MAS: Mac Archive Scanner</h1>',
                f'<p><strong>Generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>',
                '<table>']

        # Build header based on whether sandboxed info is available
        header = '<tr><th>File</th><th>Type</th><th>Size</th><th>Signed</th><th>Notarised</th><th>Gatekeeper</th>'
        if has_sandbox:
            header += '<th>Sandboxed</th>'
        header += '</tr>'
        html.append(header)

        colspan = 7 if has_sandbox else 6

        for r in results:
            if 'error' in r:
                html.append(f'<tr><td colspan="{colspan}" class="unsigned">{r.get("name", "Unknown")}: {r["error"]}</td></tr>')
                continue

            security = r.get('security', {})
            codesign = security.get('codesign', {})
            signed = '✓' if codesign.get('signed') else '✗'
            signed_class = 'signed' if codesign.get('signed') else 'unsigned'

            notarised = '✓' if security.get('notarisation', {}).get('notarised') else '✗'
            notarised_class = 'signed' if security.get('notarisation', {}).get('notarised') else 'warning'

            gatekeeper = '✓' if security.get('gatekeeper', {}).get('accepted') else '✗'
            gatekeeper_class = 'signed' if security.get('gatekeeper', {}).get('accepted') else 'unsigned'

            html.append(f'<tr>')
            html.append(f'<td><strong>{r["name"]}</strong></td>')
            html.append(f'<td>{r["type"]}</td>')
            html.append(f'<td>{r.get("size_human", "N/A")}</td>')
            html.append(f'<td class="{signed_class}">{signed}</td>')
            html.append(f'<td class="{notarised_class}">{notarised}</td>')
            html.append(f'<td class="{gatekeeper_class}">{gatekeeper}</td>')

            # Only add sandboxed column if it was checked
            if has_sandbox:
                sandboxed = '✓' if security.get('sandboxed') else '✗'
                sandboxed_class = 'signed' if security.get('sandboxed') else 'warning'
                html.append(f'<td class="{sandboxed_class}">{sandboxed}</td>')

            html.append(f'</tr>')

        html.extend(['</table>', '</div>', '</body>', '</html>'])
        return '\n'.join(html)


def main():
    parser = argparse.ArgumentParser(
        description='MAS: Mac Archive Scanner for DMG, PKG, and APP files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s suspicious.dmg                     # Analyse DMG
  %(prog)s -v installer.pkg                   # Verbose analysis of PKG
  %(prog)s /Applications/App.app              # Analyse APP bundle
  %(prog)s --entitlements App.app             # Show app permissions
  %(prog)s --format json file.dmg             # JSON output
  %(prog)s --format csv Downloads/*.dmg       # CSV report
  %(prog)s --format html *.pkg > report.html  # HTML report

Supported file types: .dmg, .pkg, .app
        """
    )

    parser.add_argument('files', nargs='+', metavar='FILE', help='DMG, PKG, or APP file(s) to analyse')
    parser.add_argument('-v', '--verbose', action='store_true', help='Show hashes and timestamps')
    parser.add_argument('--entitlements', action='store_true', help='Extract and show app entitlements')
    parser.add_argument('--format', choices=['text', 'json', 'csv', 'html'], default='text', help='Output format')
    parser.add_argument('--no-colour', action='store_true', help='Disable coloured output')
    parser.add_argument('--version', action='version', version='MAS 3.1.0 (macOS Edition)')

    args = parser.parse_args()

    analyser = SecurityAnalyser(
        verbose=args.verbose,
        show_entitlements=args.entitlements,
        no_colour=args.no_colour or args.format != 'text'
    )

    results = []
    for file_path in args.files:
        result = analyser.analyse_file(Path(file_path))
        results.append(result)

    formatter = OutputFormatter()

    if args.format == 'json':
        print(formatter.format_json(results))
    elif args.format == 'csv':
        print(formatter.format_csv(results))
    elif args.format == 'html':
        print(formatter.format_html(results))
    else:
        for i, result in enumerate(results):
            print(formatter.format_text(result, args.verbose))
            if i < len(results) - 1:
                print()


if __name__ == '__main__':
    main()
