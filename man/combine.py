#!/usr/bin/python3
from pathlib import Path
from datetime import date

# Directory where man pages are stored
data_dir = Path("./data")

# Output file path
man_dir = Path("./man1")
output_path = man_dir / "cirrus-scope.1"

# Man section headers to ignore or skip when merging
skip_sections = [".TH", ".SH NAME"]

# Combine all .1 man page files
combined_lines = [
    ".TH CIRRUS-SCOPE \"1\" \"%s\" \"cirrus-scope\" \"User Commands\"" % date.today().strftime("%Y-%m-%d"),
    ".SH NAME",
    "cirrus-scope \- diagnostic utility for debugging Entra ID authentication issues via libhimmelblau",
    ".SH SYNOPSIS",
    ".B cirrus-scope",
    "\\fI<COMMAND>\\fR [OPTIONS]",
    ".SH DESCRIPTION",
    "cirrus-scope is a command-line utility designed to help Himmelblau users and developers diagnose and investigate authentication issues when using libhimmelblau integration with Azure Entra ID.\n\nIt provides targeted test commands to simulate login, device enrollment, token refresh, and Hello for Business key provisioning. This tool collects debug output and enables packet capture through optional proxy configuration, making it easier to share failure context with Himmelblau maintainers.\n\nAuthentication input (such as usernames and passwords) is provided interactively at the terminal.",
]

top_man = data_dir / "cirrus-scope.1"
with open(top_man, "r") as f:
    in_skip = False
    for line in f:
        if any(line.startswith(section) for section in skip_sections):
            in_skip = True
            continue
        if in_skip and line.startswith(".SH"):
            in_skip = False
        if not in_skip:
            combined_lines.append(line.rstrip())

# Sort files alphabetically
man_files = sorted(data_dir.glob("cirrus-scope-*.1"))

for file in man_files:
    command_name = file.stem.replace("cirrus-scope-", "").replace("-", " ")
    combined_lines.append(".PP")
    with file.open() as f:
        in_skip = False
        for line in f:
            if any(line.startswith(section) for section in skip_sections):
                in_skip = True
                continue
            if in_skip and line.startswith(".SH"):
                in_skip = False
            if line.startswith('.SH SYNOPSIS'):
                line = line.replace('.SH SYNOPSIS', '.SH')
            if line.startswith('.SH DESCRIPTION'):
                line = line.replace('.SH DESCRIPTION', '.SS DESCRIPTION')
            if line.startswith('.SH OPTIONS'):
                line = line.replace('.SH OPTIONS', '.SS OPTIONS')
            if not in_skip:
                combined_lines.append(line.rstrip())

combined_lines.extend([
    ".SH SEE ALSO",
    ".BR aad-tool (1),",
    ".BR himmelblau.conf (5),",
    ".BR himmelblaud (8),",
    ".BR himmelblaud-tasks (8)",
    ".SH AUTHOR",
    "David Mulder <dmulder@himmelblau-idm.org>,",
    "<dmulder@samba.org>",
])

# Write combined man page
output_path.write_text("\n".join(combined_lines).replace('cirrus-scope\n\\fI\\,', 'cirrus-scope \\fI\\,').replace('.SH\n.B', '.SH SUBCOMMAND\n.B') + "\n")

output_path.name
