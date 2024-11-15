# sniff-gh-copilot-usage

A network monitoring tool that tracks GitHub Copilot usage by capturing DNS
lookups and HTTP(S) traffic to `githubcopilot.com` domains.

## Overview

This tool monitors network traffic to detect interactions with GitHub Copilot
services by:

- Capturing DNS lookups for `githubcopilot.com` domains
- Tracking HTTP(S) connections to known GitHub Copilot IP addresses
- Maintaining counts of interactions with different Copilot endpoints

## Prerequisites

- Rust toolchain
- libpcap development files
  - Ubuntu/Debian: `apt install libpcap-dev`
  - macOS: `brew install libpcap`
  - RHEL/Fedora: `dnf install libpcap-devel`

## Installation

```bash
cargo install --path .
```

## Usage

The tool requires root/administrator privileges to capture network traffic:

```bash
sudo sniff-gh-copilot-usage
```

Optionally specify a network interface:

```bash
sudo sniff-gh-copilot-usage -i eth0
```

## Output

The tool displays a table of domains and their access counts when terminated
with Ctrl+C:

```text
Domain                                | Count
-------------------------------------+-------
api.githubcopilot.com                | 42
api.enterprise.githubcopilot.com      | 15
```

## Future Work

- Remote reporting capability to aggregate usage data
- Persistent storage of metrics
- System service integration for continuous monitoring
- Authentication and secure data transmission
- User association with usage patterns

## Security Considerations

- Requires root access for packet capture
- Should be deployed with appropriate access controls
- Network traffic monitoring has privacy implications

## License

MIT
