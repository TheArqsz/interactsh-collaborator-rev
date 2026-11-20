# Interactsh Collaborator - Revised

[![Build and Publish Release](https://github.com/TheArqsz/interactsh-collaborator-rev/actions/workflows/release.yml/badge.svg)](https://github.com/TheArqsz/interactsh-collaborator-rev/actions/workflows/release.yml)

A Burp Suite extension for out-of-band (OOB) testing with Interactsh, featuring dedicated protocol formatting.

![Interactsh-Collaborator](assets/interactsh-demo.gif)

## Features

### Core Functionality

- **Interactsh Integration** - Generate unique Interactsh domains for OOB testing
- **Multiple Protocol Support** - DNS, HTTP/HTTPS, SMTP, FTP, LDAP, SMB
- **Real-time Monitoring** - Automatic polling for interactions with configurable intervals
- **Burp Integration** - Works alongside Burp's native Collaborator

### User Interface

- **Protocol Formatting** - Clean, readable display for each protocol type:
	- DNS: Section highlighting with indented queries
	- SMTP: Header/body separation with structured display
	- FTP: Command labels with password masking
	- LDAP: Query structure highlighting (base, filter, scope, attributes)
	- SMB/Responder: Authentication details with hash masking
	- HTTP/HTTPS: Uses Burp's built-in request/response viewers
- **Interactive Table** - Sortable, filterable interaction log
- **Unread Tracking** - Visual indication of new interactions
- **Copy to Clipboard** - One-click URL copying
- **Protocol Filtering** - Filter by protocol type (All, HTTP, DNS, SMTP, LDAP, SMB, FTP)

## About This Fork

I forked this project because the original repository appears to be unmaintained. [The last commit](https://github.com/wdahlenburg/interactsh-collaborator/commit/dd92e5573263bc7b341ed1b980d705dba8417d92) was on August 5, 2023, and several pull requests and issues have been ignored since then.

This fork begins at version 1.1, building on the original [1.0.2](https://github.com/wdahlenburg/interactsh-collaborator/releases/tag/v1.0.2) code.

The goal of this fork is to keep the project alive, incorporate useful community contributions, and add my own improvements. This version incorporates some changes from the following pull requests to the original repository:

- [PR #22](https://github.com/wdahlenburg/interactsh-collaborator/pull/22): Updated vulnerable dependencies.
- [PR #19](https://github.com/wdahlenburg/interactsh-collaborator/pull/19): Added a "Poll Now" button.
- [PR #18](https://github.com/wdahlenburg/interactsh-collaborator/pull/18): Major performance improvements, UI enhancements, and better table controls.

These are some other changes to the original code, released as the version [1.1](https://github.com/TheArqsz/interactsh-collaborator-rev/releases/tag/v1.1.0):

- Generating a new payload no longer creates a new client and thread. The extension now
 uses a single client, which makes it much faster and more stable.
- Added Collaborator-like filtering feature for different types of payloads
- The interactions table now supports selecting individual cells, rows, and columns for copying.
- The user interface was refreshed to better match the look and feel of Burp's native tools.

## Installation

### From Releases (Recommended)

1. Download `interactsh-collaborator.jar` from the [releases](https://github.com/TheArqsz/interactsh-collaborator-rev/releases/latest) page
2. In Burp Suite: Extensions -> Add -> Select the JAR file
3. The "Interactsh" tab will appear in Burp Suite

### Using Docker

```bash
docker build --output ./build-output .
```

The directory `./build-output` will contain all generated jars.

### Locally using Maven

1. `mvn clean package`
2. Add the target/collaborator-1.x.x-dev-jar-with-dependencies.jar file as a new Java extension in Burpsuite

## Usage

### Basic Workflow

1. Navigate to the Interactsh tab in Burp Suite
2. Copy the Interactsh URL using the "Copy URL to clipboard" button
3. Use the URL in your testing (e.g. inject into parameters, headers, etc.)
4. Monitor interactions in real-time in the table

### Buttons and Controls

| Button | Function |
|--------|----------|
| **Copy URL to clipboard** | Copies the current Interactsh URL to clipboard |
| **Regenerate Interactsh Session** | Creates a new session with a fresh URL |
| **Refresh** | Manually triggers a poll for new interactions |
| **Clear log** | Clears all interactions from the table |
| **Poll Time** | Shows current polling interval (seconds) |

### Protocol Filtering

Use the filter buttons to show only specific protocol types:

- **All** - Show all interactions
- **HTTP** - HTTP/HTTPS only
- **DNS** - DNS queries only
- **SMTP** - Email interactions only
- **LDAP** - LDAP queries only
- **SMB** - SMB/Responder only
- **FTP** - FTP connections only

### Table Features

- **Click a row** to view details
- **Sort by column** - Click column headers
- **Bold entries** - Unread interactions
- **Select cells/rows** - Copy data to clipboard

## Configuration

Navigate to the **Configuration** tab to customize settings listed below.

### Server Settings

| Setting | Default | Description |
|---------|---------|-------------|
| **Server** | `oast.live` | Interactsh server hostname |
| **Port** | `443` | Server port |
| **TLS** | Enabled | Use HTTPS/TLS connection |
| **Token** | _(empty)_ | Authentication token for private servers |
| **Poll Interval** | `60` sec | How often to check for new interactions |

### Using Self-Hosted Interactsh

To use your own Interactsh server:

1. Set up your server following [ProjectDiscovery's documentation](https://github.com/projectdiscovery/interactsh#using-self-hosted-server)
2. In the Configuration tab:
   - Enter your server hostname (e.g. `interactsh.example.com`)
   - Set port (typically `443` for HTTPS)
   - Enable TLS if using HTTPS
   - Add authorization token required
3. Click **Update Settings**
4. A new session will be created automatically

See [the list of public Interactsh servers](https://github.com/projectdiscovery/interactsh?tab=readme-ov-file#using-self-hosted-server) for alternatives.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed list of changes in each version.

Releases are automatically generated using conventional commits. 

## Troubleshooting

### No interactions appearing

- Check the poll interval isn't too high
- Click "Refresh" to manually poll
- Verify the Interactsh URL was correctly used in your test
- Check Configuration tab for server settings

### Unable to register interactsh client

- Verify server hostname and port in Configuration tab
- Check network connectivity to the Interactsh server
- If using a private server, verify authorization token
- Try the default server (`oast.live`) first

### Interactions not showing details

- HTTP/HTTPS use Burp's built-in viewers (check the tabs below the table)
- Other protocols should show formatted text in the details pane
- Try selecting a different row and coming back

## Credits

### Original Project

- **Original Author:** [wdahlenburg](https://github.com/wdahlenburg)
- **Original Repository:** [interactsh-collaborator](https://github.com/wdahlenburg/interactsh-collaborator)

### Interactsh

- **Interactsh Project:** [ProjectDiscovery/interactsh](https://github.com/projectdiscovery/interactsh)
- This extension implements the client-side logic from the Interactsh project

---

Suggestions are welcome via [GitHub Issues](https://github.com/TheArqsz/interactsh-collaborator-rev/issues)!