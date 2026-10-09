# Exploring Results

## Navigate Results

After analysis completes, the UI displays different views depending on the file type:

**For PCAP files:**

- **Stats Grid** - clickable cards showing event counts by type (Alerts, DNS, HTTP, TLS, Flows, etc.). If you've enabled "Show protocol-anomaly noise alerts" (Gear Menu → Rules), those alerts get their own **Decoder Alerts** card instead of mixing into Network Alerts. A **DNS Heuristics** card appears immediately before the **DNS Queries** card whenever any domain in the capture trips a scoring flag; see [DNS Heuristics](#dns-heuristics) below
- **Sankey Diagram** - expand the collapsible heading to visualize network flow relationships (Source IP → Dest IP → Dest Port)
- **Aggregation Tables** - frequency counts for each column; click a value to open the [pivot menu](filtering-and-drilldown.md#pivot-menu). Each table pages through its values with Prev/Next instead of growing the page, at a size (10/25/50/100) set by the "Items per page" selector, which applies to every table in the section and persists across sessions
- **Data Table** - sortable table with expandable detail rows showing full event JSON, ASCII transcripts, and hexdumps. Every row's flow carries a community ID, and a TLS row's detail panel includes JA3/JA3S/JA4 fingerprints whenever present - both computed by Suricata automatically, no configuration needed
- **Search** - full-text search across all event data using SQLite FTS5 (falls back to `LIKE` if FTS5 is unavailable)
- **Filtering** - filter via the pivot menu's Include/Exclude/Only actions on any table cell or aggregation value; filter chips show active filters; filters persist across all tabs and the Sankey diagram

### Protocols from tshark

Suricata doesn't parse every protocol. Alongside it, SO-CRATES runs tshark (Wireshark's command-line engine) over the capture, and the protocols Suricata doesn't parse join the analysis's results, each card marked with a dot in its corner - the line under the header starts with the same dot, and says how many protocols tshark added ("● tshark parsed 8 additional protocols in 43s"):

- **Records** for NBNS and LLMNR (Windows name resolution and registration), SSDP (UPnP device discovery) and S7comm (Siemens PLC reads, writes and control) - one per transaction, with their own columns and aggregations - and for **Telnet**, one per session: the server's banner (which usually names the device - the **Banner** aggregation lists the devices answering Telnet), the user name and password typed at its login prompts, whether it said the login failed, and the commands typed after. Telnet sends everything in plain text, so the password is the one in the capture - the same one the session's ASCII transcript shows. (Suricata recognizes Telnet but logs nothing about it.)
- **IEC 104** (IEC 60870-5-104, the telecontrol protocol between a power grid's control centre and its substations), as two record types. **IEC 104** has one record per control action - a command (switch on or off, raise or lower a tap changer), a set point, an interrogation, a clock synchronization, a read, a reset, a parameter or a file transfer - with the station (common address) and object address (IOA) it's for, the value sent, and its **Result**: *confirmed*, *negative* (refused), *confirmed, terminated* (finished), *no confirmation*, or *(request not seen)* for a reply whose request is before the capture started. **IEC 104 Points** has one record per monitored point on each connection - a busy link sends hundreds of thousands of measurements, so they're summarized rather than listed: the point's type, how many updates it sent and why (spontaneous, periodic, answering an interrogation), and its last value. The **Command** and **Result** aggregations show who's being controlled and how it went.
- **Connections** for every other protocol tshark recognizes - OpenVPN, PRP, RADIUS, MongoDB and so on - one row per connection: addresses, ports, packets and bytes each way, and the protocol tshark gave it

Suricata stays the source of truth for everything it parses. Nothing from tshark is added on a connection Suricata identified (gave a protocol and logged records for): a scanner's HTTP request to an rsh port is HTTP, as Suricata logged it, not rsh, as tshark - going by the port - would call it. That's worth remembering on the connection cards in general: tshark names most protocols by port, so on scanning traffic a connection card shows what was tried on that port, not necessarily what was spoken. **ALL EVENTS** doesn't count connection rows, since each is a connection Suricata's own **Flows** already list.

tshark starts with Suricata and usually finishes first; when it doesn't, Suricata's results open as usual and the line under the header says "tshark is parsing additional protocols…" with the seconds counting up. When tshark's protocols are ready, their cards join the others - once, and not while your pointer or keyboard focus is on the cards (the line offers **Show them** meanwhile); the open tab stays open. The line then says how many additional protocols tshark parsed and how long it took.

A capture of more than 4 million packets isn't run through tshark until you ask, because tshark's memory grows with the number of packets (about 1 KB each) - click **Add tshark protocols** on the line. A run that needs more than 4 GB of memory is stopped. If a run fails, the reason is shown with a **Try again** link. To turn tshark off for every analysis, clear **Add protocols decoded by tshark** in Settings; analyses keep the protocols already added.

**For log files (`.evtx`, `.json`, `.jsonl`, `.csv`, `.xml`, `.log`):**

- **Sigma Alerts** - detections matched by Sigma rules, with severity, MITRE techniques, and rule metadata
- **Log Events** - all parsed log events with dynamic column discovery based on the actual data
- **Aggregation Tables** - filterable counts for discovered fields (Channel, EventID, Image, Source IP, etc.), with the same Prev/Next paging and adjustable page size as PCAP mode
- **Search & Filtering** - same full-text search and pivot-menu filtering as PCAP mode

**For email messages (`.eml`):**

- **Emails** - the message, plus any forwarded message attached to it: From, To, Subject, the SPF/DKIM/DMARC results, and how many attachments and warnings it has. Expand a row for its key headers (From, To, Cc, Reply-To, Return-Path, Message-ID, Mailer), the Received chain (oldest hop first, with the earliest hop that isn't a private or internal address as the **Originating IP**) and the body text. Its **Warnings** flag a Reply-To or Return-Path on a different domain than From, failing SPF/DKIM/DMARC, links whose text names a different domain than they go to, and attachments that are executables or macro-enabled Office documents. A forwarded message's detail panel is marked **Forwarded**
- **Links** - every web link in the message, with its domain and visible text. The **Mismatch** column shows Yes for a link whose text names one domain (`https://www.bank.example/login`) while it actually goes to another - a classic phishing trick
- **File Info** - the message itself and each attachment, decoded, with hashes, file type and metadata. Each has a **Send to CyberChef** button
- **File Alerts** - YARA matches on the message or its decoded attachments. Scanning them decoded catches malware that base64 encoding hides from a scan of the raw message
- **Aggregation Tables, Search & Filtering** - the same as PCAP mode. There's no Sankey diagram or All Events view, since an email has no network flows

The message's HTML is read for its links and text but never displayed as a web page.

**For binary files:**

- **File Info** - metadata extracted from the file
- **File Alerts** - any YARA rules that matched, with tags and author attribution

## DNS Heuristics

When a capture contains DNS queries, a **DNS Heuristics** card appears on the Stats Grid immediately before the **DNS Queries** card, but only once at least one domain in the capture trips a flag - it's simply absent otherwise. Opening it groups every DNS query by registrable domain and scores each one 0-100 against five independent signals:

- a high-entropy, low-vowel-ratio subdomain label under an otherwise ordinary parent domain (the classic DNS tunneling shape - scored per label with the same vowel guard as the DGA check, so neither a deep chain of short labels nor a long hyphenated word-mashup reads as random)
- a high-entropy/low-vowel-ratio registrable domain itself (the DGA (Domain Generation Algorithm) shape)
- 15 or more distinct subdomains queried under the same parent (fan-out, not just repeated lookups of the same name)
- an unusually long query name or label
- TXT/NULL query types, more associated with tunneling/exfil tooling than ordinary browsing

Known CDN domains and ubiquitous OS/vendor domains (Microsoft, Google, Apple, Mozilla, and similar update/telemetry endpoints) are excluded before scoring to cut noise - DGA and tunneling both require an attacker-controlled domain, which those are not. A collapsible **About DNS Heuristics** info card at the top of the tab explains the scoring in place. Clicking a flagged domain's row searches for it and jumps straight to the real **DNS Queries** tab so you can see every individual query behind the score - unlike every other tab, a row here doesn't expand a detail panel in place. Treat a flag as a lead to investigate, not a confirmed verdict.
