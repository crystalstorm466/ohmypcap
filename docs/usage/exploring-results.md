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

### SURI-CRATES and SHAR-CRATES

A PCAP analysis has two views of the same capture, switched with the **SURI-CRATES** and **SHAR-CRATES** tabs above the search box:

- **SURI-CRATES** is Suricata's view - alerts, flows and protocol records - and is what every PCAP analysis opens on
- **SHAR-CRATES** is tshark's view. tshark (Wireshark's command-line engine) decodes far more protocols than Suricata, but packet by packet; SHAR-CRATES groups those packets into records shaped like Suricata's: one **Flow** per conversation, showing the protocol tshark found in it (**App Proto**), plus one record per transaction for DNS, mDNS, HTTP, TLS, QUIC, Modbus, FTP and SMB - and for four protocols Suricata doesn't parse: **NBNS** and **LLMNR** (Windows name resolution and registration), **SSDP** (UPnP device discovery) and **S7comm** (Siemens PLC reads, writes and control). Every other protocol tshark finds gets a tab of its own listing its connections - OpenVPN, PRP, SSH and so on. A dot in the corner of a card marks every tab, of records or of connections, for a protocol Suricata doesn't parse at all - the key beside the view tabs reads "● not in Suricata". The same aggregation tables, Sankey diagram, search and pivot menu work on both views. SHAR-CRATES has no alerts - detection is Suricata's

SHAR-CRATES starts by itself in the background as soon as Suricata finishes, so it's usually ready by the time you want it. Beside the tabs, SO-CRATES says where it is: "Analyzing with tshark…" while it works, with the seconds it's been running counting up (and a spinning ring on its tab), then how many flows and protocols tshark found and how many seconds it took. A capture of more than 4 million packets isn't analyzed until you ask, because tshark's memory grows with the number of packets (about 1 KB each) - click **Analyze now** (or the SHAR-CRATES tab) to start it. A run that needs more than 4 GB of memory is stopped. If a run fails, the reason is shown with a **Try again** link. To turn SHAR-CRATES off altogether, clear **Also analyze PCAPs with tshark** in Settings.

Switching views keeps your search and filters, so you land on the same slice of traffic in the other view. To follow one flow from one view to the other, open the pivot menu on any of its rows and choose **View in SHAR-CRATES** (or **View in SURI-CRATES**) - it finds the same flow by its Community ID, which both views compute identically.

Where both views decode a protocol, they agree on nearly every field they share - checked record by record against Suricata on dozens of real captures. The differences that remain:

- **Flows** - the two tools draw a conversation's boundaries differently. A long-lived UDP exchange with quiet gaps (mDNS, NTP) is one SHAR-CRATES flow but several Suricata flows, since Suricata ends a flow once it's been idle; and a port scan that reuses one source port is one Suricata flow but a SHAR-CRATES flow per attempt. Counted per address-and-port pair, their packet totals agree
- **Which side is the client** - Suricata takes whoever sent a flow's first packet. SHAR-CRATES takes whoever made the first request (failing that, whoever was answered first), so the two can address a flow opposite ways round: a capture that starts mid-conversation, where the first packet is a server's answer; and a multicast or broadcast question's unicast answer, which is a flow of one packet from the answerer. The first case costs Suricata more than a direction - it doesn't recognize the protocol from an answer, so it logs nothing for the whole flow: a device in the 4SICS GeekLounge capture made 43,000 DNS queries that only SHAR-CRATES shows, because the capture began on one of their answers. A search on an address still finds such a flow in both views, but a search on Source IP or Dest IP finds it in only one
- **DNS** - Suricata logs a query and its response as two records; SHAR-CRATES makes them one, so its DNS count is the number of queries. A query sent more than once, or answered more than once, is still one record, and its details say how many times (**Transmissions**, **Responses**). More than one response to a query is worth a look: an attacker spoofing DNS races the real server with answers of their own
- **HTTP** - for a response with no `Content-Length` header, Suricata counts the body's length itself; SHAR-CRATES leaves the length empty
- **FTP** - for a reply that runs over several lines (like many servers' greetings), SHAR-CRATES has every reply code but only the first line's text. And a command Suricata doesn't recognize (`OPTS`, `AUTH TLS`) gets its reply in SHAR-CRATES, where Suricata logs the reply on its own, with no command
- **SMB** - file opens, reads and writes, shares, logins (NTLM and Kerberos) and IOCTLs agree with Suricata's, record for record, on 18 of 20 Windows domain captures checked. Suricata's SMB records also show the DCERPC call a named pipe carries; SHAR-CRATES doesn't yet. Suricata spots SMB on any port, so it has records for scanners' SMB probes to web or FTP ports, which SHAR-CRATES doesn't; SHAR-CRATES, for its part, keeps going on a connection with more than 1,024 SMB transactions in flight, where Suricata stops (its *too many transactions* anomaly), and decodes SMB that follows a NetBIOS session request on port 139, which Suricata misses
- **TLS and QUIC** - a JA3 fingerprint of a QUIC handshake that uses GREASE values differs (Suricata keeps them; tshark drops them, as JA3 specifies), as can JA4 on some old SSL/TLS handshakes. Google's older gQUIC gets no QUIC record
- **More in SHAR-CRATES** - where Suricata's parser gives up on a connection (a flood of malformed or pipelined requests), or never recognizes one, SHAR-CRATES often still decodes it: its records for those are real traffic, not duplicates
- **Row notes** are kept with SURI-CRATES, so a SHAR-CRATES row can't have one

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
