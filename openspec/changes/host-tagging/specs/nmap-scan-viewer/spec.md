## MODIFIED Requirements

### Requirement: Stateless operation
The system SHALL hold everything it needs for a run in memory for the duration of
that run. It SHALL NOT require an import or indexing step before files can be
read, SHALL NOT create or depend on a database or any other persistent store *of
scan data*, and SHALL NOT write to the filesystem except when the user
explicitly exports, explicitly updates the vulnerability database, or explicitly
changes a manual tag or a tag definition. Two invocations over the same files
SHALL produce the same result regardless of what was run before them, given the
same vulnerability database and the same tag files.

The vulnerability database is reference data about public software, not about
the scanned network. It SHALL be created and changed only by an update the user
asked for or confirmed, SHALL never contain anything read from a scan or a
capture, and the viewer SHALL be fully usable without it. Only the vulnerability
and support columns then say that no database is present.

Tag files are the tester's own notes about the engagement, not a store of scan
data. A tag file SHALL hold only tag definitions and manual tag entries keyed by
address, protocol and port. It SHALL never hold scan results, and SHALL be
written only by an action of the user.

#### Scenario: Files are read directly, with no import step
- **WHEN** the user opens scan files that have never been seen before
- **THEN** they are read and presented immediately, with no prior import required

#### Scenario: Nothing is left behind
- **WHEN** a session ends in which no update was run and no tag was changed
- **THEN** no database, cache, index or tag file has been created

#### Scenario: Repeat runs are identical
- **WHEN** the same files are opened twice with no change on disk
- **THEN** both runs present the same hosts, services, counts and tags

#### Scenario: Removing a file removes its data
- **WHEN** a file is omitted from a subsequent invocation
- **THEN** nothing it contributed persists into that run

#### Scenario: The database holds nothing from the engagement
- **WHEN** the vulnerability database is updated during a session over a client's scans
- **THEN** it contains only data downloaded from the public sources, and no address, name, product list or finding from the session

#### Scenario: No database is not an error
- **WHEN** the viewer opens and no vulnerability database exists
- **THEN** every view works as before, and the support and vulnerability columns say the database is missing

#### Scenario: Tagging writes only the tag file
- **WHEN** the user tags a host
- **THEN** only `seek-tags.yaml` is created or changed, and it holds the tag, the address and nothing read from the scan

### Requirement: The filter accepts field terms and logical operators
Alongside fuzzy terms and address ranges, the filter SHALL accept field terms
that are tested against the scan model rather than the row's text:

- `open:PORT` and `open:PORT/PROTO` SHALL match a port the scan found open;
- `closed:PORT` and `closed:PORT/PROTO` SHALL match a port the scan recorded in
  any state other than open — closed, filtered or `open|filtered`;
- a port the scan never recorded SHALL match neither;
- `service:VALUE` SHALL match a port whose service name contains the value, and
  `product:VALUE` one whose detected product contains it, case-insensitively,
  with `^` and `$` anchoring as in the fuzzy grammar;
- `tag:VALUE` SHALL match a port that carries a tag whose name contains the
  value, or any port of a host that carries one, with the same anchoring. A
  `tag:` term SHALL match uncertain tags too.

The port-state keys SHALL be `open:` and `closed:`, so that "up" keeps its one
meaning: the host rule.

Terms SHALL combine with `AND`, `OR` and `NOT` written in uppercase, with `|` for
OR, with `!` for NOT as today, and with parentheses; a space between terms SHALL
mean AND; NOT SHALL bind tighter than AND, and AND tighter than OR. Lowercase
`and`, `or` and `not` SHALL remain ordinary search words, and a `key:` that is
not one of the fields SHALL remain an ordinary search term.

Field terms joined by AND SHALL describe the same port: a row matches only if one
of its ports satisfies all of them. `NOT` applied to field terms SHALL mean that
none of the row's ports satisfies them. For a row that stands for several ports —
a host, a service across hosts, a grouping bucket — the row SHALL match when any
of its ports, or pairs, does.

A filter that uses none of this syntax SHALL behave exactly as before, including
the union of several address ranges, which SHALL also hold for ranges joined by
AND inside a structured filter.

Since the filter is applied on every keystroke, an incomplete expression SHALL
NOT empty the list: a missing closing parenthesis SHALL be implied, a trailing
operator and a field with no value SHALL be ignored, and a field value that
cannot be understood SHALL be ignored. The status line SHALL show how the filter
was understood, with its operators and grouping made explicit, and SHALL name
any term it ignored.

#### Scenario: A port that is open
- **WHEN** the user filters the host list with `open:22`
- **THEN** exactly the hosts with port 22 open are listed, and a host whose address contains `22` but has no open port 22 is not

#### Scenario: A port seen not open
- **WHEN** the user filters with `closed:443/tcp`
- **THEN** hosts on which 443/tcp was recorded closed or filtered are listed, and hosts on which it was never scanned are not

#### Scenario: Service and product
- **WHEN** the user filters with `service:http product:nginx`
- **THEN** hosts with a port whose service is http-like and whose product is nginx are listed

#### Scenario: AND ties field terms to one port
- **WHEN** a host runs http served by Apache on port 80 and ssh served by OpenSSH on port 22, and the user filters with `service:http AND product:openssh`
- **THEN** the host is not listed, because no single port is both; with `service:http AND product:apache` it is

#### Scenario: OR
- **WHEN** the user filters with `service:ssh OR service:telnet`
- **THEN** hosts offering either are listed

#### Scenario: NOT means none of the ports
- **WHEN** the user filters with `NOT service:ssh`
- **THEN** only hosts with no ssh port are listed, even if they have other ports

#### Scenario: Grouping
- **WHEN** the user filters with `service:http AND NOT (product:apache | product:iis)`
- **THEN** hosts with an http port and no port served by Apache or IIS are listed

#### Scenario: Structured and plain terms together
- **WHEN** the user filters with `10.0.0.0/24 open:445 !printer`
- **THEN** hosts in that range, with 445 open, and not fuzzy-matching `printer` are listed

#### Scenario: A plain filter is unchanged
- **WHEN** the user filters with `apache !ssl 10.0.0.0/8 192.168.0.0/16`
- **THEN** the result is exactly what it was before this change

#### Scenario: Port rows are filtered by their own port
- **WHEN** a host's port list is filtered with `service:ssh OR open:80`
- **THEN** only its ssh port, and port 80 if it is open, are listed

#### Scenario: Lowercase words are search words
- **WHEN** the user filters with `rock and roll`
- **THEN** it is three fuzzy terms, not an operator

#### Scenario: An unknown key is text
- **WHEN** the user filters with `http://intranet`
- **THEN** it is matched as text, not as a field

#### Scenario: Typing an incomplete query
- **WHEN** the user has typed `service:ssh OR (open:22` and not yet closed the parenthesis
- **THEN** the list shows what the completed expression would, and the status line shows the expression with the parenthesis closed

#### Scenario: A field without a value while typing
- **WHEN** the user has typed `service:`
- **THEN** the list is not emptied, and the status line says the term is being ignored

#### Scenario: An invalid port
- **WHEN** the user filters with `open:web`
- **THEN** the term is ignored and named in the status line as not understood

#### Scenario: Matches are still highlighted
- **WHEN** the user filters with `apache OR nginx`
- **THEN** the characters matching whichever term a row matched on are highlighted

#### Scenario: A host tag
- **WHEN** the user filters with `tag:printer NOT tag:explored`
- **THEN** hosts tagged `printer` and not tagged `explored` are listed

#### Scenario: A service tag ties to its port
- **WHEN** port 80 of a host carries service tag `ricoh-web-ui`, and the user filters with `tag:ricoh-web-ui open:443`
- **THEN** the host is not listed unless port 443 also carries the tag, because both terms describe one port

#### Scenario: Before tags are ready
- **WHEN** the user filters with `tag:printer` while tags are still being computed
- **THEN** the status line says that tags are not ready yet, and the list updates when they are

### Requirement: Grouping views
The system SHALL be able to group open services by service name, by product, by
port, and by tag, listing the hosts in each group with the port and any product
and version detail. Groups SHALL be ordered by size by default.

#### Scenario: Group by service
- **WHEN** the user groups by service
- **THEN** each service name lists every host and port offering it, with product and version where known

#### Scenario: Group by product
- **WHEN** the user groups by product
- **THEN** services with no detected product are omitted from the grouping rather than collected under an empty name

#### Scenario: Group by port
- **WHEN** the user groups by port
- **THEN** each port lists the hosts exposing it, ordered by port number

#### Scenario: A group opens the hosts behind it
- **WHEN** the user opens a group
- **THEN** its hosts are listed, and each of those opens that host's record

#### Scenario: Group by tag
- **WHEN** the user groups by tag
- **THEN** each tag lists the hosts and ports that carry it, a host with several tags appears under each, and untagged services are omitted

#### Scenario: A tag group shows its issues
- **WHEN** a tag with issues is shown as a group
- **THEN** the group's record lists the tag's issues and how many of its hosts are uncertain

## ADDED Requirements

### Requirement: Each scan's port coverage is recorded
The system SHALL record which ports and protocols each scan file probed, from the
scan's own statement, and which hosts timed out. A host's coverage SHALL be the
union over the scans that include the host and did not time out on it.

#### Scenario: Two scans with different port lists
- **WHEN** a host appears in a scan of ports 1-1000 and a scan of port 8443
- **THEN** port 22 and port 8443 are covered for that host, and port 9100 is not

#### Scenario: A host that timed out
- **WHEN** a host timed out in a scan of ports 1-1000 and appears in no other scan
- **THEN** no port is covered for that host

#### Scenario: A scan with no port list
- **WHEN** a scan file is a ping sweep and states no port list
- **THEN** it covers no port, and the file still loads

#### Scenario: A protocol scanned separately
- **WHEN** a scan probed TCP ports 1-1000 and UDP port 161
- **THEN** 53/udp is not covered, and 53/tcp is

### Requirement: Tags are shown wherever their subject is
The host list SHALL have a Tags column. A record SHALL list its tags, each with
its source, its issues and, when uncertain, the missing evidence. A tag with an
issue SHALL be visible in the list without opening the record.

#### Scenario: A host with tags
- **WHEN** a host carries `printer`, `zebra-zd420` and `explored`
- **THEN** its row shows the tags, shortened with a count when they do not fit, and its record lists all three with their sources

#### Scenario: An issue in the list
- **WHEN** a host carries a tag with a `medium` issue
- **THEN** its row shows the tag in the colour for its highest severity

#### Scenario: An uncertain tag
- **WHEN** a host carries `zebra-zd420` as an assumption because 22/tcp was not scanned
- **THEN** the tag is shown with an uncertainty marker in the row, and the record says that 22/tcp was not scanned

#### Scenario: Problems with rule files
- **WHEN** a rule file could not be read
- **THEN** the status line says that some tag rules have problems, and the tag list shows each problem

### Requirement: Tags and issues can be exported
The export SHALL offer the tags and the tag issues of each record as fields, in
every export format, with uncertain tags marked.

#### Scenario: Exporting tagged hosts
- **WHEN** the user exports the host list with the tags field as CSV
- **THEN** each row holds the host's tags, with uncertain tags marked

### Requirement: Rows can be tagged by hand from the viewer
The user SHALL be able to tag the marked records, or the selected row when
nothing is marked, by choosing an existing tag or typing a new name. The same
action SHALL remove a manual tag.

#### Scenario: Tag the marks
- **WHEN** three hosts are marked and the user tags them `explored`
- **THEN** the three hosts carry `explored`, and the status line says where the tag was saved

#### Scenario: A name that is not allowed
- **WHEN** the user types `my tag` as a tag name
- **THEN** the dialog says why the name is not allowed, and nothing is saved
