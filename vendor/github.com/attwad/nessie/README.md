[![Build Status](https://travis-ci.org/attwad/nessie.svg?branch=master)](https://travis-ci.org/attwad/nessie)
[![GoDoc](https://godoc.org/github.com/attwad/nessie?status.png)](https://godoc.org/github.com/attwad/nessie)

Nessie
======

Tenable Nessus 6 API client in Go.


Usage
-----

Have a look at [the client example](https://github.com/attwad/nessie/blob/master/cli/nessie.go) for how to start a scan, wait until it finishes and exports the results to a CSV file.

Status
------

Here are the resources accessible via the official API and their current implementation status in this client:

- Editor
  - Details
  - Edit
  - List policy templates ✓
  - List scan templates ✓
  - Plugin description
- File
  - Upload
- Folders ✓
  - Create ✓
  - Delete ✓
  - Edit ✓
  - List ✓
- Groups
  - Add user
  - Create ✓
  - Delete
  - Delete user
  - Edit
  - List ✓
  - List users
- Permissions
  - Change
  - List ✓
- Plugins ✓
  - Families ✓
  - Family details ✓
  - Plugin details ✓
- Plugin rules
  - Create
  - Delete
  - Edit
  - List
- Policies
  - Configure
  - Copy
  - Create
  - Delete
  - Details
  - Import
  - Export
  - List ✓
- Scanners ✓
  - List ✓
- Scans
  - Configure
  - Create ✓
  - Delete ✓
  - Delete history
  - Details ✓
  - Download ✓
  - Export ✓
  - Export status ✓
  - Host details 
  - Import
  - Launch ✓
  - List ✓
  - Pause ✓
  - Plugin output
  - Read status
  - Resume ✓
  - Stop ✓
  - Timezones ✓
- Server ✓
  - Properties ✓
  - Status ✓ 
- Sessions
  - Create ✓
  - Destroy ✓
  - Edit
  - Get ✓
  - Password
- Users ✓
  - Create ✓
  - Delete ✓
  - Edit ✓
  - List ✓
  - Password ✓

Some methods are not part of the API but are implemented by this client to make life easier:

-  Get all plugin details
