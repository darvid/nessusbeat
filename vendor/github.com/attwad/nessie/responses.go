package nessie

// loginResp is the internal response to login attemps.
type loginResp struct {
	Token string `json:"token"`
}

// ServerProperties is the structure returned by the ServerProperties() method.
type ServerProperties struct {
	Token           string `json:"token"`
	NessusType      string `json:"nessus_type"`
	NessusUIVersion string `json:"nessus_ui_version"`
	ServerVersion   string `json:"server_version"`
	Feed            string `json:"feed"`
	Enterprise      bool   `json:"enterprise"`
	LoadedPluginSet string `json:"loaded_plugin_set"`
	ServerUUID      string `json:"server_uuid"`
	Expiration      int64  `json:"expiration"`
	Notifications   []struct {
		Type string `json:"type"`
		Msg  string `json:"message"`
	} `json:"notifications"`
	ExpirationTime int64 `json:"expiration_time"`
	Capabilities   struct {
		MultiScanner      bool `json:"multi_scanner"`
		ReportEmailConfig bool `json:"report_email_config"`
	} `json:"capabilities"`
	PluginSet       string `json:"plugin_set"`
	IdleTImeout     int64  `json:"idle_timeout"`
	ScannerBoottime int64  `json:"scanner_boottime"`
	LoginBanner     bool   `json:"login_banner"`
}

// ServerStatus is the stucture returned  by the ServerStatus() method.
type ServerStatus struct {
	Status             string `json:"status"`
	Progress           int64  `json:"progress"`
	MustDestroySession bool
}

type listUsersResp struct {
	Users []User `json:"users"`
}

type FamilyDetails struct {
	Name    string   `json:"name"`
	ID      int64    `json:"id"`
	Plugins []Plugin `json:"plugins"`
}

type PluginDetails struct {
	Plugin
	FamilyName string       `json:"family_name"`
	Attrs      []PluginAttr `json:"attributes"`
}

type listPoliciesResp struct {
	Policies []Policy `json:"policies"`
}

type ListScansResponse struct {
	Folders   []Folder `json:"folders"`
	Scans     []Scan   `json:"scans"`
	Timestamp int64    `json:"timestamp"`
}

type listTemplatesResp struct {
	Templates []Template `json:"tempaltes"`
}

type startScanResp struct {
	UUID string `json:"scan_uuid"`
}

type ScanDetailsResp struct {
	UUID string `json:"scan_uuid"`
	Info struct {
		EditAllowed   bool   `json:"edit_allowed"`
		Status        string `json:"status"`
		Policy        string `json:"policy"`
		PCICanUpload  bool   `json:"pci-can-upload"`
		HasAuditTrail bool   `json:"hasaudittrail"`
		ScanStart     int64  `json:"scan_start"`
		FolderID      int64  `json:"folder_id"`
		Targets       string `json:"targets"`
		Timestamp     int64  `json:"timestamp"`
		ObjectID      int64  `json:"object_id"`
		ScannerName   string `json:"scanner_name"`
		HasKB         bool   `json:"haskb"`
		UUID          string `json:"uuid"`
		HostCount     int64  `json:"hostcount"`
		ScanEnd       int64  `json:"scan_end"`
		Name          string `json:"name"`
		UserPerms     int64  `json:"user_permissions"`
		Control       bool   `json:"control"`
	} `json:"info"`
	Hosts        []Host `json:"hosts"`
	CompHosts    []Host `json:"comphosts"`
	Notes        []Note `json:"notes"`
	Remediations struct {
		Remediation Remediation `json:"remediation"`
	} `json:"remediations"`
	NumHosts          int64           `json:"num_hosts"`
	NumCVEs           int64           `json:"num_cves"`
	NumImpactedHosts  int64           `json:"num_impacted_hosts"`
	NumRemediatedCVEs int64           `json:"num_remediated_cves"`
	Vulnerabilities   []Vulnerability `json:"vulnerabilities"`
	Compliance        []Vulnerability `json:"compliance"`
	History           []History       `json:"history"`
	Filters           []Filter        `json:"filters"`
}

type tzResp struct {
	Timezones []TimeZone `json:"timezones"`
}

type listFoldersResp struct {
	Folders []Folder `json:"folders"`
}

type exportScanResp struct {
	File int64 `json:"file"`
}

type exportStatusResp struct {
	Status string `json:"status"`
}

type listGroupsResp struct {
	Groups []Group `json:"groups"`
}
