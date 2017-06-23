package nessie

// Editor resources.

// Template is used to create scans or policies with predefined parameters.
type Template struct {
	// The uuid for the template.
	UUID string `json:"uuid"`
	// The short name of the template.
	Name string `json:"name"`
	// The long name of the template.
	Title string `json:"title"`
	// The description of the template.
	Desc string `json:"description"`
	// If true, template is only available on the cloud.
	CloudOnly bool `json:"cloud_only"`
	// If true, the template is only available for subscribers.
	SubscriptionOnly bool `json:"subscription_only"`
	// An external URL to link the template to.
	MoreInfo string `json:"more_info"`
}

type TemplateFormInput struct {
	ID      string   `json:"id"`
	Type    string   `json:"type"`
	Label   string   `json:"label"`
	Default string   `json:"default"`
	Options []string `json:"options"`
}

type TemplateDisplayGroup struct {
	Name     string   `json:"name"`
	Title    string   `json:"title"`
	Inputs   []string `json:"inputs"`
	Sections []string `json:"sections"`
}

type TemplateSection struct {
	Name   string   `json:"name"`
	Title  string   `json:"title"`
	Inputs []string `json:"inputs"`
}

type TemplateMode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Desc string `json:"desc"`
}

type TemplatePluginFamily struct {
	ID     int64  `json:"id"`
	Count  int64  `json:"count"`
	Status string `json:"status"`
}

type Filter struct {
	Name         string           `json:"name"`
	ReadableName string           `json:"readable_name"`
	Operators    []string         `json:"operators"`
	Controls     []FilterControls `json:"controls"`
}

type FilterControls struct {
	Type          string   `json:"type"`
	ReadableRegex string   `json:"readable_regest"`
	Regex         string   `json:"regex"`
	Ooptions      []string `json:"options"`
}

// Folders resources.

type Folder struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	DefaultTag  int64  `json:"default_tag"`
	Custom      int64  `json:"custom"`
	UnreadCount int64  `json:"unread_count"`
}

// Groups resources.

type Group struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Permissions int64  `json:"permissions"`
	UserCount   int64  `json:"user_count"`
}

// Permissions resources.

type Permission struct {
	Owner       int64  `json:"owner"`
	Type        string `json:"type"`
	Permissions int64  `json:"permissions"`
	ID          int64  `json:"id"`
	Name        string `json:"name"`
}

// Plugins resources.

type PluginAttr struct {
	Name string `json:"attribute_name"`
	Val  string `json:"attribute_value"`
}

type PluginFamily struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Count int64  `json:"count"`
}

type PluginFamilies struct {
	Families []PluginFamily  `json:"families"`
}

type Plugin struct {
	ID   int64  `json:"id"`
	Name string `json:"name"`
}

// Plugin-rules resources.

type Rule struct {
	ID       int64  `json:"id"`
	PluginID int64  `json:"plugin_id"`
	Date     string `json:"date"`
	Host     string `json:"host"`
	Type     string `json:"type"`
	Owner    string `json:"owner"`
	OwnerID  int64  `json:"owner_id"`
}

// Policies resources.

type Policy struct {
	ID                   int64  `json:"id"`
	TemplateUUID         string `json:"template_uuid"`
	Name                 string `json:"uuid"`
	Desc                 string `json:"description"`
	OwnerID              int64  `json:"owner_id"`
	Owner                string `json:"owner"`
	Shared               int64  `json:"shared"`
	UserPerms            int64  `json:"user_permissions"`
	CreationDate         int64  `json:"creation_date"`
	LastModificationDate int64  `json:"last_modification_date"`
	Visibility           int64  `json:"visibility"`
	NoTarget             bool   `json:"no_target"`
}

// Scanners resources.

type Scanner struct {
	ID               int64  `json:"id"`
	UUID             string `json:"uuid"`
	Name             string `json:"name"`
	Type             string `json:"type"`
	Status           string `json:"status"`
	ScanCount        int64  `json:"scan_count"`
	EngineVersion    string `json:"engine_version"`
	Platform         string `json:"platform"`
	LoadedPluginSet  string `json:"loaded_plugin_set"`
	RegistrationCode string `json:"registration_code"`
	Owner            string `json:"owner"`
}

// Scans resources.

type Scan struct {
	ID                   int64  `json:"id"`
	UUID                 string `json:"uuid"`
	Name                 string `json:"name"`
	Owner                string `json:"owner"`
	FolderID             int64  `json:"folder_id"`
	Read                 bool   `json:"read"`
	Status               string `json:"status"`
	Shared               bool   `json:"shared"`
	UserPerms            int64  `json:"user_permissions"`
	CreationDate         int64  `json:"creation_date"`
	LastModificationDate int64  `json:"last_modification_date"`
	Control              bool   `json:"control"`
	StartTime            string `json:"starttime"`
	TimeZone             string `json:"timezone"`
	RRules               string `json:"rrules"`
}

type Host struct {
	HostID                int64  `json:"host_id"`
	HostIdx               int64  `json:"host_index"`
	Hostname              string `json:"hostname"`
	Progress              string `json:"progress"`
	Critical              int64  `json:"critical"`
	High                  int64  `json:"high"`
	Medium                int64  `json:"medium"`
	Low                   int64  `json:"low"`
	Info                  int64  `json:"info"`
	TotalChecksConsidered int64  `json:"totalchecksconsidered"`
	NumChecksConsidered   int64  `json:"numchecksconsidered"`
	ScanProgressTotal     int64  `json:"scanprogresstotal"`
	ScanProgressCurrent   int64  `json:"scanprogresscurrent"`
	Score                 int64  `json:"score"`
}

type Note struct {
	Title    string `json:"title"`
	Message  string `json:"message"`
	Severity int64  `json:"severity"`
}

type Remediation struct {
	Value       string `json:"value"`
	Remediation string `json:"remediation"`
	NumHosts    int64  `json:"hosts"`
	NumVulns    string `json:"vulns"`
}

type History struct {
	HistoryID            int64  `json:"history_id"`
	UUID                 string `json:"uuid"`
	OwnerID              int64  `json:"owner_id"`
	Status               string `json:"status"`
	CreationDate         int64  `json:"creation_date"`
	LastModificationDate int64  `json:"last_modification_date"`
}

type Vulnerability struct {
	PluginID     int64  `json:"plugin_id"`
	PluginName   string `json:"plugin_name"`
	PluginFamily string `json:"plugin_family"`
	Count        int64  `json:"count"`
	VulnIdx      int64  `json:"vuln_index"`
	SeverityIdx  int64  `json:"severity_index"`
}

type HostVulnerability struct {
	HostID       int64  `json:"host_id"`
	Hostname     string `json:"hostname"`
	PluginID     int64  `json:"plugin_id"`
	PluginName   string `json:"plugin_name"`
	PluginFamily string `json:"plugin_family"`
	Count        int64  `json:"count"`
	VulnIdx      int64  `json:"vuln_index"`
	SeverityIdx  int64  `json:"severity_index"`
	Severity     int64  `json:"severity"`
}

type HostCompliance struct {
	HostID       int64  `json:"host_id"`
	Hostname     string `json:"hostname"`
	PluginID     int64  `json:"plugin_id"`
	PluginName   string `json:"plugin_name"`
	PluginFamily string `json:"plugin_family"`
	Count        int64  `json:"count"`
	SeverityIdx  int64  `json:"severity_index"`
	Severity     int64  `json:"severity"`
}

type PluginOutput struct {
	PluginOutput string   `json:"plugin_output"`
	Hosts        string   `json:"hosts"`
	Severity     int64    `json:"severity"`
	Ports        []string `json:"ports"`
}

type TimeZone struct {
	Name string `json:"name"`
	Val  string `json:"value"`
}

// Sessions resources.

type Session struct {
	ID          int64    `json:"id"`
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	Perms       int64    `json:"permissions"`
	LastLogin   int64    `json:"last_login"`
	ContainerID int64    `json:"container_id"`
	Groups      []string `json:"groups"`
}

type User struct {
	ID          int    `json:"id"`
	Username    string `json:"username"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Permissions int    `json:"permissions"`
	LastLogin   int    `json:"lastlogin"`
	Type        string `json:"type"`
}
