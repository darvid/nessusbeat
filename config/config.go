// Config is put into a different package to prevent cyclic imports in case
// it is needed in several locations

package config

type Config struct {
    CaCertPath        string `config:"cacert_path"`
	ReportPath        string `config:"report_path"`
	NessusApiUrl      string `config:"api_url"`
	NessusApiUsername string `config:"api_username"`
	NessusApiPassword string `config:"api_password"`
}

var DefaultConfig = Config{
	ReportPath: "/opt/nessus/var/nessus/users/admin/reports",
    NessusApiUrl: "https://localhost:8834",
}
