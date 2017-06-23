package nessie

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type createUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Permissions string `json:"permissions"`
	Name        string `json:"name"`
	Email       string `json:"email"`
	Type        string `json:"type"`
}

type setUserPasswordRequest struct {
	Password string `json:"password"`
}

type editUserRequest struct {
	Permissions string `json:"permissions"`
	Name        string `json:"name"`
	Email       string `json:"email"`
}

type scanSettingsRequest struct {
	Name        string `json:"name"`
	Desc        string `json:"description"`
	FolderID    int64  `json:"folder_id"`
	ScannerID   int64  `json:"scanner_id"`
	PolicyID    int64  `json:"policy_id"`
	TextTargets string `json:"text_targets"`
	FileTargets string `json:"file_targets"`
	Launch      string `json:"launch"`
	LaunchNow   bool   `json:"launch_now"`
}
type newScanRequest struct {
	UUID     string              `json:"uuid"`
	Settings scanSettingsRequest `json:"settings"`
}

type createFolderRequest struct {
	Name string `json:"name"`
}

type editFolderRequest struct {
	Name string `json:"name"`
}

type exportScanRequest struct {
	Format string `json:"format"`
}

type createGroupRequest struct {
	Name string `json:"name"`
}
