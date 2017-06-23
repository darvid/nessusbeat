package nessie

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDoRequest(t *testing.T) {
	// Test structure to be serialized.
	type payload struct {
		A int `json:"a"`
	}
	var tests = []struct {
		method       string
		resource     string
		sentPayload  payload
		wantPayload  string
		serverStatus int
		wantStatus   []int
		wantError    bool
	}{
		// All succeeding methods.
		{"GET", "/test", payload{}, "{\"a\":0}", http.StatusOK, []int{http.StatusOK}, false},
		{"POST", "/test", payload{}, "{\"a\":0}", http.StatusOK, []int{http.StatusOK}, false},
		{"DELETE", "/test", payload{}, "{\"a\":0}", http.StatusOK, []int{http.StatusOK}, false},
		{"PUT", "/test", payload{}, "{\"a\":0}", http.StatusOK, []int{http.StatusOK}, false},
		// Payload test.
		{"GET", "/test", payload{42}, "{\"a\":42}", http.StatusOK, []int{http.StatusOK}, false},
		// Expected failure.
		{"POST", "/test", payload{}, "{\"a\":0}", http.StatusInternalServerError, []int{http.StatusInternalServerError}, false},
		// Unexpected failure
		{"POST", "/test", payload{}, "{\"a\":0}", http.StatusInternalServerError, []int{http.StatusOK}, true},
	}
	for _, tt := range tests {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tt.serverStatus)
			body, err := ioutil.ReadAll(r.Body)
			if err != nil {
				t.Errorf("could not read request body: %v", err)
				return
			}
			bodyStr := string(body)
			if bodyStr != tt.wantPayload {
				t.Errorf("unexpected payload, got=%s, want=%s", body, tt.wantPayload)
			}
		}))
		n := &nessusImpl{
			apiURL: ts.URL,
			client: &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
				},
			},
		}
		n.SetVerbose(true)
		resp, err := n.doRequest(tt.method, tt.resource, tt.sentPayload, tt.wantStatus)
		if tt.wantError {
			if err == nil {
				t.Errorf("got no error, expected one (%+v)", tt)
			}
			continue
		}
		if err != nil {
			t.Errorf("error in doRequest: %v (%+v)", err, tt)
			continue
		}
		if resp.StatusCode != tt.serverStatus {
			t.Errorf("got status code=%d, wanted=%d", resp.StatusCode, tt.serverStatus)
		}
	}
}

func TestLogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Header().Set("Content-Type", "application/json")
		j, err := json.Marshal(&loginResp{Token: "some token"})
		if err != nil {
			t.Fatalf("cannot serialize login response: %v", err)
		}
		w.Write(j)
	}))
	defer server.Close()
	n, err := NewInsecureNessus(server.URL)
	if err != nil {
		t.Fatalf("cannot create nessus instance: %v", err)
	}

	if err := n.Login("username", "password"); err != nil {
		t.Fatalf("got error during login: %v", err)
	}
	if got, want := n.AuthCookie(), "some token"; got != want {
		t.Fatalf("wrong auth cookie, got=%q, want=%q", got, want)
	}
}

func TestMethods(t *testing.T) {
	var tests = []struct {
		resp       interface{}
		statusCode int
		call       func(n Nessus)
	}{
		{&Session{}, http.StatusOK, func(n Nessus) { n.Session() }},
		{&ServerProperties{}, http.StatusOK, func(n Nessus) { n.ServerProperties() }},
		{&ServerStatus{}, http.StatusOK, func(n Nessus) { n.ServerStatus() }},
		{&User{}, http.StatusOK, func(n Nessus) {
			n.CreateUser("username", "pass", UserTypeLocal, Permissions32, "name", "email@foo.com")
		}},
		{&listUsersResp{}, http.StatusOK, func(n Nessus) { n.ListUsers() }},
		{nil, http.StatusOK, func(n Nessus) { n.DeleteUser(42) }},
		{nil, http.StatusOK, func(n Nessus) { n.SetUserPassword(42, "newpass") }},
		{&User{}, http.StatusOK, func(n Nessus) {
			n.EditUser(42, Permissions128, "newname", "newmain@goo.fom")
		}},
		{[]PluginFamily{}, http.StatusOK, func(n Nessus) { n.PluginFamilies() }},
		{&FamilyDetails{}, http.StatusOK, func(n Nessus) { n.FamilyDetails(42) }},
		{&PluginDetails{}, http.StatusOK, func(n Nessus) { n.PluginDetails(42) }},
		{[]Scanner{}, http.StatusOK, func(n Nessus) { n.Scanners() }},
		{&listPoliciesResp{}, http.StatusOK, func(n Nessus) { n.Policies() }},
		{&Scan{}, http.StatusOK, func(n Nessus) {
			n.NewScan("editorUUID", "settingsName", 42, 43, 44, LaunchDaily, []string{"target1", "target2"})
		}},
		{&ListScansResponse{}, http.StatusOK, func(n Nessus) { n.Scans() }},
		{[]Template{}, http.StatusOK, func(n Nessus) { n.ScanTemplates() }},
		{[]Template{}, http.StatusOK, func(n Nessus) { n.PolicyTemplates() }},
		{"id", http.StatusOK, func(n Nessus) { n.StartScan(42) }},
		{nil, http.StatusOK, func(n Nessus) { n.PauseScan(42) }},
		{nil, http.StatusOK, func(n Nessus) { n.ResumeScan(42) }},
		{nil, http.StatusOK, func(n Nessus) { n.StopScan(42) }},
		{nil, http.StatusOK, func(n Nessus) { n.DeleteScan(42) }},
		{&ScanDetailsResp{}, http.StatusOK, func(n Nessus) { n.ScanDetails(42) }},
		{[]TimeZone{}, http.StatusOK, func(n Nessus) { n.Timezones() }},
		{[]Folder{}, http.StatusOK, func(n Nessus) { n.Folders() }},
		{nil, http.StatusOK, func(n Nessus) { n.CreateFolder("name") }},
		{nil, http.StatusOK, func(n Nessus) { n.EditFolder(42, "newname") }},
		{nil, http.StatusOK, func(n Nessus) { n.DeleteFolder(42) }},
		{42, http.StatusOK, func(n Nessus) { n.ExportScan(42, ExportPDF) }},
		{true, http.StatusOK, func(n Nessus) { n.ExportFinished(42, 43) }},
		{[]byte("raw export"), http.StatusOK, func(n Nessus) { n.DownloadExport(42, 43) }},
		{[]Permission{}, http.StatusOK, func(n Nessus) { n.Permissions("scanner", 42) }},
	}
	for _, tt := range tests {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(tt.statusCode)
			if tt.resp != nil {
				j, err := json.Marshal(tt.resp)
				if err != nil {
					t.Fatalf("cannot serialize response: %v", err)
				}
				w.Write(j)
			}
		}))
		defer server.Close()
		n, err := NewInsecureNessus(server.URL)
		if err != nil {
			t.Fatalf("cannot create nessus instance: %v", err)
		}
		n.SetVerbose(true)
		tt.call(n)
	}
}

func TestSha256Fingerprint(t *testing.T) {
	want := "AzuD2SQxVI4TQkkDwjWpkir1bdNNU8m3KzfPFYSJIT4="
	got := sha256Fingerprint([]byte("abc123!"))
	if got != want {
		t.Errorf("fingerprint calculation failed, got=%v, want=%v", got, want)
	}
}

func generateCert(validNotBefore time.Time, validNotAfter time.Time) (*x509.Certificate, tls.Certificate, error) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	template := x509.Certificate{
		BasicConstraintsValid: true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotBefore:             validNotBefore,
		NotAfter:              validNotAfter,
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Example Inc"}},
	}
	certDer, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	certX509, err := x509.ParseCertificate(certDer)
	if err != nil {
		return nil, tls.Certificate{}, err
	}
	keypair, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer}),
		pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)}))
	return certX509, keypair, err
}

// An empty fingerprint would allow to create a nessus instance without any verification.
func TestNewFingerprintedNessus(t *testing.T) {
	_, err := NewFingerprintedNessus("https://192.0.2.1", []string{})
	if err == nil {
		t.Fatalf("should not accept empty fingerprint: %v", err)
	}
	_, err = NewFingerprintedNessus("https://192.0.2.1", []string{"a"})
	if err != nil {
		t.Fatalf("should accept a non-empty fingerprint: %v", err)
	}
}

func TestCreateDialTLSFuncToVerifyFingerprint(t *testing.T) {
	var tests = []struct {
		fingerprint    func([]byte) string
		validNotBefore time.Time
		validNotAfter  time.Time
		wantError      bool
	}{
		// Correct fingerprint, should succeed.
		{func(cert []byte) string { return sha256Fingerprint(cert) }, time.Now().Truncate(1 * time.Hour), time.Now().Add(1 * time.Hour), false},
		// Correct fingerprint, cert not yet valid, should succeed.
		{func(cert []byte) string { return sha256Fingerprint(cert) }, time.Now().Add(1 * time.Hour), time.Now().Add(2 * time.Hour), false},
		// Correct fingerprint, cert not valid anymore, should succeed.
		{func(cert []byte) string { return sha256Fingerprint(cert) }, time.Now().Truncate(2 * time.Hour), time.Now().Truncate(1 * time.Hour), false},
		// No fingerprint given (empty string), should fail.
		{func(_ []byte) string { return "" }, time.Now().Truncate(1 * time.Hour), time.Now().Add(1 * time.Hour), true},
		// Wrong fingerprint given, should fail.
		{func(_ []byte) string { return "TW1NeU5tSTBObUkyT0dabVl6WTRabVk1T1dJME5UTmpNV1E=" }, time.Now().Truncate(1 * time.Hour), time.Now().Add(1 * time.Hour), true},
		// Wrong fingerprint given, should fail.
		{func(_ []byte) string { return "x" }, time.Now().Truncate(1 * time.Hour), time.Now().Add(1 * time.Hour), true},
	}
	for _, tt := range tests {
		srvCertX509, srvKeypair, err := generateCert(tt.validNotBefore, tt.validNotAfter)
		if err != nil {
			t.Fatalf("failed to create x509 key pair: %v", err)
		}
		srvConfig := &tls.Config{Certificates: []tls.Certificate{srvKeypair}}
		srvListener, err := tls.Listen("tcp", "127.0.0.1:0", srvConfig)
		if err != nil {
			t.Fatalf("cannot listen: %v", err)
			return
		}
		go http.Serve(srvListener, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {}))
		cConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		wantFingerprint := tt.fingerprint(srvCertX509.RawSubjectPublicKeyInfo)
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: cConfig,
				DialTLS:         createDialTLSFuncToVerifyFingerprint([]string{wantFingerprint}, cConfig),
			},
		}
		_, err = client.Get("https://" + srvListener.Addr().String())
		if tt.wantError {
			if err == nil {
				t.Errorf("got no error, expected one (%+v)", tt)
			}
			continue
		}
		if err != nil {
			t.Errorf("error during fingerprint verification: %v (%+v)", err, tt)
			continue
		}
	}
}
