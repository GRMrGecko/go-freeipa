package freeipa

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"testing"
	"time"
)

// Unused port for testing.
const httpsPort = 8831

// handleLogin: Test login handler.
func handleLogin(w http.ResponseWriter, req *http.Request) {
	// Logins are form data posts.
	req.ParseForm()

	// Check username/password equals test credentials.
	user := req.Form.Get("user")
	password := req.Form.Get("password")
	if user == "test" && password == "testpassword" {
		// Successful login send session cookie.
		cookie := http.Cookie{}
		cookie.Name = "ipa_session"
		cookie.Value = "correct-session-secret"
		cookie.Expires = time.Now().Add(30 * time.Minute)
		cookie.Secure = true
		cookie.HttpOnly = true
		cookie.Path = "/ipa"
		http.SetCookie(w, &cookie)
		w.Header().Set("IPASESSION", "correct-session-secret")
	} else {
		// Invalid login, send rejection.
		w.Header().Set("X-IPA-Rejection-Reason", "invalid-password")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		fmt.Fprintf(w, `<html>
<head>
<title>401 Unauthorized</title>
</head>
<body>
<h1>Invalid Authentication</h1>
<p>
<strong>kinit: Password incorrect while getting initial credentials
</strong>
</p>
</body>
</html>`)
	}
}

// sendInvalidJSON: General invalid json error response for testing error handling.
func sendInvalidJSON(w http.ResponseWriter) {
	f, err := os.Open("test/invalid_json.json")
	if err != nil {
		log.Fatalln(err)
	}
	defer f.Close()
	io.Copy(w, f)
}

// handleJSON: Handle the json session test request.
func handleJSON(w http.ResponseWriter, req *http.Request) {
	// If session cookie doesn't exist, something is wrong. Send unauthenticated response.
	cookie, err := req.Cookie("ipa_session")
	if err != nil || cookie.Value != "correct-session-secret" {
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	// Generally json response from here.
	w.Header().Set("Content-Type", "application/json")

	// Get the request body and parse it out.
	res := new(Request)
	err = json.NewDecoder(req.Body).Decode(res)
	if err != nil {
		// If the json decode fails, send the error.
		sendInvalidJSON(w)
		return
	}

	// For testing, we'll consider user_add/user_find as an accepted method, all others will error.
	if res.Method == "user_add" {
		// Send user add response data.
		f, err := os.Open("test/user_add_response.json")
		if err != nil {
			log.Fatalln(err)
		}
		defer f.Close()
		io.Copy(w, f)
	} else if res.Method == "user_find" {
		// Send user add response data.
		f, err := os.Open("test/user_find_response.json")
		if err != nil {
			log.Fatalln(err)
		}
		defer f.Close()
		io.Copy(w, f)
	} else {
		// An unexpected method received for testing, send error message.
		sendInvalidJSON(w)
	}
}

// TestLogin: General library tests with test server.
func TestLogin(t *testing.T) {
	// Spin up test server using port specified above.
	srvAddr := fmt.Sprintf("127.0.0.1:%d", httpsPort)
	http.HandleFunc("/ipa/session/login_password", handleLogin)
	http.HandleFunc("/ipa/session/json", handleJSON)
	go func() {
		err := http.ListenAndServeTLS(srvAddr, "test/cert.pem", "test/key.pem", nil)
		if err != nil {
			log.Fatal("ListenAndServe: ", err)
		}
	}()
	// Allow the http server to initialize.
	time.Sleep(100 * time.Millisecond)

	// Test server has a self signed certificate, ignore invalid certs.
	transportConfig := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	// Connect using wrong password to confirm invalid login responses are handled correctly.
	_, err := Connect(srvAddr, transportConfig, "test", "wrong-password")
	if err == nil || err.Error() != "login failed: unauthorized response <invalid-password> (1201)" {
		t.Fatalf("expected login failure")
	}

	// Connect using correct password to confirm valid logins are handled correctly.
	client, err := Connect(srvAddr, transportConfig, "test", "testpassword")
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	// Setup test user_add request.
	params := make(map[string]interface{})
	params["givenname"] = "FreeIPA"
	params["sn"] = "Test"
	params["userpassword"] = "test-password"
	req := NewRequest(
		"user_add",
		[]interface{}{"username"},
		params,
	)

	// Send the request to the test server.
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	// Test reading bool key from response.
	v, _ := resp.GetBool("has_keytab")
	if !v {
		t.Errorf("expected true boolean")
	}

	// Test reading string from response.
	s, _ := resp.GetString("krbcanonicalname")
	if s != "username@EXAMPLE.COM" {
		t.Errorf("unexpected string: %s", s)
	}

	// Test reading date from response.
	d, _ := resp.GetDateTime("krblastpwdchange")
	year, month, day := d.Date()
	if year != 2023 || month != 8 || day != 10 {
		t.Errorf("unexpected date: %s", d)
	}

	// Test reading base64 data from response.
	b, _ := resp.GetData("krbextradata")
	if len(b) != 27 {
		t.Errorf("unexpected data: %v", b)
	}

	// Test reading a non-existant value from response.
	s, ok := resp.GetString("non-existant")
	if s != "" || ok {
		t.Errorf("expected empty string: %s", s)
	}

	a, ok := resp.GetStrings("objectclass")
	if !ok || len(a) != 13 {
		t.Errorf("unexpected data: %v", a)
	}

	// Test receiving an error message from the test server.
	req.Method = "invalid"
	_, err = client.Do(req)
	if err == nil || err.Error() != "JSONError (909): Invalid JSON-RPC request: Expecting property name enclosed in double quotes: line 4 column 4 (char 44)" {
		t.Fatalf("unexpected error: %s", err)
	}

	// Test user_find.
	params = make(map[string]interface{})
	params["pkey_only"] = true
	params["sizelimit"] = 0
	req = NewRequest(
		"user_find",
		[]interface{}{""},
		params,
	)

	// Send the request to the test server.
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("error: %s", err)
	}

	// The response should have a count as its an array.
	if resp.Result.Count != 2 {
		t.Error("expected 2 users")
	}

	// Confirm the array actually counts the same.
	if resp.CountResults() != 2 {
		t.Error("expected 2 users")
	}

	// Confirm an string at index works withou the array encapsulation.
	dn, _ := resp.GetStringAtIndex(0, "dn")
	if dn != "uid=admin,cn=users,cn=accounts,dc=example,dc=com" {
		t.Errorf("unexpected string: %s", dn)
	}

	// Confirm the UID string at index works because it is array encapsulated.
	uid, _ := resp.GetStringAtIndex(1, "uid")
	if uid != "johnny.bravo" {
		t.Errorf("unexpected string: %s", uid)
	}
}
