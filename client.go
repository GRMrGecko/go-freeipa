package freeipa

import (
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"

	krb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/spnego"
)

// The base object for connections to FreeIPA API.
type Client struct {
	uriBase  string
	client   *http.Client
	user     string
	password string
	krb5     *krb5client.Client
}

// Internal function with common init code for each connection type, mainly sets http.Client and uriBase.
func (c *Client) init(host string, transport *http.Transport) error {
	// Create a cookie jar to store FreeIPA session cookies.
	jar, err := cookiejar.New(&cookiejar.Options{})
	if err != nil {
		return err
	}
	// Setup client using provided transport configurations and the cookie jar.
	c.client = &http.Client{
		Transport: transport,
		Jar:       jar,
	}

	// Set uriBase using the provided host and test to verify a valid URL is produced.
	c.uriBase = fmt.Sprintf("https://%s/ipa", host)
	_, err = url.Parse(c.uriBase)
	if err != nil {
		return err
	}
	return nil
}

// Make a new client and login using standard username/password.
func Connect(host string, transport *http.Transport, user, password string) (*Client, error) {
	// Make the client config and save credentials.
	client := &Client{
		user:     user,
		password: password,
	}

	// Initialize common configurations.
	err := client.init(host, transport)
	if err != nil {
		return nil, err
	}

	// Login using credentials.
	err = client.login()
	if err != nil {
		return nil, fmt.Errorf("login failed: %s", err)
	}

	return client, nil
}

// Login using standard credentials.
func (c *Client) login() error {
	// If login is called, but kerberos client is configured, use kerberos login instead.
	// This allows standard re-authentication calls to work with both kerbeos and standard authenciation.
	if c.krb5 != nil {
		return c.loginWithKerberos()
	}

	// Setup form data with credentials.
	data := url.Values{
		"user":     []string{c.user},
		"password": []string{c.password},
	}
	// Authenticate using standard credentials with the http client.
	res, e := c.client.PostForm(c.uriBase+"/session/login_password", data)
	if e != nil {
		return e
	}

	// If an error occurs, provide details if possible on why.
	if res.StatusCode != http.StatusOK {
		if res.StatusCode == http.StatusUnauthorized {
			return unauthorizedHTTPError(res)
		}
		return fmt.Errorf("unexpected http status code: %d", res.StatusCode)
	}

	// Successful authentication.
	return nil
}

// Options for connecting to Kerberos.
type KerberosConnectOptions struct {
	Krb5ConfigReader io.Reader
	KeytabReader     io.Reader
	User             string
	Realm            string
}

// Create a new client using Kerberos authentication.
func ConnectWithKerberos(host string, transport *http.Transport, options *KerberosConnectOptions) (*Client, error) {
	// Read the kerberos configuration file for server connection information.
	krb5Config, err := krb5config.NewFromReader(options.Krb5ConfigReader)
	if err != nil {
		return nil, fmt.Errorf("error reading kerberos configuration: %s", err)
	}

	// Read the keytab data.
	ktData, err := io.ReadAll(options.KeytabReader)
	if err != nil {
		return nil, fmt.Errorf("error reading keytab: %s", err)
	}

	// Parse the keytab data.
	kt := keytab.New()
	err = kt.Unmarshal(ktData)
	if err != nil {
		return nil, fmt.Errorf("error parsing keytab: %s", err)
	}

	// Setup kerberos client with keytab and config.
	krb5 := krb5client.NewWithKeytab(options.User, options.Realm, kt, krb5Config)

	// Setup the client with kerberos's client for authentication.
	client := &Client{
		user: options.User,
		krb5: krb5,
	}

	// Initialize the common configurations.
	err = client.init(host, transport)
	if err != nil {
		return nil, err
	}

	// Login using kerberos authentication.
	err = client.login()
	if err != nil {
		return nil, fmt.Errorf("login failed: %s", err)
	}
	return client, nil
}

// Login using kerberos client. The regular login function will call this function if needed.
func (c *Client) loginWithKerberos() error {
	// Wrapper for authenticating with Kerberos credentials.
	spnegoCl := spnego.NewClient(c.krb5, c.client, "")

	// Setup request for authenticate.
	req, err := http.NewRequest("POST", c.uriBase+"/session/login_kerberos", nil)
	if err != nil {
		return fmt.Errorf("error building login request: %s", err)
	}
	req.Header.Add("Referer", c.uriBase)

	// Perform authenticate using Kerberos.
	res, err := spnegoCl.Do(req)
	if err != nil {
		return fmt.Errorf("error logging in using Kerberos: %s", err)
	}

	// If an error occurs, return it.
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected http status code: %d", res.StatusCode)
	}

	// Successful authentication.
	return nil
}
