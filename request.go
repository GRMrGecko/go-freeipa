package freeipa

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// Standard API version definitation.
var apiVersion = "2.237"

// Request format.
type Request struct {
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

// Create a new API request.
func NewRequest(method string, args []interface{}, parms map[string]interface{}) *Request {
	// Add API version to the parameters.
	parms["version"] = apiVersion

	// Create the request.
	req := &Request{
		Method: method,
		Params: []interface{}{
			args,
			parms,
		},
	}

	// Return new request.
	return req
}

// Have the client perform the request.
func (c *Client) Do(req *Request) (*Response, error) {
	// Send request.
	res, err := c.sendRequest(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	// If request is unauthorized, attempt to re-authenticate.
	if res.StatusCode == http.StatusUnauthorized {
		// Login.
		err = c.login()
		if err != nil {
			return nil, fmt.Errorf("renewed login failed: %s", err)
		}

		// Re-send the request, now that we're authenticated.
		res, err = c.sendRequest(req)
		if err != nil {
			return nil, err
		}
	}

	// We expect a 200 response, otherwise re-authentication failed or some other error occured.
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected http status code: %d", res.StatusCode)
	}

	// Parse the response from the body.
	return ParseResponse(res.Body)
}

// Encode and send the request to the session.
func (c *Client) sendRequest(request *Request) (*http.Response, error) {
	// Encode to JSON.
	data, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	// Make request with JSON data.
	req, err := http.NewRequest("POST", c.uriBase+"/session/json", bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Referer", c.uriBase)

	// Perform the request.
	return c.client.Do(req)
}
