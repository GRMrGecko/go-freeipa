package freeipa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// General date/time format in LDAP.
// https://github.com/freeipa/freeipa/blob/ipa-4-7/ipalib/constants.py#L271
const LDAPGeneralizedTimeFormat = "20060102150405Z"

// Used in providing extra messages and error response.
type Message struct {
	Type    string `json:"type"`
	Message string `json:"message"`
	Code    int    `json:"code"`
	Name    string `json:"name"`
}

// Convert the message into a combind string.
func (t *Message) string() string {
	return fmt.Sprintf("%v (%v): %v", t.Name, t.Code, t.Message)
}

// Standard result in response from FreeIPA.
type Result struct {
	Count     int        `json:"count"`
	Truncated bool       `json:"truncated"`
	Messages  []*Message `json:"messages,omitempty"`
	// This result differs depending on response,
	// read the API documentation below for information.
	// https://github.com/freeipa/freeipa/tree/master/doc/api
	Result  interface{} `json:"result"`
	Summary string      `json:"summary,omitempty"`
	Value   string      `json:"value,omitempty"`
}

// Standard response from FreeIPA.
type Response struct {
	Error     *Message `json:"error"`
	Result    *Result  `json:"result"`
	Version   string   `json:"version"`
	Principal string   `json:"principal"`
}

// Parse response from reader.
func ParseResponse(body io.Reader) (*Response, error) {
	// Decode JSON response.
	res := new(Response)
	err := json.NewDecoder(body).Decode(res)
	if err != nil {
		return nil, err
	}
	// If an error was provided from the API, return it.
	if res.Error != nil {
		return nil, fmt.Errorf(res.Error.string())
	}
	// We expect result to be provided on a valid response.
	if res.Result == nil {
		return nil, fmt.Errorf("no result in response")
	}
	// A valid response was decoded, return it.
	return res, nil
}

// Decode results which are boolean formatted, usually used to indicate success or state.
func (r *Response) BoolResult() bool {
	if r.Result == nil {
		return false
	}
	v, ok := r.Result.Result.(bool)
	if !ok {
		return false
	}
	return v
}

// Count the number of results that this request has.
func (r *Response) CountResults() int {
	if r.Result == nil {
		return -1
	}
	a, ok := r.Result.Result.([]interface{})
	if !ok {
		return -1
	}
	return len(a)
}

// Return dictionary at index.
func (r *Response) DictAtIndex(index int) (map[string]interface{}, bool) {
	if r.Result == nil {
		return nil, false
	}
	a, ok := r.Result.Result.([]interface{})
	if !ok {
		return nil, false
	}
	// Make sure we don't overflow.
	if len(a) < index {
		return nil, false
	}
	d := a[index]
	dict, ok := d.(map[string]interface{})
	return dict, ok
}

// Return dictionary.
func (r *Response) Dict() (map[string]interface{}, bool) {
	if r.Result == nil {
		return nil, false
	}
	dict, ok := r.Result.Result.(map[string]interface{})
	return dict, ok
}

// Get an interface for a key.
func (r *Response) GetAtIndex(index int, key string) ([]interface{}, bool) {
	dict, ok := r.DictAtIndex(index)
	if !ok {
		return nil, false
	}
	v, ok := dict[key]
	if !ok {
		return nil, false
	}
	a, ok := v.([]interface{})
	if !ok {
		// Apparently FreeIPA sometimes returns a string outside of an array, so this catches that.
		return []interface{}{v}, true
	}
	return a, true
}

// Get an interface for a key.
func (r *Response) Get(key string) ([]interface{}, bool) {
	dict, ok := r.Dict()
	if !ok {
		return nil, false
	}
	v, ok := dict[key]
	if !ok {
		return nil, false
	}
	a, ok := v.([]interface{})
	if !ok {
		// Apparently FreeIPA sometimes returns a string outside of an array, so this catches that.
		return []interface{}{v}, true
	}
	return a, true
}

// Get all keys at index.
func (r *Response) KeysAtIndex(index int) ([]string, bool) {
	var res []string
	dict, ok := r.DictAtIndex(index)
	if !ok {
		return res, false
	}
	for k := range dict {
		res = append(res, k)
	}
	return res, true
}

// Get all keys.
func (r *Response) Keys() ([]string, bool) {
	var res []string
	dict, ok := r.Dict()
	if !ok {
		return res, false
	}
	for k := range dict {
		res = append(res, k)
	}
	return res, true
}

// Process sub element with bool.
func (r *Response) processBool(v interface{}) (bool, bool) {
	a, ok := v.(bool)
	if !ok {
		return false, false
	}
	return a, true
}

// Get a boolean from a key at an index.
func (r *Response) GetBoolAtIndex(index int, key string) (bool, bool) {
	v, ok := r.GetAtIndex(index, key)
	if !ok || len(v) < 1 {
		return false, false
	}
	return r.processBool(v[0])
}

// Get a boolean from a key.
func (r *Response) GetBool(key string) (bool, bool) {
	v, ok := r.Get(key)
	if !ok || len(v) < 1 {
		return false, false
	}
	return r.processBool(v[0])
}

// Process sub element with string.
func (r *Response) processString(v []interface{}) ([]string, bool) {
	var res []string
	for _, p := range v {
		s, ok := p.(string)
		if !ok {
			return res, false
		}
		res = append(res, s)
	}
	return res, true
}

// Get string value for key at an index.
func (r *Response) GetStringsAtIndex(index int, key string) ([]string, bool) {
	v, ok := r.GetAtIndex(index, key)
	if !ok {
		return []string{}, false
	}
	return r.processString(v)
}

// Get string value for key.
func (r *Response) GetStrings(key string) ([]string, bool) {
	v, ok := r.Get(key)
	if !ok {
		return []string{}, false
	}
	return r.processString(v)
}

// Get string value for key at an index.
func (r *Response) GetStringAtIndex(index int, key string) (string, bool) {
	v, ok := r.GetStringsAtIndex(index, key)
	if !ok || len(v) < 1 {
		return "", false
	}
	return v[0], true
}

// Get string value for key.
func (r *Response) GetString(key string) (string, bool) {
	v, ok := r.GetStrings(key)
	if !ok || len(v) < 1 {
		return "", false
	}
	return v[0], true
}

// Process sub element with bytes.
func (r *Response) processData(v []interface{}) ([][]byte, bool) {
	var res [][]byte
	for _, p := range v {
		var bytes []byte
		dict, ok := p.(map[string]interface{})
		if !ok {
			return res, false
		}
		b, ok := dict["__base64__"]
		if !ok {
			return res, false
		}
		s, ok := b.(string)
		if !ok {
			return res, false
		}
		bytes, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return res, false
		}
		res = append(res, bytes)
	}
	return res, true
}

// Get byte array for key at an index.
func (r *Response) GetDatasAtIndex(index int, key string) ([][]byte, bool) {
	v, ok := r.GetAtIndex(index, key)
	if !ok {
		return [][]byte{}, false
	}
	return r.processData(v)
}

// Get byte array for key.
func (r *Response) GetDatas(key string) ([][]byte, bool) {
	v, ok := r.Get(key)
	if !ok {
		return [][]byte{}, false
	}
	return r.processData(v)
}

// Get byte array for key at an index.
func (r *Response) GetDataAtIndex(index int, key string) ([]byte, bool) {
	v, ok := r.GetDatasAtIndex(index, key)
	if !ok || len(v) < 1 {
		return []byte{}, false
	}
	return v[0], true
}

// Get byte array for key.
func (r *Response) GetData(key string) ([]byte, bool) {
	v, ok := r.GetDatas(key)
	if !ok || len(v) < 1 {
		return []byte{}, false
	}
	return v[0], true
}

// Process sub element with a date/time value.
func (r *Response) processDateTime(v []interface{}) ([]time.Time, bool) {
	var res []time.Time
	for _, p := range v {
		dict, ok := p.(map[string]interface{})
		if !ok {
			return res, false
		}
		d, ok := dict["__datetime__"]
		if !ok {
			return res, false
		}
		s, ok := d.(string)
		if !ok {
			return res, false
		}
		dateTime, err := time.Parse(LDAPGeneralizedTimeFormat, s)
		if err != nil {
			return res, false
		}
		res = append(res, dateTime)
	}
	return res, true
}

// Get date time value for key at an index.
func (r *Response) GetDateTimesAtIndex(index int, key string) ([]time.Time, bool) {
	v, ok := r.GetAtIndex(index, key)
	if !ok {
		return []time.Time{}, false
	}
	return r.processDateTime(v)
}

// Get date time value for key.
func (r *Response) GetDateTimes(key string) ([]time.Time, bool) {
	v, ok := r.Get(key)
	if !ok {
		return []time.Time{}, false
	}
	return r.processDateTime(v)
}

// Get date time value for key at an index.
func (r *Response) GetDateTimeAtIndex(index int, key string) (time.Time, bool) {
	v, ok := r.GetDateTimesAtIndex(index, key)
	if !ok || len(v) < 1 {
		return time.Time{}, false
	}
	return v[0], true
}

// Get date time value for key.
func (r *Response) GetDateTime(key string) (time.Time, bool) {
	v, ok := r.GetDateTimes(key)
	if !ok || len(v) < 1 {
		return time.Time{}, false
	}
	return v[0], true
}
