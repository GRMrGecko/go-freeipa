# go-freeipa
A FreeIPA API client library for GoLang.

## Install
```bash
go get github.com/grmrgecko/go-freeipa
```

## Example
```go
import (
    "crypto/tls"
    "log"
    "net/http"
    "github.com/grmrgecko/go-freeipa"
)

func main() {
    // Setup TLS configurations.
    tlsConifg := tls.Config{InsecureSkipVerify: false}
    transportConfig := &http.Transport{
        TLSClientConfig: &tlsConifg,
    }
    // Connect/login to FreeIPA server.
    client, err := freeipa.Connect("ipa.example.com", transportConfig, "username", "password")
    if err!=nil {
        log.Fatalln(err)
    }

    // Make a user.
    params := make(map[string]interface{})
    params["pkey_only"] = true
    params["sizelimit"] = 0
    req := freeipa.NewRequest(
        "user_find",
        []interface{}{""},
        params,
    )

    // Send the request to the test server.
    resp, err := client.Do(req)
    if err != nil {
        log.Fatalln(err)
    }

    // Print information about response.
    log.Println("Found users:", resp.Result.Count)

    dn, ok := resp.GetStringAtIndex(0, "dn")
    if !ok {
        log.Fatalln("Unable to get dn value from FreeIPA")
    }

    log.Println("Got first user DN:", dn)
}
```

## References
If you're looking for help on what API methods there are and the arguments they accept, the documentation at FreeIPA should help:

[https://github.com/freeipa/freeipa/tree/master/doc/api](https://github.com/freeipa/freeipa/tree/master/doc/api)
