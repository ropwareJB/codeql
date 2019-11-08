package main

import (
    "errors"
    "regexp"
    "net/http"
)

func checkRedirect(req *http.Request, via []*http.Request) error {
    // BAD: the host of `url` may be controlled by an attacker
    re := "^((www|beta).)?example.com/"
    if matched, _ := regexp.MatchString(re, req.URL.Host); matched {
        return nil
    }
    return errors.New("Invalid redirect")
}
