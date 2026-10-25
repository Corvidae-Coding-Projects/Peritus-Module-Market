package main

import (
    "crypto/tls"
    "os/exec"
    jwt "github.com/dgrijalva/jwt-go"
)

func main() {
    _ = &tls.Config{InsecureSkipVerify: true}
    _ = exec.Command("sh", "-c", "echo unsafe")
    _ = jwt.SigningMethodHS256
}
