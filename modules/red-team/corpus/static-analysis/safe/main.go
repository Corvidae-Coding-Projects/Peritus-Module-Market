package main

import "crypto/tls"

func main() {
    _ = &tls.Config{MinVersion: tls.VersionTLS12}
}
