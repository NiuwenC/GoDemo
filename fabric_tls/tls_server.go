package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
)

func main() {

	cer, err := tls.LoadX509KeyPair("./tls_server-cert.pem", "./tls_server-key.pem")
	if err != nil {
		log.Fatal(err)
	}

	var certPool *x509.CertPool
	config := &tls.Config{
		Certificates: []tls.Certificate{cer},
		ClientAuth:   tls.NoClientCert,
		ClientCAs:    certPool,
	}

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: config,
	}

	log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}
