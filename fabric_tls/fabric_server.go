package main

import (
	"crypto/tls"
	"crypto/x509"
	"db_demo/fabric_tls/lib"

	"fmt"
	"github.com/cloudflare/cfssl/log"
	"io"
	"net/http"
	"strings"
)

// 此程序实现Fabric 中的tls 的功能
type ServerConfig struct {
	HomeDir    string
	Enabled    bool
	CertFile   string
	KeyFile    string
	ClientAuth ClientAuth
}
type ClientAuth struct {
	Type      string   `def:"noclientcert" help:"Policy the server will follow for TLS Client Authentication."`
	CertFiles []string `help:"A list of comma-separated PEM-encoded trusted certificate files (e.g. root1.pem,root2.pem)"`
}

const (
	tlsCertFile       = "K:\\GoProject\\db_demo\\fabric_tls\\tls_server-cert.pem"
	tlsKeyFile        = "K:\\GoProject\\db_demo\\fabric_tls\\tls_server-key.pem"
	defaultClientAuth = "noclientcert"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	// Write "Hello, world!" to the response body
	io.WriteString(w, "Hello, world!\n")
}

func main() {

	http.HandleFunc("/hello", helloHandler)
	var clientAuth tls.ClientAuthType
	var ok bool

	addr := "0.0.0.0:7090"
	factoryOpts := &lib.FactoryOpts{}
	serverConfig := ServerConfig{
		HomeDir:  ".",
		Enabled:  true,
		CertFile: tlsCertFile,
		KeyFile:  tlsKeyFile,
		ClientAuth: ClientAuth{
			CertFiles: []string{"K:\\GoProject\\db_demo\\fabric_tls\\root.pem"},
		},
	}
	fmt.Println(serverConfig)
	serverConfig.ClientAuth.Type = "requireandverifyclientcert"

	csp, err := lib.InitBCCSP(&factoryOpts.CSP, "", serverConfig.HomeDir)
	if err != nil {
		log.Fatal(err)
	}

	if serverConfig.Enabled {
		cer, err := lib.LoadX509KeyPair(serverConfig.CertFile, serverConfig.KeyFile, csp)
		if err != nil {
			log.Fatal(err)
		}

		if serverConfig.ClientAuth.Type == "" {
			serverConfig.ClientAuth.Type = defaultClientAuth
		}

		authType := strings.ToLower(serverConfig.ClientAuth.Type)
		fmt.Println(authType, clientAuth, lib.ClientAuthTypes[authType])
		if clientAuth, ok = lib.ClientAuthTypes[authType]; !ok {
			log.Fatal("Invalid client auth type provided")
		}

		var certPool *x509.CertPool
		if authType != defaultClientAuth {
			certPool, err = lib.LoadPEMCertPool(serverConfig.ClientAuth.CertFiles)
			if err != nil {
				log.Fatal(err)
			}
		}
		fmt.Println(certPool)

		config := &tls.Config{
			Certificates: []tls.Certificate{*cer},
			ClientAuth:   clientAuth,
			ClientCAs:    certPool,
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS13,
			CipherSuites: lib.DefaultCipherSuites,
		}

		listener, err := tls.Listen("tcp", addr, config)
		http.Serve(listener, nil)
	}
}
