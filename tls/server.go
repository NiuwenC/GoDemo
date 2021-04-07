package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

func helloHandler(w http.ResponseWriter, r *http.Request) {
	// Write "Hello, world!" to the response body
	io.WriteString(w, "Hello, world!\n")
}

func main() {
	// Set up a /hello resource handler
	http.HandleFunc("/hello", helloHandler)

	// Listen to port 8080 and wait
	//log.Fatal(http.ListenAndServe(":8080", nil))
	//log.Fatal(http.ListenAndServeTLS(":8443", "cert.pem", "key.pem", nil))

	caCert, err := ioutil.ReadFile("cert.pem")
	if err != nil {
		log.Fatal(err)
	}

	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// 创建TLS 配置 使用CA 池
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	// 创建服务
	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}
