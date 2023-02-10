package main

import (
	"log"
	"net/http"
	"path"
	"path/filepath"
)

type myMux struct{}

func (m *myMux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	log.Printf("looking for EscapedPath: %s\n", req.URL.EscapedPath())
	http.ServeFile(w, req, filepath.Join("var/www/html", path.Clean(req.URL.EscapedPath())))
}

func main() {
	var (
		host         = "mdx.qa.swamid.se"
		port         = "443"
		serverCert   = "/etc/dehydrated/certs/cert.pem"
		srvKey       = "/etc/dehydrated/certs/privkey.pem"
		//documentRoot = "/var/www/html"
	)

	/*server := &http.Server{
		Addr:         ":" + port,
		ReadTimeout:  5 * time.Minute, // 5 min to allow for delays when 'curl' on OSx prompts for username/password
		WriteTimeout: 10 * time.Second,
		TLSConfig:    &tls.Config{ServerName: host},
	}*/


	mux := &myMux{}
	// log.Fatal(http.ListenAndServe("127.0.0.1:8080", mux))

	log.Printf("Starting HTTPS server on host %s and port %s", host, port)
	if err := http.ListenAndServeTLS("0.0.0.0:"+port, serverCert, srvKey , mux); err != nil {
		log.Fatal(err)
	}
}
