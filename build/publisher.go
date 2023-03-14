package main

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"os"
)

type myMux struct{}

func (m *myMux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// File to server
	var fileName string
	// Requested file
	var reqfile = req.URL.EscapedPath()
	if len(reqfile) > 10 && reqfile[:10] == "/entities/" {
		// it is an MDQ request for specific file
		if len(reqfile) > 19 && reqfile[:20] == "/entities/%7Bsha1%7D" {
			// Already sha1 encoded. Send filename
			fileName = reqfile
		} else {
			// URL encoded entityID
			decodedValue, err := url.QueryUnescape(reqfile[10:])
			if err != nil {
				log.Fatal(err)
				return
			}
			h := sha1.New()
			h.Write([]byte(decodedValue))
			// send sha1 version of entityID
			fileName = "/entities/%7Bsha1%7D" + hex.EncodeToString(h.Sum(nil))
		}
	} else {
		// Either /entities/ -> send full feed by sending index.html
		// Or someting else. Send that file :-)
		fileName = reqfile
	}

	var fullPath = filepath.Join("/var/www/html", path.Clean(fileName))
	if _, err := os.Stat(fullPath); errors.Is(err, os.ErrNotExist) {
		if reqfile == fileName {
			log.Printf("Missing file %s", fullPath)
		} else {
			log.Printf("Missing file %s, was %s", fullPath, reqfile)
		}
	} else {
		if reqfile == fileName {
			log.Printf("serving: %s\n", fileName)
		} else {
			log.Printf("looking for: %s, serving %s\n", reqfile, fileName)
		}
	}
	http.ServeFile(w, req, fullPath)
}

func main() {
	var (
		port         = "443"
		serverCert   = "/etc/certs/cert.pem"
		srvKey       = "/etc/certs/privkey.pem"
		//documentRoot = "/var/www/html"
	)

	log.Print("Starting up\n")
	mux := &myMux{}
	if err := http.ListenAndServeTLS("0.0.0.0:"+port, serverCert, srvKey , mux); err != nil {
		log.Fatal(err)
	}
}
