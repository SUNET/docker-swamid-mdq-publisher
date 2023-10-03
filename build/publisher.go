package main

import (
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
)

type myMux struct {
	baseURL      string
	documentRoot string
}

func (m *myMux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	// File to server
	var fileName string
	baseURL := m.baseURL
	var baseURLLength = len(baseURL)
	documentRoot := m.documentRoot

	xff := req.Header.Get("X-FORWARDED-FOR")
	remoteAddr := req.RemoteAddr

	var requestor string
	if len(xff) > 0 {
		requestor = xff
	} else if len(remoteAddr) > 0 {
		split_addr := strings.Split(remoteAddr, ":")
		requestor = split_addr[0]
	} else {
		requestor = "UNKNOWN"
	}

	// Requested file
	var reqfile = req.URL.EscapedPath()
	if len(reqfile) > 10+baseURLLength && reqfile[baseURLLength:10+baseURLLength] == "/entities/" {
		// it is an MDQ request for specific file
		if (len(reqfile) > 19+baseURLLength && reqfile[baseURLLength:20+baseURLLength] == "/entities/%7Bsha1%7D") || len(reqfile) == 10+baseURLLength {
			// Already sha1 encoded. Send filename
			fileName = reqfile
		} else {
			// URL encoded entityID
			decodedValue, err := url.QueryUnescape(reqfile[10+baseURLLength:])
			if err != nil {
				log.Fatal(err)
				return
			}
			h := sha1.New()
			h.Write([]byte(decodedValue))
			// send sha1 version of entityID
			fileName = baseURL + "/entities/%7Bsha1%7D" + hex.EncodeToString(h.Sum(nil))
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
	} else {
		if reqfile[baseURLLength:] == "/entities/" {
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
		}
		// Either /entities/ -> send full feed by sending index.html
		// Or someting else. Send that file :-)
		fileName = reqfile
	}

	var fullPath = filepath.Join(documentRoot, path.Clean(fileName))
	if _, err := os.Stat(fullPath); errors.Is(err, os.ErrNotExist) {
		if reqfile == fileName {
			log.Printf("Request from %s, Missing file %s", requestor, fileName)
		} else {
			log.Printf("Request from %s, Missing file %s, was %s", requestor, fileName, reqfile)
		}
	} else {
		if reqfile == fileName {
			log.Printf("Request from %s, serving for: %s\n", requestor, fileName)
		} else {
			log.Printf("Request from %s, looking for: %s, serving: %s\n", requestor, reqfile, fileName)
		}
	}
	http.ServeFile(w, req, fullPath)
}

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

func main() {

	baseURL := getEnv("baseURL", "")
	documentRoot := getEnv("PUBLISHER_DOCROOT", "/var/www/html")
	port := getEnv("PUBLISHER_PORT", "443")
	tls_env := getEnv("PUBLISHER_TLS", "True")
	tls, err := strconv.ParseBool(tls_env)
	if err != nil {
		log.Fatal(err)
	}

	serverCert := getEnv("PUBLISHER_CERT", "/etc/certs/cert.pem")
	srvKey := getEnv("PUBLISHER_KEY", "/etc/certs/privkey.pem")

	mux := &myMux{baseURL: baseURL, documentRoot: documentRoot}
	if tls {
		if _, err := os.Stat(serverCert); errors.Is(err, os.ErrNotExist) {
			log.Printf("Missing cert %s", serverCert)
		}
		if _, err := os.Stat(srvKey); errors.Is(err, os.ErrNotExist) {
			log.Printf("Missing key %s", srvKey)
		}

		log.Print("Starting up\n")
		if err := http.ListenAndServeTLS("0.0.0.0:"+port, serverCert, srvKey, mux); err != nil {
			log.Fatal(err)
		}
	} else {
		if err := http.ListenAndServe("0.0.0.0:"+port, mux); err != nil {
			log.Fatal(err)
		}

	}
}
