package main

import (
	"crypto/sha1" // #nosec MDQ is based on sha1 hashes
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
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

	userAgent := req.UserAgent()

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
	var reqFile = req.URL.EscapedPath()

	mdqBaseUrl := baseURL + "/entities/"
	shaUrl := mdqBaseUrl + "%7Bsha1%7D"
	if strings.HasPrefix(reqFile, mdqBaseUrl) {
		// it is an MDQ request for specific file
		if strings.HasPrefix(reqFile, shaUrl) {
			// Already sha1 encoded. Send filename
			fileName = reqFile
		} else {
			// URL encoded entityID
			entityID := strings.TrimPrefix(reqFile, mdqBaseUrl)
			decodedValue, err := url.QueryUnescape(entityID)
			if err != nil {

				extra := fmt.Sprintf("(error decoding %s: %s)", reqFile, err)
				logger(requestor, userAgent, 500, reqFile, extra)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			h := sha1.New() // #nosec MDQ is based on sha1 hashes
			h.Write([]byte(decodedValue))
			// send sha1 version of entityID
			fileName = shaUrl + hex.EncodeToString(h.Sum(nil))
		}
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
	} else {
		if reqFile[baseURLLength:] == "/entities/" {
			w.Header().Set("Content-Type", "application/samlmetadata+xml")
		}
		// Either /entities/ -> send full feed by sending index.html
		// Or someting else. Send that file :-)
		fileName = reqFile
	}

	var status int
	var fullPath = filepath.Join(documentRoot, path.Clean(fileName))
	var calculatedFrom string
	if file, err := os.Stat(fullPath); errors.Is(err, os.ErrNotExist) {
		status = 404
	} else if file.IsDir() {
		status = 200
		// http.ServeFile serves a redirect if a request for a directoy doesn't end with a slash - better log that
		if !strings.HasSuffix(reqFile, "/") {
			status = 301
		}
	} else {
		status = 200
	}
	if reqFile != fileName {
		calculatedFrom = "(calculated from " + reqFile + ")"
	}

	logger(requestor, userAgent, status, fileName, calculatedFrom)
	http.ServeFile(w, req, fullPath)
}

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

func logger(requestor string, userAgent string, status int, fileName string, extra string) {
	delimiter := ""
	if extra != "" {
		delimiter = " "
	}
	log.Printf("%s (%s) %d %s%s%s", requestor, userAgent, status, fileName, delimiter, extra)
}

func main() {

	baseURL := getEnv("baseURL", "")
	documentRoot := getEnv("PUBLISHER_DOCROOT", "/var/www/html")
	port := getEnv("PUBLISHER_PORT", "443")
	tlsEnv := getEnv("PUBLISHER_TLS", "True")
	tls, err := strconv.ParseBool(tlsEnv)
	if err != nil {
		log.Fatal(err)
	}

	serverCert := getEnv("PUBLISHER_CERT", "/etc/certs/cert.pem")
	srvKey := getEnv("PUBLISHER_KEY", "/etc/certs/privkey.pem")

	mux := &myMux{baseURL: baseURL, documentRoot: documentRoot}
	srv := http.Server{
		Addr:         "0.0.0.0:" + port,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      mux,
	}
	if tls {
		if _, err := os.Stat(serverCert); errors.Is(err, os.ErrNotExist) {
			log.Printf("Missing cert %s", serverCert)
		}
		if _, err := os.Stat(srvKey); errors.Is(err, os.ErrNotExist) {
			log.Printf("Missing key %s", srvKey)
		}

		log.Print("Starting up\n")
		if err := srv.ListenAndServeTLS(serverCert, srvKey); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Print("Starting up (without TLS)\n")
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}

	}
}
