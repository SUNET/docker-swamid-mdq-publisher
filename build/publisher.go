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
	baseURL := m.baseURL
	documentRoot := m.documentRoot

	userAgent := req.UserAgent()

	xff := req.Header.Get("X-FORWARDED-FOR")
	remoteAddr := req.RemoteAddr

	var requestor string
	if len(xff) > 0 {
		requestor = xff
	} else if len(remoteAddr) > 0 {
		splitAddr := strings.Split(remoteAddr, ":")
		requestor = splitAddr[0]
	} else {
		requestor = "UNKNOWN"
	}

	// Requested file
	reqFile := req.URL.EscapedPath()
	if !strings.HasPrefix(reqFile, baseURL) {
		logger(requestor, userAgent, http.StatusNotFound, reqFile, "(request to outside baseUrl)")
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return

	}
	fileName := reqFile

	mdqBaseUrl := baseURL + "/entities/"
	shaUrl := mdqBaseUrl + "%7Bsha1%7D"
	if reqFile == mdqBaseUrl {
		// /entities/ -> send full feed by sending index.html force Content-Type to make clients happier
		w.Header().Set("Content-Type", "application/samlmetadata+xml")
	} else if strings.HasPrefix(reqFile, mdqBaseUrl) {
		// Encoded request? If not encode the entityID and use it as the requested file
		// In both senarios set the correct Content-Type
		if !strings.HasPrefix(reqFile, shaUrl) {
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
	}

	var status int
	var fullPath = filepath.Join(documentRoot, path.Clean(fileName))
	var calculatedFrom string
	if file, err := os.Stat(fullPath); errors.Is(err, os.ErrNotExist) {
		status = http.StatusNotFound
	} else if file.IsDir() {
		status = http.StatusOK
		// http.ServeFile serves a redirect if a request for a directoy doesn't end with a slash - better log that
		if !strings.HasSuffix(reqFile, "/") {
			status = http.StatusMovedPermanently
		}
	} else {
		status = http.StatusOK
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

// The status codes logged below are assumptions since we don't know what http.Serve will return.
// This function should probably be replaced hlog sometime™
// https://github.com/rs/zerolog/tree/master#integration-with-nethttp
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
	// 90 sec should give time (with some headroom) for a 10 BASE-T connection to fetch our (current) biggest XML files (80MB)
	writeTimeoutEnv := getEnv("PUBLISHER_WRITETIMEOUT", "90s")
	writeTimeout, err := time.ParseDuration(writeTimeoutEnv)
	if err != nil {
		log.Fatal(err)
	}

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
		WriteTimeout: writeTimeout,
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
