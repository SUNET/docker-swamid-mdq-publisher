package main

import (
	"crypto/sha1" // #nosec MDQ is based on sha1 hashes
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
	var reqfile = req.URL.EscapedPath()

	mdqBaseUrl := baseURL + "/entities/"
	if strings.HasPrefix(reqfile, mdqBaseUrl) {
		// it is an MDQ request for specific file
		if strings.HasPrefix(reqfile, mdqBaseUrl+"%7Bsha1%7D") {
			// Already sha1 encoded. Send filename
			fileName = reqfile
		} else {
			// URL encoded entityID
			entityID := strings.TrimLeft(reqfile, mdqBaseUrl)
			decodedValue, err := url.QueryUnescape(entityID)
			if err != nil {

				var extra string = " (error decoding " + reqfile + ": " + err.Error() + ")"
				logger(requestor, userAgent, 500, reqfile, extra)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			h := sha1.New() // #nosec MDQ is based on sha1 hashes
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

	var status int
	var fullPath = filepath.Join(documentRoot, path.Clean(fileName))
	var calculatedFrom string
	if file, err := os.Stat(fullPath); errors.Is(err, os.ErrNotExist) {
		status = 404
	} else if file.IsDir() {
		status = 200
		// http.ServeFile serves a redirect if a request for a directoy doesn't end with a slash - better log that
		if !strings.HasSuffix(reqfile, "/") {
			status = 301
		}
	} else {
		status = 200
	}
	if reqfile != fileName {
		calculatedFrom = " (calculated from " + reqfile + ")"
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
	log.Printf("%s (%s) %d %s%s", requestor, userAgent, status, fileName, extra)
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
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}

	}
}
