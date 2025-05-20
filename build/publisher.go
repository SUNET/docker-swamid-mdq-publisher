package main

import (
	"crypto/sha1" // #nosec MDQ is based on sha1 hashes
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

type myMux struct {
	baseURL      string
	documentRoot string
}

func (m *myMux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logger := hlog.FromRequest(req)
	// File to server
	baseURL := m.baseURL
	documentRoot := m.documentRoot

	xffs := req.Header["X-Forwarded-For"]
	if len(xffs) > 0 {
		// From HAProxy's documentation:
		// Since this header is always appended at the end of the existing header list, the server must be configured to always use the last occurrence of this header only.
		xff := xffs[len(xffs)-1]
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("x_forwarded_for", xff)
		})
	}

	// Requested file
	reqFile := req.URL.EscapedPath()
	if !strings.HasPrefix(reqFile, baseURL) {
		// Handle Haproxy's default method and path for Health checks
		// https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/health-checks/#http-health-checks
		if req.Method == "OPTIONS" && reqFile == "/" {
			w.Write([]byte("Meep meep"))

			return

		} else {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
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

				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str("decoding_error", err.Error())
				})

				logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
					return c.Str("req_file", reqFile)
				})
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

	fullPath := filepath.Join(documentRoot, path.Clean(fileName))

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Str("filename", fileName)
	})

	http.ServeFile(w, req, fullPath)
}

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

// Based on example at https://github.com/rs/zerolog#integration-with-nethttp
func aliceRequestLoggerChain(zlog zerolog.Logger) alice.Chain {
	chain := alice.New()

	chain = chain.Append(hlog.NewHandler(zlog))

	chain = chain.Append(hlog.AccessHandler(func(r *http.Request, status, size int, duration time.Duration) {
		hlog.FromRequest(r).Info().
			Str("method", r.Method).
			Stringer("url", r.URL).
			Int("status", status).
			Int("size", size).
			Dur("duration", duration).
			Msg("")
	}))

	chain = chain.Append(hlog.RemoteIPHandler("ip"))
	chain = chain.Append(hlog.UserAgentHandler("user_agent"))
	chain = chain.Append(hlog.RefererHandler("referer"))
	chain = chain.Append(hlog.RequestIDHandler("req_id", "Request-Id"))

	return chain
}

func main() {
	zlog := zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "swamid-mdq-publisher").
		Logger()

	baseURL := getEnv("baseURL", "")
	documentRoot := getEnv("PUBLISHER_DOCROOT", "/var/www/html")
	port := getEnv("PUBLISHER_PORT", "443")
	// 90 sec should give time (with some headroom) for a 10 BASE-T connection to fetch our (current) biggest XML files (80MB)
	writeTimeoutEnv := getEnv("PUBLISHER_WRITETIMEOUT", "90s")
	writeTimeout, err := time.ParseDuration(writeTimeoutEnv)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Couldn't parse duration")
	}

	tlsEnv := getEnv("PUBLISHER_TLS", "True")
	tls, err := strconv.ParseBool(tlsEnv)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Couldn't parse bool")
	}

	serverCert := getEnv("PUBLISHER_CERT", "/etc/certs/cert.pem")
	srvKey := getEnv("PUBLISHER_KEY", "/etc/certs/privkey.pem")

	chain := aliceRequestLoggerChain(zlog)

	mux := &myMux{baseURL: baseURL, documentRoot: documentRoot}

	httpHandler := chain.Then(mux)
	srv := http.Server{
		Addr:         "0.0.0.0:" + port,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: writeTimeout,
		Handler:      httpHandler,
	}
	zlog.Info().Bool("tls", tls).Msg("Starting up")
	if tls {
		if _, err := os.Stat(serverCert); errors.Is(err, os.ErrNotExist) {
			zlog.Fatal().Err(err).Msg("Missing cert: " + serverCert)
		}
		if _, err := os.Stat(srvKey); errors.Is(err, os.ErrNotExist) {
			zlog.Fatal().Err(err).Msg("Missing key: " + srvKey)
		}

		if err := srv.ListenAndServeTLS(serverCert, srvKey); err != nil {
			zlog.Fatal().Err(err).Msg("Listen failed")
		}
	} else {
		if err := srv.ListenAndServe(); err != nil {
			zlog.Fatal().Err(err).Msg("Listen failed")
		}
	}
}
