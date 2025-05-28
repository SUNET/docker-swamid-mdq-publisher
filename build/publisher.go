package main

import (
	"context"
	"crypto/sha1" // #nosec MDQ is based on sha1 hashes
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

var version = "unspecified"

type myMux struct {
	baseURL      string
	documentRoot string
}

func (m *myMux) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	logger := hlog.FromRequest(req)
	// File to server
	baseURL := m.baseURL
	documentRoot := m.documentRoot

	incoming_xffs := req.Header["X-Forwarded-For"]
	merged_xffs := []string{}
	if len(incoming_xffs) > 0 {
		// Handle X-Forwarded-For as described by Mozilla
		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Forwarded-For
		for _, header := range incoming_xffs {
			adresses := strings.Split(header, ",")
			for _, adress := range adresses {
				adress := strings.TrimSpace(adress)
				merged_xffs = append(merged_xffs, adress)
			}

		}

		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Strs("x_forwarded_for", merged_xffs)
		})
	}

	// Requested file
	reqFile := req.URL.EscapedPath()
	if !strings.HasPrefix(reqFile, baseURL) {
		// Handle Haproxy's default method and path for Health checks
		// https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/health-checks/#http-health-checks
		if req.Method == "OPTIONS" && reqFile == "/" {
			_, err := w.Write([]byte("Meep meep"))
			if err != nil {
				logger.Err(err).Msg("Meeping failed")
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}

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

func newLogger(service, hostname string) zerolog.Logger {
	return zerolog.New(os.Stderr).With().
		Timestamp().
		Str("service", service).
		Str("hostname", hostname).
		Str("server_version", version).
		Str("go_version", runtime.Version()).
		Logger()
}

type certStore struct {
	cert *tls.Certificate
	pem  string
	key  string
	mtx  sync.RWMutex
}

func (cs *certStore) getServerCertficate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	cs.mtx.RLock()
	defer cs.mtx.RUnlock()
	return cs.cert, nil
}

func (cs *certStore) loadCert() error {
	cert, err := tls.LoadX509KeyPair(cs.pem, cs.key)
	if err != nil {
		return fmt.Errorf("unable to load x509 cert: %w", err)
	}
	cs.mtx.Lock()
	cs.cert = &cert
	cs.mtx.Unlock()

	return nil
}

func newCertStore(pem string, key string) (*certStore, error) {
	cs := &certStore{
		pem: pem,
		key: key,
	}
	err := cs.loadCert()
	if err != nil {
		return nil, err
	}

	return cs, nil
}

func main() {
	service := "swamid-mdq-publisher"
	hostname, err := os.Hostname()
	if err != nil {
		fmt.Fprintln(os.Stderr, "unable to get hostname, can not setup logging")
		os.Exit(1)
	}
	zlog := newLogger(service, hostname)

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
	tlsBool, err := strconv.ParseBool(tlsEnv)
	if err != nil {
		zlog.Fatal().Err(err).Msg("Couldn't parse bool")
	}

	serverCert := getEnv("PUBLISHER_CERT", "/etc/certs/cert.pem")
	serverKey := getEnv("PUBLISHER_KEY", "/etc/certs/privkey.pem")

	chain := aliceRequestLoggerChain(zlog)

	mux := &myMux{baseURL: baseURL, documentRoot: documentRoot}

	// Mozilla's Intermediate SSL Configuration created via
	// https://ssl-config.mozilla.org/#server=go&version=1.23.3&config=intermediate&guideline=5.7
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519, // Go 1.8+
			tls.CurveP256,
			tls.CurveP384,
			// tls.x25519Kyber768Draft00, // Go 1.23+
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	if tlsBool {
		httpServerCertStore, err := newCertStore(serverCert, serverKey)
		if err != nil {
			zlog.Fatal().Err(err).Msg("Unable to load x509 HTTP server cert from disk")
			os.Exit(1)
		}

		tlsCfg.GetCertificate = httpServerCertStore.getServerCertficate

		go func(*certStore) {
			sigHup := make(chan os.Signal, 1)
			signal.Notify(sigHup, syscall.SIGHUP)

			for range sigHup {
				zlog.Info().Msgf("HUP received")
				err = httpServerCertStore.loadCert()
				if err != nil {
					zlog.Error().Err(err).Msg("Unable to reload x509 HTTP server cert from disk")
				} else {
					zlog.Info().Msg("Reloaded x509 HTTP server cert from disk")
				}
			}
		}(httpServerCertStore)
	}

	httpHandler := chain.Then(mux)
	srv := http.Server{
		Addr:         "0.0.0.0:" + port,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: writeTimeout,
		Handler:      httpHandler,
		TLSConfig:    tlsCfg,
	}

	idleConnsClosed := make(chan struct{})
	go func(shutdownTimeout time.Duration) {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
		<-sigCh

		zlog.Info().Msgf("Graceful shutdown (timeout %s)", shutdownTimeout)

		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			zlog.Err(err).Msg("Graceful shutdown failed")
		}
		close(idleConnsClosed)
	}(writeTimeout)

	zlog.Info().Bool("tls", tlsBool).Msg("Starting up")
	if tlsBool {
		if _, err := os.Stat(serverCert); errors.Is(err, os.ErrNotExist) {
			zlog.Fatal().Err(err).Msg("Missing cert: " + serverCert)
		}
		if _, err := os.Stat(serverKey); errors.Is(err, os.ErrNotExist) {
			zlog.Fatal().Err(err).Msg("Missing key: " + serverKey)
		}

		if err := srv.ListenAndServeTLS("", ""); err != http.ErrServerClosed {
			zlog.Fatal().Err(err).Msg("Listener failed")
		}
	} else {
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			zlog.Fatal().Err(err).Msg("Listener failed")
		}
	}
	<-idleConnsClosed
}
