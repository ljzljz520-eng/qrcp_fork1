package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"image/jpeg"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/claudiodangelis/qrcp/body"
	"github.com/claudiodangelis/qrcp/config"
	"github.com/claudiodangelis/qrcp/identity"
	"github.com/claudiodangelis/qrcp/pages"
	"github.com/claudiodangelis/qrcp/qr"
	"github.com/claudiodangelis/qrcp/util"
	"gopkg.in/cheggaaa/pb.v1"
)

// sessionCookieName is the cookie used to tie the fingerprint confirmation
// to the requests of a single client in ephemeral TLS mode.
const sessionCookieName = "qrcp-session"

type sessionState struct {
	confirmed bool
}

// Server is the server
type Server struct {
	BaseURL string
	// SendURL is the URL used to send the file
	SendURL string
	// ReceiveURL is the URL used to Receive the file
	ReceiveURL  string
	instance    *http.Server
	body        body.Body
	outputDir   string
	stopChannel chan bool
	// expectParallelRequests is set to true when qrcp sends files, in order
	// to support downloading of parallel chunks
	expectParallelRequests bool

	// Ephemeral is true when the server runs with a temporary self-signed
	// certificate gated by fingerprint confirmation.
	Ephemeral bool
	// PublicKeyFingerprint is the hex SHA-256 of the Ed25519 public key
	// (identical to the certificate's SubjectPublicKeyInfo hash).
	PublicKeyFingerprint string
	// CertFingerprint is the hex SHA-256 of the DER certificate.
	CertFingerprint string

	mux          *http.ServeMux
	path         string
	identity     *identity.Identity
	sessions     map[string]*sessionState
	sessionsMu   sync.Mutex
	transferOnce sync.Once
}

// ReceiveTo sets the output directory
func (s *Server) ReceiveTo(dir string) error {
	output, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	// Check if the output dir exists
	fileinfo, err := os.Stat(output)
	if err != nil {
		return err
	}
	if !fileinfo.IsDir() {
		return fmt.Errorf("%s is not a valid directory", output)
	}
	s.outputDir = output
	return nil
}

// Send adds a handler for sending the file
func (s *Server) Send(p body.Body) {
	s.body = p
	s.expectParallelRequests = true
}

// DisplayQR creates a handler for serving the QR code in the browser
func (s *Server) DisplayQR(url string) {
	const PATH = "/qr"
	qrImg := qr.RenderImage(url)
	s.mux.HandleFunc(PATH, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		if err := jpeg.Encode(w, qrImg, nil); err != nil {
			panic(err)
		}
	})
	openBrowser(s.BaseURL + PATH)
}

// Wait for transfer to be completed, it waits forever if kept awlive
func (s *Server) Wait() error {
	<-s.stopChannel
	if err := s.instance.Shutdown(context.Background()); err != nil {
		log.Println(err)
	}
	if s.body.DeleteAfterTransfer {
		if err := s.body.Delete(); err != nil {
			panic(err)
		}
	}
	return nil
}

// Shutdown the server
func (s *Server) Shutdown() {
	s.stopChannel <- true
}

// ShortFingerprint returns the grouped, human-friendly fingerprint that the
// user must verify on the phone.
func (s *Server) ShortFingerprint() string {
	if s.identity == nil {
		return ""
	}
	return identity.ShortFingerprint(s.PublicKeyFingerprint)
}

// getOrCreateSession returns the session associated with the request cookie,
// creating a new unconfirmed one (and setting the cookie) if needed.
func (s *Server) getOrCreateSession(w http.ResponseWriter, r *http.Request) *sessionState {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	token := ""
	if c, err := r.Cookie(sessionCookieName); err == nil {
		if _, ok := s.sessions[c.Value]; ok {
			token = c.Value
		}
	}
	if token == "" {
		value, err := util.GetSessionID()
		if err != nil {
			log.Println("Unable to generate session ID", err)
			return &sessionState{}
		}
		http.SetCookie(w, &http.Cookie{
			Name:     sessionCookieName,
			Value:    value,
			Path:     "/",
			HttpOnly: true,
			Secure:   s.Ephemeral,
			SameSite: http.SameSiteLaxMode,
		})
		s.sessions[value] = &sessionState{}
		token = value
	}
	return s.sessions[token]
}

// isConfirmed reports whether the request belongs to a confirmed session.
func (s *Server) isConfirmed(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()
	state, ok := s.sessions[c.Value]
	return ok && state.confirmed
}

// serveConfirm renders the fingerprint confirmation page. If the fingerprint
// carried in the URL does not match the server identity, a blocking warning
// page is served instead.
func (s *Server) serveConfirm(w http.ResponseWriter, r *http.Request) {
	received := r.URL.Query().Get("fp")
	action := "upload"
	if s.expectParallelRequests {
		action = "download"
	}
	data := struct {
		Route               string
		Action              string
		Fingerprint         string
		FullFingerprint     string
		ReceivedFingerprint string
		Match               bool
	}{
		Route:               "/confirm/" + s.path,
		Action:              action,
		Fingerprint:         identity.ShortFingerprint(s.PublicKeyFingerprint),
		FullFingerprint:     s.PublicKeyFingerprint,
		ReceivedFingerprint: received,
		Match:               received == s.PublicKeyFingerprint,
	}
	serveTemplate("confirm", pages.Confirm, w, data)
}

// New instance of the server
func New(cfg *config.Config) (*Server, error) {

	app := &Server{}
	// Ephemeral TLS: explicit flag, or `--secure` without a certificate
	// (which would otherwise fail to start the server).
	ephemeral := cfg.Ephemeral || (cfg.Secure && cfg.TlsCert == "" && cfg.TlsKey == "")
	secure := cfg.Secure || ephemeral
	app.Ephemeral = ephemeral
	app.sessions = map[string]*sessionState{}
	// Get the address of the configured interface to bind the server to.
	// If `bind` configuration parameter has been configured, it takes precedence
	bind, err := util.GetInterfaceAddress(cfg.Interface)
	if err != nil {
		return &Server{}, err
	}
	if cfg.Bind != "" {
		bind = cfg.Bind
	}
	// Generate the one-shot Ed25519 identity and self-signed certificate.
	if ephemeral {
		id, err := identity.Generate(bind)
		if err != nil {
			return nil, fmt.Errorf("unable to generate ephemeral TLS identity: %w", err)
		}
		app.identity = id
		app.PublicKeyFingerprint = id.PublicKeyFingerprint
		app.CertFingerprint = id.CertFingerprint
	}
	// Create a listener. If `port: 0`, a random one is chosen
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", bind, cfg.Port))
	if err != nil {
		return nil, err
	}
	// Set the value of computed port
	port := listener.Addr().(*net.TCPAddr).Port
	// Set the host
	host := fmt.Sprintf("%s:%d", bind, port)
	// Get a random path to use
	path := cfg.Path
	if path == "" {
		path = util.GetRandomURLPath()
	}
	app.path = path
	// Set the hostname
	hostname := fmt.Sprintf("%s:%d", bind, port)
	// Use external IP when using `interface: any`, unless a FQDN is set
	if bind == "0.0.0.0" && cfg.FQDN == "" {
		fmt.Println("Retrieving the external IP...")
		extIP, err := util.GetExternalIP()
		if err != nil {
			panic(err)
		}
		extIPString := extIP.String()
		fmtstring := "%s:%d"
		if strings.Count(extIPString, ":") >= 2 {
			// IPv6 address, wrap it in [] to add a port
			fmtstring = "[%s]:%d"
		}
		hostname = fmt.Sprintf(fmtstring, extIPString, port)
	}
	// Use a fully-qualified domain name if set
	if cfg.FQDN != "" {
		hostname = fmt.Sprintf("%s:%d", cfg.FQDN, port)
	}
	// Set URLs
	protocol := "http"
	if secure {
		protocol = "https"
	}
	app.BaseURL = fmt.Sprintf("%s://%s", protocol, hostname)
	fingerprintQuery := ""
	if ephemeral {
		fingerprintQuery = "?fp=" + app.PublicKeyFingerprint
	}
	app.SendURL = fmt.Sprintf("%s/send/%s%s",
		app.BaseURL, path, fingerprintQuery)
	app.ReceiveURL = fmt.Sprintf("%s/receive/%s%s",
		app.BaseURL, path, fingerprintQuery)
	// Per-instance mux: handlers are scoped to this server instead of the
	// process-wide default mux.
	mux := http.NewServeMux()
	app.mux = mux
	// Create a server
	tlsConfig := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	if ephemeral {
		tlsConfig.Certificates = []tls.Certificate{app.identity.Certificate}
	}
	httpserver := &http.Server{
		Addr:         host,
		Handler:      mux,
		TLSConfig:    tlsConfig,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	app.instance = httpserver
	// Create channel to send message to stop server. It is buffered so
	// concurrent producers (transfer completion, error paths, signals) never
	// block waiting for Wait().
	app.stopChannel = make(chan bool, 8)
	// Create cookie used to verify request is coming from first client to connect
	cookie := http.Cookie{Name: "qrcp", Value: ""}
	// Gracefully shutdown when an OS signal is received or when "q" is pressed
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		app.stopChannel <- true
	}()
	// The handler adds and removes from the sync.WaitGroup
	// When the group is zero all requests are completed
	// and the server is shutdown
	var waitgroup sync.WaitGroup
	waitgroup.Add(1)
	var initCookie sync.Once
	// Confirmation handler (ephemeral mode only): marks the session as
	// verified and redirects back to the transfer page.
	mux.HandleFunc("/confirm/"+path, func(w http.ResponseWriter, r *http.Request) {
		if !app.Ephemeral {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		state := app.getOrCreateSession(w, r)
		if r.FormValue("fp") != app.PublicKeyFingerprint {
			http.Error(w, "fingerprint mismatch", http.StatusBadRequest)
			return
		}
		app.sessionsMu.Lock()
		state.confirmed = true
		app.sessionsMu.Unlock()
		route := "/receive/" + path
		if app.expectParallelRequests {
			route = "/send/" + path
		}
		http.Redirect(w, r, route+"?fp="+app.PublicKeyFingerprint, http.StatusSeeOther)
	})
	// Create handlers
	// Send handler (sends file to caller)
	mux.HandleFunc("/send/"+path, func(w http.ResponseWriter, r *http.Request) {
		if app.Ephemeral {
			state := app.getOrCreateSession(w, r)
			if !state.confirmed {
				app.serveConfirm(w, r)
				return
			}
			if !cfg.KeepAlive && strings.HasPrefix(r.Header.Get("User-Agent"), "Mozilla") {
				// The first confirmed download takes over the initial wait
				// group slot; every additional parallel chunk request adds
				// and removes its own slot.
				firstConfirmed := false
				app.transferOnce.Do(func() {
					firstConfirmed = true
				})
				if !firstConfirmed {
					waitgroup.Add(1)
				}
				defer waitgroup.Done()
			}
		} else if !cfg.KeepAlive && strings.HasPrefix(r.Header.Get("User-Agent"), "Mozilla") {
			if cookie.Value == "" {
				initCookie.Do(func() {
					value, err := util.GetSessionID()
					if err != nil {
						log.Println("Unable to generate session ID", err)
						app.stopChannel <- true
						return
					}
					cookie.Value = value
					http.SetCookie(w, &cookie)
				})
			} else {
				// Check for the expected cookie and value
				// If it is missing or doesn't match
				// return a 400 status
				rcookie, err := r.Cookie(cookie.Name)
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				if rcookie.Value != cookie.Value {
					http.Error(w, "mismatching cookie", http.StatusBadRequest)
					return
				}
				// If the cookie exits and matches
				// this is an aadditional request.
				// Increment the waitgroup
				waitgroup.Add(1)
			}
			// Remove connection from the waitgroup when done
			defer waitgroup.Done()
		}
		w.Header().Set("Content-Disposition", "attachment; filename=\""+
			app.body.Filename+
			"\"; filename*=UTF-8''"+
			url.QueryEscape(app.body.Filename))
		http.ServeFile(w, r, app.body.Path)
	})
	// Upload handler (serves the upload page)
	mux.HandleFunc("/receive/"+path, func(w http.ResponseWriter, r *http.Request) {
		htmlVariables := struct {
			Route string
			File  string
		}{}
		htmlVariables.Route = "/receive/" + path
		if app.Ephemeral {
			state := app.getOrCreateSession(w, r)
			if !state.confirmed {
				if r.Method == http.MethodPost {
					http.Error(w, "session not confirmed", http.StatusForbidden)
					return
				}
				app.serveConfirm(w, r)
				return
			}
		}
		switch r.Method {
		case "POST":
			filenames := util.ReadFilenames(app.outputDir)
			reader, err := r.MultipartReader()
			if err != nil {
				fmt.Fprintf(w, "Upload error: %v\n", err)
				log.Printf("Upload error: %v\n", err)
				app.stopChannel <- true
				return
			}
			transferredFiles := []string{}
			progressBar := pb.New64(r.ContentLength)
			progressBar.ShowCounters = false
			for {
				part, err := reader.NextPart()
				if err == io.EOF {
					break
				}
				// iIf part.FileName() is empty, skip this iteration.
				if part.FileName() == "" {
					continue
				}
				// Prepare the destination
				fileName := getFileName(filepath.Base(part.FileName()), filenames)
				out, err := os.Create(filepath.Join(app.outputDir, fileName))
				if err != nil {
					// Output to server
					fmt.Fprintf(w, "Unable to create the file for writing: %s\n", err)
					// Output to console
					log.Printf("Unable to create the file for writing: %s\n", err)
					// Send signal to server to shutdown
					app.stopChannel <- true
					return
				}
				defer out.Close()
				// Add name of new file
				filenames = append(filenames, fileName)
				// Write the content from POSTed file to the out
				fmt.Println("Transferring file: ", out.Name())
				progressBar.Prefix(out.Name())
				progressBar.Start()
				buf := make([]byte, 1024)
				for {
					// Read a chunk
					n, err := part.Read(buf)
					if err != nil && err != io.EOF {
						// Output to server
						fmt.Fprintf(w, "Unable to write file to disk: %v", err)
						// Output to console
						fmt.Printf("Unable to write file to disk: %v", err)
						// Send signal to server to shutdown
						app.stopChannel <- true
						return
					}
					if n == 0 {
						break
					}
					// Write a chunk
					if _, err := out.Write(buf[:n]); err != nil {
						// Output to server
						fmt.Fprintf(w, "Unable to write file to disk: %v", err)
						// Output to console
						log.Printf("Unable to write file to disk: %v", err)
						// Send signal to server to shutdown
						app.stopChannel <- true
						return
					}
					progressBar.Add(n)
				}
				transferredFiles = append(transferredFiles, out.Name())
			}
			progressBar.FinishPrint("File transfer completed")
			// Set the value of the variable to the actually transferred files
			htmlVariables.File = strings.Join(transferredFiles, ", ")
			serveTemplate("done", pages.Done, w, htmlVariables)
			if !cfg.KeepAlive {
				app.stopChannel <- true
			}
		case "GET":
			serveTemplate("upload", pages.Upload, w, htmlVariables)
		}
	})
	// Wait for all wg to be done, then send shutdown signal
	go func() {
		waitgroup.Wait()
		if cfg.KeepAlive || !app.expectParallelRequests {
			return
		}
		app.stopChannel <- true
	}()
	go func() {
		netListener := tcpKeepAliveListener{listener.(*net.TCPListener)}
		if secure {
			if ephemeral {
				// The certificate is already loaded in TLSConfig, so pass
				// empty file paths: ServeTLS skips loading when certificates
				// are already present.
				if err := httpserver.ServeTLS(netListener, "", ""); err != http.ErrServerClosed {
					log.Fatalln("error starting the server:", err)
				}
			} else {
				if err := httpserver.ServeTLS(netListener, cfg.TlsCert, cfg.TlsKey); err != http.ErrServerClosed {
					log.Fatalln("error starting the server:", err)
				}
			}
		} else {
			if err := httpserver.Serve(netListener); err != http.ErrServerClosed {
				log.Fatalln("error starting the server", err)
			}
		}
	}()
	return app, nil
}

// openBrowser navigates to a url using the default system browser
func openBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("failed to open browser on platform: %s", runtime.GOOS)
	}
	if err != nil {
		log.Fatal(err)
	}
}
