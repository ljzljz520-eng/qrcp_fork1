package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/claudiodangelis/qrcp/body"
	"github.com/claudiodangelis/qrcp/config"
)

func testConfig(path string, ephemeral bool) config.Config {
	return config.Config{
		Interface: "any",
		Bind:      "127.0.0.1",
		Port:      0,
		Path:      path,
		Ephemeral: ephemeral,
	}
}

func testClient(t *testing.T, followRedirects bool) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := &http.Client{
		Jar: jar,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	if !followRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}

func newTestServer(t *testing.T, cfg *config.Config) *Server {
	t.Helper()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("server.New() error: %v", err)
	}
	t.Cleanup(func() {
		_ = srv.instance.Shutdown(context.Background())
	})
	return srv
}

func readBody(t *testing.T, r *http.Response) string {
	t.Helper()
	defer r.Body.Close()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEphemeralSendGate(t *testing.T) {
	cfg := testConfig("sendgate", true)
	srv := newTestServer(t, &cfg)

	payload := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(payload, []byte("ephemeral-payload"), 0600); err != nil {
		t.Fatal(err)
	}
	srv.Send(body.Body{Path: payload, Filename: "secret.txt"})

	// 1. Landing page is the fingerprint confirmation page.
	c := testClient(t, true)
	resp, err := c.Get(srv.SendURL)
	if err != nil {
		t.Fatal(err)
	}
	page := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("landing status = %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{
		"Verify this connection",
		srv.ShortFingerprint(),
		srv.PublicKeyFingerprint,
		"/confirm/sendgate",
		"Confirm &amp; Download",
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("confirmation page missing %q", want)
		}
	}

	// 2. A wrong fingerprint produces a blocking warning, no confirm button.
	wrongURL := strings.Replace(srv.SendURL, "fp="+srv.PublicKeyFingerprint,
		"fp="+strings.Repeat("0", 64), 1)
	resp, err = c.Get(wrongURL)
	if err != nil {
		t.Fatal(err)
	}
	warning := readBody(t, resp)
	if !strings.Contains(warning, "Fingerprint mismatch") {
		t.Fatal("expected fingerprint mismatch warning")
	}
	if strings.Contains(warning, "Confirm &amp;") {
		t.Fatal("mismatch page must not offer a confirm button")
	}

	// 3. Confirmation with the wrong fingerprint is rejected.
	confirmURL := srv.BaseURL + "/confirm/sendgate"
	resp, err = c.PostForm(confirmURL, url.Values{"fp": {"deadbeef"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad-fp confirm status = %d, want 400", resp.StatusCode)
	}
	resp.Body.Close()

	// 4. Confirmation with the correct fingerprint redirects (303).
	noRedirect := testClient(t, false)
	noRedirect.Jar = c.Jar
	resp, err = noRedirect.PostForm(confirmURL, url.Values{"fp": {srv.PublicKeyFingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("confirm status = %d, want 303", resp.StatusCode)
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loc.Path, "/send/sendgate") || loc.Query().Get("fp") != srv.PublicKeyFingerprint {
		t.Fatalf("unexpected redirect location: %s", loc)
	}

	// 5. After confirmation the file is served.
	resp, err = c.Get(srv.SendURL)
	if err != nil {
		t.Fatal(err)
	}
	got := readBody(t, resp)
	if got != "ephemeral-payload" {
		t.Fatalf("downloaded content = %q, want %q", got, "ephemeral-payload")
	}
}

func TestEphemeralReceiveGate(t *testing.T) {
	cfg := testConfig("recvgate", true)
	srv := newTestServer(t, &cfg)
	outputDir := t.TempDir()
	if err := srv.ReceiveTo(outputDir); err != nil {
		t.Fatal(err)
	}

	c := testClient(t, true)

	// Landing page is the confirmation page (upload wording).
	resp, err := c.Get(srv.ReceiveURL)
	if err != nil {
		t.Fatal(err)
	}
	page := readBody(t, resp)
	if !strings.Contains(page, "Confirm &amp; Continue") || !strings.Contains(page, srv.ShortFingerprint()) {
		t.Fatal("receive landing page should be the confirmation page")
	}

	// Uploads are rejected before confirmation.
	upload := func(t *testing.T) *http.Response {
		t.Helper()
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, err := mw.CreateFormFile("files", "upload.txt")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte("uploaded-content")); err != nil {
			t.Fatal(err)
		}
		mw.Close()
		req, err := http.NewRequest(http.MethodPost, srv.ReceiveURL, &buf)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	if resp := upload(t); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unconfirmed upload status = %d, want 403", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// Confirm, then the upload form is served.
	confirmURL := srv.BaseURL + "/confirm/recvgate"
	resp, err = c.PostForm(confirmURL, url.Values{"fp": {srv.PublicKeyFingerprint}})
	if err != nil {
		t.Fatal(err)
	}
	page = readBody(t, resp)
	if !strings.Contains(page, "Files to transfer") {
		t.Fatal("confirmed receive page should contain the upload form")
	}

	// Confirmed upload succeeds and the file lands in the output directory.
	resp = upload(t)
	donePage := readBody(t, resp)
	if !strings.Contains(donePage, "Successfully transferred to") || !strings.Contains(donePage, "upload.txt") {
		t.Fatalf("upload not completed, page: %s", donePage)
	}
	data, err := os.ReadFile(filepath.Join(outputDir, "upload.txt"))
	if err != nil {
		t.Fatalf("uploaded file missing: %v", err)
	}
	if string(data) != "uploaded-content" {
		t.Fatalf("uploaded content = %q", string(data))
	}
}

func TestPlainHTTPSendStillWorks(t *testing.T) {
	cfg := testConfig("plainsend", false)
	srv := newTestServer(t, &cfg)

	payload := filepath.Join(t.TempDir(), "plain.txt")
	if err := os.WriteFile(payload, []byte("plain-payload"), 0600); err != nil {
		t.Fatal(err)
	}
	srv.Send(body.Body{Path: payload, Filename: "plain.txt"})

	c := testClient(t, true)
	resp, err := c.Get(srv.SendURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := readBody(t, resp); got != "plain-payload" {
		t.Fatalf("plain http download = %q", got)
	}
}
