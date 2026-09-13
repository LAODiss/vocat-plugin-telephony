// Command telephony is the backend of the vocat "电话助手" plugin.
//
// vocat already has a dialpad, answer/hangup, call history, recording and
// incoming-call notifications. This plugin adds the parts vocat has no place
// for: an ordered incoming-call rule policy, an address book, a voicemail
// mailbox, per-event notification templates, and sub-daily keep-alive tasks.
//
// Two operating modes, because vocat's reverse proxy strips the admin session
// cookie and CSRF token before a request reaches a plugin backend:
//
//   - Panel mode (default). The browser panel evaluates rules and performs
//     answer/reject with the operator's own session. Nothing happens while the
//     page is closed.
//   - Server-side mode (opt-in). The operator stores admin credentials and this
//     process logs into vocat itself, so rules and voicemail work unattended.
//     That is a real privilege escalation and is off until explicitly enabled.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"vocat-plugin-telephony/internal/contacts"
	"vocat-plugin-telephony/internal/engine"
	"vocat-plugin-telephony/internal/notify"
	"vocat-plugin-telephony/internal/recorder"
	"vocat-plugin-telephony/internal/rules"
	"vocat-plugin-telephony/internal/sipgw"
	"vocat-plugin-telephony/internal/store"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("telephony: ")

	listen := strings.TrimSpace(os.Getenv("VOCAT_PLUGIN_LISTEN"))
	dataDir := strings.TrimSpace(os.Getenv("VOCAT_PLUGIN_DATA_DIR"))
	if listen == "" || dataDir == "" {
		log.Fatal("VOCAT_PLUGIN_LISTEN and VOCAT_PLUGIN_DATA_DIR are required; this binary is launched by vocat")
	}

	database, err := store.Open(dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	runtime := engine.New(database, logger)
	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 40*time.Second)
	if err := runtime.Reload(startupCtx); err != nil {
		// A bad or absent credential set must not stop the panel from loading;
		// the status endpoint reports why server-side mode is idle.
		logger.Warn("server-side mode is not active", "error", err)
	}
	cancelStartup()

	srv := &server{store: database, engine: runtime, logger: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", srv.handleHealth)
	mux.HandleFunc("/status", srv.handleStatus)
	mux.HandleFunc("/config", srv.handleConfig)
	mux.HandleFunc("/rules", srv.handleRules)
	mux.HandleFunc("/rules/evaluate", srv.handleEvaluate)
	mux.HandleFunc("/contacts", srv.handleContacts)
	mux.HandleFunc("/voicemail/settings", srv.handleVoicemailSettings)
	mux.HandleFunc("/voicemail/messages", srv.handleMessages)
	mux.HandleFunc("/voicemail/messages/", srv.handleMessage)
	mux.HandleFunc("/notify", srv.handleNotify)
	mux.HandleFunc("/notify/test", srv.handleNotifyTest)
	mux.HandleFunc("/keepalive", srv.handleKeepalive)
	mux.HandleFunc("/events", srv.handleEvents)
	mux.HandleFunc("/recording/settings", srv.handleRecordingSettings)
	mux.HandleFunc("/calls", srv.handleCalls)
	mux.HandleFunc("/calls/", srv.handleCall)
	mux.HandleFunc("/sip/settings", srv.handleSIPSettings)
	mux.HandleFunc("/sip/status", srv.handleSIPStatus)

	httpServer := &http.Server{
		Addr:              listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	runCtx, stopRun := context.WithCancel(context.Background())
	go runtime.Run(runCtx)

	// The SIP gateway needs a logged-in vocat client, which Reload above either
	// established or deliberately left off. A failed start is logged, never
	// fatal: the panel still works and the status endpoint explains why.
	srv.applySIPGateway()

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	go func() {
		<-signalCtx.Done()
		stopRun()
		srv.stopSIPGateway()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()

	logger.Info("listening", "address", listen)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
	stopRun()
}

type server struct {
	store  *store.Store
	engine *engine.Engine
	logger *slog.Logger

	// gatewayMu guards the SIP gateway handle. The gateway is rebuilt whenever
	// the SIP settings or the vocat credentials change, and stopped at shutdown.
	gatewayMu sync.Mutex
	gateway   *sipgw.Gateway
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"status": "ok"}})
}

func (s *server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"engine":   s.engine.Status(),
		"events":   notify.AllEvents,
		"defaults": notify.DefaultTemplates(),
	}})
}

// handleConfig returns the whole configuration with secrets masked, so the panel
// can render every tab from one request.
func (s *server) handleConfig(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	snapshot, err := s.store.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	stats, err := s.store.Stats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"credentials": snapshot.Credentials,
		"rules":       snapshot.Rules,
		"fallback":    snapshot.Fallback,
		"contacts":    snapshot.Contacts,
		"voicemail":   snapshot.Voicemail,
		"recording":   snapshot.Recording,
		"notify":      snapshot.Notify,
		"sip":         snapshot.SIP,
		"keepalive":   snapshot.Keepalive,
		"stats":       stats,
		"engine":      s.engine.Status(),
	}})
}

func (s *server) handleCredentials(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}
	var request store.Credentials
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.store.SaveCredentials(request); err != nil {
		writeError(w, http.StatusBadRequest, "save_failed", err.Error())
		return
	}
	// Reload immediately so the operator sees a login failure now rather than
	// discovering it during the next call.
	reloadCtx, cancel := context.WithTimeout(r.Context(), 40*time.Second)
	defer cancel()
	reloadErr := s.engine.Reload(reloadCtx)
	// The gateway holds its own reference to the vocat client; rebuild it so a
	// credential change takes effect without restarting the plugin.
	s.applySIPGateway()

	snapshot, err := s.store.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	payload := map[string]any{
		"credentials": snapshot.Credentials,
		"engine":      s.engine.Status(),
	}
	if reloadErr != nil {
		payload["warning"] = reloadErr.Error()
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": payload})
}

func (s *server) handleRules(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}
	var request struct {
		Rules    []rules.Rule `json:"rules"`
		Fallback rules.Action `json:"fallback"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if request.Fallback == "" {
		request.Fallback = rules.ActionAllow
	}
	if err := s.store.SaveRules(request.Rules, request.Fallback); err != nil {
		writeError(w, http.StatusBadRequest, "save_failed", err.Error())
		return
	}
	snapshot, err := s.store.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"rules": snapshot.Rules, "fallback": snapshot.Fallback, "engine": s.engine.Status(),
	}})
}

// handleEvaluate answers "what would happen if this number called?" without
// waiting for a real call. Rule ordering is easy to get wrong, so this is the
// difference between a policy the operator trusts and one they hope works.
func (s *server) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		DeviceID string `json:"device_id"`
		Number   string `json:"number"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	config, err := s.store.Config()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	book := contacts.NewBook(config.Contacts)
	decision := rules.NewEngine(config.Rules, book, config.Fallback).Evaluate(request.DeviceID, request.Number)
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"action":        decision.Action,
		"rule_id":       decision.RuleID,
		"match":         decision.Match,
		"delay_seconds": decision.DelaySeconds,
		"contact_name":  decision.ContactName,
		"anonymous":     rules.IsAnonymous(request.Number),
	}})
}

func (s *server) handleContacts(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}
	var request struct {
		Contacts []contacts.Contact `json:"contacts"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.store.SaveContacts(request.Contacts); err != nil {
		writeError(w, http.StatusBadRequest, "save_failed", err.Error())
		return
	}
	snapshot, err := s.store.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"contacts": snapshot.Contacts}})
}

// handleSIPSettings reads and writes the SIP gateway policy. A change rebuilds
// the gateway: the listen address, account, and device are fixed at Start.
func (s *server) handleSIPSettings(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		snapshot, err := s.store.Snapshot()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"sip": snapshot.SIP}})
	case http.MethodPut:
		var request store.SIPSettings
		if err := decodeJSON(r, &request); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if err := s.store.SaveSIP(request); err != nil {
			writeError(w, http.StatusBadRequest, "save_failed", err.Error())
			return
		}
		s.applySIPGateway()
		snapshot, err := s.store.Snapshot()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
			"sip": snapshot.SIP, "gateway": s.sipStatusPayload(),
		}})
	default:
		w.Header().Set("Allow", "GET, PUT")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

// handleSIPStatus reports whether the gateway is up and which softphones are
// registered, so the panel can show a live picture of the SIP side.
func (s *server) handleSIPStatus(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"gateway": s.sipStatusPayload()}})
}

// sipStatusPayload describes the gateway for the panel. When it is not running
// the payload says why, so a misconfiguration is visible rather than silent.
func (s *server) sipStatusPayload() map[string]any {
	s.gatewayMu.Lock()
	gateway := s.gateway
	s.gatewayMu.Unlock()
	if gateway != nil {
		return map[string]any{"enabled": true, "status": gateway.Status()}
	}
	reason := "disabled"
	snapshot, err := s.store.Snapshot()
	if err != nil {
		reason = "store_failed: " + err.Error()
	} else if snapshot.SIP.Enabled {
		if s.engine.Client() == nil {
			reason = "需要先在「设置」里开启服务端模式：SIP 网关必须能自己调用 vocat 的通话接口"
		} else {
			reason = "启动失败，请检查监听地址是否被占用"
		}
	}
	return map[string]any{"enabled": false, "reason": reason}
}

// applySIPGateway reconciles the running gateway with the stored settings.
// Idempotent: call it after any change to SIP settings or vocat credentials.
func (s *server) applySIPGateway() {
	s.gatewayMu.Lock()
	defer s.gatewayMu.Unlock()
	config, err := s.store.Config()
	if err != nil {
		s.logger.Warn("SIP gateway: read settings failed", "error", err)
		return
	}
	settings := config.SIP.Normalize()
	if !settings.Enabled {
		s.stopSIPGatewayLocked()
		return
	}
	client := s.engine.Client()
	if client == nil {
		s.stopSIPGatewayLocked()
		s.logger.Warn("SIP gateway not started: server-side mode is off; enable it in the panel settings")
		return
	}
	// Rebuild unconditionally: the gateway captures account and address at
	// Start, so any settings change needs a fresh instance. Restarting is cheap
	// (one UDP bind) and callers invoke this only on explicit changes.
	s.stopSIPGatewayLocked()
	gateway, err := sipgw.New(sipgw.Config{
		ListenAddress: settings.ListenAddress,
		AdvertiseIP:   settings.AdvertiseIP,
		Realm:         "vocat",
		Account: sipgw.Account{
			Username: settings.Username,
			Password: settings.Password,
			DeviceID: settings.DeviceID,
		},
		AllowedSources: settings.AllowedSources,
	}, client, s.logger)
	if err != nil {
		s.logger.Warn("SIP gateway configuration rejected", "error", err)
		return
	}
	if err := gateway.Start(); err != nil {
		s.logger.Warn("SIP gateway failed to start", "listen", settings.ListenAddress, "error", err)
		return
	}
	s.gateway = gateway
	s.logger.Info("SIP gateway started", "listen", gateway.Status().Address,
		"device", settings.DeviceID, "user", settings.Username)
}

// stopSIPGateway stops and forgets the gateway, if one is running.
func (s *server) stopSIPGateway() {
	s.gatewayMu.Lock()
	defer s.gatewayMu.Unlock()
	s.stopSIPGatewayLocked()
}

func (s *server) stopSIPGatewayLocked() {
	if s.gateway == nil {
		return
	}
	s.gateway.Stop()
	s.gateway = nil
}

func (s *server) handleVoicemailSettings(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}
	var request store.VoicemailSettings
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.store.SaveVoicemail(request); err != nil {
		writeError(w, http.StatusBadRequest, "save_failed", err.Error())
		return
	}
	snapshot, err := s.store.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"voicemail": snapshot.Voicemail}})
}

func (s *server) handleRecordingSettings(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}
	var request store.RecordingSettings
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.store.SaveRecording(request); err != nil {
		writeError(w, http.StatusBadRequest, "save_failed", err.Error())
		return
	}
	// Apply the new retention and quota now rather than waiting for the next
	// recording to trigger a sweep.
	if err := s.engine.SweepRecordings(); err != nil {
		s.logger.Warn("recording sweep after a settings change", "error", err)
	}
	snapshot, err := s.store.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	stats, err := s.store.Stats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"recording": snapshot.Recording, "stats": stats,
	}})
}

// handleCalls serves the plugin's own call history.
//
// This is not vocat's call log: it is assembled by polling, so a call that
// started and ended between two polls is missing, and nothing is recorded while
// the plugin is not running. Original vocat has no call-history API to read.
func (s *server) handleCalls(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	query := r.URL.Query()
	filter := store.CallFilter{
		DeviceID:  strings.TrimSpace(query.Get("device_id")),
		Direction: strings.TrimSpace(query.Get("direction")),
		Peer:      strings.TrimSpace(query.Get("peer")),
		Limit:     100,
	}
	switch filter.Direction {
	case "", "incoming", "outgoing":
	default:
		writeError(w, http.StatusBadRequest, "invalid_request", "direction must be incoming or outgoing")
		return
	}
	if value := strings.TrimSpace(query.Get("recorded")); value == "1" || strings.EqualFold(value, "true") {
		filter.OnlyRecorded = true
	}
	if value := strings.TrimSpace(query.Get("missed")); value == "1" || strings.EqualFold(value, "true") {
		filter.OnlyMissed = true
	}
	if raw := strings.TrimSpace(query.Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 500 {
			filter.Limit = parsed
		}
	}
	calls, err := s.store.Calls(filter)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	stats, err := s.store.Stats()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"calls": calls, "stats": stats, "limit": filter.Limit,
	}})
}

// handleCall serves /calls/{id}, /{id}/recording and /{id}/recording/audio.
func (s *server) handleCall(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/calls/"), "/")
	if rest == "" {
		writeError(w, http.StatusNotFound, "not_found", "call id is required")
		return
	}
	segments := strings.Split(rest, "/")
	id := segments[0]

	switch {
	case len(segments) == 1 && r.Method == http.MethodDelete:
		path, err := s.store.DeleteCall(id)
		if err != nil {
			s.writeStoreError(w, err)
			return
		}
		if path != "" {
			s.engine.RemoveRecordingFile(path)
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"deleted": true, "id": id}})

	case len(segments) == 2 && segments[1] == "recording" && r.Method == http.MethodDelete:
		path, err := s.store.ClearRecording(id)
		if err != nil {
			s.writeStoreError(w, err)
			return
		}
		if path != "" {
			s.engine.RemoveRecordingFile(path)
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"deleted": true, "id": id}})

	case len(segments) == 3 && segments[1] == "recording" && segments[2] == "audio" && r.Method == http.MethodGet:
		s.serveCallRecording(w, r, id)

	default:
		w.Header().Set("Allow", "GET, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *server) serveCallRecording(w http.ResponseWriter, r *http.Request, id string) {
	record, err := s.store.Call(id)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	if !record.HasRecording() {
		writeError(w, http.StatusNotFound, "not_found", "this call has no recording")
		return
	}
	resolved, err := recorder.ResolveInside(s.store.Dir(), record.RecordingPath)
	if err != nil {
		s.logger.Warn("rejected a recording path", "call", id, "error", err)
		writeError(w, http.StatusNotFound, "not_found", "recording is unavailable")
		return
	}
	file, err := os.Open(resolved)
	if err != nil {
		// The record outlived its file. Clear the reference so the UI stops
		// offering a download that can never succeed.
		if _, clearErr := s.store.ClearRecording(id); clearErr != nil {
			s.logger.Warn("clear a missing recording reference", "call", id, "error", clearErr)
		}
		writeError(w, http.StatusNotFound, "not_found", "the recording file is no longer available")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_failed", "recording could not be read")
		return
	}
	w.Header().Set("Content-Type", "audio/wav")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", recordingFilename(record)))
	// Recordings are immutable once written, so a long cache is safe and makes
	// seeking in the browser player cheap.
	w.Header().Set("Cache-Control", "private, max-age=3600")
	http.ServeContent(w, r, filepath.Base(resolved), info.ModTime(), file)
}

func recordingFilename(record store.CallRecord) string {
	peer := recorder.Sanitize(record.Peer)
	return fmt.Sprintf("call-%s-%s.wav", record.StartedAt.UTC().Format("20060102-150405"), peer)
}

func (s *server) handleMessages(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	messages, err := s.store.Messages()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"messages": messages}})
}

// handleMessage serves /voicemail/messages/{id}, /{id}/audio and /{id}/read.
func (s *server) handleMessage(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/voicemail/messages/"), "/")
	if rest == "" {
		writeError(w, http.StatusNotFound, "not_found", "message id is required")
		return
	}
	segments := strings.Split(rest, "/")
	id := segments[0]

	switch {
	case len(segments) == 1 && r.Method == http.MethodDelete:
		path, err := s.store.DeleteMessage(id)
		if err != nil {
			s.writeStoreError(w, err)
			return
		}
		if path != "" {
			if resolved, resolveErr := s.resolveMessagePath(path); resolveErr == nil {
				_ = os.Remove(resolved)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"deleted": true, "id": id}})

	case len(segments) == 2 && segments[1] == "read" && r.Method == http.MethodPost:
		if err := s.store.MarkMessageRead(id); err != nil {
			s.writeStoreError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"read": true, "id": id}})

	case len(segments) == 2 && segments[1] == "audio" && r.Method == http.MethodGet:
		s.serveMessageAudio(w, r, id)

	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
}

func (s *server) serveMessageAudio(w http.ResponseWriter, r *http.Request, id string) {
	message, err := s.store.Message(id)
	if err != nil {
		s.writeStoreError(w, err)
		return
	}
	resolved, err := s.resolveMessagePath(message.Path)
	if err != nil {
		s.logger.Warn("rejected voicemail path", "id", id, "error", err)
		writeError(w, http.StatusNotFound, "not_found", "recording is unavailable")
		return
	}
	file, err := os.Open(resolved)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "recording file is no longer available")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read_failed", "recording could not be read")
		return
	}
	w.Header().Set("Content-Type", "audio/wav")
	w.Header().Set("Cache-Control", "private, max-age=3600")
	http.ServeContent(w, r, filepath.Base(resolved), info.ModTime(), file)
}

// resolveMessagePath keeps a tampered state file from becoming an arbitrary
// file read.
func (s *server) resolveMessagePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("empty path")
	}
	root, err := filepath.Abs(s.store.Dir())
	if err != nil {
		return "", err
	}
	candidate := path
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(root, candidate)
	}
	candidate, err = filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return "", err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the data directory", path)
	}
	return candidate, nil
}

func (s *server) handleNotify(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}
	var request notify.Config
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.store.SaveNotify(request); err != nil {
		writeError(w, http.StatusBadRequest, "save_failed", err.Error())
		return
	}
	snapshot, err := s.store.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"notify": snapshot.Notify}})
}

// handleNotifyTest sends a real message through the stored configuration, using
// the requested event's template so the operator sees exactly what will arrive.
func (s *server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	var request struct {
		Event string `json:"event"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	config, err := s.store.Config()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	event := notify.Event(strings.TrimSpace(request.Event))
	if event == "" {
		event = notify.EventIncoming
	}
	fields := notify.Fields{
		Event:       event,
		DeviceID:    "demo",
		DeviceName:  "演示设备",
		Caller:      "+447700900123",
		Called:      "+447700900000",
		ContactName: "测试联系人",
		Action:      "test",
		RuleID:      "test",
		Duration:    "0:12",
		Result:      "success",
		Time:        time.Now(),
	}
	// Force delivery even when this event's template is disabled, so a test is
	// never a silent no-op.
	template := config.Notify.TemplateFor(event)
	template.Enabled = true
	template.Event = event
	forced := config.Notify
	forced.Templates = replaceTemplate(forced.Templates, template)

	sendCtx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	results := s.engine.Sender().Send(sendCtx, forced, fields)
	if results == nil {
		results = []notify.Result{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{
		"results": results,
		"preview": map[string]any{
			"title": notify.Render(template.Title, fields),
			"body":  notify.Render(template.Body, fields),
		},
	}})
}

func replaceTemplate(list []notify.Template, replacement notify.Template) []notify.Template {
	out := make([]notify.Template, 0, len(list)+1)
	replaced := false
	for _, template := range list {
		if template.Event == replacement.Event {
			out = append(out, replacement)
			replaced = true
			continue
		}
		out = append(out, template)
	}
	if !replaced {
		out = append(out, replacement)
	}
	return out
}

func (s *server) handleKeepalive(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPut) {
		return
	}
	var request struct {
		Tasks []store.KeepaliveTask `json:"tasks"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.store.SaveKeepalive(request.Tasks); err != nil {
		writeError(w, http.StatusBadRequest, "save_failed", err.Error())
		return
	}
	snapshot, err := s.store.Snapshot()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"keepalive": snapshot.Keepalive}})
}

func (s *server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 500 {
			limit = parsed
		}
	}
	events, err := s.store.Events(limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": map[string]any{"events": events}})
}

func (s *server) writeStoreError(w http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "not_found", "not found")
		return
	}
	writeError(w, http.StatusInternalServerError, "store_failed", err.Error())
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return false
	}
	return true
}

func decodeJSON(r *http.Request, value any) error {
	if contentType := r.Header.Get("Content-Type"); contentType != "" &&
		!strings.HasPrefix(strings.ToLower(contentType), "application/json") {
		return errors.New("content type must be application/json")
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("decode request: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": message}})
}
