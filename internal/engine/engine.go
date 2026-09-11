// Package engine watches calls and applies the rule policy.
//
// It exists because vocat's plugin backend has no way to be told about a call:
// there is no callback, no webhook, no event socket a plugin can subscribe to.
// So the engine polls the call list of every eligible device and reacts to
// transitions it has not seen before.
//
// The poll interval is the honest cost of that design. One second is fast
// enough to reject or answer before a typical caller gives up, and cheap enough
// on the appliance because the endpoint reads in-memory state.
package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"vocat-plugin-telephony/internal/contacts"
	"vocat-plugin-telephony/internal/notify"
	"vocat-plugin-telephony/internal/recorder"
	"vocat-plugin-telephony/internal/rules"
	"vocat-plugin-telephony/internal/store"
	"vocat-plugin-telephony/internal/vocat"
	"vocat-plugin-telephony/internal/voicemail"
)

// pollInterval is how often each device's call list is read.
const pollInterval = time.Second

// Engine owns the polling loop and the in-flight call bookkeeping.
type Engine struct {
	store  *store.Store
	sender *notify.Sender
	logger *slog.Logger

	mu     sync.Mutex
	client *vocat.Client
	// clientError records why server-side mode is not running, so the panel can
	// explain it instead of just showing "off".
	clientError string
	running     bool
	// handled tracks calls already acted on, so a rule fires once per call
	// rather than once per poll.
	handled map[string]time.Time
	// seen tracks calls observed while ringing, so a call that disappears
	// without being answered can be reported as missed.
	seen map[string]seenCall
	// lastActivity is the most recent real call per device, for the keepalive
	// idle check.
	lastActivity map[string]time.Time
	// recording tracks calls a recorder goroutine already owns, so a second
	// poll does not open a second WebSocket on the same call.
	recording map[string]struct{}
}

type seenCall struct {
	deviceID   string
	deviceName string
	caller     string
	answered   bool
	lastSeen   time.Time
}

func New(database *store.Store, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		store:        database,
		sender:       notify.NewSender(),
		logger:       logger,
		handled:      map[string]time.Time{},
		seen:         map[string]seenCall{},
		lastActivity: map[string]time.Time{},
		recording:    map[string]struct{}{},
	}
}

// Status is what the panel shows about server-side mode.
type Status struct {
	Enabled      bool   `json:"enabled"`
	Running      bool   `json:"running"`
	SessionValid bool   `json:"session_valid"`
	Error        string `json:"error,omitempty"`
	// NeedsCredentials is true when a rule requires acting on vocat's API but no
	// credentials are configured. That is the one misconfiguration worth calling
	// out loudly, because rules would silently never fire.
	NeedsCredentials bool `json:"needs_credentials"`
}

func (engine *Engine) Status() Status {
	engine.mu.Lock()
	client, clientError, running := engine.client, engine.clientError, engine.running
	engine.mu.Unlock()

	status := Status{Running: running, Error: clientError}
	if config, err := engine.store.Config(); err == nil {
		status.Enabled = config.Credentials.Enabled
		status.NeedsCredentials = rules.NeedsCredentials(config.Rules) && !config.Credentials.Enabled
	}
	if client != nil {
		status.SessionValid = client.SessionValid()
	}
	return status
}

// Client returns the authenticated client, or nil when server-side mode is off.
func (engine *Engine) Client() *vocat.Client {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.client
}

// Reload rebuilds the vocat client from stored credentials. It is called at
// startup and whenever the settings change.
func (engine *Engine) Reload(ctx context.Context) error {
	config, err := engine.store.Config()
	if err != nil {
		return err
	}
	engine.mu.Lock()
	engine.client = nil
	engine.clientError = ""
	engine.mu.Unlock()

	if !config.Credentials.Enabled {
		return nil
	}
	client, err := vocat.New(vocat.Options{
		BaseURL:            config.Credentials.BaseURL,
		Username:           config.Credentials.Username,
		Password:           config.Credentials.Password,
		CertPath:           config.Credentials.CertPath,
		InsecureSkipVerify: config.Credentials.InsecureSkipVerify,
	})
	if err != nil {
		engine.mu.Lock()
		engine.clientError = err.Error()
		engine.mu.Unlock()
		return err
	}
	loginCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := client.Ensure(loginCtx); err != nil {
		engine.mu.Lock()
		engine.clientError = err.Error()
		engine.mu.Unlock()
		return err
	}
	engine.mu.Lock()
	engine.client = client
	engine.mu.Unlock()
	return nil
}

// Run polls until the context is cancelled.
func (engine *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	keepaliveTicker := time.NewTicker(time.Minute)
	defer keepaliveTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			engine.tick(ctx)
		case <-keepaliveTicker.C:
			engine.runKeepalive(ctx)
		}
	}
}

func (engine *Engine) tick(ctx context.Context) {
	client := engine.Client()
	if client == nil {
		return
	}
	config, err := engine.store.Config()
	if err != nil {
		return
	}
	engine.mu.Lock()
	engine.running = true
	engine.mu.Unlock()

	devices, err := client.Devices(ctx)
	if err != nil {
		engine.mu.Lock()
		engine.clientError = err.Error()
		engine.running = false
		engine.mu.Unlock()
		return
	}
	engine.mu.Lock()
	engine.clientError = ""
	engine.mu.Unlock()

	book := contacts.NewBook(config.Contacts)
	policy := rules.NewEngine(config.Rules, book, config.Fallback)

	for _, device := range devices {
		// The 410 backend rejects every call endpoint with 501, so polling it
		// would only produce noise.
		if device.DeviceType == "wifi_410" || !device.Running {
			continue
		}
		snapshot, err := client.Calls(ctx, device.ID)
		if err != nil {
			continue
		}
		// Only the VoWiFi transport reports a stable call id and state machine.
		// The cellular transport returns AT-derived integers with no id, so a
		// rule could not be applied reliably.
		if snapshot.Transport != "vowifi" {
			continue
		}
		engine.processDevice(ctx, client, config, policy, book, device, snapshot.Calls)
	}
	engine.reapMissed(ctx, config, book)
}

func (engine *Engine) processDevice(
	ctx context.Context,
	client *vocat.Client,
	config store.Snapshot,
	policy *rules.Engine,
	book *contacts.Book,
	device vocat.Device,
	calls []vocat.Call,
) {
	now := time.Now()
	for _, call := range calls {
		key := device.ID + "|" + call.ID

		// History first, so a call is recorded whatever the rules decide. This
		// is polling, not a signalling hook: a call that starts and ends between
		// two polls is simply never seen.
		engine.persistCall(device, call, book)

		if call.Live() {
			engine.mu.Lock()
			engine.lastActivity[device.ID] = now
			entry := engine.seen[key]
			entry.deviceID = device.ID
			entry.deviceName = displayName(device)
			entry.caller = call.Number
			entry.lastSeen = now
			if call.AnsweredAt != nil || call.State == "active" {
				entry.answered = true
			}
			engine.seen[key] = entry
			engine.mu.Unlock()
		} else {
			// Terminal: drop the bookkeeping so a future call with the same id
			// (unlikely, but possible after a restart) is not suppressed.
			engine.mu.Lock()
			delete(engine.seen, key)
			delete(engine.handled, key)
			delete(engine.recording, key)
			engine.mu.Unlock()
			continue
		}

		// An active call with negotiated media is the only thing that has an
		// audio socket, so recording can only start here.
		if call.State == "active" && call.MediaReady {
			engine.maybeRecord(ctx, client, config, device, call, book)
		}

		if !call.Ringing() {
			continue
		}
		engine.mu.Lock()
		_, already := engine.handled[key]
		engine.mu.Unlock()
		if already {
			continue
		}

		decision := policy.Evaluate(device.ID, call.Number)
		if decision.Action == rules.ActionAllow {
			// Allow needs no action, but it should still be recorded once so the
			// operator can see the rule matched.
			engine.mu.Lock()
			engine.handled[key] = now
			engine.mu.Unlock()
			engine.notifyEvent(ctx, config, notify.EventIncoming, device, call, decision, "", nil)
			continue
		}
		// Honour the delay before acting, so a human can pick up first.
		if decision.DelaySeconds > 0 && time.Since(call.StartedAt) < time.Duration(decision.DelaySeconds)*time.Second {
			continue
		}
		engine.mu.Lock()
		engine.handled[key] = now
		engine.mu.Unlock()
		engine.act(ctx, client, config, book, device, call, decision)
	}
}

func (engine *Engine) act(
	ctx context.Context,
	client *vocat.Client,
	config store.Snapshot,
	book *contacts.Book,
	device vocat.Device,
	call vocat.Call,
	decision rules.Decision,
) {
	actionCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	switch decision.Action {
	case rules.ActionReject:
		// vocat answers a ringing-call hangup with SIP 486 Busy Here; there is
		// no API to send 603 Decline.
		err := client.HangupCall(actionCtx, device.ID, call.ID)
		engine.record(device, call, decision, "rejected", err)
		engine.notifyEvent(ctx, config, notify.EventRejected, device, call, decision, "", err)

	case rules.ActionAnswer:
		_, err := client.AnswerCall(actionCtx, device.ID, call.ID)
		engine.record(device, call, decision, "answered", err)
		engine.notifyEvent(ctx, config, notify.EventAnswered, device, call, decision, "", err)

	case rules.ActionVoicemail:
		if !config.Voicemail.Enabled {
			// A rule asking for voicemail while the mailbox is off would
			// otherwise answer and then sit silently on the call.
			err := errors.New("语音留言未启用")
			engine.record(device, call, decision, "voicemail_skipped", err)
			return
		}
		if _, err := client.AnswerCall(actionCtx, device.ID, call.ID); err != nil {
			engine.record(device, call, decision, "voicemail_answer_failed", err)
			return
		}
		go engine.recordVoicemail(context.WithoutCancel(ctx), client, config, book, device, call, decision)
	}
}

// recordVoicemail waits for media to become ready, then records the caller.
func (engine *Engine) recordVoicemail(
	ctx context.Context,
	client *vocat.Client,
	config store.Snapshot,
	book *contacts.Book,
	device vocat.Device,
	call vocat.Call,
	decision rules.Decision,
) {
	settings := config.Voicemail.Normalize()
	// The media socket only exists once the call is active with negotiated
	// media, which lags the answer by a moment.
	ready := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		snapshot, err := client.Calls(ctx, device.ID)
		if err == nil {
			for _, current := range snapshot.Calls {
				if current.ID == call.ID && current.State == "active" && current.MediaReady {
					ready = true
				}
			}
		}
		if ready {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !ready {
		engine.record(device, call, decision, "voicemail_media_unavailable",
			errors.New("通话音频未就绪"))
		return
	}

	directory := filepath.Join(engine.store.Dir(), "voicemail")
	result, err := voicemail.Record(ctx, voicemail.Options{
		MediaURL:       client.MediaURL(device.ID, call.ID),
		HTTPClient:     client.HTTPClient(),
		GreetingPath:   engine.greetingPath(settings),
		MaxDuration:    time.Duration(settings.MaxSeconds) * time.Second,
		SilenceTimeout: time.Duration(settings.SilenceSeconds) * time.Second,
		Directory:      directory,
		Name:           time.Now().UTC().Format("20060102T150405Z") + "-" + sanitizeCaller(call.Number),
	})
	// Hang up regardless: leaving the line open after recording would bill the
	// caller and hold the modem.
	hangupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	_ = client.HangupCall(hangupCtx, device.ID, call.ID)
	cancel()

	if err != nil {
		engine.record(device, call, decision, "voicemail_failed", err)
		return
	}
	if result.Path == "" {
		engine.record(device, call, decision, "voicemail_empty", nil)
		return
	}
	relative, relErr := filepath.Rel(engine.store.Dir(), result.Path)
	if relErr != nil {
		relative = result.Path
	}
	message := store.VoicemailMessage{
		DeviceID:    device.ID,
		DeviceName:  displayName(device),
		Caller:      call.Number,
		ContactName: book.Name(call.Number),
		CallID:      call.ID,
		Path:        relative,
		Bytes:       result.Bytes,
		Seconds:     int(result.Duration.Seconds()),
	}
	orphaned, err := engine.store.AppendMessage(message)
	if err != nil {
		engine.logger.Warn("record voicemail", "error", err)
	}
	engine.removeOrphaned(orphaned)
	engine.record(device, call, decision, "voicemail_saved", nil)
	engine.notifyEvent(ctx, config, notify.EventVoicemail, device, call, decision,
		formatDuration(result.Duration), nil)
}

func (engine *Engine) greetingPath(settings store.VoicemailSettings) string {
	if strings.TrimSpace(settings.GreetingPath) == "" {
		return ""
	}
	if filepath.IsAbs(settings.GreetingPath) {
		return settings.GreetingPath
	}
	return filepath.Join(engine.store.Dir(), settings.GreetingPath)
}

// persistCall writes what the current poll knows about a call. Repeated calls
// converge on one record because the store merges by device and call id.
func (engine *Engine) persistCall(device vocat.Device, call vocat.Call, book *contacts.Book) {
	if strings.TrimSpace(call.ID) == "" {
		return
	}
	record := store.CallRecord{
		CallID:      call.ID,
		DeviceID:    device.ID,
		DeviceName:  displayName(device),
		Direction:   call.Direction,
		Peer:        call.Number,
		ContactName: book.Name(call.Number),
		State:       call.State,
		SIPCode:     call.SIPCode,
		Reason:      call.Reason,
		Codec:       call.Codec,
		StartedAt:   call.StartedAt,
		AnsweredAt:  call.AnsweredAt,
		EndedAt:     call.EndedAt,
	}
	// A terminal state without an end time still ended; without this the record
	// would show an open-ended call forever.
	if !call.Live() && record.EndedAt == nil {
		now := time.Now().UTC()
		record.EndedAt = &now
	}
	if _, err := engine.store.UpsertCall(record); err != nil {
		engine.logger.Warn("persist call record",
			"device_id", device.ID, "call_id", call.ID, "error", err)
	}
}

// maybeRecord starts a recorder for a call when the policy asks for it. It runs
// at most one recorder per call, and never blocks the poll loop.
func (engine *Engine) maybeRecord(
	ctx context.Context,
	client *vocat.Client,
	config store.Snapshot,
	device vocat.Device,
	call vocat.Call,
	book *contacts.Book,
) {
	settings := config.Recording.Normalize()
	if !settings.Records(call.Direction) {
		return
	}
	key := device.ID + "|" + call.ID
	engine.mu.Lock()
	if _, already := engine.recording[key]; already {
		engine.mu.Unlock()
		return
	}
	engine.recording[key] = struct{}{}
	engine.mu.Unlock()

	// context.WithoutCancel: a recording outlives one poll tick and must not be
	// cut short when the tick's context is released.
	go engine.runRecording(context.WithoutCancel(ctx), client, config, device, call, book, settings)
}

func (engine *Engine) runRecording(
	ctx context.Context,
	client *vocat.Client,
	config store.Snapshot,
	device vocat.Device,
	call vocat.Call,
	book *contacts.Book,
	settings store.RecordingSettings,
) {
	key := device.ID + "|" + call.ID
	defer func() {
		engine.mu.Lock()
		delete(engine.recording, key)
		engine.mu.Unlock()
	}()

	directory := filepath.Join(engine.store.Dir(), "recordings")
	name := call.StartedAt.UTC().Format("20060102T150405Z") + "-" + sanitizeCaller(call.Number)
	result, err := recorder.Record(ctx, recorder.Options{
		MediaURL:    client.MediaURL(device.ID, call.ID),
		HTTPClient:  client.HTTPClient(),
		MaxDuration: time.Duration(settings.MaxSeconds) * time.Second,
		// No silence timeout: a pause in conversation must not end a recording.
		Directory: directory,
		Name:      name,
	})
	if err != nil {
		engine.logger.Warn("call recording failed",
			"device_id", device.ID, "call_id", call.ID, "error", err)
		return
	}
	if result.Path == "" {
		// The call carried no audio; recorder already removed the empty file.
		return
	}
	relative, relErr := filepath.Rel(engine.store.Dir(), result.Path)
	if relErr != nil {
		relative = result.Path
	}
	orphaned, err := engine.store.AttachRecording(device.ID, call.ID, relative, result.Bytes)
	if err != nil {
		// The call record may have been pruned while recording. Do not leave the
		// audio file behind with nothing pointing at it.
		engine.logger.Warn("attach call recording",
			"device_id", device.ID, "call_id", call.ID, "error", err)
		_ = os.Remove(result.Path)
		return
	}
	engine.removeOrphaned(orphaned)
	engine.logger.Info("call recorded",
		"device_id", device.ID, "call_id", call.ID,
		"seconds", int(result.Duration.Seconds()), "truncated", result.Truncated)
}

// removeOrphaned deletes recording files whose reference the store just cleared.
func (engine *Engine) removeOrphaned(paths []string) {
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		resolved, err := recorder.ResolveInside(engine.store.Dir(), path)
		if err != nil {
			engine.logger.Warn("refusing to delete a recording outside the data directory",
				"path", path, "error", err)
			continue
		}
		if err := os.Remove(resolved); err != nil && !os.IsNotExist(err) {
			engine.logger.Warn("delete recording", "path", path, "error", err)
		}
	}
}

// reapMissed reports calls that stopped ringing without being answered.
func (engine *Engine) reapMissed(ctx context.Context, config store.Snapshot, book *contacts.Book) {
	cutoff := time.Now().Add(-3 * pollInterval)
	var missed []seenCall
	engine.mu.Lock()
	for key, entry := range engine.seen {
		if entry.lastSeen.After(cutoff) {
			continue
		}
		delete(engine.seen, key)
		delete(engine.handled, key)
		if !entry.answered {
			missed = append(missed, entry)
		}
	}
	engine.mu.Unlock()

	for _, entry := range missed {
		engine.sendNotification(ctx, config, notify.Fields{
			Event:       notify.EventMissed,
			DeviceID:    entry.deviceID,
			DeviceName:  entry.deviceName,
			Caller:      entry.caller,
			ContactName: book.Name(entry.caller),
			Time:        time.Now(),
		})
	}
}

// runKeepalive places keepalive calls or SMS for due tasks.
func (engine *Engine) runKeepalive(ctx context.Context) {
	client := engine.Client()
	if client == nil {
		return
	}
	config, err := engine.store.Config()
	if err != nil {
		return
	}
	for _, task := range config.Keepalive {
		if !task.Enabled || time.Now().Before(task.DueAt()) {
			continue
		}
		if task.OnlyIfIdleHours > 0 {
			engine.mu.Lock()
			last := engine.lastActivity[task.DeviceID]
			engine.mu.Unlock()
			if !last.IsZero() && time.Since(last) < time.Duration(task.OnlyIfIdleHours)*time.Hour {
				// The line is in use; recording a skip keeps the reason visible.
				_ = engine.store.RecordKeepaliveRun(task.ID, "skipped_recent_activity", nil)
				continue
			}
		}
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		var runErr error
		switch task.Kind {
		case "call":
			_, runErr = client.DialCall(runCtx, task.DeviceID, task.Target, task.DurationSeconds)
		case "sms":
			runErr = client.Post(runCtx, "/api/sms/send", map[string]any{
				"device_id": task.DeviceID,
				"phone":     task.Target,
				"message":   task.Message,
			}, nil)
		}
		cancel()

		status := "success"
		if runErr != nil {
			status = "failed"
		}
		if err := engine.store.RecordKeepaliveRun(task.ID, status, runErr); err != nil {
			engine.logger.Warn("record keepalive run", "task", task.ID, "error", err)
		}
		engine.sendNotification(ctx, config, notify.Fields{
			Event:      notify.EventKeepalive,
			DeviceID:   task.DeviceID,
			DeviceName: task.Name,
			Result:     status,
			Time:       time.Now(),
		})
	}
}

func (engine *Engine) record(device vocat.Device, call vocat.Call, decision rules.Decision, outcome string, actionErr error) {
	event := store.CallEvent{
		DeviceID:    device.ID,
		DeviceName:  displayName(device),
		Caller:      call.Number,
		ContactName: decision.ContactName,
		CallID:      call.ID,
		Action:      string(decision.Action),
		RuleID:      decision.RuleID,
		Match:       string(decision.Match),
		Outcome:     outcome,
	}
	if actionErr != nil {
		event.Error = actionErr.Error()
	}
	if err := engine.store.AppendEvent(event); err != nil {
		engine.logger.Warn("append call event", "error", err)
	}
	engine.logger.Info("call rule applied",
		"device_id", device.ID, "action", decision.Action,
		"rule", decision.RuleID, "outcome", outcome, "error", actionErr)
}

func (engine *Engine) notifyEvent(
	ctx context.Context,
	config store.Snapshot,
	event notify.Event,
	device vocat.Device,
	call vocat.Call,
	decision rules.Decision,
	duration string,
	actionErr error,
) {
	fields := notify.Fields{
		Event:       event,
		DeviceID:    device.ID,
		DeviceName:  displayName(device),
		Caller:      call.Number,
		Called:      device.Modem.PhoneNumber,
		ContactName: decision.ContactName,
		Action:      string(decision.Action),
		RuleID:      decision.RuleID,
		Duration:    duration,
		Time:        time.Now(),
	}
	if actionErr != nil {
		fields.Result = actionErr.Error()
	}
	engine.sendNotification(ctx, config, fields)
}

func (engine *Engine) sendNotification(ctx context.Context, config store.Snapshot, fields notify.Fields) {
	sendCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 20*time.Second)
	go func() {
		defer cancel()
		for _, result := range engine.sender.Send(sendCtx, config.Notify, fields) {
			if !result.OK {
				engine.logger.Warn("notification failed",
					"channel", result.Channel, "event", fields.Event, "error", result.Error)
			}
		}
	}()
}

// Sender exposes the notifier so the HTTP layer can run a test push.
func (engine *Engine) Sender() *notify.Sender {
	return engine.sender
}

// SweepRecordings applies the retention window and quota now, deleting the
// files whose references the store cleared. Called after a settings change so a
// shortened retention takes effect immediately.
func (engine *Engine) SweepRecordings() error {
	orphaned, err := engine.store.SweepRecordings()
	if err != nil {
		return err
	}
	engine.removeOrphaned(orphaned)
	return nil
}

// RemoveRecordingFile deletes one recording, refusing any path outside the data
// directory.
func (engine *Engine) RemoveRecordingFile(path string) {
	engine.removeOrphaned([]string{path})
}

func displayName(device vocat.Device) string {
	if name := strings.TrimSpace(device.Name); name != "" {
		return name
	}
	return device.ID
}

func sanitizeCaller(number string) string {
	digits := contacts.Digits(number)
	if digits == "" {
		return "anonymous"
	}
	if len(digits) > 20 {
		digits = digits[len(digits)-20:]
	}
	return digits
}

func formatDuration(value time.Duration) string {
	seconds := int(value.Seconds())
	return fmt.Sprintf("%d:%02d", seconds/60, seconds%60)
}
