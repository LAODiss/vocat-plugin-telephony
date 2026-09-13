package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vocat-plugin-telephony/internal/contacts"
	"vocat-plugin-telephony/internal/notify"
	"vocat-plugin-telephony/internal/rules"
)

func openTestStore(t *testing.T) *Store {
	t.Helper()
	database, err := Open(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	return database
}

func TestSnapshotMasksSecretsAndConfigDoesNot(t *testing.T) {
	database := openTestStore(t)
	if err := database.SaveCredentials(Credentials{
		Enabled: true, Username: "admin", Password: "s3cret",
		BaseURL: "https://127.0.0.1:7575", InsecureSkipVerify: true,
	}); err != nil {
		t.Fatalf("SaveCredentials() error = %v", err)
	}
	if err := database.SaveNotify(notify.Config{
		Webhook:  notify.WebhookConfig{Enabled: true, URLs: []string{"https://example.com/hook"}, Secret: "whsec"},
		Telegram: notify.TelegramConfig{Enabled: true, BotToken: "bot123", ChatID: "42"},
		PushPlus: notify.PushPlusConfig{Enabled: true, Token: "pp123"},
	}); err != nil {
		t.Fatalf("SaveNotify() error = %v", err)
	}

	snapshot, err := database.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot.Credentials.Password != SecretMask {
		t.Fatalf("Snapshot password = %q, must be masked", snapshot.Credentials.Password)
	}
	if snapshot.Notify.Webhook.Secret != SecretMask ||
		snapshot.Notify.Telegram.BotToken != SecretMask ||
		snapshot.Notify.PushPlus.Token != SecretMask {
		t.Fatalf("Snapshot leaked a notification secret: %+v", snapshot.Notify)
	}

	config, err := database.Config()
	if err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	if config.Credentials.Password != "s3cret" {
		t.Fatalf("Config password = %q, want the real value", config.Credentials.Password)
	}
	if config.Notify.Telegram.BotToken != "bot123" {
		t.Fatalf("Config bot token = %q", config.Notify.Telegram.BotToken)
	}
}

func TestSavingAMaskedSecretKeepsTheStoredOne(t *testing.T) {
	database := openTestStore(t)
	if err := database.SaveCredentials(Credentials{
		Enabled: true, Username: "admin", Password: "original", InsecureSkipVerify: true,
	}); err != nil {
		t.Fatalf("SaveCredentials() error = %v", err)
	}
	// The panel sends back the mask when the operator edits another field.
	if err := database.SaveCredentials(Credentials{
		Enabled: true, Username: "admin2", Password: SecretMask, InsecureSkipVerify: true,
	}); err != nil {
		t.Fatalf("SaveCredentials(masked) error = %v", err)
	}
	config, err := database.Config()
	if err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	if config.Credentials.Password != "original" {
		t.Fatalf("password = %q, want the stored value preserved", config.Credentials.Password)
	}
	if config.Credentials.Username != "admin2" {
		t.Fatalf("username = %q, want the edit applied", config.Credentials.Username)
	}
}

func TestSIPSettingsMaskValidationAndDefaults(t *testing.T) {
	database := openTestStore(t)
	// Disabled by default with a usable listen address.
	snapshot, err := database.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot.SIP.Enabled || snapshot.SIP.ListenAddress == "" {
		t.Fatalf("default SIP = %+v, want disabled with a listen address", snapshot.SIP)
	}
	// Enabling without an account or device is rejected.
	if err := database.SaveSIP(SIPSettings{Enabled: true}); err == nil {
		t.Fatal("enabling the SIP gateway without credentials must fail")
	}
	if err := database.SaveSIP(SIPSettings{
		Enabled: true, Username: "iphone", Password: "dialtone", DeviceID: "modem1",
	}); err != nil {
		t.Fatalf("SaveSIP() error = %v", err)
	}
	// The panel sends the mask back when editing another field.
	if err := database.SaveSIP(SIPSettings{
		Enabled: true, Username: "iphone", Password: SecretMask, DeviceID: "modem2",
	}); err != nil {
		t.Fatalf("SaveSIP(masked) error = %v", err)
	}
	config, err := database.Config()
	if err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	if config.SIP.Password != "dialtone" {
		t.Fatalf("password = %q, want the stored value preserved", config.SIP.Password)
	}
	if config.SIP.DeviceID != "modem2" {
		t.Fatalf("device = %q, want the edit applied", config.SIP.DeviceID)
	}
	// Snapshot masks, Config does not: same rule as the vocat credentials.
	snapshot, err = database.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot.SIP.Password != SecretMask {
		t.Fatalf("Snapshot SIP password = %q, must be masked", snapshot.SIP.Password)
	}
}

func TestEnablingServerModeRequiresCredentials(t *testing.T) {
	database := openTestStore(t)
	if err := database.SaveCredentials(Credentials{Enabled: true, Username: "admin"}); err == nil {
		t.Fatal("enabling server-side mode without a password must fail")
	}
	// Disabled is fine with nothing filled in.
	if err := database.SaveCredentials(Credentials{Enabled: false}); err != nil {
		t.Fatalf("SaveCredentials(disabled) error = %v", err)
	}
}

func TestDefaultsAreSafe(t *testing.T) {
	snapshot, err := openTestStore(t).Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if snapshot.Credentials.Enabled {
		t.Fatal("server-side mode must be off by default")
	}
	if snapshot.Voicemail.Enabled {
		t.Fatal("voicemail must be off by default")
	}
	if snapshot.Fallback != rules.ActionAllow {
		t.Fatalf("fallback = %q, want allow so a fresh install never eats calls", snapshot.Fallback)
	}
	// Empty slices, not nil, so the panel renders empty tables.
	if snapshot.Rules == nil || snapshot.Contacts == nil || snapshot.Keepalive == nil {
		t.Fatalf("collections must be empty slices: %+v", snapshot)
	}
	if len(snapshot.Notify.Templates) == 0 {
		t.Fatal("default templates must be exposed so the UI has something to edit")
	}
}

func TestSaveRulesAssignsIDsAndValidates(t *testing.T) {
	database := openTestStore(t)
	if err := database.SaveRules([]rules.Rule{
		{Enabled: true, Match: rules.MatchAny, Action: rules.ActionReject},
	}, rules.ActionAllow); err != nil {
		t.Fatalf("SaveRules() error = %v", err)
	}
	snapshot, err := database.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if len(snapshot.Rules) != 1 || snapshot.Rules[0].ID == "" {
		t.Fatalf("rule id was not assigned: %+v", snapshot.Rules)
	}
	if err := database.SaveRules([]rules.Rule{
		{Enabled: true, Match: "sideways", Action: rules.ActionAllow},
	}, rules.ActionAllow); err == nil {
		t.Fatal("SaveRules() must reject an invalid rule")
	}
	if err := database.SaveRules(nil, "explode"); err == nil {
		t.Fatal("SaveRules() must reject an unknown fallback")
	}
}

func TestKeepaliveValidationAndHistoryPreservation(t *testing.T) {
	database := openTestStore(t)
	task := KeepaliveTask{
		Name: "Monthly", Enabled: true, DeviceID: "ec20", Kind: "call",
		Target: "10086", DurationSeconds: 20, IntervalHours: 24,
	}
	if err := database.SaveKeepalive([]KeepaliveTask{task}); err != nil {
		t.Fatalf("SaveKeepalive() error = %v", err)
	}
	config, err := database.Config()
	if err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	stored := config.Keepalive[0]
	if stored.ID == "" {
		t.Fatal("keepalive id was not assigned")
	}
	if err := database.RecordKeepaliveRun(stored.ID, "success", nil); err != nil {
		t.Fatalf("RecordKeepaliveRun() error = %v", err)
	}
	// An edit carries no run history, so it must not erase it.
	stored.Name = "Renamed"
	stored.LastStatus = ""
	stored.LastRunAt = time.Time{}
	if err := database.SaveKeepalive([]KeepaliveTask{stored}); err != nil {
		t.Fatalf("SaveKeepalive(edit) error = %v", err)
	}
	config, err = database.Config()
	if err != nil {
		t.Fatalf("Config() error = %v", err)
	}
	if config.Keepalive[0].LastStatus != "success" || config.Keepalive[0].LastRunAt.IsZero() {
		t.Fatalf("run history erased by an edit: %+v", config.Keepalive[0])
	}
	if config.Keepalive[0].Name != "Renamed" {
		t.Fatalf("edit not applied: %q", config.Keepalive[0].Name)
	}

	invalid := map[string]KeepaliveTask{
		"no name":       {DeviceID: "ec20", Kind: "call", Target: "1", DurationSeconds: 5, IntervalHours: 1},
		"no device":     {Name: "x", Kind: "call", Target: "1", DurationSeconds: 5, IntervalHours: 1},
		"bad kind":      {Name: "x", DeviceID: "ec20", Kind: "fax", Target: "1", IntervalHours: 1},
		"no target":     {Name: "x", DeviceID: "ec20", Kind: "call", Target: "abc", DurationSeconds: 5, IntervalHours: 1},
		"sms no body":   {Name: "x", DeviceID: "ec20", Kind: "sms", Target: "1", IntervalHours: 1},
		"call duration": {Name: "x", DeviceID: "ec20", Kind: "call", Target: "1", DurationSeconds: 0, IntervalHours: 1},
		"bad interval":  {Name: "x", DeviceID: "ec20", Kind: "call", Target: "1", DurationSeconds: 5, IntervalHours: 0},
	}
	for name, candidate := range invalid {
		if err := database.SaveKeepalive([]KeepaliveTask{candidate}); err == nil {
			t.Fatalf("%s: SaveKeepalive() must fail", name)
		}
	}
}

func TestKeepaliveDueAt(t *testing.T) {
	// A task that never ran is due immediately, otherwise a fresh task would
	// wait a full interval before its first run.
	fresh := KeepaliveTask{IntervalHours: 6}
	if !fresh.DueAt().Before(time.Now().Add(time.Second)) {
		t.Fatal("a task that never ran must be due now")
	}
	last := time.Now().UTC().Add(-2 * time.Hour)
	task := KeepaliveTask{IntervalHours: 6, LastRunAt: last}
	if !task.DueAt().Equal(last.Add(6 * time.Hour)) {
		t.Fatalf("DueAt() = %v", task.DueAt())
	}
}

func TestVoicemailQuotaPrunesOldestFirst(t *testing.T) {
	database := openTestStore(t)
	if err := database.SaveVoicemail(VoicemailSettings{
		Enabled: true, MaxTotalBytes: 8 << 20, RetentionDays: 0,
	}); err != nil {
		t.Fatalf("SaveVoicemail() error = %v", err)
	}
	now := time.Now().UTC()
	// Three 4 MiB messages against an 8 MiB cap.
	for index, name := range []string{"old", "middle", "new"} {
		orphaned, err := database.AppendMessage(VoicemailMessage{
			DeviceID: "ec20", Caller: "+1", Path: "voicemail/" + name + ".wav",
			Bytes: 4 << 20, CreatedAt: now.Add(time.Duration(index) * time.Minute),
		})
		if err != nil {
			t.Fatalf("AppendMessage(%s) error = %v", name, err)
		}
		if index < 2 && len(orphaned) != 0 {
			t.Fatalf("%s: unexpected pruning %v", name, orphaned)
		}
		if index == 2 {
			if len(orphaned) != 1 || !strings.Contains(orphaned[0], "old") {
				t.Fatalf("quota sweep removed %v, want the oldest", orphaned)
			}
		}
	}
	messages, err := database.Messages()
	if err != nil {
		t.Fatalf("Messages() error = %v", err)
	}
	if len(messages) != 2 {
		t.Fatalf("len(messages) = %d, want 2", len(messages))
	}
	// Newest first.
	if !messages[0].CreatedAt.After(messages[1].CreatedAt) {
		t.Fatal("messages must be newest first")
	}
}

func TestVoicemailRetentionWindow(t *testing.T) {
	database := openTestStore(t)
	now := time.Now().UTC()
	// Store the old message while retention is off, which is what actually
	// happens: a message is recorded, then time passes.
	if err := database.SaveVoicemail(VoicemailSettings{Enabled: true, RetentionDays: 0}); err != nil {
		t.Fatalf("SaveVoicemail() error = %v", err)
	}
	orphaned, err := database.AppendMessage(VoicemailMessage{
		DeviceID: "ec20", Path: "voicemail/stale.wav", Bytes: 1024,
		CreatedAt: now.AddDate(0, 0, -40),
	})
	if err != nil {
		t.Fatalf("AppendMessage(stale) error = %v", err)
	}
	if len(orphaned) != 0 {
		t.Fatalf("nothing should be pruned with retention off, got %v", orphaned)
	}

	if err := database.SaveVoicemail(VoicemailSettings{Enabled: true, RetentionDays: 30}); err != nil {
		t.Fatalf("SaveVoicemail(retention) error = %v", err)
	}
	orphaned, err = database.AppendMessage(VoicemailMessage{
		DeviceID: "ec20", Path: "voicemail/fresh.wav", Bytes: 1024, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("AppendMessage(fresh) error = %v", err)
	}
	if len(orphaned) != 1 || !strings.Contains(orphaned[0], "stale") {
		t.Fatalf("retention sweep removed %v, want the stale message", orphaned)
	}
	messages, err := database.Messages()
	if err != nil {
		t.Fatalf("Messages() error = %v", err)
	}
	if len(messages) != 1 || !strings.Contains(messages[0].Path, "fresh") {
		t.Fatalf("remaining messages = %+v", messages)
	}
}

func TestMessageReadDeleteAndNotFound(t *testing.T) {
	database := openTestStore(t)
	if _, err := database.AppendMessage(VoicemailMessage{
		DeviceID: "ec20", Path: "voicemail/a.wav", Bytes: 100,
	}); err != nil {
		t.Fatalf("AppendMessage() error = %v", err)
	}
	messages, err := database.Messages()
	if err != nil {
		t.Fatalf("Messages() error = %v", err)
	}
	id := messages[0].ID
	if messages[0].Read {
		t.Fatal("a new message must be unread")
	}
	if err := database.MarkMessageRead(id); err != nil {
		t.Fatalf("MarkMessageRead() error = %v", err)
	}
	message, err := database.Message(id)
	if err != nil {
		t.Fatalf("Message() error = %v", err)
	}
	if !message.Read {
		t.Fatal("MarkMessageRead did not persist")
	}
	path, err := database.DeleteMessage(id)
	if err != nil {
		t.Fatalf("DeleteMessage() error = %v", err)
	}
	if path != "voicemail/a.wav" {
		t.Fatalf("DeleteMessage() path = %q", path)
	}
	for name, err := range map[string]error{
		"message":   func() error { _, e := database.Message("nope"); return e }(),
		"read":      database.MarkMessageRead("nope"),
		"delete":    func() error { _, e := database.DeleteMessage("nope"); return e }(),
		"keepalive": database.RecordKeepaliveRun("nope", "success", nil),
	} {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s: error = %v, want os.ErrNotExist", name, err)
		}
	}
}

func TestEventLogIsBoundedAndNewestFirst(t *testing.T) {
	database := openTestStore(t)
	for index := 0; index < maxCallEvents+20; index++ {
		if err := database.AppendEvent(CallEvent{
			DeviceID: "ec20", Caller: "+1", Action: "reject", Outcome: "rejected",
			CreatedAt: time.Now().UTC().Add(time.Duration(index) * time.Second),
		}); err != nil {
			t.Fatalf("AppendEvent(%d) error = %v", index, err)
		}
	}
	events, err := database.Events(0)
	if err != nil {
		t.Fatalf("Events() error = %v", err)
	}
	if len(events) != maxCallEvents {
		t.Fatalf("len(events) = %d, want %d", len(events), maxCallEvents)
	}
	if events[0].CreatedAt.Before(events[1].CreatedAt) {
		t.Fatal("events must be newest first")
	}
	if limited, err := database.Events(10); err != nil || len(limited) != 10 {
		t.Fatalf("Events(10) = %d rows, err = %v", len(limited), err)
	}
}

func TestContactsAndStatePersistAcrossReopen(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "data")
	first, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := first.SaveContacts([]contacts.Contact{{Number: "+447700900123", Name: "Alice"}}); err != nil {
		t.Fatalf("SaveContacts() error = %v", err)
	}
	second, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	snapshot, err := second.Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	if len(snapshot.Contacts) != 1 || snapshot.Contacts[0].Name != "Alice" {
		t.Fatalf("state did not survive a reopen: %+v", snapshot.Contacts)
	}
	if err := second.SaveContacts([]contacts.Contact{{Number: "abc", Name: "Bad"}}); err == nil {
		t.Fatal("SaveContacts() must validate")
	}
}

func TestStateFileIsNotWorldReadable(t *testing.T) {
	// The file holds the vocat administrator password in server-side mode.
	database := openTestStore(t)
	if err := database.SaveCredentials(Credentials{Enabled: false}); err != nil {
		t.Fatalf("SaveCredentials() error = %v", err)
	}
	info, err := os.Stat(filepath.Join(database.Dir(), "state.json"))
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("state file mode = %o, want 600", mode)
	}
}

func TestVoicemailSettingsNormalize(t *testing.T) {
	clamped := VoicemailSettings{MaxSeconds: -1, SilenceSeconds: -1, MaxTotalBytes: -1, RetentionDays: -1}.Normalize()
	defaults := DefaultVoicemail()
	if clamped.MaxSeconds != defaults.MaxSeconds || clamped.SilenceSeconds != defaults.SilenceSeconds {
		t.Fatalf("negative values not defaulted: %+v", clamped)
	}
	if clamped.RetentionDays != 0 {
		t.Fatalf("RetentionDays = %d, want 0", clamped.RetentionDays)
	}
	huge := VoicemailSettings{MaxSeconds: 9999, SilenceSeconds: 9999, MaxTotalBytes: 1 << 50, RetentionDays: 99999}.Normalize()
	if huge.MaxSeconds != 300 || huge.SilenceSeconds != 60 || huge.MaxTotalBytes != 8<<30 || huge.RetentionDays != 3650 {
		t.Fatalf("oversized values not clamped: %+v", huge)
	}
	tiny := VoicemailSettings{MaxTotalBytes: 1024}.Normalize()
	if tiny.MaxTotalBytes != 8<<20 {
		t.Fatalf("tiny quota not clamped up: %d", tiny.MaxTotalBytes)
	}
}
