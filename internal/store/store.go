// Package store persists this plugin's configuration and its voicemail index.
//
// A plugin backend only gets VOCAT_PLUGIN_DATA_DIR, so state lives in a JSON
// file here. Admin credentials are part of that state when server-side mode is
// enabled, which is why the file is written 0600 and the password is never
// returned by the read path — see Redacted.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"vocat-plugin-telephony/internal/contacts"
	"vocat-plugin-telephony/internal/notify"
	"vocat-plugin-telephony/internal/rules"
)

// SecretMask is what a stored secret looks like when read back. It matches
// vocat's own convention so the UI behaves the same way.
const SecretMask = "********"

// Credentials lets the plugin act on vocat's API without a browser. This is a
// genuine privilege escalation: the plugin gains full administrator rights, so
// it is opt-in and off by default.
type Credentials struct {
	// Enabled turns on server-side mode. When false the rule engine only runs
	// while the panel is open in a browser.
	Enabled  bool   `json:"enabled"`
	BaseURL  string `json:"base_url"`
	Username string `json:"username"`
	Password string `json:"password"`
	// CertPath points at vocat's self-signed certificate for pinning.
	CertPath string `json:"cert_path"`
	// InsecureSkipVerify is the fallback when the certificate is unreadable.
	// Acceptable only because the target is forced to loopback.
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

// VoicemailSettings controls the answering machine.
type VoicemailSettings struct {
	Enabled bool `json:"enabled"`
	// GreetingPath is an 8 kHz mono 16-bit WAV played before recording. Empty
	// means record immediately with no greeting.
	GreetingPath   string `json:"greeting_path,omitempty"`
	MaxSeconds     int    `json:"max_seconds"`
	SilenceSeconds int    `json:"silence_seconds"`
	// MaxTotalBytes bounds the mailbox; the oldest messages are pruned first.
	MaxTotalBytes int64 `json:"max_total_bytes"`
	RetentionDays int   `json:"retention_days"`
}

// DefaultVoicemail is the policy applied before anything is configured.
func DefaultVoicemail() VoicemailSettings {
	return VoicemailSettings{
		Enabled:        false,
		MaxSeconds:     60,
		SilenceSeconds: 8,
		MaxTotalBytes:  128 << 20,
		RetentionDays:  30,
	}
}

// Normalize clamps voicemail settings into a workable range.
func (settings VoicemailSettings) Normalize() VoicemailSettings {
	defaults := DefaultVoicemail()
	if settings.MaxSeconds <= 0 {
		settings.MaxSeconds = defaults.MaxSeconds
	}
	if settings.MaxSeconds > 300 {
		settings.MaxSeconds = 300
	}
	if settings.SilenceSeconds <= 0 {
		settings.SilenceSeconds = defaults.SilenceSeconds
	}
	if settings.SilenceSeconds > 60 {
		settings.SilenceSeconds = 60
	}
	if settings.MaxTotalBytes <= 0 {
		settings.MaxTotalBytes = defaults.MaxTotalBytes
	}
	if settings.MaxTotalBytes < 8<<20 {
		settings.MaxTotalBytes = 8 << 20
	}
	if settings.MaxTotalBytes > 8<<30 {
		settings.MaxTotalBytes = 8 << 30
	}
	if settings.RetentionDays < 0 {
		settings.RetentionDays = 0
	}
	if settings.RetentionDays > 3650 {
		settings.RetentionDays = 3650
	}
	return settings
}

// KeepaliveTask keeps a line active by placing a short call or sending an SMS.
//
// vocat's own automatic tasks already do daily per-ICCID call and SMS with eSIM
// profile switching and IMS environment forcing. This exists for the cadence
// vocat cannot express — sub-daily, and "only if the line has been idle" — and
// deliberately does not re-implement profile switching.
type KeepaliveTask struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	DeviceID string `json:"device_id"`
	// Kind is "call" or "sms".
	Kind string `json:"kind"`
	// Target is the number to call or text.
	Target string `json:"target"`
	// Message is the SMS body; ignored for a call.
	Message string `json:"message,omitempty"`
	// DurationSeconds is how long to hold a keepalive call. vocat caps it at 600.
	DurationSeconds int `json:"duration_seconds,omitempty"`
	// IntervalHours is the cadence. Hours rather than days is the whole point.
	IntervalHours int `json:"interval_hours"`
	// OnlyIfIdleHours skips the task when the line saw real traffic recently, so
	// a busy line is not disturbed. Zero means always run.
	OnlyIfIdleHours int       `json:"only_if_idle_hours,omitempty"`
	LastRunAt       time.Time `json:"last_run_at,omitempty"`
	LastStatus      string    `json:"last_status,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
}

// DueAt is when this task should next run.
func (task KeepaliveTask) DueAt() time.Time {
	if task.LastRunAt.IsZero() {
		return time.Now()
	}
	return task.LastRunAt.Add(time.Duration(task.IntervalHours) * time.Hour)
}

// RecordingSettings controls automatic call recording.
//
// Recording here is a poll-and-tap arrangement, not a wire capture: the plugin
// watches the call list and, once a call is active with negotiated media, opens
// vocat's PCM WebSocket. Anything vocat's jitter buffer dropped is already gone,
// and a call that ends within a poll interval may not be recorded at all. vocat
// has no RTP-level hook a plugin could use instead.
type RecordingSettings struct {
	Enabled bool `json:"enabled"`
	// Direction limits which calls are recorded: "all", "incoming", "outgoing".
	Direction string `json:"direction"`
	// MaxSeconds bounds one recording so a stuck call cannot fill the disk.
	MaxSeconds int `json:"max_seconds"`
	// MaxTotalBytes caps the whole library; the oldest recordings go first.
	MaxTotalBytes int64 `json:"max_total_bytes"`
	RetentionDays int   `json:"retention_days"`
}

// DefaultRecording is off, because recording a call has consent and legal
// implications only the operator can assess.
func DefaultRecording() RecordingSettings {
	return RecordingSettings{
		Enabled:       false,
		Direction:     "all",
		MaxSeconds:    600,
		MaxTotalBytes: 256 << 20,
		RetentionDays: 30,
	}
}

// Normalize clamps recording settings into a workable range.
func (settings RecordingSettings) Normalize() RecordingSettings {
	defaults := DefaultRecording()
	switch settings.Direction {
	case "all", "incoming", "outgoing":
	default:
		settings.Direction = defaults.Direction
	}
	if settings.MaxSeconds <= 0 {
		settings.MaxSeconds = defaults.MaxSeconds
	}
	if settings.MaxSeconds > 3600 {
		settings.MaxSeconds = 3600
	}
	if settings.MaxTotalBytes <= 0 {
		settings.MaxTotalBytes = defaults.MaxTotalBytes
	}
	if settings.MaxTotalBytes < 8<<20 {
		settings.MaxTotalBytes = 8 << 20
	}
	if settings.MaxTotalBytes > 16<<30 {
		settings.MaxTotalBytes = 16 << 30
	}
	if settings.RetentionDays < 0 {
		settings.RetentionDays = 0
	}
	if settings.RetentionDays > 3650 {
		settings.RetentionDays = 3650
	}
	return settings
}

// Records reports whether a call in this direction should be recorded.
func (settings RecordingSettings) Records(direction string) bool {
	if !settings.Enabled {
		return false
	}
	return settings.Direction == "all" || settings.Direction == direction
}

// CallRecord is one observed call.
//
// It is assembled by polling vocat, so it is the plugin's own view rather than
// vocat's: a call that started and ended between two polls will be missing, and
// the plugin only sees calls while it is running.
type CallRecord struct {
	ID          string `json:"id"`
	CallID      string `json:"call_id"`
	DeviceID    string `json:"device_id"`
	DeviceName  string `json:"device_name"`
	Direction   string `json:"direction"`
	Peer        string `json:"peer"`
	ContactName string `json:"contact_name,omitempty"`
	// State is the last state observed, so an interrupted call is not silently
	// reported as completed.
	State      string     `json:"state"`
	SIPCode    int        `json:"sip_code,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	Codec      string     `json:"codec,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	AnsweredAt *time.Time `json:"answered_at,omitempty"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
	// DurationSeconds is billable talk time: answer to hangup. An unanswered
	// call has none even though it occupied the line while ringing.
	DurationSeconds int       `json:"duration_seconds"`
	Answered        bool      `json:"answered"`
	Missed          bool      `json:"missed"`
	RecordingPath   string    `json:"recording_path,omitempty"`
	RecordingBytes  int64     `json:"recording_bytes,omitempty"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// HasRecording reports whether an audio file is attached.
func (record CallRecord) HasRecording() bool {
	return strings.TrimSpace(record.RecordingPath) != ""
}

// maxCallRecords bounds call history. Records holding a recording are kept
// preferentially, because dropping them would orphan the audio file.
const maxCallRecords = 2000

// VoicemailMessage is one recorded message.
type VoicemailMessage struct {
	ID          string    `json:"id"`
	DeviceID    string    `json:"device_id"`
	DeviceName  string    `json:"device_name"`
	Caller      string    `json:"caller"`
	ContactName string    `json:"contact_name,omitempty"`
	CallID      string    `json:"call_id,omitempty"`
	Path        string    `json:"path"`
	Bytes       int64     `json:"bytes"`
	Seconds     int       `json:"seconds"`
	Read        bool      `json:"read"`
	CreatedAt   time.Time `json:"created_at"`
}

// CallEvent is an audited decision, so an operator can see why a call was
// rejected rather than inferring it from vocat's logs.
type CallEvent struct {
	ID          string    `json:"id"`
	DeviceID    string    `json:"device_id"`
	DeviceName  string    `json:"device_name"`
	Caller      string    `json:"caller"`
	ContactName string    `json:"contact_name,omitempty"`
	CallID      string    `json:"call_id,omitempty"`
	Action      string    `json:"action"`
	RuleID      string    `json:"rule_id,omitempty"`
	Match       string    `json:"match,omitempty"`
	Outcome     string    `json:"outcome"`
	Error       string    `json:"error,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// maxCallEvents bounds the audit log; the oldest entries are dropped.
const maxCallEvents = 500

type document struct {
	Credentials Credentials        `json:"credentials"`
	Rules       []rules.Rule       `json:"rules"`
	Fallback    rules.Action       `json:"fallback_action"`
	Contacts    []contacts.Contact `json:"contacts"`
	Voicemail   VoicemailSettings  `json:"voicemail"`
	Recording   RecordingSettings  `json:"recording"`
	Notify      notify.Config      `json:"notify"`
	Keepalive   []KeepaliveTask    `json:"keepalive"`
	Messages    []VoicemailMessage `json:"messages"`
	Calls       []CallRecord       `json:"calls"`
	Events      []CallEvent        `json:"events"`
}

// Store is the JSON-file-backed state. Every public method locks.
type Store struct {
	path string
	dir  string
	mu   sync.Mutex
}

func Open(dir string) (*Store, error) {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil, errors.New("store: data directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	return &Store{path: filepath.Join(dir, "state.json"), dir: dir}, nil
}

// Dir is the plugin data directory, used for voicemail and greeting files.
func (store *Store) Dir() string {
	return store.dir
}

func (store *Store) load() (document, error) {
	raw, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) || len(raw) == 0 {
		return document{
			Fallback:  rules.ActionAllow,
			Voicemail: DefaultVoicemail(),
			Recording: DefaultRecording(),
		}, nil
	}
	if err != nil {
		return document{}, fmt.Errorf("read state: %w", err)
	}
	var loaded document
	if err := json.Unmarshal(raw, &loaded); err != nil {
		return document{}, fmt.Errorf("decode state: %w", err)
	}
	if loaded.Fallback == "" {
		loaded.Fallback = rules.ActionAllow
	}
	if loaded.Voicemail.MaxSeconds == 0 {
		loaded.Voicemail = DefaultVoicemail()
	}
	// A state file written before recording existed has a zeroed struct, which
	// would otherwise read as "enabled with a zero cap".
	if loaded.Recording.MaxSeconds == 0 {
		loaded.Recording = DefaultRecording()
	}
	return loaded, nil
}

func (store *Store) save(loaded document) error {
	raw, err := json.MarshalIndent(loaded, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	temporary := store.path + ".tmp"
	// 0600: this file holds the vocat administrator password when server-side
	// mode is on.
	if err := os.WriteFile(temporary, raw, 0o600); err != nil {
		return fmt.Errorf("write state: %w", err)
	}
	if err := os.Rename(temporary, store.path); err != nil {
		return fmt.Errorf("replace state: %w", err)
	}
	return nil
}

// Snapshot is the whole configuration, for the panel.
type Snapshot struct {
	Credentials Credentials        `json:"credentials"`
	Rules       []rules.Rule       `json:"rules"`
	Fallback    rules.Action       `json:"fallback_action"`
	Contacts    []contacts.Contact `json:"contacts"`
	Voicemail   VoicemailSettings  `json:"voicemail"`
	Recording   RecordingSettings  `json:"recording"`
	Notify      notify.Config      `json:"notify"`
	Keepalive   []KeepaliveTask    `json:"keepalive"`
}

// Snapshot returns the configuration with secrets masked.
func (store *Store) Snapshot() (Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Credentials: redactCredentials(loaded.Credentials),
		Rules:       nonNilRules(loaded.Rules),
		Fallback:    loaded.Fallback,
		Contacts:    nonNilContacts(loaded.Contacts),
		Voicemail:   loaded.Voicemail,
		Recording:   loaded.Recording,
		Notify:      redactNotify(loaded.Notify),
		Keepalive:   nonNilTasks(loaded.Keepalive),
	}, nil
}

// Config returns the configuration with secrets intact, for internal use only.
func (store *Store) Config() (Snapshot, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Credentials: loaded.Credentials,
		Rules:       nonNilRules(loaded.Rules),
		Fallback:    loaded.Fallback,
		Contacts:    nonNilContacts(loaded.Contacts),
		Voicemail:   loaded.Voicemail,
		Recording:   loaded.Recording,
		Notify:      loaded.Notify,
		Keepalive:   nonNilTasks(loaded.Keepalive),
	}, nil
}

func redactCredentials(value Credentials) Credentials {
	if value.Password != "" {
		value.Password = SecretMask
	}
	return value
}

func redactNotify(config notify.Config) notify.Config {
	if config.Webhook.Secret != "" {
		config.Webhook.Secret = SecretMask
	}
	if config.Telegram.BotToken != "" {
		config.Telegram.BotToken = SecretMask
	}
	if config.PushPlus.Token != "" {
		config.PushPlus.Token = SecretMask
	}
	if config.Templates == nil {
		config.Templates = notify.DefaultTemplates()
	}
	return config
}

func (store *Store) SaveCredentials(value Credentials) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return err
	}
	if value.Password == SecretMask || value.Password == "" {
		value.Password = loaded.Credentials.Password
	}
	value.BaseURL = strings.TrimSpace(value.BaseURL)
	value.Username = strings.TrimSpace(value.Username)
	value.CertPath = strings.TrimSpace(value.CertPath)
	if value.Enabled && (value.Username == "" || value.Password == "") {
		return errors.New("server-side mode needs a username and password")
	}
	loaded.Credentials = value
	return store.save(loaded)
}

// SaveRules replaces the rule list and the fallback action.
func (store *Store) SaveRules(ruleList []rules.Rule, fallback rules.Action) error {
	if len(ruleList) > 200 {
		return errors.New("rule limit reached (200)")
	}
	for index := range ruleList {
		if strings.TrimSpace(ruleList[index].ID) == "" {
			ruleList[index].ID = newID()
		}
		if err := rules.Validate(ruleList[index]); err != nil {
			return fmt.Errorf("rule %d: %w", index+1, err)
		}
	}
	switch fallback {
	case rules.ActionAllow, rules.ActionReject, rules.ActionAnswer, rules.ActionVoicemail:
	default:
		return fmt.Errorf("unknown fallback action %q", fallback)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return err
	}
	loaded.Rules = ruleList
	loaded.Fallback = fallback
	return store.save(loaded)
}

// SaveContacts replaces the address book.
func (store *Store) SaveContacts(list []contacts.Contact) error {
	if len(list) > 2000 {
		return errors.New("contact limit reached (2000)")
	}
	for index, contact := range list {
		if err := contacts.Validate(contact); err != nil {
			return fmt.Errorf("contact %d: %w", index+1, err)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return err
	}
	loaded.Contacts = list
	return store.save(loaded)
}

// SaveVoicemail stores the answering-machine policy.
func (store *Store) SaveVoicemail(settings VoicemailSettings) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return err
	}
	loaded.Voicemail = settings.Normalize()
	return store.save(loaded)
}

// SaveRecording stores the call-recording policy.
func (store *Store) SaveRecording(settings RecordingSettings) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return err
	}
	loaded.Recording = settings.Normalize()
	return store.save(loaded)
}

// UpsertCall records or updates one observed call, keyed by device and call id.
//
// Call state advances over the life of a call, so a later write reconciles the
// earlier one rather than appending a duplicate. Fields that a later poll no
// longer carries are preserved: a terminal snapshot without a peer number must
// not erase the number seen while ringing.
func (store *Store) UpsertCall(record CallRecord) (CallRecord, error) {
	record.DeviceID = strings.TrimSpace(record.DeviceID)
	record.CallID = strings.TrimSpace(record.CallID)
	if record.DeviceID == "" || record.CallID == "" {
		return CallRecord{}, errors.New("call record needs a device id and call id")
	}
	if record.StartedAt.IsZero() {
		record.StartedAt = time.Now().UTC()
	}
	record.UpdatedAt = time.Now().UTC()

	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return CallRecord{}, err
	}
	for index, existing := range loaded.Calls {
		if existing.DeviceID != record.DeviceID || existing.CallID != record.CallID {
			continue
		}
		merged := existing
		merged.State = record.State
		merged.UpdatedAt = record.UpdatedAt
		if record.Peer != "" {
			merged.Peer = record.Peer
		}
		if record.ContactName != "" {
			merged.ContactName = record.ContactName
		}
		if record.DeviceName != "" {
			merged.DeviceName = record.DeviceName
		}
		if record.Codec != "" {
			merged.Codec = record.Codec
		}
		if record.SIPCode != 0 {
			merged.SIPCode = record.SIPCode
		}
		if record.Reason != "" {
			merged.Reason = record.Reason
		}
		if record.AnsweredAt != nil {
			merged.AnsweredAt = record.AnsweredAt
		}
		if record.EndedAt != nil {
			merged.EndedAt = record.EndedAt
		}
		merged.Answered = merged.AnsweredAt != nil
		merged.Missed = merged.Direction == "incoming" && !merged.Answered
		merged.DurationSeconds = talkTime(merged)
		loaded.Calls[index] = merged
		if err := store.save(loaded); err != nil {
			return CallRecord{}, err
		}
		return merged, nil
	}

	if record.ID == "" {
		record.ID = newID()
	}
	record.Answered = record.AnsweredAt != nil
	record.Missed = record.Direction == "incoming" && !record.Answered
	record.DurationSeconds = talkTime(record)
	loaded.Calls = append(loaded.Calls, record)
	loaded.Calls = pruneCalls(loaded.Calls)
	if err := store.save(loaded); err != nil {
		return CallRecord{}, err
	}
	return record, nil
}

// talkTime measures answer to hangup. A call that rang but was never answered
// has no talk time even though it occupied the line.
func talkTime(record CallRecord) int {
	if record.AnsweredAt == nil || record.EndedAt == nil {
		return 0
	}
	seconds := int(record.EndedAt.Sub(*record.AnsweredAt).Seconds())
	if seconds < 0 {
		return 0
	}
	return seconds
}

// pruneCalls enforces maxCallRecords, dropping the oldest records that hold no
// recording so a sweep never orphans an audio file.
func pruneCalls(calls []CallRecord) []CallRecord {
	if len(calls) <= maxCallRecords {
		return calls
	}
	sort.SliceStable(calls, func(i, j int) bool { return calls[i].StartedAt.Before(calls[j].StartedAt) })
	excess := len(calls) - maxCallRecords
	kept := make([]CallRecord, 0, maxCallRecords)
	for _, record := range calls {
		if excess > 0 && !record.HasRecording() {
			excess--
			continue
		}
		kept = append(kept, record)
	}
	return kept
}

// AttachRecording links an audio file to a call and applies the retention and
// quota policy, returning the files the caller should delete from disk.
func (store *Store) AttachRecording(deviceID, callID, path string, size int64) ([]string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return nil, err
	}
	found := false
	for index, existing := range loaded.Calls {
		if existing.DeviceID != deviceID || existing.CallID != callID {
			continue
		}
		existing.RecordingPath = path
		existing.RecordingBytes = size
		existing.UpdatedAt = time.Now().UTC()
		loaded.Calls[index] = existing
		found = true
		break
	}
	if !found {
		return nil, os.ErrNotExist
	}
	orphaned := sweepRecordings(&loaded)
	if err := store.save(loaded); err != nil {
		return nil, err
	}
	return orphaned, nil
}

// sweepRecordings applies the retention window then the size quota, oldest
// first. Only the recording reference is cleared; the call record itself stays,
// because history is more valuable than the audio.
func sweepRecordings(loaded *document) []string {
	settings := loaded.Recording.Normalize()
	var orphaned []string

	if settings.RetentionDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -settings.RetentionDays)
		for index, record := range loaded.Calls {
			if record.HasRecording() && record.StartedAt.Before(cutoff) {
				orphaned = append(orphaned, record.RecordingPath)
				record.RecordingPath = ""
				record.RecordingBytes = 0
				loaded.Calls[index] = record
			}
		}
	}

	recorded := make([]int, 0, len(loaded.Calls))
	var total int64
	for index, record := range loaded.Calls {
		if record.HasRecording() {
			recorded = append(recorded, index)
			total += record.RecordingBytes
		}
	}
	sort.SliceStable(recorded, func(i, j int) bool {
		return loaded.Calls[recorded[i]].StartedAt.Before(loaded.Calls[recorded[j]].StartedAt)
	})
	for _, index := range recorded {
		if total <= settings.MaxTotalBytes {
			break
		}
		record := loaded.Calls[index]
		orphaned = append(orphaned, record.RecordingPath)
		total -= record.RecordingBytes
		record.RecordingPath = ""
		record.RecordingBytes = 0
		loaded.Calls[index] = record
	}
	return orphaned
}

// SweepRecordings applies retention and quota outside of a call, so shortening
// retention takes effect without waiting for the next recording.
func (store *Store) SweepRecordings() ([]string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return nil, err
	}
	orphaned := sweepRecordings(&loaded)
	if len(orphaned) == 0 {
		return nil, nil
	}
	if err := store.save(loaded); err != nil {
		return nil, err
	}
	return orphaned, nil
}

// CallFilter narrows a history query.
type CallFilter struct {
	DeviceID  string
	Direction string
	Peer      string
	// OnlyRecorded restricts results to calls that produced an audio file.
	OnlyRecorded bool
	OnlyMissed   bool
	Limit        int
}

// Calls returns call history, newest first.
func (store *Store) Calls(filter CallFilter) ([]CallRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return nil, err
	}
	matched := make([]CallRecord, 0, len(loaded.Calls))
	for _, record := range loaded.Calls {
		if filter.DeviceID != "" && record.DeviceID != filter.DeviceID {
			continue
		}
		if filter.Direction != "" && record.Direction != filter.Direction {
			continue
		}
		if filter.OnlyRecorded && !record.HasRecording() {
			continue
		}
		if filter.OnlyMissed && !record.Missed {
			continue
		}
		if filter.Peer != "" &&
			!strings.Contains(contacts.Digits(record.Peer), contacts.Digits(filter.Peer)) {
			continue
		}
		matched = append(matched, record)
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].StartedAt.After(matched[j].StartedAt)
	})
	if filter.Limit > 0 && len(matched) > filter.Limit {
		matched = matched[:filter.Limit]
	}
	return matched, nil
}

// Call returns one record by its plugin-assigned id.
func (store *Store) Call(id string) (CallRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return CallRecord{}, err
	}
	for _, record := range loaded.Calls {
		if record.ID == id {
			return record, nil
		}
	}
	return CallRecord{}, os.ErrNotExist
}

// DeleteCall removes one record, returning its recording path for cleanup.
func (store *Store) DeleteCall(id string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return "", err
	}
	for index, record := range loaded.Calls {
		if record.ID != id {
			continue
		}
		loaded.Calls = append(loaded.Calls[:index], loaded.Calls[index+1:]...)
		if err := store.save(loaded); err != nil {
			return "", err
		}
		return record.RecordingPath, nil
	}
	return "", os.ErrNotExist
}

// ClearRecording drops a call's audio reference, returning the path to delete.
func (store *Store) ClearRecording(id string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return "", err
	}
	for index, record := range loaded.Calls {
		if record.ID != id {
			continue
		}
		path := record.RecordingPath
		record.RecordingPath = ""
		record.RecordingBytes = 0
		record.UpdatedAt = time.Now().UTC()
		loaded.Calls[index] = record
		if err := store.save(loaded); err != nil {
			return "", err
		}
		return path, nil
	}
	return "", os.ErrNotExist
}

// CallStats summarises history for the panel header.
type CallStats struct {
	Total          int   `json:"total"`
	Incoming       int   `json:"incoming"`
	Outgoing       int   `json:"outgoing"`
	Missed         int   `json:"missed"`
	Recorded       int   `json:"recorded"`
	RecordingBytes int64 `json:"recording_bytes"`
}

// Stats counts history without transferring it.
func (store *Store) Stats() (CallStats, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return CallStats{}, err
	}
	var stats CallStats
	for _, record := range loaded.Calls {
		stats.Total++
		switch record.Direction {
		case "incoming":
			stats.Incoming++
		case "outgoing":
			stats.Outgoing++
		}
		if record.Missed {
			stats.Missed++
		}
		if record.HasRecording() {
			stats.Recorded++
			stats.RecordingBytes += record.RecordingBytes
		}
	}
	return stats, nil
}

// SaveNotify stores the notification configuration, preserving masked secrets.
func (store *Store) SaveNotify(config notify.Config) error {
	if err := notify.ValidateConfig(config); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return err
	}
	if config.Webhook.Secret == SecretMask {
		config.Webhook.Secret = loaded.Notify.Webhook.Secret
	}
	if config.Telegram.BotToken == SecretMask {
		config.Telegram.BotToken = loaded.Notify.Telegram.BotToken
	}
	if config.PushPlus.Token == SecretMask {
		config.PushPlus.Token = loaded.Notify.PushPlus.Token
	}
	loaded.Notify = config
	return store.save(loaded)
}

// SaveKeepalive replaces the keepalive task list.
func (store *Store) SaveKeepalive(tasks []KeepaliveTask) error {
	if len(tasks) > 50 {
		return errors.New("keepalive task limit reached (50)")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return err
	}
	previous := make(map[string]KeepaliveTask, len(loaded.Keepalive))
	for _, task := range loaded.Keepalive {
		previous[task.ID] = task
	}
	for index := range tasks {
		task := tasks[index]
		task.Name = strings.TrimSpace(task.Name)
		task.Target = strings.TrimSpace(task.Target)
		if task.Name == "" {
			return fmt.Errorf("keepalive task %d: name is required", index+1)
		}
		if task.DeviceID == "" {
			return fmt.Errorf("keepalive task %d: device is required", index+1)
		}
		if task.Kind != "call" && task.Kind != "sms" {
			return fmt.Errorf("keepalive task %d: kind must be call or sms", index+1)
		}
		if contacts.Digits(task.Target) == "" {
			return fmt.Errorf("keepalive task %d: target must contain digits", index+1)
		}
		if task.Kind == "sms" && strings.TrimSpace(task.Message) == "" {
			return fmt.Errorf("keepalive task %d: SMS needs a message", index+1)
		}
		if task.Kind == "call" && (task.DurationSeconds < 1 || task.DurationSeconds > 600) {
			return fmt.Errorf("keepalive task %d: duration_seconds must be 1-600", index+1)
		}
		if task.IntervalHours < 1 || task.IntervalHours > 24*365 {
			return fmt.Errorf("keepalive task %d: interval_hours must be 1-8760", index+1)
		}
		if task.OnlyIfIdleHours < 0 || task.OnlyIfIdleHours > 24*365 {
			return fmt.Errorf("keepalive task %d: only_if_idle_hours is out of range", index+1)
		}
		if task.ID == "" {
			task.ID = newID()
		}
		// Run history belongs to the task, not the form.
		if existing, ok := previous[task.ID]; ok {
			task.LastRunAt = existing.LastRunAt
			task.LastStatus = existing.LastStatus
			task.LastError = existing.LastError
		}
		tasks[index] = task
	}
	loaded.Keepalive = tasks
	return store.save(loaded)
}

// RecordKeepaliveRun stores a run outcome.
func (store *Store) RecordKeepaliveRun(id, status string, runErr error) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return err
	}
	for index, task := range loaded.Keepalive {
		if task.ID != id {
			continue
		}
		task.LastRunAt = time.Now().UTC()
		task.LastStatus = status
		if runErr != nil {
			task.LastError = runErr.Error()
		} else {
			task.LastError = ""
		}
		loaded.Keepalive[index] = task
		return store.save(loaded)
	}
	return os.ErrNotExist
}

// AppendEvent records a decision and prunes the audit log.
func (store *Store) AppendEvent(event CallEvent) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return err
	}
	if event.ID == "" {
		event.ID = newID()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	loaded.Events = append(loaded.Events, event)
	if len(loaded.Events) > maxCallEvents {
		loaded.Events = loaded.Events[len(loaded.Events)-maxCallEvents:]
	}
	return store.save(loaded)
}

// Events returns the audit log, newest first.
func (store *Store) Events(limit int) ([]CallEvent, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return nil, err
	}
	events := append([]CallEvent(nil), loaded.Events...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].CreatedAt.After(events[j].CreatedAt) })
	if limit > 0 && len(events) > limit {
		events = events[:limit]
	}
	if events == nil {
		return []CallEvent{}, nil
	}
	return events, nil
}

// AppendMessage records a voicemail and applies the retention policy, returning
// the files that should be deleted from disk.
func (store *Store) AppendMessage(message VoicemailMessage) ([]string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return nil, err
	}
	if message.ID == "" {
		message.ID = newID()
	}
	if message.CreatedAt.IsZero() {
		message.CreatedAt = time.Now().UTC()
	}
	loaded.Messages = append(loaded.Messages, message)

	settings := loaded.Voicemail.Normalize()
	sort.SliceStable(loaded.Messages, func(i, j int) bool {
		return loaded.Messages[i].CreatedAt.Before(loaded.Messages[j].CreatedAt)
	})
	var orphaned []string
	if settings.RetentionDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -settings.RetentionDays)
		kept := loaded.Messages[:0]
		for _, existing := range loaded.Messages {
			if existing.CreatedAt.Before(cutoff) {
				orphaned = append(orphaned, existing.Path)
				continue
			}
			kept = append(kept, existing)
		}
		loaded.Messages = kept
	}
	var total int64
	for _, existing := range loaded.Messages {
		total += existing.Bytes
	}
	// Oldest first, so a quota sweep keeps the most recent messages.
	for total > settings.MaxTotalBytes && len(loaded.Messages) > 1 {
		orphaned = append(orphaned, loaded.Messages[0].Path)
		total -= loaded.Messages[0].Bytes
		loaded.Messages = loaded.Messages[1:]
	}
	if err := store.save(loaded); err != nil {
		return nil, err
	}
	return orphaned, nil
}

// Messages returns voicemails, newest first.
func (store *Store) Messages() ([]VoicemailMessage, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return nil, err
	}
	messages := append([]VoicemailMessage(nil), loaded.Messages...)
	sort.SliceStable(messages, func(i, j int) bool {
		return messages[i].CreatedAt.After(messages[j].CreatedAt)
	})
	if messages == nil {
		return []VoicemailMessage{}, nil
	}
	return messages, nil
}

// Message returns one voicemail by id.
func (store *Store) Message(id string) (VoicemailMessage, error) {
	messages, err := store.Messages()
	if err != nil {
		return VoicemailMessage{}, err
	}
	for _, message := range messages {
		if message.ID == id {
			return message, nil
		}
	}
	return VoicemailMessage{}, os.ErrNotExist
}

// MarkMessageRead flags a voicemail as heard.
func (store *Store) MarkMessageRead(id string) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return err
	}
	for index, message := range loaded.Messages {
		if message.ID != id {
			continue
		}
		message.Read = true
		loaded.Messages[index] = message
		return store.save(loaded)
	}
	return os.ErrNotExist
}

// DeleteMessage removes a voicemail, returning its file path for cleanup.
func (store *Store) DeleteMessage(id string) (string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	loaded, err := store.load()
	if err != nil {
		return "", err
	}
	for index, message := range loaded.Messages {
		if message.ID != id {
			continue
		}
		loaded.Messages = append(loaded.Messages[:index], loaded.Messages[index+1:]...)
		if err := store.save(loaded); err != nil {
			return "", err
		}
		return message.Path, nil
	}
	return "", os.ErrNotExist
}

func nonNilRules(value []rules.Rule) []rules.Rule {
	if value == nil {
		return []rules.Rule{}
	}
	return value
}

func nonNilContacts(value []contacts.Contact) []contacts.Contact {
	if value == nil {
		return []contacts.Contact{}
	}
	return value
}

func nonNilTasks(value []KeepaliveTask) []KeepaliveTask {
	if value == nil {
		return []KeepaliveTask{}
	}
	return value
}

var idCounter struct {
	sync.Mutex
	value uint32
}

func newID() string {
	idCounter.Lock()
	defer idCounter.Unlock()
	idCounter.value++
	return fmt.Sprintf("%s-%04x", time.Now().UTC().Format("20060102150405"), idCounter.value%0xffff)
}
