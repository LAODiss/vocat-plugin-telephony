package store

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpsertCallMergesWithoutErasingEarlierFields(t *testing.T) {
	database := openTestStore(t)
	started := time.Now().UTC().Add(-2 * time.Minute)

	ringing, err := database.UpsertCall(CallRecord{
		CallID: "c1", DeviceID: "ec20", DeviceName: "Bench",
		Direction: "incoming", Peer: "+447700900123", ContactName: "Alice",
		State: "ringing", StartedAt: started, Codec: "PCMA",
	})
	if err != nil {
		t.Fatalf("UpsertCall(ringing) error = %v", err)
	}
	if ringing.ID == "" {
		t.Fatal("UpsertCall must assign an id")
	}
	if ringing.DurationSeconds != 0 || ringing.Answered {
		t.Fatalf("a ringing call must have no talk time: %+v", ringing)
	}
	if !ringing.Missed {
		t.Fatal("an unanswered incoming call must read as missed until it is answered")
	}

	answered := started.Add(5 * time.Second)
	ended := answered.Add(42 * time.Second)
	// A terminal poll carries no peer, contact or codec. Those must survive.
	final, err := database.UpsertCall(CallRecord{
		CallID: "c1", DeviceID: "ec20", Direction: "incoming",
		State: "ended", StartedAt: started, AnsweredAt: &answered, EndedAt: &ended,
	})
	if err != nil {
		t.Fatalf("UpsertCall(ended) error = %v", err)
	}
	if final.ID != ringing.ID {
		t.Fatalf("terminal write created a new record: %q vs %q", final.ID, ringing.ID)
	}
	if final.Peer != "+447700900123" || final.ContactName != "Alice" || final.Codec != "PCMA" {
		t.Fatalf("earlier fields were erased: %+v", final)
	}
	if final.DurationSeconds != 42 {
		t.Fatalf("DurationSeconds = %d, want 42", final.DurationSeconds)
	}
	if !final.Answered || final.Missed {
		t.Fatalf("an answered call must not be missed: %+v", final)
	}

	calls, err := database.Calls(CallFilter{})
	if err != nil {
		t.Fatalf("Calls() error = %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("len(calls) = %d, want 1 (merge must not duplicate)", len(calls))
	}
}

func TestUpsertCallRequiresIdentity(t *testing.T) {
	database := openTestStore(t)
	// Without a call id the store cannot merge polls, so a record would be
	// created on every tick.
	if _, err := database.UpsertCall(CallRecord{DeviceID: "ec20", Direction: "incoming"}); err == nil {
		t.Fatal("UpsertCall must require a call id")
	}
	if _, err := database.UpsertCall(CallRecord{CallID: "c1", Direction: "incoming"}); err == nil {
		t.Fatal("UpsertCall must require a device id")
	}
}

func TestUnansweredOutgoingCallIsNotMissed(t *testing.T) {
	database := openTestStore(t)
	record, err := database.UpsertCall(CallRecord{
		CallID: "c1", DeviceID: "ec20", Direction: "outgoing",
		Peer: "10086", State: "failed", StartedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("UpsertCall() error = %v", err)
	}
	// "Missed" only makes sense for a call someone tried to reach us on.
	if record.Missed {
		t.Fatal("an outgoing call must never be reported as missed")
	}
}

func TestCallFilters(t *testing.T) {
	database := openTestStore(t)
	now := time.Now().UTC()
	answered := now.Add(-time.Minute)
	seed := []CallRecord{
		{CallID: "in-missed", DeviceID: "ec20", Direction: "incoming", Peer: "+447700900001",
			State: "ended", StartedAt: now.Add(-3 * time.Hour)},
		{CallID: "in-answered", DeviceID: "ec20", Direction: "incoming", Peer: "+447700900002",
			State: "ended", StartedAt: now.Add(-2 * time.Hour), AnsweredAt: &answered, EndedAt: &now},
		{CallID: "out", DeviceID: "ec25", Direction: "outgoing", Peer: "10086",
			State: "ended", StartedAt: now.Add(-time.Hour)},
	}
	for _, record := range seed {
		if _, err := database.UpsertCall(record); err != nil {
			t.Fatalf("UpsertCall(%s) error = %v", record.CallID, err)
		}
	}
	if _, err := database.AttachRecording("ec25", "out", "recordings/out.wav", 2048); err != nil {
		t.Fatalf("AttachRecording() error = %v", err)
	}

	for name, testCase := range map[string]struct {
		filter CallFilter
		want   int
	}{
		"all":           {CallFilter{}, 3},
		"by device":     {CallFilter{DeviceID: "ec20"}, 2},
		"by direction":  {CallFilter{Direction: "outgoing"}, 1},
		"only missed":   {CallFilter{OnlyMissed: true}, 1},
		"only recorded": {CallFilter{OnlyRecorded: true}, 1},
		"peer digits":   {CallFilter{Peer: "9000"}, 2},
		"limit":         {CallFilter{Limit: 2}, 2},
	} {
		calls, err := database.Calls(testCase.filter)
		if err != nil {
			t.Fatalf("%s: Calls() error = %v", name, err)
		}
		if len(calls) != testCase.want {
			t.Fatalf("%s: len(calls) = %d, want %d", name, len(calls), testCase.want)
		}
	}

	// Newest first, so the panel shows recent activity without sorting.
	calls, err := database.Calls(CallFilter{})
	if err != nil {
		t.Fatalf("Calls() error = %v", err)
	}
	if calls[0].CallID != "out" || calls[2].CallID != "in-missed" {
		t.Fatalf("calls are not newest-first: %v", []string{calls[0].CallID, calls[1].CallID, calls[2].CallID})
	}
}

func TestPeerFilterMatchesAcrossFormats(t *testing.T) {
	database := openTestStore(t)
	if _, err := database.UpsertCall(CallRecord{
		CallID: "c1", DeviceID: "ec20", Direction: "incoming",
		Peer: "+44 7700 900123", State: "ended", StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertCall() error = %v", err)
	}
	// The stored number is formatted; a digits-only search must still find it.
	calls, err := database.Calls(CallFilter{Peer: "7700900123"})
	if err != nil {
		t.Fatalf("Calls() error = %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("digits search found %d calls, want 1", len(calls))
	}
}

func TestAttachRecordingAndQuotaSweep(t *testing.T) {
	database := openTestStore(t)
	if err := database.SaveRecording(RecordingSettings{
		Enabled: true, Direction: "all", MaxTotalBytes: 8 << 20, RetentionDays: 0,
	}); err != nil {
		t.Fatalf("SaveRecording() error = %v", err)
	}
	now := time.Now().UTC()
	for index, name := range []string{"old", "middle", "new"} {
		if _, err := database.UpsertCall(CallRecord{
			CallID: name, DeviceID: "ec20", Direction: "incoming", State: "ended",
			StartedAt: now.Add(time.Duration(index) * time.Minute),
		}); err != nil {
			t.Fatalf("UpsertCall(%s) error = %v", name, err)
		}
		orphaned, err := database.AttachRecording("ec20", name, "recordings/"+name+".wav", 4<<20)
		if err != nil {
			t.Fatalf("AttachRecording(%s) error = %v", name, err)
		}
		if index < 2 && len(orphaned) != 0 {
			t.Fatalf("%s: unexpected pruning %v", name, orphaned)
		}
		if index == 2 {
			// 3 x 4 MiB against an 8 MiB cap: the oldest must go.
			if len(orphaned) != 1 || !strings.Contains(orphaned[0], "old") {
				t.Fatalf("quota sweep removed %v, want the oldest", orphaned)
			}
		}
	}
	// The call records themselves must survive; only the audio reference goes.
	calls, err := database.Calls(CallFilter{})
	if err != nil {
		t.Fatalf("Calls() error = %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("len(calls) = %d, want 3 — history must outlive its audio", len(calls))
	}
	recorded, err := database.Calls(CallFilter{OnlyRecorded: true})
	if err != nil {
		t.Fatalf("Calls() error = %v", err)
	}
	if len(recorded) != 2 {
		t.Fatalf("recorded calls = %d, want 2", len(recorded))
	}
}

func TestRecordingRetentionSweep(t *testing.T) {
	database := openTestStore(t)
	now := time.Now().UTC()
	// Store with retention off, as really happens: a call is recorded, then time
	// passes and the policy is applied later.
	if err := database.SaveRecording(RecordingSettings{Enabled: true, RetentionDays: 0}); err != nil {
		t.Fatalf("SaveRecording() error = %v", err)
	}
	if _, err := database.UpsertCall(CallRecord{
		CallID: "stale", DeviceID: "ec20", Direction: "incoming", State: "ended",
		StartedAt: now.AddDate(0, 0, -40),
	}); err != nil {
		t.Fatalf("UpsertCall() error = %v", err)
	}
	if _, err := database.AttachRecording("ec20", "stale", "recordings/stale.wav", 1024); err != nil {
		t.Fatalf("AttachRecording() error = %v", err)
	}

	if err := database.SaveRecording(RecordingSettings{Enabled: true, RetentionDays: 30}); err != nil {
		t.Fatalf("SaveRecording(retention) error = %v", err)
	}
	orphaned, err := database.SweepRecordings()
	if err != nil {
		t.Fatalf("SweepRecordings() error = %v", err)
	}
	if len(orphaned) != 1 || !strings.Contains(orphaned[0], "stale") {
		t.Fatalf("retention sweep removed %v, want the stale recording", orphaned)
	}
	recorded, err := database.Calls(CallFilter{OnlyRecorded: true})
	if err != nil {
		t.Fatalf("Calls() error = %v", err)
	}
	if len(recorded) != 0 {
		t.Fatalf("stale recording survived: %+v", recorded)
	}
}

func TestDeleteCallAndClearRecording(t *testing.T) {
	database := openTestStore(t)
	saved, err := database.UpsertCall(CallRecord{
		CallID: "c1", DeviceID: "ec20", Direction: "incoming", State: "ended",
		StartedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("UpsertCall() error = %v", err)
	}
	if _, err := database.AttachRecording("ec20", "c1", "recordings/c1.wav", 100); err != nil {
		t.Fatalf("AttachRecording() error = %v", err)
	}

	path, err := database.ClearRecording(saved.ID)
	if err != nil {
		t.Fatalf("ClearRecording() error = %v", err)
	}
	if path != "recordings/c1.wav" {
		t.Fatalf("ClearRecording() path = %q", path)
	}
	record, err := database.Call(saved.ID)
	if err != nil {
		t.Fatalf("Call() error = %v", err)
	}
	if record.HasRecording() {
		t.Fatal("ClearRecording did not clear the reference")
	}

	if _, err := database.DeleteCall(saved.ID); err != nil {
		t.Fatalf("DeleteCall() error = %v", err)
	}
	if _, err := database.Call(saved.ID); !os.IsNotExist(err) {
		t.Fatalf("Call() after delete = %v, want os.ErrNotExist", err)
	}
	for name, err := range map[string]error{
		"delete": func() error { _, e := database.DeleteCall("nope"); return e }(),
		"clear":  func() error { _, e := database.ClearRecording("nope"); return e }(),
		"attach": func() error { _, e := database.AttachRecording("ec20", "nope", "x", 1); return e }(),
	} {
		if !os.IsNotExist(err) {
			t.Fatalf("%s: error = %v, want os.ErrNotExist", name, err)
		}
	}
}

func TestStatsCountsHistory(t *testing.T) {
	database := openTestStore(t)
	now := time.Now().UTC()
	answered := now.Add(-time.Minute)
	if _, err := database.UpsertCall(CallRecord{
		CallID: "a", DeviceID: "ec20", Direction: "incoming", State: "ended", StartedAt: now,
	}); err != nil {
		t.Fatalf("UpsertCall(a) error = %v", err)
	}
	if _, err := database.UpsertCall(CallRecord{
		CallID: "b", DeviceID: "ec20", Direction: "outgoing", State: "ended",
		StartedAt: now, AnsweredAt: &answered, EndedAt: &now,
	}); err != nil {
		t.Fatalf("UpsertCall(b) error = %v", err)
	}
	if _, err := database.AttachRecording("ec20", "b", "recordings/b.wav", 4096); err != nil {
		t.Fatalf("AttachRecording() error = %v", err)
	}
	stats, err := database.Stats()
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Total != 2 || stats.Incoming != 1 || stats.Outgoing != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	if stats.Missed != 1 {
		t.Fatalf("Missed = %d, want 1", stats.Missed)
	}
	if stats.Recorded != 1 || stats.RecordingBytes != 4096 {
		t.Fatalf("recording stats = %+v", stats)
	}
}

func TestRecordingSettingsDefaultsAndClamping(t *testing.T) {
	snapshot, err := openTestStore(t).Snapshot()
	if err != nil {
		t.Fatalf("Snapshot() error = %v", err)
	}
	// Recording a call has consent implications, so it must never default on.
	if snapshot.Recording.Enabled {
		t.Fatal("recording must be off by default")
	}
	if snapshot.Recording.Direction != "all" {
		t.Fatalf("Direction = %q, want all", snapshot.Recording.Direction)
	}

	clamped := RecordingSettings{
		Direction: "sideways", MaxSeconds: -1, MaxTotalBytes: -1, RetentionDays: -1,
	}.Normalize()
	defaults := DefaultRecording()
	if clamped.Direction != defaults.Direction || clamped.MaxSeconds != defaults.MaxSeconds {
		t.Fatalf("invalid values not defaulted: %+v", clamped)
	}
	if clamped.RetentionDays != 0 {
		t.Fatalf("RetentionDays = %d, want 0", clamped.RetentionDays)
	}
	huge := RecordingSettings{MaxSeconds: 99999, MaxTotalBytes: 1 << 50, RetentionDays: 99999}.Normalize()
	if huge.MaxSeconds != 3600 || huge.MaxTotalBytes != 16<<30 || huge.RetentionDays != 3650 {
		t.Fatalf("oversized values not clamped: %+v", huge)
	}
	if tiny := (RecordingSettings{MaxTotalBytes: 1024}).Normalize(); tiny.MaxTotalBytes != 8<<20 {
		t.Fatalf("tiny quota not clamped up: %d", tiny.MaxTotalBytes)
	}
}

func TestRecordingDirectionFilter(t *testing.T) {
	off := RecordingSettings{Enabled: false, Direction: "all"}
	if off.Records("incoming") {
		t.Fatal("disabled recording must record nothing")
	}
	all := RecordingSettings{Enabled: true, Direction: "all"}
	if !all.Records("incoming") || !all.Records("outgoing") {
		t.Fatal("all must record both directions")
	}
	inbound := RecordingSettings{Enabled: true, Direction: "incoming"}
	if !inbound.Records("incoming") || inbound.Records("outgoing") {
		t.Fatal("incoming-only must record inbound calls only")
	}
}

func TestCallHistorySurvivesAReopen(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "data")
	first, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := first.UpsertCall(CallRecord{
		CallID: "c1", DeviceID: "ec20", Direction: "incoming", State: "ended",
		StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertCall() error = %v", err)
	}
	second, err := Open(directory)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	calls, err := second.Calls(CallFilter{})
	if err != nil {
		t.Fatalf("Calls() error = %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("history did not survive a reopen: %+v", calls)
	}
}
