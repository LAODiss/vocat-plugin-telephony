// Audio bridge between a softphone's RTP stream and vocat's PCM WebSocket.
//
// Both sides are 8 kHz mono, so this is a relay with codec companding and no
// resampling. The two directions are pumped by separate goroutines because they
// are independently paced: RTP arrives on the network's schedule, the WebSocket
// on vocat's.
package sipgw

import (
	"context"
	"net/http"
	"sync"
	"time"

	"vocat-plugin-telephony/internal/media"
	"vocat-plugin-telephony/internal/rtp"
)

// bridge relays audio for one call.
type bridge struct {
	rtpSession *rtp.Session
	pcm        *media.Session

	closeOnce sync.Once
	done      chan struct{}
	// wg tracks the two pump goroutines so Close does not return while they are
	// still touching the sockets.
	wg sync.WaitGroup
}

// startBridge connects an RTP session to vocat's audio socket for a call.
func startBridge(
	ctx context.Context,
	rtpSession *rtp.Session,
	mediaURL string,
	client *http.Client,
) (*bridge, error) {
	pcm, err := media.Dial(ctx, mediaURL, client)
	if err != nil {
		return nil, err
	}
	relay := &bridge{rtpSession: rtpSession, pcm: pcm, done: make(chan struct{})}
	relay.wg.Add(2)
	go relay.pumpToVocat(ctx)
	go relay.pumpToPhone(ctx)
	return relay, nil
}

// pumpToVocat carries the phone's audio into the call.
func (relay *bridge) pumpToVocat(ctx context.Context) {
	defer relay.wg.Done()
	for {
		select {
		case <-relay.done:
			return
		case <-ctx.Done():
			return
		default:
		}
		// A read timeout is silence, not an error: the phone may simply be quiet,
		// and treating that as failure would tear down a live call.
		samples, err := relay.rtpSession.Read(500 * time.Millisecond)
		if err != nil {
			return
		}
		if samples == nil {
			continue
		}
		if err := relay.pcm.Write(ctx, samples); err != nil {
			return
		}
	}
}

// pumpToPhone carries the call's audio to the phone.
func (relay *bridge) pumpToPhone(ctx context.Context) {
	defer relay.wg.Done()
	for {
		select {
		case <-relay.done:
			return
		case <-ctx.Done():
			return
		default:
		}
		readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		samples, err := relay.pcm.Read(readCtx)
		cancel()
		if err != nil {
			// A closed socket means vocat ended the call; a timeout is silence.
			if media.IsClosed(err) || ctx.Err() != nil {
				return
			}
			continue
		}
		if err := relay.rtpSession.Write(samples); err != nil {
			return
		}
	}
}

// Stats reports the RTP counters, for the panel.
func (relay *bridge) Stats() rtp.Stats {
	return relay.rtpSession.Stats()
}

// Close tears down both directions. Safe to call twice.
func (relay *bridge) Close() {
	relay.closeOnce.Do(func() {
		close(relay.done)
		// Closing the sockets is what unblocks a pump parked in a read, so it has
		// to happen before waiting on them.
		relay.pcm.Close()
		relay.rtpSession.Close()
		relay.wg.Wait()
	})
}
