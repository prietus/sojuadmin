package main

import (
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"gopkg.in/irc.v4"
)

// Bouncer talks to soju through its unix+admin socket, the same way sojuctl
// does: one BOUNCERSERV line per connection, PRIVMSG lines as output, then
// "BOUNCERSERV OK" or "FAIL BOUNCERSERV <reason>".
type Bouncer struct {
	SocketPath string
	Timeout    time.Duration
}

type CommandError struct {
	Output []string
	Reason string
}

func (e *CommandError) Error() string { return e.Reason }

func (b *Bouncer) Run(ctx context.Context, words ...string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, b.Timeout)
	defer cancel()

	var d net.Dialer
	uc, err := d.DialContext(ctx, "unix", b.SocketPath)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to admin socket %v: %w", b.SocketPath, err)
	}
	defer uc.Close()
	if deadline, ok := ctx.Deadline(); ok {
		uc.SetDeadline(deadline)
	}

	c := irc.NewConn(uc)
	if err := c.WriteMessage(&irc.Message{
		Command: "BOUNCERSERV",
		Params:  []string{quoteWords(words)},
	}); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}

	var out []string
	for {
		m, err := c.ReadMessage()
		if err != nil {
			return out, fmt.Errorf("read: %w", err)
		}
		switch m.Command {
		case "PRIVMSG":
			out = append(out, m.Trailing())
		case "BOUNCERSERV":
			if m.Param(0) == "OK" {
				return out, nil
			}
			return out, &CommandError{Output: out, Reason: m.Trailing()}
		default:
			return out, &CommandError{Output: out, Reason: m.Trailing()}
		}
	}
}

// RunAs runs a BouncerServ command in the context of a soju user.
func (b *Bouncer) RunAs(ctx context.Context, username string, words ...string) ([]string, error) {
	return b.Run(ctx, append([]string{"user", "run", username}, words...)...)
}

// DeleteUser performs the two-step deletion; the confirmation token is the
// first 3 bytes of sha1(username), as computed by soju itself.
func (b *Bouncer) DeleteUser(ctx context.Context, username string) ([]string, error) {
	sum := sha1.Sum([]byte(username))
	return b.Run(ctx, "user", "delete", username, fmt.Sprintf("%x", sum[0:3]))
}

func (b *Bouncer) Ping(ctx context.Context) error {
	_, err := b.Run(ctx, "server", "status")
	return err
}

func quoteWords(words []string) string {
	var s strings.Builder
	for _, word := range words {
		if s.Len() > 0 {
			s.WriteRune(' ')
		}
		s.WriteString(strconv.Quote(word))
	}
	return s.String()
}

func isCommandError(err error) bool {
	var ce *CommandError
	return errors.As(err, &ce)
}
