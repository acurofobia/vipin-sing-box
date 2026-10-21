package libbox

import (
	stdlog "log"
	"regexp"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/log"
)

// The transport bootstraps before the command server exists. Keep a bounded
// backlog, then deliver its standard-library logs to the normal sing-box stream.
var prototypeLogs = newPrototypeLogWriter()
var prototypeSecretField = regexp.MustCompile(`(?i)((?:access_token|success_token|anonym_token|anonymous_token|session_token|token|password|private_key|pre_shared_key|captcha_sid)"?\s*[=:]\s*"?)[^"\s&,}]+`)
var prototypeURL = regexp.MustCompile(`(?i)(?:https?|wdtt|vkturnproxy)://[^\s"'<>]+`)
var prototypeKey = regexp.MustCompile(`(?i)((?:privatekey|publickey|username|credential|turn_password)"?\s*[=:]\s*"?)[^"\s&,}]+`)

type prototypeLogWriter struct {
	sync.Mutex
	server  *CommandServer
	pending []string
	history []string
	secrets []string
	active  bool
}

func newPrototypeLogWriter() *prototypeLogWriter { return &prototypeLogWriter{active: true} }

func (w *prototypeLogWriter) reset(secrets []string) {
	w.Lock()
	defer w.Unlock()
	w.server = nil
	w.pending = nil
	w.history = nil
	w.secrets = secrets
	w.active = true
}

func (w *prototypeLogWriter) Write(data []byte) (int, error) {
	w.Lock()
	defer w.Unlock()
	if !w.active {
		return len(data), nil
	}
	message := strings.TrimSpace(string(data))
	for _, secret := range w.secrets {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[redacted]")
		}
	}
	message = prototypeSecretField.ReplaceAllString(message, "${1}[redacted]")
	message = prototypeKey.ReplaceAllString(message, "${1}[redacted]")
	message = prototypeURL.ReplaceAllString(message, "[redacted-url]")
	if len(message) > 2048 {
		message = string([]rune(message)[:min(len([]rune(message)), 1024)]) + "…"
	}
	message = "[VK TURN] " + message
	if len(w.history) == 200 {
		w.history = w.history[1:]
	}
	w.history = append(w.history, message)
	if w.server != nil {
		w.server.WriteMessage(int32(log.LevelInfo), message)
	} else {
		if len(w.pending) == 100 {
			w.pending = w.pending[1:]
		}
		w.pending = append(w.pending, message)
	}
	return len(data), nil
}

func (w *prototypeLogWriter) attach(server *CommandServer) {
	w.Lock()
	defer w.Unlock()
	w.server = server
	if server != nil {
		for _, message := range w.pending {
			server.WriteMessage(int32(log.LevelInfo), message)
		}
		w.pending = nil
	}
}

func SetVKTurnPrototypeLogServer(server *CommandServer) { prototypeLogs.attach(server) }

func beginPrototypeLogs() {
	prototypeLogs.reset(nil)
	stdlog.SetOutput(prototypeLogs)
}
