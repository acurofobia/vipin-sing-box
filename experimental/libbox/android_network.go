package libbox

import (
	"encoding/json"
	"github.com/cacggghp/vk-turn-proxy/pkg/proxy"
	"runtime"
)

// AndroidNetwork binds/protects each socket before connect and resolves hostnames
// through the currently selected physical Android Network.
type AndroidNetwork interface {
	Protect(fd int32) error
	Resolve(host string) (StringIterator, error)
}

func SetAndroidNetwork(network AndroidNetwork) {
	if network == nil {
		proxy.SetPhysicalNetwork(nil, nil)
		return
	}
	proxy.SetPhysicalNetwork(network.Protect, func(host string) ([]string, error) {
		addresses, err := network.Resolve(host)
		if err != nil {
			return nil, err
		}
		return iteratorToArray[string](addresses), nil
	})
}

type RuntimeStats struct {
	HeapBytes  int64
	Goroutines int32
}

func AndroidRuntimeStats() *RuntimeStats {
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	return &RuntimeStats{HeapBytes: int64(stats.HeapAlloc), Goroutines: int32(runtime.NumGoroutine())}
}

// ReadAndroidLogs returns the bounded, redacted transport log as a JSON array.
func ReadAndroidLogs() string {
	prototypeLogs.Lock()
	defer prototypeLogs.Unlock()
	values := prototypeLogs.history
	if values == nil {
		values = []string{}
	}
	data, _ := json.Marshal(values)
	prototypeLogs.history = nil
	return string(data)
}
