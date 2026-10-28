package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	"golang.org/x/sys/unix"
)

// maxReportedMapErrors bounds how many per-entry failures BulkRefresh logs and
// returns, so a systemic errno does not produce one log line and error per entry.
const maxReportedMapErrors = 8

// mapEntryWriter is the subset of the SDK map BulkRefresh writes through.
type mapEntryWriter interface {
	UpdateMapEntry(key, value uintptr) error
	DeleteMapEntry(key uintptr) error
}

// InMemoryBpfMap provides an in-memory representation of an eBPF map
// with synchronized updates to the underlying kernel map
type InMemoryBpfMap struct {
	// Underlying BPF map
	bpfMap *maps.BpfMap
	// In-memory representation of the map contents
	contents map[string][]byte
	// Mutex for thread safety
	mutex sync.RWMutex
	// ops overrides bpfMap for writes; nil means bpfMap. Set by tests.
	ops mapEntryWriter
}

func (m *InMemoryBpfMap) writer() mapEntryWriter {
	if m.ops != nil {
		return m.ops
	}
	return m.bpfMap
}

// isNotExist reports whether err is ENOENT. The SDK formats the errno with %s
// instead of wrapping it, so only its text survives.
func isNotExist(err error) bool {
	return err != nil && strings.Contains(err.Error(), unix.ENOENT.Error())
}

// mapErrors collects per-entry failures, keeping only the first few.
type mapErrors struct {
	errs    []error
	dropped int
}

func (e *mapErrors) add(err error) {
	if len(e.errs) < maxReportedMapErrors {
		log().Errorf("%v", err)
		e.errs = append(e.errs, err)
		return
	}
	e.dropped++
}

func (e *mapErrors) count() int { return len(e.errs) + e.dropped }

func (e *mapErrors) err() error {
	if e.dropped > 0 {
		e.errs = append(e.errs, fmt.Errorf("%d more map operation(s) failed", e.dropped))
	}
	return errors.Join(e.errs...)
}

// newInMemoryBpfMap is the constructor shadowMapForLocked uses. It is a variable so
// tests can build shadow maps without a kernel.
var newInMemoryBpfMap = NewInMemoryBpfMap

// NewInMemoryBpfMap creates a new in-memory representation of an eBPF map
// and optionally loads the initial state from the kernel
func NewInMemoryBpfMap(bpfMap *maps.BpfMap) (*InMemoryBpfMap, error) {
	m := &InMemoryBpfMap{
		bpfMap:   bpfMap,
		contents: make(map[string][]byte),
	}

	log().Infof("creating new In memory map via loading bpfmap: %+v", bpfMap)
	if err := m.loadFromKernel(); err != nil {
		return nil, err
	}
	log().Infof("created in mem map for bpfmap: %+v", bpfMap)

	return m, nil
}

// loadFromKernel loads the current state of the eBPF map from the kernel
func (m *InMemoryBpfMap) loadFromKernel() error {
	startTime := time.Now()

	defer func() {
		totalTime := time.Since(startTime)
		log().Infof("loadFromKernel completed in %v ms, loaded %d entries from kernel map",
			totalTime.Milliseconds(), len(m.contents))
	}()

	log().Infof("Starting loadFromKernel operation")

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Clear current contents
	m.contents = make(map[string][]byte)

	// Get all keys from the kernel map
	keys, err := m.bpfMap.GetAllMapKeys()
	if err != nil {
		log().Errorf("Failed to get keys from kernel map: %v", err)
		return err
	}

	// For each key, get the value and store in memory
	for _, key := range keys {
		keyByte := []byte(key)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))

		// Create a buffer for the value based on map's value size
		value := make([]byte, m.bpfMap.MapMetaData.ValueSize)
		valuePtr := uintptr(unsafe.Pointer(&value[0]))

		if err := m.bpfMap.GetMapEntry(keyPtr, valuePtr); err != nil {
			log().Errorf("Failed to get value for key %s: %v", key, err)
			return err
		}

		m.contents[key] = value
	}

	log().Infof("Loaded %d entries from kernel map", len(m.contents))
	return nil
}

// BulkRefresh efficiently handles both additions and deletions in a single operation
func (m *InMemoryBpfMap) BulkRefresh(newMapContents map[string][]byte) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Find entries to add or update
	toAdd := make(map[string][]byte)
	for k, v := range newMapContents {
		currentVal, exists := m.contents[k]
		if !exists || !bytes.Equal(currentVal, v) {
			toAdd[k] = v
		}
	}

	// Find entries to delete
	toDelete := make([]string, 0)
	for k := range m.contents {
		if _, exists := newMapContents[k]; !exists {
			toDelete = append(toDelete, k)
		}
	}

	// Every add and every delete is attempted, so one failure neither skips the
	// stale-entry sweep nor is reported as success. Failed entries stay out of
	// sync in the shadow map and are retried by the next refresh.
	var failures mapErrors
	writer := m.writer()
	for k, v := range toAdd {
		keyByte := []byte(k)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))
		valuePtr := uintptr(unsafe.Pointer(&v[0]))

		if err := writer.UpdateMapEntry(keyPtr, valuePtr); err != nil {
			sdkAPIErr.WithLabelValues("bulkRefresh-update").Inc()
			failures.add(fmt.Errorf("update kernel map entry %x: %w", keyByte, err))
			continue
		}
		m.contents[k] = v
	}

	for _, k := range toDelete {
		keyByte := []byte(k)
		keyPtr := uintptr(unsafe.Pointer(&keyByte[0]))

		if err := writer.DeleteMapEntry(keyPtr); err != nil && !isNotExist(err) {
			sdkAPIErr.WithLabelValues("bulkRefresh-delete").Inc()
			failures.add(fmt.Errorf("delete kernel map entry %x: %w", keyByte, err))
			continue
		}
		delete(m.contents, k)
	}

	log().Infof("Bulk refresh: added/updated %d entries, deleted %d entries, failed %d", len(toAdd), len(toDelete), failures.count())
	return failures.err()
}

// GetUnderlyingMap returns the underlying BpfMap
func (m *InMemoryBpfMap) GetUnderlyingMap() *maps.BpfMap {
	return m.bpfMap
}
