package ebpf

import (
	"errors"
	"fmt"
	"testing"
	"unsafe"

	goebpfmaps "github.com/aws/aws-ebpf-sdk-go/pkg/maps"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const fakeKeySize = 4

// fakeKernelMap stands in for the kernel map behind an InMemoryBpfMap. Keys
// listed in failUpdate/failDelete fail with the given error.
type fakeKernelMap struct {
	entries    map[string][]byte
	failUpdate map[string]error
	failDelete map[string]error
	updates    int
	deletes    int
}

func newFakeKernelMap() *fakeKernelMap {
	return &fakeKernelMap{entries: map[string][]byte{}, failUpdate: map[string]error{}, failDelete: map[string]error{}}
}

func readKey(ptr uintptr) string {
	p := *(*unsafe.Pointer)(unsafe.Pointer(&ptr))
	return string(unsafe.Slice((*byte)(p), fakeKeySize))
}

func (f *fakeKernelMap) UpdateMapEntry(key, value uintptr) error {
	f.updates++
	k := readKey(key)
	if err := f.failUpdate[k]; err != nil {
		return err
	}
	v := *(*unsafe.Pointer)(unsafe.Pointer(&value))
	f.entries[k] = append([]byte(nil), unsafe.Slice((*byte)(v), 1)...)
	return nil
}

func (f *fakeKernelMap) DeleteMapEntry(key uintptr) error {
	f.deletes++
	k := readKey(key)
	if err := f.failDelete[k]; err != nil {
		return err
	}
	if _, ok := f.entries[k]; !ok {
		return sdkErr("no such file or directory")
	}
	delete(f.entries, k)
	return nil
}

// sdkErr formats an errno the way aws-ebpf-sdk-go does: as text, not wrapped.
func sdkErr(errno string) error { return fmt.Errorf("unable to update map: %s", errno) }

func key(i int) string { return fmt.Sprintf("k%03d", i) }

// newTestMap returns a shadow map whose kernel already holds keys 0..n-1.
func newTestMap(n int) (*InMemoryBpfMap, *fakeKernelMap) {
	kernel := newFakeKernelMap()
	m := &InMemoryBpfMap{bpfMap: &goebpfmaps.BpfMap{}, contents: map[string][]byte{}, ops: kernel}
	for i := 0; i < n; i++ {
		kernel.entries[key(i)] = []byte{1}
		m.contents[key(i)] = []byte{1}
	}
	return m, kernel
}

func counter(fn string) float64 {
	var m dto.Metric
	if err := sdkAPIErr.WithLabelValues(fn).Write(&m); err != nil {
		panic(err)
	}
	return m.GetCounter().GetValue()
}

func TestBulkRefresh_OneOfNDeleteFails(t *testing.T) {
	const n = 10
	m, kernel := newTestMap(n)
	kernel.failDelete[key(3)] = sdkErr("cannot allocate memory")
	before := counter("bulkRefresh-delete")

	err := m.BulkRefresh(map[string][]byte{})

	require.Error(t, err, "a failed delete must not be reported as success")
	assert.Contains(t, err.Error(), "cannot allocate memory")
	assert.Equal(t, 1.0, counter("bulkRefresh-delete")-before)
	assert.Equal(t, n, kernel.deletes, "every delete must be attempted")
	assert.Equal(t, map[string][]byte{key(3): {1}}, kernel.entries, "the other N-1 entries must be deleted")
	assert.Contains(t, m.contents, key(3), "the shadow keeps the stale key so the retry re-attempts it")
	assert.Len(t, m.contents, 1)

	delete(kernel.failDelete, key(3))
	require.NoError(t, m.BulkRefresh(map[string][]byte{}), "the retry must converge")
	assert.Empty(t, kernel.entries)
	assert.Empty(t, m.contents)
}

func TestBulkRefresh_UpdateENOMEMPropagated(t *testing.T) {
	m, kernel := newTestMap(0)
	desired := map[string][]byte{key(0): {1}, key(1): {1}, key(2): {1}}
	kernel.failUpdate[key(1)] = sdkErr("cannot allocate memory")
	before := counter("bulkRefresh-update")

	err := m.BulkRefresh(desired)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot allocate memory")
	assert.Equal(t, 1.0, counter("bulkRefresh-update")-before)
	assert.Equal(t, 3, kernel.updates, "a failed update must not abort the remaining updates")
	assert.NotContains(t, m.contents, key(1), "a rejected entry must not enter the shadow")
	assert.Len(t, m.contents, 2)
}

func TestBulkRefresh_AddFailureStillRunsDeletes(t *testing.T) {
	m, kernel := newTestMap(2) // k000, k001 are stale
	kernel.failUpdate[key(5)] = sdkErr("cannot allocate memory")

	err := m.BulkRefresh(map[string][]byte{key(5): {1}})

	require.Error(t, err)
	assert.Equal(t, 2, kernel.deletes, "stale allows must be revoked even when an add fails")
	assert.Empty(t, kernel.entries)
}

func TestBulkRefresh_ENOSPCRecoversOnRetry(t *testing.T) {
	m, kernel := newTestMap(2)
	full := sdkErr("no space left on device")
	kernel.failUpdate[key(9)] = full

	require.ErrorContains(t, m.BulkRefresh(map[string][]byte{key(9): {1}}), "no space left on device")
	assert.Empty(t, kernel.entries, "the delete sweep must free slots in a full map")

	delete(kernel.failUpdate, key(9)) // slots are free now
	require.NoError(t, m.BulkRefresh(map[string][]byte{key(9): {1}}))
	assert.Equal(t, map[string][]byte{key(9): {1}}, kernel.entries)
}

func TestBulkRefresh_DeleteENOENTIsSuccess(t *testing.T) {
	m, kernel := newTestMap(1)
	delete(kernel.entries, key(0)) // gone from the kernel, still in the shadow
	before := counter("bulkRefresh-delete")

	require.NoError(t, m.BulkRefresh(map[string][]byte{}))
	assert.Empty(t, m.contents)
	assert.Equal(t, 0.0, counter("bulkRefresh-delete")-before)
}

func TestBulkRefresh_ErrorsCapped(t *testing.T) {
	const n = 50
	m, kernel := newTestMap(n)
	for i := 0; i < n; i++ {
		kernel.failDelete[key(i)] = sdkErr("invalid argument")
	}

	err := m.BulkRefresh(map[string][]byte{})

	require.Error(t, err)
	var joined interface{ Unwrap() []error }
	require.True(t, errors.As(err, &joined))
	assert.Len(t, joined.Unwrap(), maxReportedMapErrors+1)
	assert.Contains(t, err.Error(), fmt.Sprintf("%d more map operation(s) failed", n-maxReportedMapErrors))
	assert.Equal(t, n, kernel.deletes)
}

func TestBulkRefresh_NoChangeNoSyscall(t *testing.T) {
	m, kernel := newTestMap(3)
	require.NoError(t, m.BulkRefresh(map[string][]byte{key(0): {1}, key(1): {1}, key(2): {1}}))
	assert.Zero(t, kernel.updates+kernel.deletes)
}
