package controllers

import (
	"testing"
	"time"

	"github.com/aws/aws-network-policy-agent/pkg/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestReconcilePolicyEndpoint_MapWriteErrorRequeues(t *testing.T) {
	web, api := identifierOf("web-aaa"), identifierOf("api-aaa")
	fx := newPEFixture(t)
	fx.setSlices(
		sliceSpec{name: "np-1-aaaaa", parent: "np-1",
			pods:    []podRef{localPod("web-aaa", "10.1.1.1"), localPod("api-aaa", "10.1.1.2")},
			ingress: []ruleRef{allow("192.168.90.1/32")}},
	)
	enomem := assert.AnError
	fx.bpf.UpdateEbpfMapsErrFor = map[string]error{web: enomem}

	err := fx.reconcile("np-1-aaaaa")

	require.Error(t, err, "a failed map write must reach controller-runtime so the PE is requeued (#686)")
	assert.ErrorIs(t, err, enomem)
	assert.Contains(t, err.Error(), web)
	assert.Equal(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(api),
		"one failing identifier must not stop the others from being programmed")
	state, ok := fx.podState(api)
	require.True(t, ok)
	assert.Equal(t, ebpf.POLICIES_APPLIED, state)

	fx.bpf.UpdateEbpfMapsErrFor = nil
	require.NoError(t, fx.reconcile("np-1-aaaaa"), "the requeued reconcile converges once the write succeeds")
	assert.Equal(t, []string{"192.168.90.1/32"}, fx.ingressCIDRs(web))
}

func TestProgrammingRateLimiter_BoundedBackoff(t *testing.T) {
	rl := newProgrammingRateLimiter()
	req := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "np-1-aaaaa"}}

	assert.Equal(t, 100*time.Millisecond, rl.When(req), "first retry is not a hot loop")
	prev := programmingRetryBaseDelay
	var total time.Duration
	for i := 0; i < 40; i++ {
		d := rl.When(req)
		assert.GreaterOrEqual(t, d, prev, "delay never shrinks while failures continue")
		assert.LessOrEqual(t, d, programmingRetryMaxDelay, "delay is capped below the 1000s default")
		prev = d
		total += d
	}
	assert.Equal(t, 2*time.Minute, prev, "the retry gap must stay under the ~781s #686 outage")
	// 41 retries take > 1 hour: a permanently failing PE is retried about every 2 minutes, not spun.
	assert.Greater(t, total, time.Hour)
}

func TestProgrammingRateLimiter_ForgetResets(t *testing.T) {
	rl := newProgrammingRateLimiter()
	a := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "a"}}
	b := reconcile.Request{NamespacedName: types.NamespacedName{Namespace: "ns", Name: "b"}}
	for i := 0; i < 10; i++ {
		rl.When(a)
	}
	assert.Equal(t, programmingRetryBaseDelay, rl.When(b), "backoff is per PolicyEndpoint")
	rl.Forget(a)
	assert.Equal(t, programmingRetryBaseDelay, rl.When(a), "a success resets the backoff")
}
