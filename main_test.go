package main

import (
	"reflect"
	"testing"

	"github.com/aws/aws-network-policy-agent/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildManagerOptions_TrimsPolicyEndpointCache(t *testing.T) {
	opts := buildManagerOptions(config.RuntimeConfig{MetricsBindAddress: ":8162", HealthProbeBindAddress: ":8163"})
	assert.Equal(t, ":8162", opts.Metrics.BindAddress)
	assert.Equal(t, ":8163", opts.HealthProbeBindAddress)
	assert.Same(t, scheme, opts.Scheme)
	var kinds []string
	for obj, byObj := range opts.Cache.ByObject {
		require.NotNil(t, byObj.Transform, "%T has no Transform", obj)
		kinds = append(kinds, reflect.TypeOf(obj).Elem().Name())
	}
	assert.ElementsMatch(t, []string{"PolicyEndpoint", "ClusterPolicyEndpoint"}, kinds)
}
