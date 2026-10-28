package controllers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	networking "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	toolscache "k8s.io/client-go/tools/cache"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const lastAppliedAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

func fullObjectMeta(name, namespace string) metav1.ObjectMeta {
	created := metav1.NewTime(time.Date(2026, 10, 28, 1, 2, 3, 0, time.UTC))
	deleted := metav1.NewTime(time.Date(2026, 10, 28, 4, 5, 6, 0, time.UTC))
	grace := int64(30)
	ctrl := true
	return metav1.ObjectMeta{
		Name:                       name,
		GenerateName:               "allow-frontend-",
		Namespace:                  namespace,
		UID:                        types.UID("0b1f6f2e-6f8a-4c39-9d7e-2a1b3c4d5e6f"),
		ResourceVersion:            "123456789",
		Generation:                 3,
		CreationTimestamp:          created,
		DeletionTimestamp:          &deleted,
		DeletionGracePeriodSeconds: &grace,
		Labels:                     map[string]string{"app": "frontend"},
		Annotations: map[string]string{
			LastChangeTriggerTimeAnnotation: "2026-10-28T01:02:03.000000004Z",
			lastAppliedAnnotation:           `{"apiVersion":"networking.k8s.aws/v1alpha1"}`,
			"example.com/unused":            "x",
		},
		OwnerReferences: []metav1.OwnerReference{{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy",
			Name: "allow-frontend", UID: "9a8b7c6d-1111-2222-3333-444455556666", Controller: &ctrl, BlockOwnerDeletion: &ctrl}},
		Finalizers: []string{"networking.k8s.aws/resources"},
		ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "controller", Operation: metav1.ManagedFieldsOperationUpdate,
			APIVersion: "networking.k8s.aws/v1alpha1", Time: &created, FieldsType: "FieldsV1",
			FieldsV1: &metav1.FieldsV1{Raw: []byte(`{"f:spec":{"f:ingress":{}}}`)}}},
	}
}

func fullPorts() []policyk8sawsv1.Port {
	proto := corev1.ProtocolTCP
	port, end := int32(8080), int32(8090)
	return []policyk8sawsv1.Port{{Protocol: &proto, Port: &port, EndPort: &end}}
}

func fullPodEndpoints() []policyk8sawsv1.PodEndpoint {
	return []policyk8sawsv1.PodEndpoint{{HostIP: "10.0.0.1", PodIP: "10.0.0.10", Name: "frontend-1", Namespace: "team-a"}}
}

func fullPolicyEndpoint() *policyk8sawsv1.PolicyEndpoint {
	return &policyk8sawsv1.PolicyEndpoint{
		TypeMeta:   metav1.TypeMeta{Kind: "PolicyEndpoint", APIVersion: "networking.k8s.aws/v1alpha1"},
		ObjectMeta: fullObjectMeta("allow-frontend-abcde", "team-a"),
		Spec: policyk8sawsv1.PolicyEndpointSpec{
			PodSelector: &metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "frontend"},
				MatchExpressions: []metav1.LabelSelectorRequirement{{Key: "tier", Operator: metav1.LabelSelectorOpIn,
					Values: []string{"web"}}},
			},
			PolicyRef:            policyk8sawsv1.PolicyReference{Name: "allow-frontend", Namespace: "team-a"},
			PodIsolation:         []networking.PolicyType{networking.PolicyTypeIngress, networking.PolicyTypeEgress},
			PodSelectorEndpoints: fullPodEndpoints(),
			Ingress: []policyk8sawsv1.EndpointInfo{{CIDR: "10.1.0.0/16", DomainName: "example.com",
				Except: []policyk8sawsv1.NetworkAddress{"10.1.2.0/24"}, Ports: fullPorts()}},
			Egress: []policyk8sawsv1.EndpointInfo{{CIDR: "2001:db8::/64", DomainName: "*.example.com",
				Except: []policyk8sawsv1.NetworkAddress{"2001:db8::1/128"}, Ports: fullPorts()}},
		},
	}
}

func fullClusterPolicyEndpoint() *policyk8sawsv1.ClusterPolicyEndpoint {
	return &policyk8sawsv1.ClusterPolicyEndpoint{
		TypeMeta:   metav1.TypeMeta{Kind: "ClusterPolicyEndpoint", APIVersion: "networking.k8s.aws/v1alpha1"},
		ObjectMeta: fullObjectMeta("baseline-deny-xyz", ""),
		Spec: policyk8sawsv1.ClusterPolicyEndpointSpec{
			PolicyRef:            policyk8sawsv1.ClusterPolicyReference{Name: "baseline-deny"},
			Tier:                 policyk8sawsv1.BaselineTier,
			Priority:             42,
			PodSelectorEndpoints: fullPodEndpoints(),
			Ingress: []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "10.2.0.0/16", Ports: fullPorts(),
				DomainName: "example.com", Action: "Deny"}},
			Egress: []policyk8sawsv1.ClusterEndpointInfo{{CIDR: "10.3.0.0/16", Ports: fullPorts(),
				DomainName: "*.example.com", Action: "Accept"}},
		},
	}
}

// assertAllFieldsSet fails when the fixture leaves a field at its zero value, so a new Spec field
// cannot be added without this test also proving the Transform preserves it.
func assertAllFieldsSet(t *testing.T, path string, v reflect.Value) {
	t.Helper()
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			t.Errorf("fixture leaves %s nil", path)
			return
		}
		assertAllFieldsSet(t, path, v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			assertAllFieldsSet(t, path+"."+v.Type().Field(i).Name, v.Field(i))
		}
	case reflect.Slice, reflect.Map:
		if v.Len() == 0 {
			t.Errorf("fixture leaves %s empty", path)
			return
		}
		if v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				assertAllFieldsSet(t, fmt.Sprintf("%s[%d]", path, i), v.Index(i))
			}
		}
	default:
		if v.IsZero() {
			t.Errorf("fixture leaves %s zero", path)
		}
	}
}

func assertKeptMeta(t *testing.T, want, got metav1.ObjectMeta) {
	t.Helper()
	assert.Equal(t, want.Name, got.Name)
	assert.Equal(t, want.Namespace, got.Namespace)
	assert.Equal(t, want.UID, got.UID)
	assert.Equal(t, want.ResourceVersion, got.ResourceVersion)
	assert.Equal(t, want.Generation, got.Generation)
	assert.Equal(t, want.CreationTimestamp, got.CreationTimestamp)
	assert.Equal(t, want.DeletionTimestamp, got.DeletionTimestamp)
	assert.Equal(t, want.DeletionGracePeriodSeconds, got.DeletionGracePeriodSeconds)
	assert.Equal(t, want.Labels, got.Labels)
	assert.Equal(t, want.OwnerReferences, got.OwnerReferences)
	assert.Equal(t, want.Finalizers, got.Finalizers)
	assert.Equal(t, map[string]string{LastChangeTriggerTimeAnnotation: want.Annotations[LastChangeTriggerTimeAnnotation]}, got.Annotations)
	assert.Nil(t, got.ManagedFields)
}

func TestStripPolicyEndpoint_PreservesSpecAndReadMetadata(t *testing.T) {
	orig := fullPolicyEndpoint()
	assertAllFieldsSet(t, "PolicyEndpoint.Spec", reflect.ValueOf(orig.Spec))

	out, err := StripPolicyEndpointTransformFunc(orig.DeepCopy())
	require.NoError(t, err)
	got := out.(*policyk8sawsv1.PolicyEndpoint)

	assert.Equal(t, orig.TypeMeta, got.TypeMeta)
	assert.True(t, reflect.DeepEqual(orig.Spec, got.Spec), "Spec must be preserved verbatim")
	assertKeptMeta(t, orig.ObjectMeta, got.ObjectMeta)
	assert.Empty(t, got.GenerateName)
}

func TestStripClusterPolicyEndpoint_PreservesSpecAndReadMetadata(t *testing.T) {
	orig := fullClusterPolicyEndpoint()
	assertAllFieldsSet(t, "ClusterPolicyEndpoint.Spec", reflect.ValueOf(orig.Spec))

	out, err := StripPolicyEndpointTransformFunc(orig.DeepCopy())
	require.NoError(t, err)
	got := out.(*policyk8sawsv1.ClusterPolicyEndpoint)

	assert.True(t, reflect.DeepEqual(orig.Spec, got.Spec), "Spec must be preserved verbatim")
	assertKeptMeta(t, orig.ObjectMeta, got.ObjectMeta)
}

func TestStripPolicyEndpoint_AnnotationEdgeCases(t *testing.T) {
	cases := map[string]struct {
		in   map[string]string
		want map[string]string
	}{
		"nil annotations stay nil":        {in: nil, want: nil},
		"only unread annotations -> nil":  {in: map[string]string{lastAppliedAnnotation: "{}"}, want: nil},
		"empty trigger time is preserved": {in: map[string]string{LastChangeTriggerTimeAnnotation: ""}, want: map[string]string{LastChangeTriggerTimeAnnotation: ""}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			pe := &policyk8sawsv1.PolicyEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "pe", Namespace: "ns", Annotations: c.in}}
			out, err := StripPolicyEndpointTransformFunc(pe)
			require.NoError(t, err)
			assert.Equal(t, c.want, out.(*policyk8sawsv1.PolicyEndpoint).Annotations)
		})
	}
}

func TestStripPolicyEndpoint_EmptyPEUnchangedSpec(t *testing.T) {
	pe := &policyk8sawsv1.PolicyEndpoint{ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "ns"},
		Spec: policyk8sawsv1.PolicyEndpointSpec{PolicyRef: policyk8sawsv1.PolicyReference{Name: "np", Namespace: "ns"}}}
	want := pe.Spec.DeepCopy()
	out, err := StripPolicyEndpointTransformFunc(pe)
	require.NoError(t, err)
	got := out.(*policyk8sawsv1.PolicyEndpoint)
	assert.Equal(t, *want, got.Spec)
	assert.Nil(t, got.Spec.PodSelectorEndpoints)
	assert.Nil(t, got.Spec.Ingress)
}

func TestStripPolicyEndpoint_Idempotent(t *testing.T) {
	once, err := StripPolicyEndpointTransformFunc(fullPolicyEndpoint())
	require.NoError(t, err)
	snapshot := once.(*policyk8sawsv1.PolicyEndpoint).DeepCopy()
	twice, err := StripPolicyEndpointTransformFunc(once)
	require.NoError(t, err)
	assert.Equal(t, snapshot, twice.(*policyk8sawsv1.PolicyEndpoint))
}

func TestStripPolicyEndpoint_OtherObjectsPassThrough(t *testing.T) {
	pod := &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "p", ManagedFields: []metav1.ManagedFieldsEntry{{Manager: "m"}}}}
	out, err := StripPolicyEndpointTransformFunc(pod)
	require.NoError(t, err)
	assert.Same(t, pod, out)
	assert.Len(t, out.(*corev1.Pod).ManagedFields, 1)

	tombstone := toolscache.DeletedFinalStateUnknown{Key: "ns/pe", Obj: fullPolicyEndpoint()}
	out, err = StripPolicyEndpointTransformFunc(tombstone)
	require.NoError(t, err)
	assert.Equal(t, tombstone, out)
}

func TestStripPolicyEndpoint_ProgrammingLatencyStillObserved(t *testing.T) {
	r := &PolicyEndpointsReconciler{trackerStartTime: time.Now().Add(-time.Minute)}
	before := histSampleCount(t, policyProgrammingLatency)
	pe := newPEWithTriggerTime("pe-latency", "ns", time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano))
	pe.Annotations[lastAppliedAnnotation] = "{}"
	out, err := StripPolicyEndpointTransformFunc(pe)
	require.NoError(t, err)
	r.observePolicyProgrammingLatency(out.(*policyk8sawsv1.PolicyEndpoint), true)
	assert.Equal(t, before+1, histSampleCount(t, policyProgrammingLatency))
}

func TestStripPolicyEndpoint_FirewallRulesUnchanged(t *testing.T) {
	derive := func(pe *policyk8sawsv1.PolicyEndpoint) ([]string, bool, bool) {
		var rules []string
		for _, e := range pe.Spec.Ingress {
			rules = append(rules, fmt.Sprintf("in %s %v %d", e.CIDR, e.Except, len(e.Ports)))
		}
		for _, e := range pe.Spec.Egress {
			rules = append(rules, fmt.Sprintf("out %s %v %d", e.CIDR, e.Except, len(e.Ports)))
		}
		r := &PolicyEndpointsReconciler{}
		in, eg := r.deriveDefaultPodIsolation(pe, 0, 0)
		return rules, in, eg
	}
	orig := fullPolicyEndpoint()
	out, err := StripPolicyEndpointTransformFunc(orig.DeepCopy())
	require.NoError(t, err)
	wantRules, wantIn, wantEg := derive(orig)
	gotRules, gotIn, gotEg := derive(out.(*policyk8sawsv1.PolicyEndpoint))
	assert.Equal(t, wantRules, gotRules)
	assert.Equal(t, wantIn, gotIn)
	assert.Equal(t, wantEg, gotEg)
}

func TestCacheOptions_TransformsPolicyEndpointTypes(t *testing.T) {
	opts := CacheOptions()
	var kinds []string
	for obj, byObj := range opts.ByObject {
		require.NotNil(t, byObj.Transform, "%T has no Transform", obj)
		kinds = append(kinds, reflect.TypeOf(obj).Elem().Name())
	}
	assert.ElementsMatch(t, []string{"PolicyEndpoint", "ClusterPolicyEndpoint"}, kinds)
}

// fakeListWatchServer serves one PolicyEndpoint and one ClusterPolicyEndpoint to a real informer cache,
// over both the list+watch and the streaming watch-list protocols.
func fakeListWatchServer(pe *policyk8sawsv1.PolicyEndpoint, cpe *policyk8sawsv1.ClusterPolicyEndpoint) *httptest.Server {
	items := map[string]client.Object{
		"/apis/networking.k8s.aws/v1alpha1/policyendpoints":        pe,
		"/apis/networking.k8s.aws/v1alpha1/clusterpolicyendpoints": cpe,
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		obj, ok := items[req.URL.Path]
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		q := req.URL.Query()
		if q.Get("watch") != "true" {
			list := map[string]interface{}{"kind": obj.GetObjectKind().GroupVersionKind().Kind + "List",
				"apiVersion": "networking.k8s.aws/v1alpha1", "metadata": map[string]string{"resourceVersion": "10"},
				"items": []client.Object{obj}}
			_ = json.NewEncoder(w).Encode(list)
			return
		}
		flusher := w.(http.Flusher)
		enc := json.NewEncoder(w)
		if q.Get("sendInitialEvents") == "true" {
			_ = enc.Encode(map[string]interface{}{"type": "ADDED", "object": obj})
			_ = enc.Encode(map[string]interface{}{"type": "BOOKMARK", "object": map[string]interface{}{
				"kind": obj.GetObjectKind().GroupVersionKind().Kind, "apiVersion": "networking.k8s.aws/v1alpha1",
				"metadata": map[string]interface{}{"resourceVersion": "10",
					"annotations": map[string]string{metav1.InitialEventsAnnotationKey: "true"}}}})
		}
		flusher.Flush()
		<-req.Context().Done()
	}))
}

func TestCacheOptions_InformerCacheHoldsStrippedObjects(t *testing.T) {
	pe, cpe := fullPolicyEndpoint(), fullClusterPolicyEndpoint()
	pe.DeletionTimestamp, cpe.DeletionTimestamp = nil, nil
	srv := fakeListWatchServer(pe, cpe)
	defer srv.Close()

	scheme := runtime.NewScheme()
	require.NoError(t, policyk8sawsv1.AddToScheme(scheme))
	gv := policyk8sawsv1.GroupVersion
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(gv.WithKind("PolicyEndpoint"), meta.RESTScopeNamespace)
	mapper.Add(gv.WithKind("ClusterPolicyEndpoint"), meta.RESTScopeRoot)

	opts := CacheOptions()
	opts.Scheme, opts.Mapper = scheme, mapper
	c, err := cache.New(&rest.Config{Host: srv.URL}, opts)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	gotPE := &policyk8sawsv1.PolicyEndpoint{}
	gotCPE := &policyk8sawsv1.ClusterPolicyEndpoint{}
	_, err = c.GetInformer(ctx, gotPE)
	require.NoError(t, err)
	_, err = c.GetInformer(ctx, gotCPE)
	require.NoError(t, err)
	go func() { _ = c.Start(ctx) }()
	require.True(t, c.WaitForCacheSync(ctx))

	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(pe), gotPE))
	require.NoError(t, c.Get(ctx, client.ObjectKeyFromObject(cpe), gotCPE))
	assert.True(t, reflect.DeepEqual(pe.Spec, gotPE.Spec))
	assert.True(t, reflect.DeepEqual(cpe.Spec, gotCPE.Spec))
	for _, m := range []metav1.ObjectMeta{gotPE.ObjectMeta, gotCPE.ObjectMeta} {
		assert.Nil(t, m.ManagedFields)
		assert.Equal(t, map[string]string{LastChangeTriggerTimeAnnotation: pe.Annotations[LastChangeTriggerTimeAnnotation]}, m.Annotations)
		assert.Equal(t, pe.OwnerReferences, m.OwnerReferences)
		assert.Equal(t, pe.UID, m.UID)
	}
}
