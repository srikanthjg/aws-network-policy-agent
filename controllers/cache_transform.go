package controllers

import (
	policyk8sawsv1 "github.com/aws/aws-network-policy-agent/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// CacheOptions trims the cached PolicyEndpoint and ClusterPolicyEndpoint objects to what the reconcilers read.
func CacheOptions() cache.Options {
	return cache.Options{
		ByObject: map[client.Object]cache.ByObject{
			&policyk8sawsv1.PolicyEndpoint{}:        {Transform: StripPolicyEndpointTransformFunc},
			&policyk8sawsv1.ClusterPolicyEndpoint{}: {Transform: StripPolicyEndpointTransformFunc},
		},
	}
}

// StripPolicyEndpointTransformFunc keeps Spec whole and drops managedFields, status and unread annotations.
// If a reconciler starts reading another metadata field or annotation, add it to stripObjectMeta.
func StripPolicyEndpointTransformFunc(obj interface{}) (interface{}, error) {
	switch o := obj.(type) {
	case *policyk8sawsv1.PolicyEndpoint:
		o.ObjectMeta = stripObjectMeta(o.ObjectMeta)
		o.Status = policyk8sawsv1.PolicyEndpointStatus{}
	case *policyk8sawsv1.ClusterPolicyEndpoint:
		o.ObjectMeta = stripObjectMeta(o.ObjectMeta)
		o.Status = policyk8sawsv1.ClusterPolicyEndpointStatus{}
	}
	return obj, nil
}

func stripObjectMeta(in metav1.ObjectMeta) metav1.ObjectMeta {
	var annotations map[string]string
	if v, ok := in.Annotations[LastChangeTriggerTimeAnnotation]; ok {
		annotations = map[string]string{LastChangeTriggerTimeAnnotation: v}
	}
	return metav1.ObjectMeta{
		Name:                       in.Name,
		Namespace:                  in.Namespace,
		UID:                        in.UID,
		ResourceVersion:            in.ResourceVersion,
		Generation:                 in.Generation,
		CreationTimestamp:          in.CreationTimestamp,
		DeletionTimestamp:          in.DeletionTimestamp,
		DeletionGracePeriodSeconds: in.DeletionGracePeriodSeconds,
		Labels:                     in.Labels,
		Annotations:                annotations,
		OwnerReferences:            in.OwnerReferences,
		Finalizers:                 in.Finalizers,
	}
}
