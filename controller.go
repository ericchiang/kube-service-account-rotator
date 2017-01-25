package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/ericchiang/k8s"
	"github.com/ericchiang/k8s/api/v1"
	"gopkg.in/square/go-jose.v2"
)

const (
	annotationDeletePodAt  = "ericchiang.github.io/delete-pod-at"
	annotationNextRotation = "ericchiang.github.io/service-account-rotate-at"

	// Same format as used by JSON marshaling.
	timeFormat = time.RFC3339Nano
)

// controller is a service that rotates the service account credentials
// for a namespace of a Kubernetes cluster.
type controller struct {
	// A kubernetes client.
	client *k8s.CoreV1

	// Namespace that this controller acts on. Required for now though it
	// may be possible for this to act on a cluster wide basis.
	namespace string

	// Raw root CA of the API server. Must be embedded in the service
	// account secret.
	rootCA []byte

	// Private key to sign service account tokens with.
	signer jose.Signer

	// Logger to print info and error messages with.
	logger *logrus.Logger

	// Function for determining time. Outside of tests this should be
	// set to time.Now.
	now func() time.Time

	// Amount of time between token rotations.
	rotateAfter time.Duration
}

func (c *controller) run(ctx context.Context) {
	firstTime := true
	for {
		if firstTime {
			firstTime = false
		} else {
			time.Sleep(time.Second)
		}

		if err := c.rotate(ctx); err != nil {
			c.logger.Errorf("rotate service account creds: %v", err)
		}

		if err := c.markPods(ctx); err != nil {
			c.logger.Errorf("mark pods for deletion: %v", err)
		}

		if err := c.deletePods(ctx); err != nil {
			c.logger.Errorf("rotate pods: %v", err)
		}
	}
}

func (c *controller) rotate(ctx context.Context) (err error) {
	serviceAccounts, err := c.client.ListServiceAccounts(ctx, c.namespace)
	if err != nil {
		return fmt.Errorf("list service accounts: %v", err)
	}
	var toRotate []*v1.ServiceAccount
	for _, account := range serviceAccounts.Items {
		expiresAt, ok := nextRotation(account)
		if !ok || c.now().After(expiresAt) {
			toRotate = append(toRotate, account)
		}
	}

	for _, account := range toRotate {
		// TODO: Do this concurrently.
		if err := c.rotateServiceAccountCreds(ctx, account); err != nil {
			return fmt.Errorf("update service account: %v", err)
		}
		c.logger.Infof("rotated credentials for service account %s", *account.Metadata.Name)
	}
	return nil
}

func (c *controller) markPods(ctx context.Context) (err error) {
	serviceAccounts, err := c.client.ListServiceAccounts(ctx, c.namespace)
	if err != nil {
		return fmt.Errorf("list service accounts: %v", err)
	}
	pods, err := c.client.ListPods(ctx, c.namespace)
	if err != nil {
		return fmt.Errorf("list service accounts: %v", err)
	}
	for _, pod := range markPodsToDelete(serviceAccounts.Items, pods.Items, c.now) {
		// TODO: Do this concurrently.
		if _, err := c.client.UpdatePod(ctx, pod); err != nil {
			return fmt.Errorf("update pods: %v", err)
		}

		// Pod has been marked with the correct annotation already. Don't
		// check error.
		t, _ := deleteAt(pod)
		c.logger.Infof("pod %s marked for deletion at %s", *pod.Metadata.Name, t)
	}
	return nil
}

func (c *controller) deletePods(ctx context.Context) (err error) {
	pods, err := c.client.ListPods(ctx, c.namespace)
	if err != nil {
		return fmt.Errorf("list pods: %v", err)
	}
	for _, pod := range pods.Items {
		// TODO: Do this concurrently.

		if t, ok := deleteAt(pod); ok && c.now().After(t) {
			err := c.client.DeletePod(ctx, *pod.Metadata.Name, c.namespace)
			if err != nil {
				return fmt.Errorf("delete pod: %v", err)
			}
			c.logger.Infof("pod %s deleted", *pod.Metadata.Name)
		}
	}
	return nil
}

// rotateServiceAccountCreds creates a new secret for a service account and updates
// the service account to use it.
func (c *controller) rotateServiceAccountCreds(ctx context.Context, s *v1.ServiceAccount) (err error) {
	// Create a new secret for the service account and try to create it.
	secret, err := newSecret(c.signer, c.rootCA, s)
	if err != nil {
		return fmt.Errorf("update secret: %v", err)
	}
	if secret, err = c.client.CreateSecret(ctx, secret); err != nil {
		return fmt.Errorf("create secret: %v", err)
	}
	c.logger.Infof("created secret %s", *secret.Metadata.Name)

	newRef := &v1.ObjectReference{
		Kind:       k8s.String("Secret"),
		Namespace:  secret.Metadata.Namespace,
		Name:       secret.Metadata.Name,
		Uid:        secret.Metadata.Uid,
		ApiVersion: k8s.String("v1"),
	}
	var toDelete []*v1.ObjectReference
	if len(s.Secrets) == 0 {
		s.Secrets = []*v1.ObjectReference{newRef}
	} else {
		if len(s.Secrets) > 1 {
			toDelete = s.Secrets[1:]
		}
		s.Secrets = []*v1.ObjectReference{newRef, s.Secrets[0]}
	}

	if s.Metadata.Annotations == nil {
		s.Metadata.Annotations = make(map[string]string)
	}
	s.Metadata.Annotations[annotationNextRotation] = c.now().Add(c.rotateAfter).Format(timeFormat)

	if _, err := c.client.UpdateServiceAccount(ctx, s); err != nil {
		// Failed to update service account. Try to delete the new secret.
		if err := c.client.DeleteSecret(ctx, *secret.Metadata.Name, c.namespace); err != nil {
			c.logger.Errorf("delete secret: %v", err)
		}
		return fmt.Errorf("update service account: %v", err)
	}

	// Clean up any old secret.
	for _, secret := range toDelete {
		if err := c.client.DeleteSecret(ctx, *secret.Name, c.namespace); err != nil {
			c.logger.Errorf("delete secret: %v", err)
		}
	}
	return nil
}

// nextRotation determines the next rotation of a service account based
// on its annotations.
func nextRotation(s *v1.ServiceAccount) (time.Time, bool) {
	if s.Metadata == nil || len(s.Metadata.Annotations) == 0 {
		return time.Time{}, false
	}
	nextRotation := s.Metadata.Annotations[annotationNextRotation]
	if nextRotation == "" {
		return time.Time{}, false
	}
	expiresAt, err := time.Parse(timeFormat, nextRotation)
	if err != nil {
		// ignore any parsing errors.
		return time.Time{}, false
	}
	return expiresAt, true
}

// deleteAt determines when to delete a pod that is using an service
// account token that will expire.
func deleteAt(p *v1.Pod) (time.Time, bool) {
	if p.Metadata == nil || len(p.Metadata.Annotations) == 0 {
		return time.Time{}, false
	}
	at := p.Metadata.Annotations[annotationDeletePodAt]
	if at == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(timeFormat, at)
	if err != nil {
		// ignore any parsing errors.
		return time.Time{}, false
	}
	return t, true
}

func markPodsToDelete(serviceAccounts []*v1.ServiceAccount, pods []*v1.Pod, nowFunc func() time.Time) (toUpdate []*v1.Pod) {
	secretExpiresAt := make(map[string]time.Time)
	for _, account := range serviceAccounts {
		expiresAt, ok := nextRotation(account)
		if !ok {
			continue
		}
		if len(account.Secrets) > 0 {
			for _, secret := range account.Secrets[1:] {
				secretExpiresAt[*secret.Name] = expiresAt
			}
		}
	}

	podsToMark := make(map[string][]*v1.Pod)
	for _, pod := range pods {
		if _, ok := deleteAt(pod); ok {
			// pod is already marked for deletion
			continue
		}

		for _, secret := range secretsForPod(pod) {
			// TODO: What if the pod mounts multiple service accounts?
			// TODO: Don't assume everything is in the same namespace.

			if _, ok := secretExpiresAt[secret]; ok {
				podsToMark[secret] = append(podsToMark[secret], pod)
				break
			}
		}
	}

	now := nowFunc()

	annotateDeletion := func(pod *v1.Pod, deleteAt time.Time) {
		if pod.Metadata.Annotations == nil {
			pod.Metadata.Annotations = make(map[string]string)
		}
		pod.Metadata.Annotations[annotationDeletePodAt] = deleteAt.Format(timeFormat)
	}

	for secret, pods := range podsToMark {
		expiresAt := secretExpiresAt[secret]
		if now.After(expiresAt) {
			// Pods should have already been deleted!
			for _, pod := range pods {
				annotateDeletion(pod, now)
				toUpdate = append(toUpdate, pod)
			}

		} else {
			// space out deletion
			step := int64(expiresAt.Sub(now)) / (int64(len(pods)) + 1)

			for i, pod := range pods {
				afterNow := time.Duration(step * (int64(i) + 1))
				annotateDeletion(pod, now.Add(afterNow))
				toUpdate = append(toUpdate, pod)
			}
		}
	}
	return toUpdate
}

// secretsForPod returns the names of all secrets the pod has
// requested to mount.
func secretsForPod(pod *v1.Pod) (secrets []string) {
	if pod.Spec == nil || len(pod.Spec.Volumes) == 0 {
		return nil
	}

	for _, v := range pod.Spec.Volumes {
		if v.VolumeSource == nil ||
			v.VolumeSource.Secret == nil ||
			v.VolumeSource.Secret.SecretName == nil ||
			*v.VolumeSource.Secret.SecretName == "" {
			continue
		}
		secrets = append(secrets, *v.VolumeSource.Secret.SecretName)
	}
	return
}

// newSecret generates a new secret for a service account including
// signing a new bearer token.
func newSecret(signer jose.Signer, rootCA []byte, s *v1.ServiceAccount) (*v1.Secret, error) {
	secretName := *s.Metadata.Name + "-token-" + randName()

	// Values taken from the Kubernetes code base.
	//
	// See: https://github.com/kubernetes/kubernetes/blob/v1.5.2/pkg/serviceaccount/jwt.go
	t := struct {
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		Name      string `json:"kubernetes.io/serviceaccount/service-account.name"`
		Uid       string `json:"kubernetes.io/serviceaccount/service-account.uid"`
		Namespace string `json:"kubernetes.io/serviceaccount/namespace"`
		Secret    string `json:"kubernetes.io/serviceaccount/secret.name"`
	}{
		Issuer:    "kubernetes/serviceaccount",
		Subject:   "system:serviceaccount:" + *s.Metadata.Namespace + ":" + *s.Metadata.Name,
		Name:      *s.Metadata.Name,
		Uid:       *s.Metadata.Uid,
		Namespace: *s.Metadata.Namespace,
		Secret:    secretName,
	}

	// Marshal, sign, and serialize the service account JWT.
	payload, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("encode token: %v", err)
	}
	jwt, err := signer.Sign(payload)
	if err != nil {
		return nil, fmt.Errorf("sign token: %v", err)
	}
	token, err := jwt.CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("serialize token: %v", err)
	}

	return &v1.Secret{
		Metadata: &v1.ObjectMeta{
			Name:      &secretName,
			Namespace: s.Metadata.Namespace,
			// Required annotations for all service accounts.
			Annotations: map[string]string{
				"kubernetes.io/service-account.name": *s.Metadata.Name,
				"kubernetes.io/service-account.uid":  *s.Metadata.Uid,
			},
		},
		Type: k8s.String("kubernetes.io/service-account-token"),
		Data: map[string][]byte{
			"ca.crt":    rootCA,
			"namespace": []byte(*s.Metadata.Namespace),
			"token":     []byte(token),
		},
	}, nil
}

func init() {
	rand.Seed(time.Now().UnixNano())
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")

func randName() string {
	b := make([]rune, 5)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
