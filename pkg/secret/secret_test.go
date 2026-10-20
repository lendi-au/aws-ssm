/**
 * Copyright 2018 Curtis Mattoon
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package secret

import (
	//"reflect"
	"testing"

	anno "github.com/cmattoon/aws-ssm/pkg/annotations"
	"github.com/cmattoon/aws-ssm/pkg/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestParseStringList(t *testing.T) {
	for _, tc := range []struct {
		title    string
		pvalue   string
		expected map[string]string
	}{
		{
			title:    "parse empty value",
			pvalue:   "",
			expected: map[string]string{},
		},
		{
			title:    "parse whitespace-only value",
			pvalue:   "    ",
			expected: map[string]string{},
		},
		{
			title:  "parse some simple values",
			pvalue: "key1=val1,key2=val2,key3=val3,key4=val4",
			expected: map[string]string{
				"key1": "val1",
				"key2": "val2",
				"key3": "val3",
				"key4": "val4",
			},
		},
		{
			title:  "parse equal sign in value",
			pvalue: "key1=val1,key2=val2,key3=val3,key4=val4=true",
			expected: map[string]string{
				"key1": "val1",
				"key2": "val2",
				"key3": "val3",
				"key4": "val4=true",
			},
		},
		{
			title:  "parse non-list",
			pvalue: "key1",
			expected: map[string]string{
				"key1": "",
			},
		},
		{
			title:  "parse trailing comma",
			pvalue: "key1=value1,",
			expected: map[string]string{
				"key1": "value1",
			},
		},
		{
			title:  "parse leading/trailing comma",
			pvalue: ",key1=value1,key2=val2,key3=val3,",
			expected: map[string]string{
				"key1": "value1",
				"key2": "val2",
				"key3": "val3",
			},
		},
		{
			title:  "not a StringList",
			pvalue: "asdfjkl",
			expected: map[string]string{
				"asdfjkl": "",
			},
		},
		{
			title:  "fine i guess",
			pvalue: "ThIsMiGhTBeBaSe64==",
			expected: map[string]string{
				"ThIsMiGhTBeBaSe64": "=",
			},
		},
		{
			title:  "another StringList",
			pvalue: "123,456,789",
			expected: map[string]string{
				"123": "",
				"456": "",
				"789": "",
			},
		},
	} {
		t.Run(tc.title, func(t *testing.T) {
			s := &Secret{
				Name:       "test_secret",
				Namespace:  "test",
				ParamName:  "FOO_PARAM",
				ParamType:  "StringList",
				ParamKey:   "some-string-list",
				ParamValue: tc.pvalue,
				Data:       map[string]string{},
			}
			data := s.ParseStringList()
			assert.Equal(t, tc.expected, data)
		})
	}

}

// Should set the key/value pair
func TestSet(t *testing.T) {
	s := &Secret{
		Name:       "test_secret",
		Namespace:  "test",
		ParamName:  "FOO_PARAM",
		ParamType:  "StringList",
		ParamKey:   "foo-param",
		ParamValue: "key1=val1,key2=val2,key3=val3,key4=val4=true",
		Data:       map[string]string{},
	}
	require.NoError(t, s.Set("foo", "bar"))
	assert.Equal(t, s.Secret.StringData["foo"], "bar")
}

func TestSetRefusesToOverwriteKey(t *testing.T) {
	s := &Secret{
		Name:       "test_secret",
		Namespace:  "test",
		ParamName:  "FOO_PARAM",
		ParamType:  "StringList",
		ParamKey:   "foo-param",
		ParamValue: "key1=val1,key2=val2,key3=val3,key4=val4=true",
		Data: map[string]string{
			"foo": "bar",
		},
	}
	require.Error(t, s.Set("foo", "baz"))

	assert.Equal(t, "bar", s.Data["foo"])
	// "foo=bar" was specified initially, not via Set
	// so strictly speaking, it shouldn't be set here yet
	// (because s.Set() should fail)
	assert.Equal(t, "", s.Secret.StringData["foo"])
}

func TestSetsValue(t *testing.T) {
	p := provider.MockProvider{"FooBar123", "PlaintextIsAnError", make(map[string]string)}
	s := v1.Secret{}
	testSecret, err := NewSecret(s, p, "foo-secret", "namespace", "foo-param", "String", "", "")

	assert.Equal(t, err, nil)
	assert.Equal(t, testSecret.ParamValue, "FooBar123")
}

// When the encryption key is defined, the decrypted value should be returned
func TestNewSecretDecryptsIfKeyIsSet(t *testing.T) {
	p := provider.MockProvider{"$@#*$(@)*$", "FooBar123", make(map[string]string)}
	s := v1.Secret{}
	testSecret, err := NewSecret(s, p, "foo-secret", "namespace", "foo-param", "String", "my/test/key", "")
	assert.Equal(t, nil, err)
	assert.Equal(t, testSecret.ParamValue, p.DecryptedValue)
}

func TestNewSecretHandlesStringList(t *testing.T) {
	p := provider.MockProvider{"$@#*$(@)*$", "key1=val1,key2=val2,key3=val3", make(map[string]string)}
	s := v1.Secret{}
	ts, err := NewSecret(s, p, "foo-secret", "namespace", "foo-param", "StringList", "my/test/key", "")
	assert.True(t, err == nil)
	exp := map[string]string{
		"key1": "val1",
		"key2": "val2",
		"key3": "val3",
	}

	for k, v := range exp {
		v3, ok := ts.Secret.StringData[k]
		assert.Equal(t, ok, true)
		assert.Equal(t, v, v3)
	}

}

func TestFromKubernetesSecretReturnsErrorIfIrrelevant(t *testing.T) {
	p := provider.MockProvider{"$@#*$(@)*$", "FooBar123", make(map[string]string)}
	s := v1.Secret{} // No annotations, so no params

	_, err := FromKubernetesSecret(p, s)
	if err.Error() != "Irrelevant Secret" {
		t.Fail()
	}
}

// If the parameter is of Type=SecureString, and no key is supplied,
// attempt to use the default key.
func TestFromKubernetesSecretUsesDefaultEncryptionKey(t *testing.T) {
	p := provider.MockProvider{"$@#*$(@)*$", "FooBar123", make(map[string]string)}

	s := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"alpha.ssm.cmattoon.com/aws-param-name": "foo-param",
				"alpha.ssm.cmattoon.com/aws-param-type": "SecureString",
			},
		},
	}

	ks, err := FromKubernetesSecret(p, s)

	if err != nil || ks.ParamKey != "alias/aws/ssm" || ks.ParamValue != "FooBar123" {
		t.Fail()
	}
}

func TestFromKubernetesSecretUsesSpecifiedEncryptionKey(t *testing.T) {
	p := provider.MockProvider{"$@#*$(@)*$", "FooBar123", make(map[string]string)}

	s := v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Annotations: map[string]string{
				"alpha.ssm.cmattoon.com/aws-param-name": "foo-param",
				"alpha.ssm.cmattoon.com/aws-param-type": "SecureString",
				"alpha.ssm.cmattoon.com/aws-param-key":  "foo/bar/baz",
			},
		},
	}

	ks, err := FromKubernetesSecret(p, s)

	if err != nil || ks.ParamKey != "foo/bar/baz" || ks.ParamValue != "FooBar123" {
		t.Fail()
	}
}

// TestUpdateObjectRefetchesUID verifies that UpdateObject re-fetches the
// current secret before calling Update so that a stale UID (held in the
// in-memory snapshot from a previous List call) is replaced with the live
// UID from the API server.  Without the fix this would fail with:
//
//	StorageError: invalid object, Code: 4
//	Precondition failed: UID in precondition: <old>, UID in object meta: <new>
func TestUpdateObjectRefetchesUID(t *testing.T) {
	const namespace = "test-ns"
	const name = "my-secret"
	const staleUID types.UID = "stale-uid-from-list-snapshot"
	const currentUID types.UID = "current-uid-after-recreate"
	const currentRV = "42"

	// The secret that currently lives in the API server (new UID after a
	// delete+recreate cycle).
	liveSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			UID:             currentUID,
			ResourceVersion: currentRV,
		},
	}

	fakeClient := fake.NewSimpleClientset(liveSecret)

	// Build an internal Secret that carries the *stale* snapshot UID –
	// exactly the situation that causes the precondition failure.
	s := &Secret{
		Name:      name,
		Namespace: namespace,
		Secret: v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				UID:       staleUID, // stale – would trigger UID mismatch without fix
			},
			StringData: map[string]string{"mykey": "myvalue"},
		},
	}

	result, err := s.UpdateObject(fakeClient)
	require.NoError(t, err, "UpdateObject should succeed even when the in-memory UID is stale")
	assert.Equal(t, currentUID, result.UID, "result should carry the live UID")
	assert.Equal(t, currentRV, result.ResourceVersion, "result should carry the live ResourceVersion")
	assert.Equal(t, "myvalue", string(result.Data["mykey"]), "SSM value should be written to the secret")
	assert.Empty(t, result.StringData, "StringData should not survive the update")
}

// TestUpdateObjectRebasesOnLiveObject verifies that UpdateObject applies the
// SSM data payload onto the *live* secret rather than writing the List
// snapshot back to the API server. A stale snapshot (annotations, labels, or
// other data keys changed by another actor after the list was taken) must be
// preserved — historically the controller reverted such changes on every poll.
func TestUpdateObjectRebasesOnLiveObject(t *testing.T) {
	const namespace = "test-ns"
	const name = "my-secret"

	// The secret that currently lives in the API server. Its annotations and
	// extra data key were written by another actor (helm) *after* our List
	// snapshot was taken, so the in-memory snapshot below is stale.
	liveSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			UID:             "live-uid",
			ResourceVersion: "42",
			Annotations: map[string]string{
				"BUILD_LINK":                "https://buildkite.example/builds/209",
				anno.AWSParamName:           "/aurora/tools/amplitude/deployment-key",
				anno.AWSParamType:           "SecureString",
				"meta.helm.sh/release-name": "app-secrets",
			},
		},
		Data: map[string][]byte{
			"SecureString":   []byte("live-ssm-value"),
			"kafka-password": []byte("keep-me"),
		},
	}

	fakeClient := fake.NewSimpleClientset(liveSecret)

	// In-memory snapshot from an earlier List: stale annotations and missing
	// the other actor's data key.
	s := &Secret{
		Name:      name,
		Namespace: namespace,
		Secret: v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Annotations: map[string]string{
					"BUILD_LINK":      "https://buildkite.example/builds/186",
					anno.AWSParamName: "/aurora-dev/tools/amplitude/deployment-key-server",
					anno.AWSParamType: "SecureString",
				},
			},
			StringData: map[string]string{"SecureString": "fresh-ssm-value"},
		},
	}

	result, err := s.UpdateObject(fakeClient)
	require.NoError(t, err)

	// Data value replaced with the SSM payload...
	assert.Equal(t, "fresh-ssm-value", string(result.Data["SecureString"]))
	// ...unmanaged data keys preserved...
	assert.Equal(t, "keep-me", string(result.Data["kafka-password"]))
	// ...and the live metadata untouched: the other actor's BUILD_LINK and
	// aws-ssm param-name survive instead of being reverted to the snapshot.
	assert.Equal(t, "https://buildkite.example/builds/209", result.Annotations["BUILD_LINK"])
	assert.Equal(t, "/aurora/tools/amplitude/deployment-key", result.Annotations[anno.AWSParamName])
}

// TestUpdateObjectSkipsWhenAlreadyUpToDate verifies the no-op fast path: when
// the payload value is already present on the live secret, no Update should be
// issued at all.
func TestUpdateObjectSkipsWhenAlreadyUpToDate(t *testing.T) {
	const namespace = "test-ns"
	const name = "my-secret"

	liveSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       namespace,
			UID:             "live-uid",
			ResourceVersion: "7",
		},
		Data: map[string][]byte{
			"SecureString": []byte("unchanged-value"),
		},
	}

	fakeClient := fake.NewSimpleClientset(liveSecret)

	s := &Secret{
		Name:      name,
		Namespace: namespace,
		Secret: v1.Secret{
			StringData: map[string]string{"SecureString": "unchanged-value"},
		},
	}

	result, err := s.UpdateObject(fakeClient)
	require.NoError(t, err)
	assert.Equal(t, "7", result.ResourceVersion, "no write should occur when the payload is already present")

	actions := fakeClient.Actions()
	for _, a := range actions {
		assert.NotEqual(t, "update", a.GetVerb(), "expected no update action for an unchanged secret")
	}
}

// TestUpdateObjectRefusesEmptyPayload verifies that UpdateObject refuses to
// run when no SSM data was prepared (e.g. StringData was never populated by
// the provider), instead of writing an empty object over live secrets.
func TestUpdateObjectRefusesEmptyPayload(t *testing.T) {
	fakeClient := fake.NewSimpleClientset() // empty – nothing even reachable

	s := &Secret{
		Name:      "some-secret",
		Namespace: "test-ns",
		Secret: v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "some-secret", Namespace: "test-ns"},
			// No StringData: no payload.
		},
	}

	_, err := s.UpdateObject(fakeClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no SSM data payload prepared")
}

// TestUpdateObjectReturnsErrorWhenSecretGone verifies that UpdateObject
// returns a meaningful error when the secret no longer exists (i.e. was
// deleted and not yet recreated).
func TestUpdateObjectReturnsErrorWhenSecretGone(t *testing.T) {
	fakeClient := fake.NewSimpleClientset() // empty – no secrets

	s := &Secret{
		Name:      "missing-secret",
		Namespace: "test-ns",
		Secret: v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "missing-secret",
				Namespace: "test-ns",
			},
			StringData: map[string]string{
				"SecureString": "some-value",
			},
		},
	}

	_, err := s.UpdateObject(fakeClient)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to get current secret")
}

func TestSafeKeyName(t *testing.T) {
	keys := map[string]string{
		"/foo/bar":     "foo_bar",
		"/foo/bar/":    "foo_bar",
		"//foo/bar":    "_foo_bar",
		"//foo/bar/":   "_foo_bar",
		"/foo/bar/baz": "foo_bar_baz",
	}
	for path, exp := range keys {
		assert.Equal(t, safeKeyName(path), exp)
	}
}
