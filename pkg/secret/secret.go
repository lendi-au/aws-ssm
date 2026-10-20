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
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"

	anno "github.com/cmattoon/aws-ssm/pkg/annotations"
	"github.com/cmattoon/aws-ssm/pkg/provider"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/util/retry"
)

type Secret struct {
	Secret v1.Secret
	// Kubernetes Secret Name
	Name string
	// Kubernetes Namespace
	Namespace string
	// AWS Param Name
	ParamName string
	// AWS Param Type
	ParamType string
	// AWS Param Key (Default: "alias/aws/ssm")
	ParamKey string
	// AWS Param Value
	ParamValue string
	// The data to add to Kubernetes Secret Data
	Data map[string]string
}

func NewSecret(sec v1.Secret, p provider.Provider, secret_name string, secret_namespace string, param_name string, param_type string, param_key string, roleArn string) (*Secret, error) {

	s := &Secret{
		Secret:     sec,
		Name:       secret_name,
		Namespace:  secret_namespace,
		ParamName:  param_name,
		ParamType:  param_type,
		ParamKey:   param_key,
		ParamValue: "",
		Data:       map[string]string{},
	}

	log.Debugf("Getting value for '%s/%s'", s.Namespace, s.Name)

	decrypt := false
	if s.ParamKey != "" {
		decrypt = true
	}

	if s.ParamType == "String" || s.ParamType == "SecureString" {
		value, err := p.GetParameterValue(s.ParamName, decrypt, roleArn)
		if err != nil {
			return nil, err
		}
		s.ParamValue = value
	} else if s.ParamType == "StringList" {
		value, err := p.GetParameterValue(s.ParamName, decrypt, roleArn)
		if err != nil {
			return nil, err
		}
		s.ParamValue = value
		// StringList: Also set each key
		values := s.ParseStringList()
		for k, v := range values {
			s.Set(k, v)
		}
	} else if s.ParamType == "Directory" {
		// Directory: Set each sub-key
		all_params, err := p.GetParameterDataByPath(s.ParamName, decrypt, roleArn)
		if err != nil {
			return nil, err
		}

		for k, v := range all_params {
			s.Set(safeKeyName(k), v)
		}
		s.ParamValue = "true" // Reads "Directory": "true"
		return s, nil
	}

	// Always set the "$ParamType" key:
	//   String: Value
	//   SecureString: Value
	//   StringList: Value
	//   Directory: <ssm-path>
	s.Set(s.ParamType, s.ParamValue)

	return s, nil
}

// FromKubernetesSecret returns an internal Secret struct, if the v1.Secret is properly annotated.
func FromKubernetesSecret(p provider.Provider, secret v1.Secret) (*Secret, error) {
	param_name := ""
	param_type := ""
	param_key := ""
	role := ""

	for k, v := range secret.ObjectMeta.Annotations {
		switch k {
		case anno.AWSParamName, anno.V1ParamName:
			param_name = v
		case anno.AWSParamType, anno.V1ParamType:
			param_type = v
		case anno.AWSParamKey, anno.V1ParamKey:
			param_key = v
		case anno.AWSRoleArn, anno.V1RoleArn:
			role = v
		}
	}

	if param_name == "" || param_type == "" {
		return nil, errors.New("Irrelevant Secret")
	}

	if param_name != "" && param_type != "" {
		if param_type == "SecureString" && param_key == "" {
			log.Info("No KMS key defined. Using default key 'alias/aws/ssm'")
			param_key = "alias/aws/ssm"
		}
	}

	s, err := NewSecret(
		secret,
		p,
		secret.ObjectMeta.Name,
		secret.ObjectMeta.Namespace,
		param_name,
		param_type,
		param_key,
		role)

	if err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Secret) ParseStringList() (values map[string]string) {
	values = make(map[string]string)

	for _, pair := range strings.Split(strings.TrimSpace(s.ParamValue), ",") {
		pair = strings.TrimSpace(pair)
		key := pair
		val := ""

		if strings.Contains(pair, "=") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				if kv[0] != "" {
					key = kv[0]
					val = kv[1]
				}
			}
		}
		if key != "" {
			values[key] = val
		}
	}

	return
}

func (s *Secret) Set(key string, val string) (err error) {
	log.Debugf("Setting key=%s", key)
	if s.Secret.StringData == nil {
		s.Secret.StringData = make(map[string]string)
	}
	// StringData isn't populated initially, so check s.Data
	if _, ok := s.Data[key]; ok {
		// Refuse to overwite existing keys
		return errors.New(fmt.Sprintf("Key '%s' already exists for Secret %s/%s", key, s.Namespace, s.Name))
	}
	s.Secret.StringData[key] = val
	return
}

func (s *Secret) UpdateObject(cli kubernetes.Interface) (result *v1.Secret, err error) {
	log.Info("Updating Kubernetes Secret...")

	// The controller builds its work list from a point-in-time List snapshot
	// and NewSecret keeps that snapshot on s.Secret so it can derive the SSM
	// binding from the listed annotations. That snapshot must never be written
	// back to the API server verbatim: the list may predate concurrent edits
	// by other actors (helm/lcd updates to BUILD_LINK, labels, or the
	// aws-ssm/aws-param-* annotations, for example). A full-object Update of
	// the listed body restores those stale values and silently reverts the
	// other actor's change on every poll cycle.
	//
	// The only thing this controller owns is the SSM-derived data payload
	// captured below from StringData (populated during construction). From
	// here on s.Secret is intentionally ignored: each attempt re-fetches the
	// live object and applies the payload to it, so concurrent metadata edits
	// always survive.
	payload := map[string]string{}
	for k, v := range s.Secret.StringData {
		payload[k] = v
	}
	if len(payload) == 0 {
		log.Warnf("Refusing to update secret %s/%s: no SSM data payload was prepared", s.Namespace, s.Name)
		return nil, fmt.Errorf("no SSM data payload prepared for secret %s/%s", s.Namespace, s.Name)
	}

	// Wrap the Get+Update in RetryOnConflict to handle the race window between
	// reading the current ResourceVersion and writing the update.  Kubernetes
	// uses optimistic concurrency: if any other actor modifies the secret
	// between our Get and our Update the API server returns HTTP 409 Conflict:
	//
	//   the object has been modified; please apply your changes to the latest
	//   version and try again
	//
	// RetryOnConflict detects that error and retries up to 5 times with
	// exponential back-off (10 ms … 1 s).
	//
	// Re-fetching the live object inside the retry loop also refreshes the
	// UID, keeping the write valid when the secret was deleted and recreated
	// between the List snapshot and this call.
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current, getErr := cli.CoreV1().Secrets(s.Namespace).Get(s.Name, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("failed to get current secret %s/%s before update: %v", s.Namespace, s.Name, getErr)
		}

		// Skip the write when every payload key already holds the same value
		// on the live secret. This avoids needless churn across large secret
		// populations (the full-cycle instance no longer rewrites objects
		// whose SSM values have not changed) and preserves any other data keys
		// present on the secret.
		unchanged := true
		for k, v := range payload {
			if string(current.Data[k]) != v {
				unchanged = false
				break
			}
		}
		if unchanged {
			log.Debugf("Secret %s/%s is already up to date; skipping update", s.Namespace, s.Name)
			result = current
			return nil
		}

		desired := current.DeepCopy()
		if desired.Data == nil {
			desired.Data = map[string][]byte{}
		}
		for k, v := range payload {
			desired.Data[k] = []byte(v)
		}
		desired.StringData = nil

		var updateErr error
		result, updateErr = cli.CoreV1().Secrets(s.Namespace).Update(desired)
		return updateErr
	})

	return result, retryErr
}

func safeKeyName(key string) string {
	key = strings.TrimRight(key, "/")
	if strings.HasPrefix(key, "/") {
		key = strings.Replace(key, "/", "", 1)
	}
	return strings.Replace(key, "/", "_", -1)
}
