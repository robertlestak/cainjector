package main

import (
	"context"
	"encoding/json"
	"testing"

	jsonpatch "gopkg.in/evanphx/json-patch.v4"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// A pod with a native sidecar, plus fields no k8s.io/api version knows, which
// stand in for whatever Kubernetes adds after this build.
const sidecarPod = `{
  "apiVersion": "v1",
  "kind": "Pod",
  "metadata": {"name": "job", "namespace": "default"},
  "spec": {
    "futurePodField": {"enabled": true},
    "initContainers": [
      {
        "name": "proxy",
        "image": "proxy",
        "restartPolicy": "Always",
        "startupProbe": {"exec": {"command": ["true"]}},
        "futureContainerField": "keep"
      },
      {"name": "istio-proxy", "image": "istio"}
    ],
    "containers": [
      {
        "name": "main",
        "image": "main",
        "env": [{"name": "A", "value": "1"}],
        "volumeMounts": [{"name": "work", "mountPath": "/work"}]
      }
    ],
    "volumes": [{"name": "work", "emptyDir": {}}]
  }
}`

func handle(t *testing.T, m *mutator, pod string) admission.Response {
	t.Helper()
	return m.Handle(context.Background(), admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
		Kind:      metav1.GroupVersionKind{Version: "v1", Kind: "Pod"},
		Namespace: "default",
		Object:    runtime.RawExtension{Raw: []byte(pod)},
	}})
}

func apply(t *testing.T, pod string, resp admission.Response) map[string]any {
	t.Helper()
	if !resp.Allowed {
		t.Fatalf("not allowed: %+v", resp.Result)
	}
	ops, err := json.Marshal(resp.Patches)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := jsonpatch.DecodePatch(ops)
	if err != nil {
		t.Fatal(err)
	}
	out, err := patch.Apply([]byte(pod))
	if err != nil {
		t.Fatalf("apply %s: %v", ops, err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func testMutator() *mutator {
	return &mutator{Options: Options{
		ConfigMap:         "my-org.com",
		MountPath:         "/cacerts",
		CertFileName:      "ca.crt",
		ExcludeContainers: []string{"istio-proxy"},
	}}
}

func container(t *testing.T, pod map[string]any, list string, i int) map[string]any {
	t.Helper()
	return pod["spec"].(map[string]any)[list].([]any)[i].(map[string]any)
}

func hasMount(c map[string]any) bool {
	mounts, _ := c["volumeMounts"].([]any)
	for _, m := range mounts {
		if m.(map[string]any)["mountPath"] == "/cacerts" {
			return true
		}
	}
	return false
}

func certEnv(c map[string]any) int {
	n := 0
	env, _ := c["env"].([]any)
	for _, e := range env {
		if e.(map[string]any)["name"] == "SSL_CERT_FILE" && e.(map[string]any)["value"] == "/cacerts/ca.crt" {
			n++
		}
	}
	return n
}

func TestPatchKeepsFieldsItDoesNotKnow(t *testing.T) {
	got := apply(t, sidecarPod, handle(t, testMutator(), sidecarPod))

	spec := got["spec"].(map[string]any)
	if spec["futurePodField"] == nil {
		t.Error("futurePodField was dropped")
	}
	proxy := container(t, got, "initContainers", 0)
	if proxy["restartPolicy"] != "Always" {
		t.Errorf("sidecar restartPolicy = %v, want Always", proxy["restartPolicy"])
	}
	if proxy["startupProbe"] == nil {
		t.Error("sidecar startupProbe was dropped")
	}
	if proxy["futureContainerField"] != "keep" {
		t.Error("futureContainerField was dropped")
	}
}

func TestPatchInjectsInitAndRegularContainers(t *testing.T) {
	got := apply(t, sidecarPod, handle(t, testMutator(), sidecarPod))

	proxy := container(t, got, "initContainers", 0)
	if !hasMount(proxy) || certEnv(proxy) != 1 {
		t.Errorf("sidecar not injected: %v", proxy)
	}
	if istio := container(t, got, "initContainers", 1); hasMount(istio) || certEnv(istio) != 0 {
		t.Errorf("excluded container was injected: %v", istio)
	}
	main := container(t, got, "containers", 0)
	if !hasMount(main) || certEnv(main) != 1 {
		t.Errorf("main container not injected: %v", main)
	}
	if n := len(main["volumeMounts"].([]any)); n != 2 {
		t.Errorf("main container has %d mounts, want its own plus the CA", n)
	}
	if n := len(main["env"].([]any)); n != 2 {
		t.Errorf("main container has %d env vars, want its own plus SSL_CERT_FILE", n)
	}
	volumes := got["spec"].(map[string]any)["volumes"].([]any)
	if len(volumes) != 2 {
		t.Fatalf("volumes = %v, want work plus the CA", volumes)
	}
	ca := volumes[1].(map[string]any)
	if ca["name"] != "cainjector-my-org.com" || ca["configMap"].(map[string]any)["name"] != "my-org.com" {
		t.Errorf("CA volume = %v", ca)
	}
}

func TestPatchIsIdempotent(t *testing.T) {
	m := testMutator()
	once := apply(t, sidecarPod, handle(t, m, sidecarPod))
	raw, err := json.Marshal(once)
	if err != nil {
		t.Fatal(err)
	}
	resp := handle(t, m, string(raw))
	if !resp.Allowed || len(resp.Patches) != 0 {
		t.Errorf("second pass patched again: %+v", resp.Patches)
	}
}

func TestPodWithoutVolumesOrEnv(t *testing.T) {
	pod := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"p"},"spec":{"containers":[{"name":"c","image":"c"}]}}`
	got := apply(t, pod, handle(t, testMutator(), pod))
	c := container(t, got, "containers", 0)
	if !hasMount(c) || certEnv(c) != 1 {
		t.Errorf("container not injected: %v", c)
	}
	if n := len(got["spec"].(map[string]any)["volumes"].([]any)); n != 1 {
		t.Errorf("volumes = %d, want 1", n)
	}
}

func TestSetEnvVarFalse(t *testing.T) {
	m := testMutator()
	m.Options.SetEnvVar = "false"
	got := apply(t, sidecarPod, handle(t, m, sidecarPod))
	main := container(t, got, "containers", 0)
	if !hasMount(main) || certEnv(main) != 0 {
		t.Errorf("want mount without SSL_CERT_FILE: %v", main)
	}
}

func TestNoBundleConfiguredLeavesPodAlone(t *testing.T) {
	resp := handle(t, &mutator{Options: Options{MountPath: "/cacerts"}}, sidecarPod)
	if !resp.Allowed || len(resp.Patches) != 0 {
		t.Errorf("patched without a secret or configMap: %+v", resp.Patches)
	}
}
