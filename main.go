package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/bombsimon/logrusr/v4"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	v1 "k8s.io/api/core/v1"
	klog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

var (
	operatorName   = os.Getenv("OPERATOR_NAME")
	operatorDomain = os.Getenv("OPERATOR_DOMAIN")
)

func init() {
	ll, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
	logr := logrusr.New(log.StandardLogger())
	klog.SetLogger(logr)
	setDefaults()
}

func setDefaults() {
	if operatorName == "" {
		operatorName = "cainjector"
	}
	if operatorDomain == "" {
		operatorDomain = "lestak.sh"
	}
}

type Options struct {
	Inject            string   `json:"inject" yaml:"inject"`
	Secret            string   `json:"secret" yaml:"secret"`
	ConfigMap         string   `json:"configMap" yaml:"configMap"`
	CertFileName      string   `json:"certFile" yaml:"certFile"`
	MountPath         string   `json:"mountPath" yaml:"mountPath"`
	SetEnvVar         string   `json:"setEnvVar" yaml:"setEnvVar"`
	IncludeNamespaces []string `json:"includeNamespaces" yaml:"includeNamespaces"`
	ExcludeContainers []string `json:"excludeContainers" yaml:"excludeContainers"`
	ExcludeNamespaces []string `json:"excludeNamespaces" yaml:"excludeNamespaces"`
}

func (m *mutator) parsePodOptions(annotations map[string]string) Options {
	l := log.WithFields(log.Fields{
		"fn": "parsePodOptions",
	})
	l.Debug("parsing pod options")
	var opts Options
	opDomain := operatorName + "." + operatorDomain
	if annotations[opDomain+"/inject"] != "" {
		l.Debug("found inject annotation")
		opts.Inject = annotations[opDomain+"/inject"]
	}
	if annotations[opDomain+"/secret"] != "" {
		l.Debug("found secret annotation")
		opts.Secret = annotations[opDomain+"/secret"]
	}
	if annotations[opDomain+"/configMap"] != "" {
		l.Debug("found configMap annotation")
		opts.ConfigMap = annotations[opDomain+"/configMap"]
	}
	if annotations[opDomain+"/mountPath"] != "" {
		l.Debug("found mountPath annotation")
		opts.MountPath = annotations[opDomain+"/mountPath"]
	}
	if annotations[opDomain+"/certFile"] != "" {
		l.Debug("found certFile annotation")
		opts.CertFileName = annotations[opDomain+"/certFile"]
	}
	if annotations[opDomain+"/setEnvVar"] != "" {
		l.Debug("found setEnvVar annotation")
		opts.SetEnvVar = annotations[opDomain+"/setEnvVar"]
	}
	if annotations[opDomain+"/excludeContainers"] != "" {
		l.Debug("found excludeContainers annotation")
		sv := strings.Split(annotations[opDomain+"/excludeContainers"], ",")
		for _, s := range sv {
			opts.ExcludeContainers = append(opts.ExcludeContainers, strings.TrimSpace(s))
		}
	}
	if annotations[opDomain+"/excludeNamespaces"] != "" {
		l.Debug("found excludeNamespaces annotation")
		sv := strings.Split(annotations[opDomain+"/excludeNamespaces"], ",")
		for _, s := range sv {
			opts.ExcludeNamespaces = append(opts.ExcludeNamespaces, strings.TrimSpace(s))
		}
	}
	if annotations[opDomain+"/includeNamespaces"] != "" {
		l.Debug("found includeNamespaces annotation")
		sv := strings.Split(annotations[opDomain+"/includeNamespaces"], ",")
		for _, s := range sv {
			opts.IncludeNamespaces = append(opts.IncludeNamespaces, strings.TrimSpace(s))
		}
	}

	// set defaults
	if opts.Inject == "" {
		l.Debug("inject not set, using default")
		opts.Inject = m.Options.Inject
	}
	if opts.Secret == "" && opts.ConfigMap == "" {
		l.Debug("secret not set, using default")
		opts.Secret = m.Options.Secret
	}
	if opts.ConfigMap == "" && opts.Secret == "" {
		l.Debug("configMap not set, using default")
		opts.ConfigMap = m.Options.ConfigMap
	}
	if opts.MountPath == "" {
		l.Debug("mountPath not set, using default")
		opts.MountPath = m.Options.MountPath
	}
	if opts.CertFileName == "" {
		l.Debug("certFileName not set, using default")
		opts.CertFileName = m.Options.CertFileName
	}
	if opts.SetEnvVar == "" {
		l.Debug("setEnvVar not set, using default")
		opts.SetEnvVar = m.Options.SetEnvVar
	}
	if len(opts.ExcludeContainers) == 0 {
		l.Debug("excludeContainers not set, using default")
		opts.ExcludeContainers = m.Options.ExcludeContainers
	}
	if len(opts.ExcludeNamespaces) == 0 {
		l.Debug("excludeNamespaces not set, using default")
		opts.ExcludeNamespaces = m.Options.ExcludeNamespaces
	}
	if len(opts.IncludeNamespaces) == 0 {
		l.Debug("includeNamespaces not set, using default")
		opts.IncludeNamespaces = m.Options.IncludeNamespaces
	}
	l.WithField("opts", fmt.Sprintf("%+v", opts)).Debug("parsed options")
	return opts
}

type mutator struct {
	Options Options `json:"options"`
}

func (m *mutator) loadConfig(f string) error {
	l := log.WithFields(log.Fields{
		"fn": "loadConfig",
	})
	l.Info("loading config")
	// if file does not exist, skip
	if _, err := os.Stat(f); os.IsNotExist(err) {
		l.Debug("config file does not exist, skipping")
		return nil
	}
	// load the config file
	b, err := os.ReadFile(f)
	if err != nil {
		l.WithError(err).Error("failed to read config file")
		return err
	}
	// unmarshal the config file
	if err := json.Unmarshal(b, &m.Options); err != nil {
		l.WithError(err).Debug("failed to unmarshal config file as json")
		// try as yaml
		if err := yaml.Unmarshal(b, &m.Options); err != nil {
			l.WithError(err).Error("failed to unmarshal config file as yaml")
			return err
		}
	}
	return nil
}

func (m *mutator) Handle(ctx context.Context, req admission.Request) admission.Response {
	l := log.WithFields(log.Fields{
		"fn": "Handle",
	})
	l.Info("handling request")
	// if the object is not a Pod, skip mutation
	if req.Kind.Kind != "Pod" {
		l.Debug("not a pod, skipping")
		return admission.Allowed("ok")
	}
	l.Debug("mutating pod")
	if req.AdmissionRequest.Object.Raw == nil {
		l.Debug("no raw object, skipping")
		return admission.Allowed("ok")
	}
	pod := &v1.Pod{}
	if err := json.Unmarshal(req.AdmissionRequest.Object.Raw, pod); err != nil {
		l.WithError(err).Error("failed to unmarshal pod")
		return admission.Errored(http.StatusBadRequest, err)
	}
	l = l.WithFields(log.Fields{
		"namespace": req.AdmissionRequest.Namespace,
	})
	l.Info("evaluating pod")
	opts := m.parsePodOptions(pod.Annotations)
	if opts.Inject == "false" {
		l.Debug("inject is false, skipping")
		return admission.Allowed("ok")
	}
	// if includeNamespaces is greater than 0 and the pod is not in an enabled namespace, skip
	if len(opts.IncludeNamespaces) > 0 {
		l.Debug("includeNamespaces is greater than 0")
		var enabled bool
	RangeEnabledNamespaces:
		for _, ns := range opts.IncludeNamespaces {
			if strings.EqualFold(req.AdmissionRequest.Namespace, ns) {
				l.Debug("pod is in an enabled namespace, continuing")
				enabled = true
				break RangeEnabledNamespaces
			}
		}
		if !enabled {
			l.Debug("pod is not in an enabled namespace, skipping")
			return admission.Allowed("ok")
		}
	}
	// if the pod is in a excluded namespace, skip
	if len(opts.ExcludeNamespaces) > 0 {
		l.Debug("excludeNamespaces is greater than 0")
		for _, ns := range opts.ExcludeNamespaces {
			if strings.EqualFold(req.AdmissionRequest.Namespace, ns) {
				l.Debug("pod is in a excluded namespace, skipping")
				return admission.Allowed("ok")
			}
		}
	}
	// if both a secret and a configMap are specified, error
	if opts.Secret != "" && opts.ConfigMap != "" {
		l.Error("both secret and configMap specified, skipping")
		return admission.Errored(http.StatusBadRequest, fmt.Errorf("both secret and configMap specified"))
	}
	l.Info("pod is enabled for injection")
	volumeName := fmt.Sprintf("%s-%s", operatorName, opts.Secret)
	if opts.Secret != "" {
		l.Debug("injecting secret")
		pod.Spec.Volumes = append(pod.Spec.Volumes, v1.Volume{
			Name: volumeName,
			VolumeSource: v1.VolumeSource{
				Secret: &v1.SecretVolumeSource{
					SecretName: opts.Secret,
				},
			},
		})
	} else if opts.ConfigMap != "" {
		l.Debug("injecting configMap")
		volumeName = fmt.Sprintf("%s-%s", operatorName, opts.ConfigMap)
		pod.Spec.Volumes = append(pod.Spec.Volumes, v1.Volume{
			Name: volumeName,
			VolumeSource: v1.VolumeSource{
				ConfigMap: &v1.ConfigMapVolumeSource{
					LocalObjectReference: v1.LocalObjectReference{
						Name: opts.ConfigMap,
					},
				},
			},
		})
	}
RangeContainers:
	for i, c := range pod.Spec.Containers {
		if len(opts.ExcludeContainers) > 0 {
			for _, dc := range opts.ExcludeContainers {
				if c.Name == dc {
					l.WithField("container", c.Name).Debug("container excluded, skipping")
					continue RangeContainers
				}
			}
		}
		// add the volume mount if it is not already there
		if c.VolumeMounts == nil {
			c.VolumeMounts = []v1.VolumeMount{}
		}
		for _, vm := range c.VolumeMounts {
			if vm.Name == volumeName {
				l.WithField("container", c.Name).Debug("volume mount already exists, skipping")
				continue RangeContainers
			}
			if vm.MountPath == opts.MountPath {
				l.WithField("container", c.Name).Debug("mount path already exists, skipping")
				continue RangeContainers
			}
		}
		pod.Spec.Containers[i].VolumeMounts = append(c.VolumeMounts, v1.VolumeMount{
			Name:      volumeName,
			MountPath: opts.MountPath,
		})
		// add the env var
		if opts.SetEnvVar == "false" {
			continue RangeContainers
		}
		pod.Spec.Containers[i].Env = append(c.Env, v1.EnvVar{
			Name:  "SSL_CERT_FILE",
			Value: fmt.Sprintf("%s/%s", opts.MountPath, opts.CertFileName),
		})
	}
	// marshal the mutated pod
	raw, err := json.Marshal(pod)
	if err != nil {
		l.WithError(err).Error("failed to marshal pod")
		return admission.Errored(http.StatusBadRequest, err)
	}
	// return the mutated pod
	l.Info("pod mutated")
	return admission.PatchResponseFromRaw(req.AdmissionRequest.Object.Raw, raw)
}

func main() {
	l := log.WithFields(log.Fields{
		"fn": "main",
	})
	l.Info("starting...")
	port := flag.Int("port", 8443, "port to listen on")
	certDir := flag.String("cert-dir", "/etc/webhook/certs", "directory containing TLS certs and keys")
	configFile := flag.String("config", "/etc/webhook/config.yaml", "path to config file")
	logLevel := flag.String("log-level", log.GetLevel().String(), "log level")
	opName := flag.String("operator-name", operatorName, "name of the operator")
	opDomain := flag.String("operator-domain", operatorDomain, "domain of the operator")
	flag.Parse()
	ll, err := log.ParseLevel(*logLevel)
	if err != nil {
		l.WithError(err).Fatal("failed to parse log level")
	}
	log.SetLevel(ll)
	operatorName = *opName
	operatorDomain = *opDomain
	opts := webhook.Options{
		Port:    *port,
		CertDir: *certDir,
	}
	server := webhook.NewServer(opts)
	l.Info("registering webhook")
	m := &mutator{}
	if err := m.loadConfig(*configFile); err != nil {
		l.WithError(err).Fatal("failed to load config")
	}
	server.Register("/mutate", &webhook.Admission{Handler: m})
	if err := server.Start(signals.SetupSignalHandler()); err != nil {
		l.WithError(err).Fatal("failed to start server")
	}
}
