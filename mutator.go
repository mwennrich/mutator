package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	jsonpatch "github.com/evanphx/json-patch"
	"github.com/sirupsen/logrus"
	kwhhttp "github.com/slok/kubewebhook/v2/pkg/http"
	"github.com/slok/kubewebhook/v2/pkg/log"
	kwhlogrus "github.com/slok/kubewebhook/v2/pkg/log/logrus"
	kwhmodel "github.com/slok/kubewebhook/v2/pkg/model"
	kwhmutating "github.com/slok/kubewebhook/v2/pkg/webhook/mutating"
)

type config struct {
	certFile            string
	keyFile             string
	rulesFile           string
	HealthCheckNodePort int
}

type Rule struct {
	NamespaceRe string `json:"namespace"`
	NameRe      string `json:"name"`
	KindRe      string `json:"kind"`
	Patch       string `json:"patch"`
}

type Rules struct {
	Rules []Rule `json:"rules"`
}

func initFlags() (*config, error) {
	cfg := &config{}

	fl := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fl.StringVar(&cfg.certFile, "tls-cert-file", "/etc/mutator/tls/cert.pem", "TLS certificate file")
	fl.StringVar(&cfg.keyFile, "tls-key-file", "/etc/mutator/tls/key.pem", "TLS key file")
	fl.StringVar(&cfg.rulesFile, "rules-file", "/etc/mutator/rules/rules.json", "rules file")
	fl.IntVar(&cfg.HealthCheckNodePort, "health-check-node-port", 31397, "Health check node port")

	err := fl.Parse(os.Args[1:])
	if err != nil {
		return nil,
			err
	}
	return cfg, nil
}

func run() error {
	logrusLogEntry := logrus.NewEntry(logrus.New())

	// Set log level from environment variable, default to ErrorLevel
	logLevel := logrus.ErrorLevel
	if envLogLevel := os.Getenv("LOG_LEVEL"); envLogLevel != "" {
		if level, err := logrus.ParseLevel(envLogLevel); err == nil {
			logLevel = level
		} else {
			// Log warning for invalid log level, but continue with default
			logrusLogEntry.Logger.SetLevel(logrus.WarnLevel)
			logrusLogEntry.Warnf("Invalid LOG_LEVEL '%s': %v. Using default 'error' level.", envLogLevel, err)
		}
	}
	logrusLogEntry.Logger.SetLevel(logLevel)

	logger := kwhlogrus.NewLogrus(logrusLogEntry)

	cfg, err := initFlags()
	if err != nil {
		return err
	}

	rules := readRules(cfg, logger)

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		panic(err)
	}
	defer func() {
		err := watcher.Close()
		if err != nil {
			logger.Errorf("error closing watcher: %v", err)
		}
	}()

	// Start watching the config file
	err = watcher.Add(cfg.rulesFile)
	if err != nil {
		panic(err)
	}

	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Op == fsnotify.Remove {

					err = watcher.Add(cfg.rulesFile)
					if err != nil {
						logger.Errorf("failed to add file to watcher: %v", err)
					}

					rules = readRules(cfg, logger)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				fmt.Println("error:", err)
			}
		}
	}()

	// Create mutator.
	mt := kwhmutating.MutatorFunc(func(_ context.Context, _ *kwhmodel.AdmissionReview, obj metav1.Object) (*kwhmutating.MutatorResult, error) {
		metaObj, err := handleObject(obj, rules, logger)
		return &kwhmutating.MutatorResult{MutatedObject: metaObj}, err
	})

	// Create webhook.
	mcfg := kwhmutating.WebhookConfig{
		ID:      "mutator.metal-stack.dev",
		Mutator: mt,
		Logger:  logger,
	}
	wh, err := kwhmutating.NewWebhook(mcfg)
	if err != nil {
		return fmt.Errorf("error creating webhook: %w", err)
	}

	// Get HTTP handler from webhook.
	whHandler, err := kwhhttp.HandlerFor(kwhhttp.HandlerConfig{Webhook: wh, Logger: logger})
	if err != nil {
		return fmt.Errorf("error creating webhook handler: %w", err)
	}

	// Serve.
	logger.Infof("Listening on :8080")

	http.Handle("/", whHandler)

	server := &http.Server{
		Addr:              ":8080",
		ReadHeaderTimeout: 1 * time.Minute,
	}

	err = server.ListenAndServeTLS(cfg.certFile, cfg.keyFile)
	if err != nil {
		return fmt.Errorf("error serving webhook: %w", err)
	}

	return nil
}

func applyRules(name string, namespace string, kind string, origJson []byte, rules Rules, logger log.Logger) ([]byte, bool, error) {
	for _, rule := range rules.Rules {
		// Check if the rule applies to the namespace
		namespacere, err := regexp.Compile(rule.NamespaceRe)
		if err != nil {
			return nil, false, fmt.Errorf("bad namespace regex: %w", err)
		}
		if !namespacere.MatchString(namespace) {
			logger.Debugf("Object does not match namespace regex %q: %s/%s (kind: %s)", rule.NamespaceRe, namespace, name, kind)
			continue
		}

		// Check if the rule applies to the name
		namere, err := regexp.Compile(rule.NameRe)
		if err != nil {
			return nil, false, fmt.Errorf("bad name regex: %w", err)
		}
		if !namere.MatchString(name) {
			logger.Debugf("Object does not match name regex %q: %s/%s (kind: %s)", rule.NameRe, namespace, name, kind)
			continue
		}

		kindre, err := regexp.Compile(rule.KindRe)
		if err != nil {
			return nil, false, fmt.Errorf("bad kind regex: %w", err)
		}
		if !kindre.MatchString(kind) {
			logger.Debugf("Object does not match kind regex %q: %s/%s (kind: %s)", rule.KindRe, namespace, name, kind)
			continue
		}

		// Apply the patch
		patch, err := jsonpatch.DecodePatch([]byte(rule.Patch))
		if err != nil {
			return nil, false, fmt.Errorf("failed to decode patch: %w", err)
		}

		patchedJson, err := patch.Apply(origJson)
		if err != nil {
			return nil, false, fmt.Errorf("failed to apply patch: %w", err)
		}

		logger.Debugf("Object matched: %s/%s (kind: %s) - will apply patch", namespace, name, kind)

		// Log if the object was actually mutated
		if !bytes.Equal(origJson, patchedJson) {
			logger.Infof("Object mutated: %s/%s (kind: %s) - rule applied", namespace, name, kind)
		}

		return patchedJson, true, nil
	}
	return origJson, false, nil
}

func readRules(cfg *config, logger log.Logger) Rules {
	var rules Rules

	_, err := os.Stat(cfg.rulesFile)
	if !os.IsNotExist(err) {
		// if the file exists, open it
		f, err := os.Open(cfg.rulesFile)
		if err != nil {
			logger.Errorf("error opening file %s: %v", cfg.rulesFile, err)
		}
		// read the file contents into a byte array
		j, err := io.ReadAll(f)
		if err != nil {
			logger.Errorf("error reading file %s: %v", cfg.rulesFile, err)
		}
		err = f.Close()
		if err != nil {
			logger.Errorf("error closing file %s: %v", cfg.rulesFile, err)
		}
		// unmarshal the json into the Rules struct
		if err := json.Unmarshal(j, &rules); err != nil {
			logger.Errorf("error unmarshling rules %v", err)
		}
	} else {
		logger.Infof("file %s does not exist", cfg.rulesFile)
	}

	rls, err := json.Marshal(rules)
	if err != nil {
		logger.Errorf("error marshling rules %v", err)
	}
	logger.Infof("new rules: %s\n", string(rls))

	return rules
}

func handleObject(obj metav1.Object, rules Rules, logger log.Logger) (metav1.Object, error) {
	// Marshal the object to JSON
	origJSON, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal object: %w", err)
	}

	parts := strings.Split(reflect.TypeOf(obj).String(), ".")
	kind := parts[len(parts)-1]

	// Patch the object based on the type
	patchedJSON, ok, err := applyRules(obj.GetName(), obj.GetNamespace(), kind, origJSON, rules, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to patch object: %w", err)
	}
	if !ok {
		return nil, nil
	}

	// Unmarshal the patched object
	if err := json.Unmarshal(patchedJSON, obj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal object: %w", err)
	}

	return obj, nil
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error running app: %s", err)
		os.Exit(1)
	}
}
