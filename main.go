package main

import (
	"context"
	"encoding/json"
	"fmt"
	cmmetav1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/dnsimple/dnsimple-go/dnsimple"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	"os"
	"strconv"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&dnsimpleDNSProviderSolver{},
	)
}

// dnsimpleDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type dnsimpleDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// dnsimpleDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type dnsimpleDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	APIKeySecretRef cmmetav1.SecretKeySelector `json:"apiKeySecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (solver *dnsimpleDNSProviderSolver) Name() string {
	return "dnsimple"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (solver *dnsimpleDNSProviderSolver) Present(challengeRequest *v1alpha1.ChallengeRequest) error {
	config, err := loadConfig(challengeRequest.Config)
	klog.V(6).Infof("call function Present: namespace=%s, zone=%s, fqdn=%s",
		challengeRequest.ResourceNamespace, challengeRequest.ResolvedZone, challengeRequest.ResolvedFQDN)

	if err != nil {
		return fmt.Errorf("unable to get secret `%s`; %v", challengeRequest.ResourceNamespace, err)
	}

	client, err := solver.getClient(&config, challengeRequest.ResourceNamespace)
	userID, err := whoAmI(client)
	if err != nil {
		return fmt.Errorf("unable to fetch account ID: %s", err)
	}

	entry, domain := solver.getDomainAndEntry(challengeRequest)
	klog.V(6).Infof("present for entry=%s, domain=%s", entry, domain)

	existingRecord, err := solver.getExistingRecord(client, userID, domain, entry, challengeRequest.Key)

	if err != nil {
		return fmt.Errorf("error retrieving domain records: %s", err)
	}

	if existingRecord != nil {
		_, err = solver.updateRecord(client, userID, existingRecord, challengeRequest.Key)

		if err != nil {
			return fmt.Errorf("unable to update record: %s", err)
		}
	} else {
		_, err = solver.createRecord(client, userID, &entry, domain, challengeRequest.Key)

		if err != nil {
			return fmt.Errorf("unable to create record: %s", err)
		}
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.dnsimple.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (solver *dnsimpleDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}

	client, err := solver.getClient(&cfg, ch.ResourceNamespace)

	if err != nil {
		return fmt.Errorf("unable to get client: %s", err)
	}

	accountID, err := whoAmI(client)
	if err != nil {
		return fmt.Errorf("unable to fetch account ID: %s", err)
	}

	entry, domain := solver.getDomainAndEntry(ch)
	klog.V(6).Infof("present for entry=%s, domain=%s", entry, domain)

	existingRecord, err := solver.getExistingRecord(client, accountID, domain, entry, ch.Key)

	if existingRecord != nil {
		_, err = solver.deleteRecord(client, accountID, domain, existingRecord)

		if err != nil {
			return fmt.Errorf("unable to delete record: %s", err)
		}
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (solver *dnsimpleDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	var err error
	solver.client, err = kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (dnsimpleDNSProviderConfig, error) {
	cfg := dnsimpleDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func (solver *dnsimpleDNSProviderSolver) getClient(cfg *dnsimpleDNSProviderConfig, namespace string) (*dnsimple.Client, error) {
	// Extracted the logic to get API key into a new function
	apiKey, err := solver.getAPIKeyFromSecret(cfg, namespace)
	if err != nil {
		return nil, err
	}

	tc := dnsimple.StaticTokenHTTPClient(context.TODO(), apiKey)

	client := dnsimple.NewClient(tc)
	client.BaseURL = "https://api.dnsimple.com"
	return client, nil
}

func (solver *dnsimpleDNSProviderSolver) getAPIKeyFromSecret(cfg *dnsimpleDNSProviderConfig, namespace string) (string, error) {
	secretName := cfg.APIKeySecretRef.LocalObjectReference.Name
	klog.V(6).Infof("Try to load secret `%s` with key `%s`", secretName, cfg.APIKeySecretRef.Key)
	secret, err := solver.client.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("unable to get secret `%s`; %v", secretName, err)
	}
	secretData, ok := stringFromSecretData(secret.Data, cfg.APIKeySecretRef.Key)
	if ok != nil {
		return "", fmt.Errorf("unable to extract string from secret data; %v", err)
	}
	return secretData, nil
}

func stringFromSecretData(secretData map[string][]byte, key string) (string, error) {
	data, err := secretData[key]
	if !err {
		return "", fmt.Errorf("key %q not found in secret data", key)
	}
	return string(data), nil
}

func whoAmI(client *dnsimple.Client) (string, error) {
	whoAmIResponse, err := client.Identity.Whoami(context.TODO())
	if err != nil {
		return "Error retrieving response from WhoAmI request.", err
	}
	// whoAmIResponse.Data.User.ID if apart of a Team.
	return strconv.FormatInt(whoAmIResponse.Data.Account.ID, 10), nil
}
func (solver *dnsimpleDNSProviderSolver) getDomainAndEntry(ch *v1alpha1.ChallengeRequest) (string, string) {
	// Both ch.ResolvedZone and ch.ResolvedFQDN end with a dot: '.'
	entry := strings.TrimSuffix(ch.ResolvedFQDN, ch.ResolvedZone)
	entry = strings.TrimSuffix(entry, ".")
	domain := strings.TrimSuffix(ch.ResolvedZone, ".")
	return entry, domain
}

func (solver *dnsimpleDNSProviderSolver) getExistingRecord(client *dnsimple.Client, accountID string, zoneName string, entry string, key string) (*dnsimple.ZoneRecord, error) {
	zone, err := client.Zones.GetZone(context.TODO(), accountID, zoneName)

	if err != nil {
		return nil, fmt.Errorf("unable to get zone: %s", err)
	}

	// Look for existing TXT records.
	records, err := client.Zones.ListRecords(context.TODO(), accountID, zone.Data.Name, &dnsimple.ZoneRecordListOptions{Type: dnsimple.String("TXT"), Name: dnsimple.String(entry)})

	if err != nil {
		return nil, fmt.Errorf("unable to get resource records: %s", err)
	}

	for _, record := range records.Data {
		if strings.ReplaceAll(record.Content, `"`, ``) == key {
			return &record, nil
		}
	}

	return nil, nil
}

func (solver *dnsimpleDNSProviderSolver) updateRecord(client *dnsimple.Client, accountID string, record *dnsimple.ZoneRecord, key string) (*dnsimple.ZoneRecord, error) {
	attributes := dnsimple.ZoneRecordAttributes{Content: key}
	updatedRecord, err := client.Zones.UpdateRecord(context.TODO(), accountID, record.ZoneID, record.ID, attributes)

	if err != nil {
		return nil, fmt.Errorf("unable to update record: %s", err)
	}

	return updatedRecord.Data, nil
}

func (solver *dnsimpleDNSProviderSolver) createRecord(client *dnsimple.Client, accountID string, entry *string, zoneName string, key string) (*dnsimple.ZoneRecord, error) {
	attributes := dnsimple.ZoneRecordAttributes{Name: entry, Type: "TXT", Content: key, TTL: 60}
	createdRecord, err := client.Zones.CreateRecord(context.TODO(), accountID, zoneName, attributes)

	if err != nil {
		return nil, fmt.Errorf("unable to create record: %s", err)
	}

	return createdRecord.Data, nil
}

func (solver *dnsimpleDNSProviderSolver) deleteRecord(client *dnsimple.Client, accountID string, zoneName string, record *dnsimple.ZoneRecord) (*dnsimple.ZoneRecord, error) {
	createdRecord, err := client.Zones.DeleteRecord(context.TODO(), accountID, zoneName, record.ID)

	if err != nil {
		return nil, fmt.Errorf("unable to delete record: %s", err)
	}

	return createdRecord.Data, nil
}
