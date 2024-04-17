package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"github.com/rhpds/sandbox/internal/log"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	//	"k8s.io/client-go/rest"
	v1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type OcpSandboxProvider struct {
	DbPool      *pgxpool.Pool `json:"-"`
	VaultSecret string        `json:"-"`
}

type OcpSharedClusterConfiguration struct {
	ID             int               `json:"id"`
	Name           string            `json:"name"`
	ApiUrl         string            `json:"api_url"`
	IngressDomain  string            `json:"ingress_domain"`
	Kubeconfig     string            `json:"kubeconfig"`
	CreatedAt      time.Time         `json:"created_at"`
	UpdatedAt      time.Time         `json:"updated_at"`
	Annotations    map[string]string `json:"annotations"`
	Valid          bool              `json:"valid"`
	AdditionalVars map[string]any    `json:"additional_vars,omitempty"`
	DbPool         *pgxpool.Pool     `json:"-"`
	VaultSecret    string            `json:"-"`
}

type OcpSharedClusterConfigurations []OcpSharedClusterConfiguration

type OcpSandbox struct {
	Account
	Name                              string            `json:"name"`
	Kind                              string            `json:"kind"` // "OcpSandbox"
	ServiceUuid                       string            `json:"service_uuid"`
	OcpSharedClusterConfigurationName string            `json:"ocp_cluster"`
	OcpIngressDomain                  string            `json:"ingress_domain"`
	OcpApiUrl                         string            `json:"api_url"`
	Annotations                       map[string]string `json:"annotations"`
	Status                            string            `json:"status"`
	CleanupCount                      int               `json:"cleanup_count"`
	Namespace                         string            `json:"namespace"`
	ClusterAdditionalVars             map[string]any    `json:"cluster_additional_vars,omitempty"`
}

type OcpSandboxWithCreds struct {
	OcpSandbox

	Credentials []any               `json:"credentials"`
	Provider    *OcpSandboxProvider `json:"-"`
}

// Credential for service account
type OcpServiceAccount struct {
	Kind  string `json:"kind"` // "ServiceAccount"
	Name  string `json:"name"`
	Token string `json:"token"`
}

type OcpSandboxes []OcpSandbox

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// Bind and Render
func (p *OcpSharedClusterConfiguration) Bind(r *http.Request) error {
	// Ensure the name is not empty
	if p.Name == "" {
		return errors.New("name is required")
	}

	// Ensure the name is valid
	if !nameRegex.MatchString(p.Name) {
		return errors.New("name is invalid, must be only alphanumeric and '-'")
	}

	// Ensure the api_url is not empty
	if p.ApiUrl == "" {
		return errors.New("api_url is required")
	}

	// Ensure the kubeconfig is not empty
	if p.Kubeconfig == "" {
		return errors.New("kubeconfig is required")
	}

	// Ensure IngressDomain is provided
	if p.IngressDomain == "" {
		return errors.New("ingress_domain is required")
	}

	// Ensure Annotations is provided
	if len(p.Annotations) == 0 {
		return errors.New("annotations is required")
	}

	p.Valid = true

	return nil
}

func (p *OcpSharedClusterConfiguration) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// Bind and Render for OcpSharedClusterConfigurations
func (p *OcpSharedClusterConfigurations) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *OcpSharedClusterConfiguration) Save() error {
	if p.ID != 0 {
		return p.Update()
	}

	// Insert resource and get Id
	if err := p.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO ocp_shared_cluster_configurations
			(name, api_url, ingress_domain, kubeconfig, annotations, valid, additional_vars)
			VALUES ($1, $2, $3, pgp_sym_encrypt($4::text, $5), $6, $7, $8) RETURNING id`,
		p.Name, p.ApiUrl, p.IngressDomain, p.Kubeconfig, p.VaultSecret, p.Annotations, p.Valid, p.AdditionalVars,
	).Scan(&p.ID); err != nil {
		return err
	}
	return nil
}

func (p *OcpSharedClusterConfiguration) Update() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	// Update resource
	if _, err := p.DbPool.Exec(
		context.Background(),
		`UPDATE ocp_shared_cluster_configurations
		 SET name = $1,
			 api_url = $2,
             ingress_domain = $3,
			 kubeconfig = pgp_sym_encrypt($4::text, $5),
			 annotations = $6,
			 valid = $7,
			 additional_vars = $8
		 WHERE id = $9`,
		p.Name, p.ApiUrl, p.IngressDomain, p.Kubeconfig, p.VaultSecret, p.Annotations, p.Valid, p.AdditionalVars, p.ID,
	); err != nil {
		return err
	}
	return nil
}

func (p *OcpSharedClusterConfiguration) Delete() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	_, err := p.DbPool.Exec(
		context.Background(),
		"DELETE FROM ocp_shared_cluster_configurations WHERE id = $1",
		p.ID,
	)
	return err
}

// Disable an OcpSharedClusterConfiguration
func (p *OcpSharedClusterConfiguration) Disable() error {
	p.Valid = false
	return p.Update()
}

// CountAccounts returns the number of accounts for an OcpSharedClusterConfiguration
func (p *OcpSharedClusterConfiguration) GetAccountCount() (int, error) {
	var count int
	if err := p.DbPool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM resources WHERE resource_type = 'OcpSandbox' AND resource_data->>'ocp_cluster' = $1",
		p.Name,
	).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// GetOcpSharedClusterConfigurationByName returns an OcpSharedClusterConfiguration by name
func (p *OcpSandboxProvider) GetOcpSharedClusterConfigurationByName(name string) (OcpSharedClusterConfiguration, error) {
	// Get resource from above 'ocp_shared_cluster_configurations' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
		 id, name, api_url, ingress_domain, pgp_sym_decrypt(kubeconfig::bytea, $1), created_at, updated_at, annotations, valid, additional_vars
		 FROM ocp_shared_cluster_configurations WHERE name = $2`,
		p.VaultSecret, name,
	)

	var cluster OcpSharedClusterConfiguration
	if err := row.Scan(
		&cluster.ID,
		&cluster.Name,
		&cluster.ApiUrl,
		&cluster.IngressDomain,
		&cluster.Kubeconfig,
		&cluster.CreatedAt,
		&cluster.UpdatedAt,
		&cluster.Annotations,
		&cluster.Valid,
		&cluster.AdditionalVars,
	); err != nil {
		return OcpSharedClusterConfiguration{}, err
	}
	cluster.DbPool = p.DbPool
	cluster.VaultSecret = p.VaultSecret
	return cluster, nil
}

// GetOcpSharedClusterConfigurations returns the full list of OcpSharedClusterConfiguration
func (p *OcpSandboxProvider) GetOcpSharedClusterConfigurations() (OcpSharedClusterConfigurations, error) {
	clusters := []OcpSharedClusterConfiguration{}

	// Get resource from 'ocp_shared_cluster_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT
		 id, name, api_url, ingress_domain, pgp_sym_decrypt(kubeconfig::bytea, $1), created_at, updated_at, annotations, valid, additional_vars
		 FROM ocp_shared_cluster_configurations`,
		p.VaultSecret,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No cluster found")
		}
		return []OcpSharedClusterConfiguration{}, err
	}

	for rows.Next() {
		var cluster OcpSharedClusterConfiguration

		if err := rows.Scan(
			&cluster.ID,
			&cluster.Name,
			&cluster.ApiUrl,
			&cluster.IngressDomain,
			&cluster.Kubeconfig,
			&cluster.CreatedAt,
			&cluster.UpdatedAt,
			&cluster.Annotations,
			&cluster.Valid,
			&cluster.AdditionalVars,
		); err != nil {
			return []OcpSharedClusterConfiguration{}, err
		}

		cluster.DbPool = p.DbPool
		cluster.VaultSecret = p.VaultSecret
		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

// GetOcpSharedClusterConfigurationByAnnotations returns a list of OcpSharedClusterConfiguration by annotations
func (p *OcpSandboxProvider) GetOcpSharedClusterConfigurationByAnnotations(annotations map[string]string) ([]OcpSharedClusterConfiguration, error) {
	clusters := []OcpSharedClusterConfiguration{}
	// Get resource from above 'ocp_shared_cluster_configurations' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT name FROM ocp_shared_cluster_configurations WHERE annotations @> $1`,
		annotations,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No cluster found", "annotations", annotations)
		}
		return []OcpSharedClusterConfiguration{}, err
	}

	for rows.Next() {
		var clusterName string

		if err := rows.Scan(&clusterName); err != nil {
			return []OcpSharedClusterConfiguration{}, err
		}

		cluster, err := p.GetOcpSharedClusterConfigurationByName(clusterName)
		if err != nil {
			return []OcpSharedClusterConfiguration{}, err
		}

		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

var OcpErrNoEnoughAccountsAvailable = errors.New("no enough accounts available")

func (a *OcpSandbox) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *OcpSandboxWithCreds) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *OcpSandbox) Save(dbpool *pgxpool.Pool) error {
	// Check if resource already exists in the DB
	if err := dbpool.QueryRow(
		context.Background(),
		`INSERT INTO resources
		 (resource_name, resource_type, service_uuid, resource_data, status, cleanup_count)
		 VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		a.Name, a.Kind, a.ServiceUuid, a, a.Status, a.CleanupCount).Scan(&a.ID); err != nil {
		return err
	}

	return nil
}

func (a *OcpSandboxWithCreds) Update() error {

	if a.ID == 0 {
		return errors.New("id must be > 0")
	}

	creds, _ := json.Marshal(a.Credentials)
	withoutCreds := *a
	withoutCreds.Credentials = []any{}

	// Update resource
	if _, err := a.Provider.DbPool.Exec(
		context.Background(),
		`UPDATE resources
		 SET resource_name = $1,
             resource_type = $2,
             service_uuid = $3,
             resource_data = $4,
             resource_credentials = pgp_sym_encrypt($5::text, $6),
             status = $7,
             cleanup_count = $8
		 WHERE id = $9`,
		a.Name,
		a.Kind,
		a.ServiceUuid,
		withoutCreds,
		creds,
		a.Provider.VaultSecret,
		a.Status,
		a.CleanupCount,
		a.ID,
	); err != nil {
		return err
	}
	return nil
}

func (a *OcpSandboxWithCreds) Save() error {
	if a.ID != 0 {
		return a.Update()
	}
	creds, _ := json.Marshal(a.Credentials)
	// Unset credentials in a struct withoutCreds
	withoutCreds := *a
	withoutCreds.Credentials = []any{}
	// Insert resource and get Id
	if err := a.Provider.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO resources
			(resource_name, resource_type, service_uuid, to_cleanup, resource_data, resource_credentials, status, cleanup_count)
			VALUES ($1, $2, $3, $4, $5, pgp_sym_encrypt($6::text, $7), $8, $9) RETURNING id`,
		a.Name, a.Kind, a.ServiceUuid, false, withoutCreds, creds, a.Provider.VaultSecret, a.Status, a.CleanupCount,
	).Scan(&a.ID); err != nil {
		return err
	}

	return nil
}

func (a *OcpSandboxWithCreds) SetStatus(status string) error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET status = $1 WHERE id = $2",
		status, a.ID,
	)

	return err
}

func (a *OcpSandboxWithCreds) GetStatus() (string, error) {
	var status string
	err := a.Provider.DbPool.QueryRow(
		context.Background(),
		"SELECT status FROM resources WHERE id = $1",
		a.ID,
	).Scan(&status)

	return status, err
}

func (a *OcpSandboxWithCreds) MarkForCleanup() error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET to_cleanup = true WHERE id = $1",
		a.ID,
	)

	return err
}

func (a *OcpSandboxWithCreds) IncrementCleanupCount() error {
	a.CleanupCount = a.CleanupCount + 1
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET cleanup_count = cleanup_count + 1 WHERE id = $1",
		a.ID,
	)

	return err
}
func (a *OcpSandboxProvider) FetchAllByServiceUuid(serviceUuid string) ([]OcpSandbox, error) {
	accounts := []OcpSandbox{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
			r.resource_data,
			r.id,
			r.resource_name,
			r.resource_type,
			r.created_at,
			r.updated_at,
			r.status,
			r.cleanup_count,
			COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		FROM
			resources r
		LEFT JOIN
			ocp_shared_cluster_configurations oc ON oc.name = r.resource_data->>'ocp_cluster'
		WHERE r.service_uuid = $1`,
		serviceUuid,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found", "service_uuid", serviceUuid)
		}
		return accounts, err
	}

	for rows.Next() {
		var account OcpSandbox
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&account.ClusterAdditionalVars,
		); err != nil {
			return accounts, err
		}

		account.ServiceUuid = serviceUuid
		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (a *OcpSandboxProvider) FetchAllByServiceUuidWithCreds(serviceUuid string) ([]OcpSandboxWithCreds, error) {
	accounts := []OcpSandboxWithCreds{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
			r.resource_data,
			r.id,
			r.resource_name,
			r.resource_type,
			r.created_at,
			r.updated_at,
			r.status,
			r.cleanup_count,
			pgp_sym_decrypt(r.resource_credentials, $2),
			COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		FROM
			resources r
		LEFT JOIN
			ocp_shared_cluster_configurations oc ON oc.name = r.resource_data->>'ocp_cluster'
		WHERE r.service_uuid = $1`,
		serviceUuid, a.VaultSecret,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found", "service_uuid", serviceUuid)
		}
		return accounts, err
	}

	for rows.Next() {
		var account OcpSandboxWithCreds

		creds := ""
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&creds,
			&account.ClusterAdditionalVars,
		); err != nil {
			return accounts, err
		}
		// Unmarshal creds into account.Credentials
		if err := json.Unmarshal([]byte(creds), &account.Credentials); err != nil {
			return accounts, err
		}

		account.ServiceUuid = serviceUuid
		account.Provider = a

		accounts = append(accounts, account)
	}

	return accounts, nil
}

var ErrNoSchedule error = errors.New("No OCP shared cluster configuration found")

func (a *OcpSandboxProvider) GetSchedulableClusters(cloud_selector map[string]string) (OcpSharedClusterConfigurations, error) {
	clusters := OcpSharedClusterConfigurations{}
	// Get resource from 'ocp_shared_cluster_configurations' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT name FROM ocp_shared_cluster_configurations WHERE annotations @> $1 and valid=true`,
		cloud_selector,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No cluster found", "cloud_selector", cloud_selector)
			return OcpSharedClusterConfigurations{}, ErrNoSchedule
		}

		log.Logger.Error("Error querying ocp clusters", "error", err)
		return OcpSharedClusterConfigurations{}, err
	}

	for rows.Next() {
		var clusterName string

		if err := rows.Scan(&clusterName); err != nil {
			return OcpSharedClusterConfigurations{}, err
		}

		cluster, err := a.GetOcpSharedClusterConfigurationByName(clusterName)
		if err != nil {
			return OcpSharedClusterConfigurations{}, err
		}

		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

func (a *OcpSandboxProvider) Request(serviceUuid string, cloud_selector map[string]string, annotations map[string]string) (OcpSandboxWithCreds, error) {
	var rowcount int
	var minOcpMemoryUsage float64
	var selectedCluster OcpSharedClusterConfiguration

	// Ensure annotation has guid
	if _, exists := annotations["guid"]; !exists {
		return OcpSandboxWithCreds{}, errors.New("guid not found in annotations")
	}

	// Version with OcpSharedClusterConfiguration methods
	candidateClusters, err := a.GetSchedulableClusters(cloud_selector)
	if err != nil {
		log.Logger.Error("Error getting schedulable clusters", "error", err)
		return OcpSandboxWithCreds{}, err
	}
	if len(candidateClusters) == 0 {
		log.Logger.Error("No OCP shared cluster configuration found", "cloud_selector", cloud_selector)
		return OcpSandboxWithCreds{}, ErrNoSchedule
	}

	// Determine guid, auto increment the guid if there are multiple resources
	// for a serviceUuid
	guid := annotations["guid"]
	increment := 0

	for {
		if increment > 100 {
			// something clearly went wrong, shouldn't never happen, but be defensive
			return OcpSandboxWithCreds{}, errors.New("Too many iterations guessing guid")
		}

		if increment > 0 {
			guid = annotations["guid"] + "-" + fmt.Sprintf("%v", increment+1)
		}
		// If a sandbox already has the same name for that serviceuuid, increment
		// If so, increment the guid and try again
		candidateName := guid + "-" + serviceUuid

		err := a.DbPool.QueryRow(
			context.Background(),
			`SELECT count(*) FROM resources
			WHERE resource_name = $1
			AND resource_type = 'OcpSandbox'`,
			candidateName,
		).Scan(&rowcount)

		if err != nil {
			log.Logger.Error("Error checking resources names", "error", err)
			return OcpSandboxWithCreds{}, err
		}

		if rowcount == 0 {
			break
		}
		increment++
	}

	// Return the Placement with a status 'initializing'
	rnew := OcpSandboxWithCreds{
		OcpSandbox: OcpSandbox{
			Name:        guid + "-" + serviceUuid,
			Kind:        "OcpSandbox",
			Annotations: annotations,
			ServiceUuid: serviceUuid,
			Status:      "initializing",
		},
		Provider: a,
	}

	rnew.Resource.CreatedAt = time.Now()
	rnew.Resource.UpdatedAt = time.Now()

	if err := rnew.Save(); err != nil {
		log.Logger.Error("Error saving OCP account", "error", err)
		return OcpSandboxWithCreds{}, err
	}

	//--------------------------------------------------
	// The following is async
	go func() {
	providerLoop:
		for _, cluster := range candidateClusters {
			rnew.SetStatus("scheduling")

			log.Logger.Info("Cluster",
				"name", cluster.Name,
				"ApiUrl", cluster.ApiUrl)

			config, err := clientcmd.RESTConfigFromKubeConfig([]byte(cluster.Kubeconfig))
			if err != nil {
				log.Logger.Error("Error creating OCP config", "error", err)
				rnew.SetStatus("error")
				continue providerLoop
			}

			clientset, err := kubernetes.NewForConfig(config)
			if err != nil {
				log.Logger.Error("Error creating OCP client", "error", err)
				rnew.SetStatus("error")
				continue providerLoop
			}

			nodes, err := clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/worker="})
			if err != nil {
				log.Logger.Error("Error listing OCP nodes", "error", err)
				rnew.SetStatus("error")
				continue providerLoop
			}

			var totalAllocatableCpu, totalAllocatableMemory int64
			var totalRequestedCpu, totalRequestedMemory int64

			for _, node := range nodes.Items {
				allocatableCpu := node.Status.Allocatable.Cpu().MilliValue()
				allocatableMemory := node.Status.Allocatable.Memory().Value()

				podList, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{FieldSelector: "spec.nodeName=" + node.Name})
				if err != nil {
					log.Logger.Error("Error listing OCP pods", "error", err)
					rnew.SetStatus("error")
					continue providerLoop
				}

				totalRequestedCpuForNode := int64(0)
				totalRequestedMemoryForNode := int64(0)
				for _, pod := range podList.Items {
					totalRequestedCpuForNode += pod.Spec.Containers[0].Resources.Requests.Cpu().MilliValue()
					totalRequestedMemoryForNode += pod.Spec.Containers[0].Resources.Requests.Memory().Value()
				}

				totalAllocatableCpu += allocatableCpu
				totalAllocatableMemory += allocatableMemory
				totalRequestedCpu += totalRequestedCpuForNode
				totalRequestedMemory += totalRequestedMemoryForNode
			}

			// Calculate total usage for the cluster
			cpuUsage := (float64(totalRequestedCpu) / float64(totalAllocatableCpu)) * 100
			memoryUsage := (float64(totalRequestedMemory) / float64(totalAllocatableMemory)) * 100
			if minOcpMemoryUsage == 0 || memoryUsage < minOcpMemoryUsage {
				selectedCluster = cluster
				minOcpMemoryUsage = memoryUsage
			}
			log.Logger.Info("Cluster Usage",
				"CPU Usage (Requests)", cpuUsage,
				"Memory Usage (Requests)", memoryUsage)
		}
		log.Logger.Info("selectedCluster", "cluster", selectedCluster.Name)

		if selectedCluster.Name == "" {
			log.Logger.Error("Error electing cluster", "name", rnew.Name)
			rnew.SetStatus("error")
			return
		}

		rnew.OcpApiUrl = selectedCluster.ApiUrl
		rnew.OcpSharedClusterConfigurationName = selectedCluster.Name

		if err := rnew.Save(); err != nil {
			log.Logger.Error("Error saving OCP account", "error", err)
			rnew.SetStatus("error")
			return
		}

		config, err := clientcmd.RESTConfigFromKubeConfig([]byte(selectedCluster.Kubeconfig))
		if err != nil {
			log.Logger.Error("Error creating OCP config", "error", err)
			rnew.SetStatus("error")
			return
		}

		// Create an OpenShift client
		clientset, err := kubernetes.NewForConfig(config)
		if err != nil {
			log.Logger.Error("Error creating OCP client", "error", err)
			rnew.SetStatus("error")
			return
		}

		serviceAccountName := "sandbox"
		namespaceName := "sandbox-" + rnew.Name
		namespaceName = namespaceName[:min(63, len(namespaceName))] // truncate to 63

		delay := time.Second
		for {
			// Create the Namespace
			// Add serviceUuid as label to the namespace

			_, err = clientset.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespaceName,
					Labels: map[string]string{
						"mutatepods.kubemacpool.io":            "ignore",
						"mutatevirtualmachines.kubemacpool.io": "ignore",
						"serviceUuid":                          serviceUuid,
						"guid":                                 annotations["guid"],
					},
				},
			}, metav1.CreateOptions{})

			if err != nil {
				log.Logger.Error("Error creating OCP namespace", "error", err)
				if strings.Contains(err.Error(), "object is being deleted: namespace") {
					time.Sleep(delay)
					delay = delay * 2
					if delay > 60*time.Second {
						rnew.SetStatus("error")
						return
					}

					continue
				}
				rnew.SetStatus("error")
				return
			}

			rnew.Namespace = namespaceName
			if err := rnew.Save(); err != nil {
				log.Logger.Error("Error saving OCP account", "error", err)
				rnew.SetStatus("error")
				return
			}
			break
		}

		_, err = clientset.CoreV1().ServiceAccounts(namespaceName).Create(context.TODO(), &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: serviceAccountName,
				Labels: map[string]string{
					"serviceUuid": serviceUuid,
					"guid":        annotations["guid"],
				},
			},
		}, metav1.CreateOptions{})

		if err != nil {
			log.Logger.Error("Error creating OCP service account", "error", err)
			// Delete the namespace
			if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
				log.Logger.Error("Error cleaning up the namespace", "error", err)
			}
			rnew.SetStatus("error")
			return
		}

		// Create RoleBind for the Service Account in the Namespace
		_, err = clientset.RbacV1().RoleBindings(namespaceName).Create(context.TODO(), &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: serviceAccountName,
				Labels: map[string]string{
					"serviceUuid": serviceUuid,
					"guid":        annotations["guid"],
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: rbacv1.GroupName,
				Kind:     "ClusterRole",
				Name:     "admin",
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      serviceAccountName,
					Namespace: namespaceName,
				},
			},
		}, metav1.CreateOptions{})

		if err != nil {
			log.Logger.Error("Error creating OCP RoleBind", "error", err)
			if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
				log.Logger.Error("Error cleaning up the namespace", "error", err)
			}
			rnew.SetStatus("error")
			return
		}

		// TODO: parameterize this, or detect when to execute it, otherwise it'll fail
		// // Create RoleBind for the Service Account in the Namespace for kubevirt
		// _, err = clientset.RbacV1().RoleBindings(namespaceName).Create(context.TODO(), &rbacv1.RoleBinding{
		// 	ObjectMeta: metav1.ObjectMeta{
		// 		Name: "kubevirt-" + namespaceName[:min(53, len(namespaceName))],
		// 		Labels: map[string]string{
		// 			"serviceUuid": serviceUuid,
		// 			"guid":        annotations["guid"],
		// 		},
		// 	},
		// 	RoleRef: rbacv1.RoleRef{
		// 		APIGroup: rbacv1.GroupName,
		// 		Kind:     "ClusterRole",
		// 		Name:     "kubevirt.io:admin",
		// 	},
		// 	Subjects: []rbacv1.Subject{
		// 		{
		// 			Kind:      "ServiceAccount",
		// 			Name:      serviceAccountName,
		// 			Namespace: namespaceName,
		// 		},
		// 	},
		// }, metav1.CreateOptions{})

		// if err != nil {
		// 	log.Logger.Error("Error creating OCP RoleBind", "error", err)
		// 	if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
		// 		log.Logger.Error("Error cleaning up the namespace", "error", err)
		// 	}
		// 	rnew.SetStatus("error")
		// 	return
		// }

		// Look if namespace 'cnv-images' exists
		if _, err := clientset.CoreV1().Namespaces().Get(context.TODO(), "cnv-images", metav1.GetOptions{}); err == nil {

			rb := &rbacv1.RoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "allow-clone-" + namespaceName[:min(51, len(namespaceName))],
					Namespace: "cnv-images",
					Labels: map[string]string{
						"serviceUuid": serviceUuid,
						"guid":        annotations["guid"],
					},
				},
				Subjects: []rbacv1.Subject{
					{
						Kind:      "ServiceAccount",
						Name:      "default",
						Namespace: namespaceName,
					},
				},
				RoleRef: rbacv1.RoleRef{
					Kind:     "ClusterRole",
					Name:     "datavolume-cloner",
					APIGroup: "rbac.authorization.k8s.io",
				},
			}

			_, err = clientset.RbacV1().RoleBindings("cnv-images").Create(context.TODO(), rb, metav1.CreateOptions{})
			if err != nil {
				log.Logger.Error("Error creating rolebinding on cnv-images", "error", err)

				if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
					log.Logger.Error("Error cleaning up the namespace", "error", err)
				}
				rnew.SetStatus("error")
				return
			}
		}

		secrets, err := clientset.CoreV1().Secrets(namespaceName).List(context.TODO(), metav1.ListOptions{})

		if err != nil {
			log.Logger.Error("Error listing OCP secrets", "error", err)
			// Delete the namespace
			if err := clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{}); err != nil {
				log.Logger.Error("Error creating OCP service account", "error", err)
			}
			rnew.SetStatus("error")
			return
		}

		var saSecret *v1.Secret
		// Loop till token exists
		for {
			for _, secret := range secrets.Items {
				if val, exists := secret.ObjectMeta.Annotations["kubernetes.io/service-account.name"]; exists {
					if _, exists := secret.Data["token"]; exists {
						if val == serviceAccountName {
							saSecret = &secret
							break
						}
					}
				}
			}
			if saSecret != nil {
				break
			}
		}
		creds := []any{
			OcpServiceAccount{
				Kind:  "ServiceAccount",
				Name:  serviceAccountName,
				Token: string(saSecret.Data["token"]),
			},
		}
		r := OcpSandboxWithCreds{
			OcpSandbox: OcpSandbox{
				Name:                              rnew.Name,
				Kind:                              "OcpSandbox",
				OcpSharedClusterConfigurationName: selectedCluster.Name,
				OcpApiUrl:                         selectedCluster.ApiUrl,
				OcpIngressDomain:                  selectedCluster.IngressDomain,
				Annotations:                       annotations,
				ServiceUuid:                       serviceUuid,
				Status:                            "success",
				Namespace:                         namespaceName,
			},
			Credentials: creds,
			Provider:    a,
		}

		r.ID = rnew.ID

		if err := r.Save(); err != nil {
			log.Logger.Error("Error saving OCP account", "error", err)
			log.Logger.Info("Trying to cleanup OCP account")
			if err := r.Delete(); err != nil {
				log.Logger.Error("Error cleaning up OCP account", "error", err)
			}
		}
		log.Logger.Info("Ocp sandbox booked", "account", r.Name, "service_uuid", r.ServiceUuid,
			"cluster", r.OcpSharedClusterConfigurationName, "namespace", r.Namespace)
	}()
	//--------------------------------------------------

	return rnew, nil
}

func (a *OcpSandboxProvider) Release(service_uuid string) error {
	accounts, err := a.FetchAllByServiceUuidWithCreds(service_uuid)

	if err != nil {
		return err
	}

	var errorHappened error

	for _, account := range accounts {
		if account.Namespace == "" {
			log.Logger.Error("Namespace not found for account", "account", account)
			errorHappened = errors.New("Namespace not found for account")
			continue
		}

		if err := account.Delete(); err != nil {
			errorHappened = err
			continue
		}
	}
	return errorHappened
}

func NewOcpSandboxProvider(dbpool *pgxpool.Pool, vaultSecret string) OcpSandboxProvider {
	return OcpSandboxProvider{
		DbPool:      dbpool,
		VaultSecret: vaultSecret,
	}
}

func (a *OcpSandboxProvider) FetchAll() ([]OcpSandbox, error) {
	accounts := []OcpSandbox{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
		 r.resource_data,
         r.id,
		 r.resource_name,
		 r.resource_type,
		 r.created_at,
		 r.updated_at,
		 r.status,
		 r.cleanup_count,
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ocp_shared_cluster_configurations oc ON oc.name = r.resource_data->>'ocp_cluster'`,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found")
		}
		return accounts, err
	}

	for rows.Next() {
		var account OcpSandbox
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
			&account.ClusterAdditionalVars,
		); err != nil {
			return accounts, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (account *OcpSandboxWithCreds) Delete() error {
	var api_url string
	var kubeconfig string

	if account.ID == 0 {
		return errors.New("resource ID must be > 0")
	}

	// Wait for the status of the resource until it's in final state
	maxRetries := 10
	for {
		status, err := account.GetStatus()
		if err != nil {
			log.Logger.Error("cannot get status of resource", "error", err, "name", account.Name)
			break
		}
		if maxRetries == 0 {
			log.Logger.Error("Resource is not in a final state", "name", account.Name, "status", status)
			return errors.New("Resource is not in a final state, cannot delete")
		}

		if status == "success" || status == "error" {
			break
		}

		time.Sleep(5 * time.Second)
		maxRetries--
	}

	// Reload account
	if err := account.Reload(); err != nil {
		log.Logger.Error("Error reloading account", "error", err)
		return err
	}

	if account.OcpSharedClusterConfigurationName == "" {
		// Get the OCP shared cluster configuration name from the resources.resource_data column using ID
		err := account.Provider.DbPool.QueryRow(
			context.Background(),
			"SELECT resource_data->>'ocp_cluster' FROM resources WHERE id = $1",
			account.ID,
		).Scan(&account.OcpSharedClusterConfigurationName)

		if err != nil {
			if err == pgx.ErrNoRows {
				log.Logger.Error("Ocp cluster doesn't exist for resource", "name", account.Name)
				account.SetStatus("error")
				return errors.New("Ocp cluster doesn't exist for resource")
			}

			log.Logger.Error("Ocp cluster query error", "err", err)
			account.SetStatus("error")
			return err
		}
	}

	account.SetStatus("deleting")
	// In case anything goes wrong, we'll know it can safely be deleted
	account.MarkForCleanup()
	account.IncrementCleanupCount()

	// Get the OCP shared cluster configuration from the resources.resource_data column

	// TODO: use GetOcpSharedClusterConfigurationByName
	err := account.Provider.DbPool.QueryRow(
		context.Background(),
		"SELECT api_url, pgp_sym_decrypt(kubeconfig::bytea, $1) FROM ocp_shared_cluster_configurations WHERE name = $2",
		account.Provider.VaultSecret,
		account.OcpSharedClusterConfigurationName,
	).Scan(&api_url, &kubeconfig)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Error("Ocp cluster doesn't exist for resource", "cluster", account.OcpSharedClusterConfigurationName, "name", account.Name)
			account.SetStatus("error")
			return errors.New("Ocp cluster doesn't exist for resource")
		} else {
			log.Logger.Error("Ocp cluster query error", "err", err)
			account.SetStatus("error")
			return err
		}
	}

	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfig))
	if err != nil {
		log.Logger.Error("Error creating OCP config", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}

	// Create an OpenShift client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Logger.Error("Error creating OCP client", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}
	// Define the Service Account name
	serviceAccountName := "sandbox"

	// Check if the namespace exists
	_, err = clientset.CoreV1().Namespaces().Get(context.TODO(), account.Namespace, metav1.GetOptions{})
	if err != nil {
		// if error ends with 'not found', consider deletion a success
		if strings.Contains(err.Error(), "not found") {
			log.Logger.Info("Namespace not found, consider deletion a success", "name", account.Name)
			_, err = account.Provider.DbPool.Exec(
				context.Background(),
				"DELETE FROM resources WHERE id = $1",
				account.ID,
			)
			return err
		}

		log.Logger.Error("Error getting OCP namespace", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}
	// Delete the Namespace
	err = clientset.CoreV1().Namespaces().Delete(context.TODO(), account.Namespace, metav1.DeleteOptions{})
	if err != nil {
		log.Logger.Error("Error deleting OCP namespace", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}

	// Delete the Service Account
	if err = clientset.CoreV1().
		ServiceAccounts(account.Namespace).
		Delete(context.TODO(), serviceAccountName, metav1.DeleteOptions{}); err != nil {
		log.Logger.Error("Error deleting OCP service account", "error", err)
		account.SetStatus("error")
		return err
	}

	_, err = account.Provider.DbPool.Exec(
		context.Background(),
		"DELETE FROM resources WHERE id = $1",
		account.ID,
	)
	return err
}

func (p *OcpSandboxProvider) FetchByName(name string) (OcpSandbox, error) {
	// Get resource from above 'resources' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
		 r.resource_data,
		 r.id,
		 r.resource_name,
		 r.resource_type,
		 r.created_at,
		 r.updated_at,
		 r.status,
		 r.cleanup_count,
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ocp_shared_cluster_configurations oc ON oc.name = resource_data->>'ocp_cluster'
		 WHERE r.resource_name = $1 and r.resource_type = 'OcpSandbox'`,
		name,
	)

	var account OcpSandbox
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&account.ClusterAdditionalVars,
	); err != nil {
		return OcpSandbox{}, err
	}
	return account, nil
}

func (p *OcpSandboxProvider) FetchById(id int) (OcpSandbox, error) {
	// Get resource from above 'resources' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
		 r.resource_data,
		 r.id,
		 r.resource_name,
		 r.resource_type,
		 r.created_at,
		 r.updated_at,
		 r.status,
		 r.cleanup_count,
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ocp_shared_cluster_configurations oc ON oc.name = resource_data->>'ocp_cluster'
		 WHERE r.id = $1`,
		id,
	)

	var account OcpSandbox
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&account.ClusterAdditionalVars,
	); err != nil {
		return OcpSandbox{}, err
	}
	return account, nil
}

func (a *OcpSandboxWithCreds) Reload() error {
	// Ensude ID is set
	if a.ID == 0 {
		return errors.New("id must be > 0 to use Reload()")
	}

	// Enusre provider is set
	if a.Provider == nil {
		return errors.New("provider must be set to use Reload()")
	}

	// Get resource from above 'resources' table
	row := a.Provider.DbPool.QueryRow(
		context.Background(),
		`SELECT
		 r.resource_data,
         r.id,
		 r.resource_name,
		 r.resource_type,
		 r.created_at,
		 r.updated_at,
		 r.status,
		 r.cleanup_count,
		 pgp_sym_decrypt(r.resource_credentials, $2),
		 COALESCE(oc.additional_vars, '{}'::jsonb) AS cluster_additional_vars
		 FROM resources r
		 LEFT JOIN ocp_shared_cluster_configurations oc ON oc.name = resource_data->>'ocp_cluster'
		 WHERE r.id = $1`,
		a.ID, a.Provider.VaultSecret,
	)

	var creds string
	var account OcpSandboxWithCreds
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
		&creds,
		&account.ClusterAdditionalVars,
	); err != nil {
		return err
	}
	// Add provider before copying
	account.Provider = a.Provider
	// Copy account into a
	*a = account

	// Unmarshal creds into account.Credentials
	if err := json.Unmarshal([]byte(creds), &a.Credentials); err != nil {
		return err
	}

	return nil
}