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

type OcpAccountProvider struct {
	DbPool      *pgxpool.Pool `json:"-"`
	VaultSecret string        `json:"-"`
}

type OcpCluster struct {
	ID          int               `json:"id"`
	Name        string            `json:"name"`
	ApiUrl      string            `json:"api_url"`
	Kubeconfig  string            `json:"kubeconfig"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	Annotations map[string]string `json:"annotations"`
	Valid       bool              `json:"valid"`
	DbPool      *pgxpool.Pool     `json:"-"`
	VaultSecret string            `json:"-"`
}

type OcpClusters []OcpCluster

var nameRegex = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)

// Bind and Render
func (p *OcpCluster) Bind(r *http.Request) error {
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

	// Ensure Annotations is provided
	if len(p.Annotations) == 0 {
		return errors.New("annotations is required")
	}

	p.Valid = true

	return nil
}

func (p *OcpCluster) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

// Bind and Render for OcpClusters
func (p *OcpClusters) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (p *OcpCluster) Save() error {
	if p.ID != 0 {
		return p.Update()
	}

	// Insert resource and get Id
	if err := p.DbPool.QueryRow(
		context.Background(),
		`INSERT INTO ocp_clusters
			(name, api_url, kubeconfig, annotations, valid)
			VALUES ($1, $2, pgp_sym_encrypt($3::text, $4), $5, $6) RETURNING id`,
		p.Name, p.ApiUrl, p.Kubeconfig, p.VaultSecret, p.Annotations, p.Valid,
	).Scan(&p.ID); err != nil {
		return err
	}
	return nil
}

func (p *OcpCluster) Update() error {
	if p.ID == 0 {
		return errors.New("id must be > 0")
	}

	// Update resource
	if _, err := p.DbPool.Exec(
		context.Background(),
		`UPDATE ocp_clusters
		 SET name = $1,
			 api_url = $2,
			 kubeconfig = pgp_sym_encrypt($3::text, $4),
			 annotations = $5,
			 valid = $6
		 WHERE id = $7`,
		p.Name, p.ApiUrl, p.Kubeconfig, p.VaultSecret, p.Annotations, p.Valid, p.ID,
	); err != nil {
		return err
	}
	return nil
}

func (p *OcpCluster) Delete() error {
	_, err := p.DbPool.Exec(
		context.Background(),
		"DELETE FROM ocp_clusters WHERE id = $1",
		p.ID,
	)
	return err
}

// Disable an OcpCluster
func (p *OcpCluster) Disable() error {
	p.Valid = false
	return p.Update()
}

// CountAccounts returns the number of accounts for an OcpCluster
func (p *OcpCluster) GetAccountCount() (int, error) {
	var count int
	if err := p.DbPool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM resources WHERE resource_type = 'OcpAccount' AND resource_data->>'ocp_cluster' = $1",
		p.Name,
	).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

// GetOcpClusterByName returns an OcpCluster by name
func (p *OcpAccountProvider) GetOcpClusterByName(name string) (OcpCluster, error) {
	// Get resource from above 'ocp_clusters' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
		 id, name, api_url, pgp_sym_decrypt(kubeconfig::bytea, $1), created_at, updated_at, annotations, valid
		 FROM ocp_clusters WHERE name = $2`,
		p.VaultSecret, name,
	)

	var cluster OcpCluster
	if err := row.Scan(
		&cluster.ID,
		&cluster.Name,
		&cluster.ApiUrl,
		&cluster.Kubeconfig,
		&cluster.CreatedAt,
		&cluster.UpdatedAt,
		&cluster.Annotations,
		&cluster.Valid,
	); err != nil {
		return OcpCluster{}, err
	}
	cluster.DbPool = p.DbPool
	cluster.VaultSecret = p.VaultSecret
	return cluster, nil
}

// GetOcpClusters returns the full list of OcpCluster
func (p *OcpAccountProvider) GetOcpClusters() (OcpClusters, error) {
	clusters := []OcpCluster{}

	// Get resource from 'ocp_clusters' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT
		 id, name, api_url, pgp_sym_decrypt(kubeconfig::bytea, $1), created_at, updated_at, annotations, valid
		 FROM ocp_clusters`,
		p.VaultSecret,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No cluster found")
		}
		return []OcpCluster{}, err
	}

	for rows.Next() {
		var cluster OcpCluster

		if err := rows.Scan(
			&cluster.ID,
			&cluster.Name,
			&cluster.ApiUrl,
			&cluster.Kubeconfig,
			&cluster.CreatedAt,
			&cluster.UpdatedAt,
			&cluster.Annotations,
			&cluster.Valid,
		); err != nil {
			return []OcpCluster{}, err
		}

		cluster.DbPool = p.DbPool
		cluster.VaultSecret = p.VaultSecret
		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

// GetOcpClusterByAnnotations returns a list of OcpCluster by annotations
func (p *OcpAccountProvider) GetOcpClusterByAnnotations(annotations map[string]string) ([]OcpCluster, error) {
	clusters := []OcpCluster{}
	// Get resource from above 'ocp_clusters' table
	rows, err := p.DbPool.Query(
		context.Background(),
		`SELECT
		 id, name, api_url, pgp_sym_decrypt(kubeconfig::bytea, $1), created_at, updated_at, annotations, valid
		 FROM ocp_clusters WHERE annotations @> $2`,
		p.VaultSecret, annotations,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No cluster found", "annotations", annotations)
		}
		return []OcpCluster{}, err
	}

	for rows.Next() {
		var cluster OcpCluster

		if err := rows.Scan(
			&cluster.ID,
			&cluster.Name,
			&cluster.ApiUrl,
			&cluster.Kubeconfig,
			&cluster.CreatedAt,
			&cluster.UpdatedAt,
			&cluster.Annotations,
			&cluster.Valid,
		); err != nil {
			return []OcpCluster{}, err
		}

		cluster.DbPool = p.DbPool
		cluster.VaultSecret = p.VaultSecret
		clusters = append(clusters, cluster)
	}

	return clusters, nil
}

var OcpErrNoEnoughAccountsAvailable = errors.New("no enough accounts available")

type OcpAccount struct {
	Account
	Name           string            `json:"name"`
	Kind           string            `json:"kind"` // "OcpSandbox"
	ServiceUuid    string            `json:"service_uuid"`
	OcpClusterName string            `json:"ocp_cluster"`
	OCPApiUrl      string            `json:"api_url"`
	Annotations    map[string]string `json:"annotations"`
	Status         string            `json:"status"`
	CleanupCount   int               `json:"cleanup_count"`
}

type OcpAccountWithCreds struct {
	OcpAccount

	Credentials []any `json:"credentials"`
	// TODO: move to OcpAccount
	Provider *OcpAccountProvider `json:"-"`
}

// Credential for service account
type OcpServiceAccount struct {
	Kind  string `json:"kind"` // "service_account"
	Name  string `json:"name"`
	Token string `json:"token"`
}

func (a *OcpAccount) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

func (a *OcpAccountWithCreds) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type OcpAccounts []OcpAccount

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

func (a *OcpAccount) Save(dbpool *pgxpool.Pool) error {
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

func (a *OcpAccountWithCreds) Update() error {

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
		a.Name, a.Kind, a.ServiceUuid, withoutCreds, creds, a.Provider.VaultSecret, a.Status, a.CleanupCount, a.ID,
	); err != nil {
		return err
	}
	return nil
}

func (a *OcpAccountWithCreds) Save() error {
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

func (a *OcpAccountWithCreds) SetStatus(status string) error {
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET status = $1 WHERE id = $2",
		status, a.ID,
	)

	return err
}

func (a *OcpAccountWithCreds) IncrementCleanupCount() error {
	a.CleanupCount = a.CleanupCount + 1
	_, err := a.Provider.DbPool.Exec(
		context.Background(),
		"UPDATE resources SET cleanup_count = cleanup_count + 1 WHERE id = $1",
		a.ID,
	)

	return err
}
func (a *OcpAccountProvider) FetchAllByServiceUuid(serviceUuid string) ([]OcpAccount, error) {
	accounts := []OcpAccount{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
		 resource_data, id, resource_name, resource_type,
		 created_at, updated_at, status, cleanup_count
		 FROM resources WHERE service_uuid = $1`,
		serviceUuid,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found", "service_uuid", serviceUuid)
		}
		return accounts, err
	}

	for rows.Next() {
		var account OcpAccount
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
		); err != nil {
			return accounts, err
		}

		account.ServiceUuid = serviceUuid
		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (a *OcpAccountProvider) FetchAllByServiceUuidWithCreds(serviceUuid string) ([]OcpAccountWithCreds, error) {
	accounts := []OcpAccountWithCreds{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
         resource_data, id, resource_name, resource_type,
         created_at, updated_at, status, cleanup_count,
         pgp_sym_decrypt(resource_credentials, $2)
		 FROM resources WHERE service_uuid = $1`,
		serviceUuid, a.VaultSecret,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found", "service_uuid", serviceUuid)
		}
		return accounts, err
	}

	for rows.Next() {
		var account OcpAccountWithCreds

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
			&creds); err != nil {
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

var ErrNoSchedule error = errors.New("No OCP cluster found")

func (a *OcpAccountProvider) Request(serviceUuid string, cloud_selector map[string]string, annotations map[string]string) (OcpAccountWithCreds, error) {
	var name string
	var api_url string
	var kubeconfig string
	var rowcount int
	var minOcpMemoryUsage float64
	var selectedCluster string
	var selectedApiUrl string

	// Ensure annotation has guid
	if _, exists := annotations["guid"]; !exists {
		return OcpAccountWithCreds{}, errors.New("guid not found in annotations")
	}

	// TODO use the OcpCluster type don't interact directly with this table from here
	err := a.DbPool.QueryRow(
		context.Background(),
		`SELECT count(*) FROM ocp_clusters
         WHERE annotations @> $1
         and valid=true`,
		cloud_selector,
	).Scan(&rowcount)

	if rowcount == 0 {
		log.Logger.Error("No OCP cluster found", "cloud_selector", cloud_selector)
		return OcpAccountWithCreds{}, ErrNoSchedule
	}
	if err != nil {
		log.Logger.Error("OCP cluster query error", "err", err)
		return OcpAccountWithCreds{}, err
	}
	// TODO use the OcpCluster type don't interact directly with this table from here
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT name, api_url, pgp_sym_decrypt(kubeconfig::bytea, $1)
  		 FROM ocp_clusters WHERE annotations @> $2 and valid=true`,
		a.VaultSecret, cloud_selector,
	)

	if err != nil {
		log.Logger.Error("Error querying ocp providers", "error", err)
		return OcpAccountWithCreds{}, err
	}

	// Determine guid, auto increment the guid if there are multiple resources
	// for a serviceUuid
	guid := annotations["guid"]
	increment := 0

	for {
		if increment > 100 {
			// something clearly went wrong, shouldn't never happen, but be defensive
			return OcpAccountWithCreds{}, errors.New("Too many iterations guessing guid")
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
			AND resource_type = 'OcpAccount'`,
			candidateName,
		).Scan(&rowcount)

		if err != nil {
			log.Logger.Error("Error checking resources names", "error", err)
			return OcpAccountWithCreds{}, err
		}

		if rowcount == 0 {
			break
		}
		increment++
	}

	// Return the Placement with a status 'initializing'
	rnew := OcpAccountWithCreds{
		OcpAccount: OcpAccount{
			Name:        guid + "-" + serviceUuid,
			Kind:        "OcpAccount",
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
		return OcpAccountWithCreds{}, err
	}

	//--------------------------------------------------
	// The following is async
	go func() {
		defer rows.Close()
	providerLoop:
		for rows.Next() {
			rnew.SetStatus("scheduling")
			if err := rows.Scan(&name, &api_url, &kubeconfig); err != nil {
				log.Logger.Error("Error scanning ocp providers", "error", err)
				rnew.SetStatus("error")
				continue providerLoop
			}

			log.Logger.Info("Cluster",
				"name", name,
				"api_url", api_url)

			config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfig))
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
				selectedCluster = name
				selectedApiUrl = api_url
			}
			log.Logger.Info("Cluster Usage",
				"CPU Usage (Requests)", cpuUsage,
				"Memory Usage (Requests)", memoryUsage)
		}
		log.Logger.Info("selectedCluster", "cluster", selectedCluster)

		if selectedCluster == "" {
			log.Logger.Error("Error electing cluster", "name", rnew.Name)
			rnew.SetStatus("error")
			return
		}
		err = a.DbPool.QueryRow(
			context.Background(),
			"SELECT pgp_sym_decrypt(kubeconfig::bytea, $1) FROM ocp_clusters WHERE name = $2",
			a.VaultSecret, selectedCluster,
		).Scan(&kubeconfig)

		if err != nil {
			log.Logger.Error("Error decrypting kubeconfig", "error", err)
			rnew.SetStatus("error")
			return
		}

		config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfig))
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

		serviceAccountName := "sandbox-" + rnew.Name
		serviceAccountName = serviceAccountName[:min(63, len(serviceAccountName))] // truncate to 63
		namespaceName := "sandbox-" + rnew.Name
		namespaceName = namespaceName[:min(63, len(namespaceName))] // truncate to 63

		delay := time.Second
		for {
			// Create the Namespace
			_, err = clientset.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: namespaceName,
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
			break
		}

		_, err = clientset.CoreV1().ServiceAccounts(serviceAccountName).Create(context.TODO(), &v1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name: serviceAccountName,
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
		_, err = clientset.RbacV1().RoleBindings(serviceAccountName).Create(context.TODO(), &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: serviceAccountName,
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
					Namespace: serviceAccountName,
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

		secrets, err := clientset.CoreV1().Secrets(serviceAccountName).List(context.TODO(), metav1.ListOptions{})

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
		r := OcpAccountWithCreds{
			OcpAccount: OcpAccount{
				Name:           rnew.Name,
				Kind:           "OcpAccount",
				OcpClusterName: selectedCluster,
				OCPApiUrl:      selectedApiUrl,
				Annotations:    annotations,
				ServiceUuid:    serviceUuid,
				Status:         "success",
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
	}()
	//--------------------------------------------------

	return rnew, nil
}

func (a *OcpAccountProvider) Release(service_uuid string) error {
	accounts, err := a.FetchAllByServiceUuidWithCreds(service_uuid)

	if err != nil {
		return err
	}

	var errorHappened error

	for _, account := range accounts {
		if err := account.Delete(); err != nil {
			errorHappened = err
			continue
		}
	}
	return errorHappened
}

func NewOcpAccountProvider(dbpool *pgxpool.Pool, vaultSecret string) OcpAccountProvider {
	return OcpAccountProvider{
		DbPool:      dbpool,
		VaultSecret: vaultSecret,
	}
}

func (a *OcpAccountProvider) FetchAll() ([]OcpAccount, error) {
	accounts := []OcpAccount{}
	// Get resource from above 'resources' table
	rows, err := a.DbPool.Query(
		context.Background(),
		`SELECT
		 resource_data, id, resource_name, resource_type,
		 created_at, updated_at, status, cleanup_count
		 FROM resources`,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Info("No account found")
		}
		return accounts, err
	}

	for rows.Next() {
		var account OcpAccount
		if err := rows.Scan(
			&account,
			&account.ID,
			&account.Name,
			&account.Kind,
			&account.CreatedAt,
			&account.UpdatedAt,
			&account.Status,
			&account.CleanupCount,
		); err != nil {
			return accounts, err
		}

		accounts = append(accounts, account)
	}

	return accounts, nil
}

func (account *OcpAccountWithCreds) Delete() error {
	account.SetStatus("deleting")
	account.IncrementCleanupCount()
	var api_url string
	var kubeconfig string

	// Get the OCP provider from the resources.resource_data column

	err := account.Provider.DbPool.QueryRow(
		context.Background(),
		"SELECT api_url, pgp_sym_decrypt(kubeconfig::bytea, $1) FROM ocp_clusters WHERE name = $2",
		account.Provider.VaultSecret,
		account.OcpClusterName,
	).Scan(&api_url, &kubeconfig)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Error("Ocp provider doesn't exist", "provider", account.OcpClusterName, "name", account.Name)
			account.SetStatus("error")
			return errors.New("Ocp provider doesn't exist for resource")
		} else {
			log.Logger.Error("Ocp provider query error", "err", err)
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
	namespaceName := "sandbox-" + account.Name
	namespaceName = namespaceName[:min(63, len(namespaceName))] // truncate to 63
	serviceAccountName := "sandbox-" + account.Name
	serviceAccountName = serviceAccountName[:min(63, len(serviceAccountName))] // truncate to 63

	// Check if the namespace exists
	_, err = clientset.CoreV1().Namespaces().Get(context.TODO(), namespaceName, metav1.GetOptions{})
	if err != nil {
		// TODO: if namespace is not found, consider deletion a success
		log.Logger.Error("Error getting OCP namespace", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}
	// Delete the Namespace
	err = clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{})
	if err != nil {
		log.Logger.Error("Error deleting OCP namespace", "error", err, "name", account.Name)
		account.SetStatus("error")
		return err
	}

	// Delete the Service Account
	if err = clientset.CoreV1().
		ServiceAccounts(namespaceName).
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

func (p *OcpAccountProvider) FetchByName(name string) (OcpAccount, error) {
	// Get resource from above 'resources' table
	row := p.DbPool.QueryRow(
		context.Background(),
		`SELECT
		 resource_data, id, resource_name, resource_type,
		 created_at, updated_at, status, cleanup_count
		 FROM resources WHERE resource_name = $1 and resource_type = 'OcpAccount'`,
		name,
	)

	var account OcpAccount
	if err := row.Scan(
		&account,
		&account.ID,
		&account.Name,
		&account.Kind,
		&account.CreatedAt,
		&account.UpdatedAt,
		&account.Status,
		&account.CleanupCount,
	); err != nil {
		return OcpAccount{}, err
	}
	return account, nil
}
