package models

import (
	"context"
	"errors"
	"net/http"
  "os"

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

var OcpErrNoEnoughAccountsAvailable = errors.New("no enough accounts available")

var OcpErrAccountNotFound = errors.New("account not found")

type OcpAccount struct {
	Account
	Kind        string `json:"kind"` // "OcpSandbox"
	OCPProvider string `json:"ocp_provider"`
	OCPApiUrl   string `json:"api_url"`
	Name        string `json:"name"`
	SAAccount   string `json:"sa_account"`
	SAToken     string `json:"sa_token"`
}

func (a *OcpAccount) Render(w http.ResponseWriter, r *http.Request) error {
	return nil
}

type OcpAccounts []OcpAccount

type TokenResponse struct {
	AccessToken string `json:"access_token"`
}

// OcpAccountProvider interface to interact with different databases:
// dynamodb and postgresql
type OcpAccountProvider interface {
	//	FetchByName(name string) (OcpAccount, error)
	FetchAll() ([]OcpAccount, error)
	//	FetchAllToCleanup() ([]OcpAccount, error)
	//	FetchAllSorted(by string) ([]OcpAccount, error)
	FetchAllAvailable() ([]OcpAccount, error)
	//	FetchAllByServiceUuid(serviceUuid string) ([]OcpAccount, error)
	//	FetchAllActiveByServiceUuid(serviceUuid string) ([]OcpAccount, error)
	//	FetchAllByServiceUuidWithCreds(serviceUuid string) ([]OcpAccountWithCreds, error)
	//	FetchAllActiveByServiceUuidWithCreds(serviceUuid string) ([]OcpAccountWithCreds, error)
	Request(service_uuid string, cloud_selector map[string]string, dbpool *pgxpool.Pool, annotations map[string]string) (OcpAccount, error)
	Release(service_uuid string, dbpool *pgxpool.Pool, annotations map[string]interface{}) error
	//	MarkForCleanup(name string) error
	//	MarkForCleanupByServiceUuid(serviceUuid string) error
	//	DecryptSecret(encrypted string) (string, error)
	//	CountAvailable(reservation string) (int, error)
	//	Count() (int, error)
	//
	// Annotations(account OcpAccount) (map[string]string, error)
}

type OcpAccountRequest struct {
	instances OcpAccountProvider
}

func (a *OcpAccountRequest) Request(service_uuid string, cloud_selector map[string]string, dbpool *pgxpool.Pool, annotations map[string]string) (OcpAccount, error) {
	var name string
	var api_url string
	var kubeconfig string
	var rowcount int
  var minOcpMemoryUsage float64
  var selectedCluster string
  var selectedApiUrl string
	err := dbpool.QueryRow(
		context.Background(),
		"SELECT count(*) FROM ocp_providers WHERE annotations @> $1 and valid=true", cloud_selector,
	).Scan(&rowcount)
	if rowcount == 0 {
			log.Logger.Error("No ocp provider found", "cloud_selector", cloud_selector)
			return OcpAccount{}, errors.New("Ocp provider not found")
  }
	if err != nil {
			log.Logger.Error("Ocp provider query error", "err", err)
			return OcpAccount{}, errors.New("Ocp provider query error")
	}
	rows, err := dbpool.Query(
		context.Background(),
		"SELECT name,api_url,kubeconfig FROM ocp_providers WHERE annotations @> $1 and valid=true", cloud_selector,
	)
	defer rows.Close()
	for rows.Next() {
		rows.Scan(&name,&api_url, &kubeconfig)
		log.Logger.Info("name", name)
		log.Logger.Info("api_url", api_url)
		log.Logger.Info("kubeconfig", kubeconfig)
    kubeconfigcontent, err := os.ReadFile(kubeconfig)
		config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfigcontent))
		clientset, err := kubernetes.NewForConfig(config)
		nodes, err := clientset.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{LabelSelector: "node-role.kubernetes.io/worker="})
		if err != nil {
      continue
		}
		var totalAllocatableCpu, totalAllocatableMemory int64
		var totalRequestedCpu, totalRequestedMemory int64

		for _, node := range nodes.Items {
			allocatableCpu := node.Status.Allocatable.Cpu().MilliValue()
			allocatableMemory := node.Status.Allocatable.Memory().Value()

			podList, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{FieldSelector: "spec.nodeName=" + node.Name})
			if err != nil {
				panic(err.Error())
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
		log.Logger.Info("Cluster CPU Usage (Requests): %.2f%%\n", cpuUsage)
		log.Logger.Info("Cluster Memory Usage (Requests): %.2f%%\n", memoryUsage)
	}
  log.Logger.Info("selectedCluster: %s\n", selectedCluster)
  if (selectedCluster == "") {
		return OcpAccount{}, errors.New("Error selecting a proper cluster")
  }
	err = dbpool.QueryRow(
		context.Background(),
		"SELECT kubeconfig FROM ocp_providers WHERE name = $1", selectedCluster,
	).Scan(&kubeconfig)

  kubeconfigcontent, err := os.ReadFile(kubeconfig)
	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfigcontent))
	// Create an OpenShift client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Logger.Error("Error creating OCP client", "error", err)
		return OcpAccount{}, errors.New("Error creating OCP client")
	}
	// Define the Service Account name
	serviceAccountName := annotations["env_type"] + "-" + annotations["guid"]

	// Create the Namespace
	_, err = clientset.CoreV1().Namespaces().Create(context.TODO(), &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceAccountName,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		log.Logger.Error("Error creating OCP namespace", "error", err)
		//TODO: Uncomment 
    // Should we fail if namespace exists? or only if it fails
    //return OcpAccount{}, errors.New("Error creating OCP namespace")
	}

	// Create the Service Account
	_, err = clientset.CoreV1().ServiceAccounts(serviceAccountName).Create(context.TODO(), &v1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: serviceAccountName,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		log.Logger.Error("Error creating OCP service account", "error", err)
    // Should we fail if sa exists? or only if it fails
		//TODO: Uncomment 
    // return OcpAccount{}, errors.New("Error creating OCP service account")
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
		//TODO: Uncomment 
    // Should we fail if rolebind exists? or only if it fails
    // return OcpAccount{}, errors.New("Error creating OCP role binding")
	}

  secrets, err := clientset.CoreV1().Secrets(serviceAccountName).List(context.TODO(), metav1.ListOptions{})

  if err != nil {
      log.Logger.Error("Error listing OCP secrets", "error", err)
      return OcpAccount{}, err
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
    if saSecret != nil { break }
  } 
	return OcpAccount{
		Name:         "sandbox_ocp_" + annotations["guid"],
    Kind:         "OcpSandbox",
    OCPProvider:  selectedCluster,
    OCPApiUrl:    selectedApiUrl,
		SAAccount:    serviceAccountName,
		SAToken:      string(saSecret.Data["token"]),
	}, nil
}
func (a *OcpAccountRequest) Release(service_uuid string, dbpool *pgxpool.Pool, annotations map[string]interface{}) error {
	var api_url string
	var kubeconfig string
  var provider = annotations["OCPProvider"]
	err := dbpool.QueryRow(
		context.Background(),
		"SELECT api_url,kubeconfig FROM ocp_providers WHERE name = $1", provider,
	).Scan(&api_url, &kubeconfig)

	if err != nil {
		if err == pgx.ErrNoRows {
			log.Logger.Error("Ocp provider doesn't exist", "provider", provider)
			return errors.New("Ocp provider doesnt exist")
		} else {
			log.Logger.Error("Ocp provider query error", "err", err)
			return errors.New("Ocp provider query error")
		}
	}

  kubeconfigcontent, err := os.ReadFile(kubeconfig)
	config, err := clientcmd.RESTConfigFromKubeConfig([]byte(kubeconfigcontent))
	// Create an OpenShift client
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Logger.Error("Error creating OCP client", "error", err)
		return errors.New("Error creating OCP client")
	}
	// Define the Service Account name
	namespaceName := annotations["env_type"].(string) + "-" + annotations["guid"].(string)

	// Check if the namespace exists
	_, err = clientset.CoreV1().Namespaces().Get(context.TODO(), namespaceName, metav1.GetOptions{})
	if err != nil {
		return nil
	}
	// Delete the Namespace
	err = clientset.CoreV1().Namespaces().Delete(context.TODO(), namespaceName, metav1.DeleteOptions{})
	if err != nil {
		log.Logger.Error("Error deleting OCP namespace", "error", err)
		return errors.New("Error deleting OCP namespace")
	}
	return nil
}
func NewOcpAccountProvider(vaultSecret string) *OcpAccountRequest {
	return &OcpAccountRequest{}
}

func (a *OcpAccountRequest) FetchAll() ([]OcpAccount, error) {
	log.Logger.Error("Error getting accounts", "error", "hello")
	return []OcpAccount{}, errors.New("count must be > 0")
}

func (a *OcpAccountRequest) FetchAllAvailable() ([]OcpAccount, error) {
	log.Logger.Error("Error getting accounts", "error", "hello")
	return []OcpAccount{}, errors.New("count must be > 0")
}
