package models

import (

//	"github.com/jackc/pgx/v4/pgxpool"
//	"github.com/rhpds/sandbox/internal/log"

//  buildv1client "github.com/openshift/client-go/build/clientset/versioned/typed/build/v1"

//  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
//  corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
//  "k8s.io/client-go/tools/clientcmd"

)


type OcpAccount struct {
	Account

	Name string `json:"name"`
	Kind string `json:"kind"`
	SAtoken string `json:"sa_token"`

}

type OcpAccountWithCreds struct {
	OcpAccount

	Credentials []any `json:"credentials"`
}

// OcpAccountProvider interface to interact with different databases:
// dynamodb and postgresql
type OcpAccountProvider interface {
	FetchByName(name string) (OcpAccount, error)
	FetchAll() ([]OcpAccount, error)
	FetchAllToCleanup() ([]OcpAccount, error)
	FetchAllSorted(by string) ([]OcpAccount, error)
	FetchAllByServiceUuid(serviceUuid string) ([]OcpAccount, error)
	FetchAllByServiceUuidWithCreds(serviceUuid string) ([]OcpAccountWithCreds, error)
	Request(service_uuid string, count int, annotations map[string]string) ([]OcpAccountWithCreds, error)
	MarkForCleanup(name string) error
	MarkForCleanupByServiceUuid(serviceUuid string) error
	DecryptSecret(encrypted string) (string, error)
	//Annotations(account OcpAccount) (map[string]string, error)
}
type OcpAccountProviderImpl struct {
  OcpAccountProvider
}

/*func  (a *OcpAccountProviderImpl) FetchAll() ([]OcpAccount, error) {
  log.Logger.Warn("OCP accounts2")
  return nil,nil
}*/


