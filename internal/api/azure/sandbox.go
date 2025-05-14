package azure

import (
	"github.com/rhpds/sandbox/internal/log"
)

const (
	sandboxRoleName    = "Custom-Owner (Block Billing and Subscription deletion)"
	rgNamePrefix       = "openenv-"
	rgDefaultLocation  = "eastus"
	dnsDefaultLocation = "Global"
	defaultAppPrefix   = "api://openenv-"
)

type AzureCredentials struct {
	TenantID string
	ClientID string
	Secret   string
}

type SandboxClient struct {
	graphClient      *graphClient
	managementClient *managementClient
}

type SandboxInfo struct {
	SubscriptionName  string
	SubscriptionId    string
	ResourceGroupName string
	AppID             string
	DisplayName       string
	Password          string
}

func InitSandboxClient( /*pool Pool, */ credentials AzureCredentials) *SandboxClient {
	gc := initGraphClient(
		credentials.TenantID,
		credentials.ClientID,
		credentials.Secret,
	)

	mc := initManagementClient(
		credentials.TenantID,
		credentials.ClientID,
		credentials.Secret,
	)

	return &SandboxClient{
		graphClient:      gc,
		managementClient: mc,
	}
}

func (sc *SandboxClient) CreateSandboxEnvironment(
	subscriptionName string,
	requestorEmail string,
	guid string,
	costCenter string,
	zoneDomain string,
) (*SandboxInfo, error) {
	adUser, err := sc.graphClient.getUser(requestorEmail)
	if err != nil {
		log.Logger.Error("Error sc.graphClient.getUser", "email", requestorEmail)
		return nil, err
	}
	log.Logger.Info("Step1")

	subscription, err := sc.managementClient.getSubscription(subscriptionName)
	if err != nil {
		log.Logger.Error("Error getSub")
		return nil, err
	}
	log.Logger.Info("subscription", "subscription", subscription)

	err = sc.setSandboxTags(guid, requestorEmail, costCenter, subscription.SubscriptionFQID)
	if err != nil {
		log.Logger.Error("Error Tags")
		return nil, err
	}
	log.Logger.Info("Step3")

	err = sc.createRoleAssignment(subscription.SubscriptionFQID, adUser.Id, "User")
	if err != nil {
		log.Logger.Error("Error Role")
		return nil, err
	}
	log.Logger.Info("Step4")

	rgName, err := sc.createResourceGroup(subscription.SubscriptionId, guid)
	if err != nil {
		log.Logger.Error("Error RG")
		return nil, err
	}
	log.Logger.Info("Step5")

	err = sc.createDNSZone(subscription.SubscriptionId, guid, rgName, zoneDomain)
	if err != nil {
		log.Logger.Error("Error DNSZo")
		return nil, err
	}
	log.Logger.Info("Step6")

	appDetails, err := sc.registerApplication(
		subscription.SubscriptionFQID,
		defaultAppPrefix+guid)
	if err != nil {
		log.Logger.Error("Error RegisterApp")
		return nil, err
	}

	log.Logger.Info("Created correctly", "email", requestorEmail)
	return &SandboxInfo{
		SubscriptionName:  subscriptionName,
		SubscriptionId:    subscription.SubscriptionId,
		ResourceGroupName: rgName,
		AppID:             appDetails.AppID,
		DisplayName:       appDetails.DisplayName,
		Password:          appDetails.Password,
	}, nil
}

func (sc *SandboxClient) CleanupSandboxEnvironment(subscriptionName string, guid string) error {
	subscription, err := sc.managementClient.getSubscription(subscriptionName)
	if err != nil {
		return err
	}

	err = sc.deleteResourceGroups(subscription.SubscriptionId)
	if err != nil {
		return err
	}

	err = sc.deleteApplications(defaultAppPrefix + guid)
	if err != nil {
		return err
	}

	err = sc.deleteRoleAssignments(subscription.SubscriptionFQID)
	if err != nil {
		return err
	}

	err = sc.deleteSandboxTags(subscription.SubscriptionFQID)
	if err != nil {
		return err
	}

	return nil
}

func (sc *SandboxClient) setSandboxTags(
	guid string,
	requestorEmail string,
	costCenter string,
	scope string,
) error {
	tags := make(map[string]string)
	tags["GUID"] = guid
	tags["guid"] = guid
	tags["EMAIL"] = requestorEmail
	tags["email"] = requestorEmail
	tags["cost-center"] = costCenter

	err := sc.managementClient.setTags(scope, tags)
	if err != nil {
		return err
	}

	return nil
}

func (sc *SandboxClient) deleteSandboxTags(scope string) error {
	tags := make(map[string]string)
	tags["GUID"] = ""
	tags["guid"] = ""
	tags["EMAIL"] = ""
	tags["email"] = ""
	err := sc.managementClient.updateTags(scope, tags, "delete")
	if err != nil {
		return err
	}

	return nil
}

func (sc *SandboxClient) createRoleAssignment(scope string, principalID string, principalType string) error {
	roleDefinition, err := sc.managementClient.getRoleDefinition(
		scope,
		sandboxRoleName)
	if err != nil {
		return err
	}

	_, err = sc.managementClient.createRoleAssignment(
		scope,
		roleDefinition.ID,
		principalID,
		principalType,
	)
	if err != nil {
		return err
	}

	return nil
}

func (sc *SandboxClient) deleteRoleAssignments(scope string) error {
	roleDefinition, err := sc.managementClient.getRoleDefinition(
		scope,
		sandboxRoleName)
	if err != nil {
		return err
	}

	roleAssignments, err := sc.managementClient.getRoleAssignments(
		scope,
		roleDefinition.ID)
	if err != nil {
		return err
	}

	for _, assignment := range roleAssignments {
		err = sc.managementClient.deleteRoleAssignment(assignment.ID)
		if err != nil {
			return err
		}
	}

	return nil
}

func (sc *SandboxClient) createResourceGroup(subscriptionId string, guid string) (string, error) {
	rgTags := make(map[string]string)
	rgTags["GUID"] = guid
	rgTags["guid"] = guid
	rgParams := resourceGroupParameters{
		SubscriptionId:    subscriptionId,
		ResourceGroupName: rgNamePrefix + guid,
		Location:          rgDefaultLocation,
		Tags:              rgTags,
	}

	rg, err := sc.managementClient.createResourceGroup(rgParams)
	if err != nil {
		return "", err
	}

	return rg.Name, nil
}

func (sc *SandboxClient) deleteResourceGroups(subscriptionId string) error {
	rgs, err := sc.managementClient.listResourceGroups(subscriptionId)
	if err != nil {
		return err
	}

	for _, rg := range rgs {
		err = sc.managementClient.deleteResourceGroup(rg.Id)
		if err != nil {
			return err
		}
	}

	return nil
}

func (sc *SandboxClient) createDNSZone(subscriptionId string, guid string, rgName string, zoneDomain string) error {
	dnsTags := make(map[string]string)
	dnsTags["GUID"] = guid
	dnsZoneParams := dnsZoneParameters{
		SubscriptionID:    subscriptionId,
		ResourceGroupName: rgName,
		ZoneName:          guid + "." + zoneDomain,
		Location:          dnsDefaultLocation,
		Tags:              dnsTags,
	}

	_, err := sc.managementClient.createDNSZone(dnsZoneParams)
	if err != nil {
		return err
	}

	return nil
}

func (sc *SandboxClient) registerApplication(scope string, name string) (*application, error) {
	app, err := sc.graphClient.createApplication(name)
	if err != nil {
		return nil, err
	}

	sp, err := sc.graphClient.createServicePrincipal(app.AppID)
	if err != nil {
		return nil, err
	}

	err = sc.createRoleAssignment(scope, sp.id, "ServicePrincipal")
	if err != nil {
		return nil, err
	}

	return app, nil
}

func (sc *SandboxClient) deleteApplications(name string) error {
	appIds, err := sc.graphClient.getApplicationObjectIDs(name)
	if err != nil {
		return err
	}

	for _, id := range appIds {
		err = sc.graphClient.deleteApplication(id)
		if err != nil {
			return err
		}

		err = sc.graphClient.permanentDeleteApplication(id)
		if err != nil {
			return err
		}
	}

	return nil
}
