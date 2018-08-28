package smokescreen

import (
	"errors"
	"fmt"
	"io/ioutil"
	"strings"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

type EgressAclRule struct {
	Project    string
	Policy     ConfigEnforcementPolicy
	DomainGlob []string
}

type EgressAclConfig struct {
	Services map[string]EgressAclRule
	Default  *EgressAclRule
}

func (ew *EgressAclConfig) Decide(fromService string, toHost string) (EgressAclDecision, error) {

	var (
		found   bool
		service EgressAclRule
	)
	if fromService == "" {
		found = false
	} else {
		service, found = ew.Services[fromService]
	}

	if !found && ew.Default != nil {
		found = true
		service = *ew.Default
	}

	if !found {
		return 0, UnknownRoleError{fromService}
	}

	if service.Policy == ConfigEnforcementPolicyOpen {
		return EgressAclDecisionAllow, nil
	}

	matches := false
	for _, host := range service.DomainGlob {
		if len(host) > 0 && host[0] == '*' {
			postfix := host[1:]
			if strings.HasSuffix(toHost, postfix) {
				matches = true
				break
			}
		} else {
			if host == toHost {
				matches = true
				break
			}
		}
	}

	switch service.Policy {
	case ConfigEnforcementPolicyReport:
		if matches {
			return EgressAclDecisionAllow, nil
		} else {
			return EgressAclDecisionAllowAndReport, nil
		}
	case ConfigEnforcementPolicyEnforce:
		if matches {
			return EgressAclDecisionAllow, nil
		} else {
			return EgressAclDecisionDeny, nil
		}
	default:
		return 0, errors.New("unexpected state")
	}
}

func (ew *EgressAclConfig) Project(fromService string) (string, error) {
	service, found := ew.Services[fromService]

	if found {
		return service.Project, nil
	}

	if ew.Default != nil {
		return ew.Default.Project, nil
	}

	return "", fmt.Errorf("warn: No known project: role=%#v\n", fromService)
}

// Configuration

type ServiceRule struct {
	Name         string   `yaml:"name"`
	Project      string   `yaml:"project"`
	Action       string   `yaml:"action"`
	AllowedHosts []string `yaml:"allowed_domains"`
}

type EgressAclConfiguration struct {
	Services []ServiceRule `yaml:"services"`
	Default  *ServiceRule  `yaml:"default"`
	Version  string        `yaml:"version"`
}

func LoadFromYamlFile(config *Config, aclPath string, disabledAclPolicyActions []string) (*EgressAclConfig, error) {
	fail := func(err error) (*EgressAclConfig, error) { return nil, err }

	yamlConfig := EgressAclConfiguration{}

	yamlFile, err := ioutil.ReadFile(aclPath)
	if err != nil {
		log.Fatalf("Could not load whitelist configuration at '%s': #%v", aclPath, err)
		return nil, err
	}

	err = yaml.Unmarshal(yamlFile, &yamlConfig)

	if yamlConfig.Version != "v1" {
		return fail(fmt.Errorf("Expected version \"v1\" got %#v\n", yamlConfig.Version))
	}

	if err != nil {
		return nil, err
	}

	acl := EgressAclConfig{Services: make(map[string]EgressAclRule)}

	if yamlConfig.Services == nil {
		return nil, errors.New("Top level list 'services' is missing")
	}

	for _, v := range yamlConfig.Services {
		res, err := aclConfigToRule(&v, disabledAclPolicyActions)
		if err != nil {
			config.Log.Error("gnored policy", err)
		} else {
			acl.Services[v.Name] = res
		}
	}

	if yamlConfig.Default != nil {
		res, err := aclConfigToRule(yamlConfig.Default, disabledAclPolicyActions)
		if err != nil {
			config.Log.Error("gnored policy", err)
		} else {
			acl.Default = &res
		}
	}
	return &acl, nil
}

func aclConfigToRule(v *ServiceRule, disabledAclPolicyAction []string) (EgressAclRule, error) {
	var enforcementPolicy ConfigEnforcementPolicy

	// Validate policy action
	for _, disabledAction := range disabledAclPolicyAction {
		if disabledAction == v.Action {
			return EgressAclRule{}, fmt.Errorf("policy action %#v has been disabled but is used in rule for service %#v", disabledAction, v.Name)
		}
	}

	// Validate hosts

	for _, host := range v.AllowedHosts {
		if !strings.HasPrefix(host, "*.") && strings.HasPrefix(host, "*") {
			return EgressAclRule{}, fmt.Errorf("glob must represent a full prefxi (sub)domain")
		}

		// Check for stars elsewhere
		hostToCheck := host
		if strings.HasPrefix(hostToCheck, "*") {
			hostToCheck = hostToCheck[1:]
		}
		if strings.Contains(hostToCheck, "*") {
			return EgressAclRule{}, fmt.Errorf("globs are only supported as prefix")
		}
	}

	switch v.Action {
	case "open":
		enforcementPolicy = ConfigEnforcementPolicyOpen
	case "report":
		enforcementPolicy = ConfigEnforcementPolicyReport
	case "enforce":
		enforcementPolicy = ConfigEnforcementPolicyEnforce
	default:
		enforcementPolicy = 0
		return EgressAclRule{}, errors.New(fmt.Sprintf("Unknown action '%s' under '%s'.", v.Action, v.Name))
	}

	return EgressAclRule{
		Project:    v.Project,
		Policy:     enforcementPolicy,
		DomainGlob: v.AllowedHosts,
	}, nil
}
