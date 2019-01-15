package smokescreen

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

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
	rule := ew.ruleForService(fromService)
	if rule == nil {
		return 0, fmt.Errorf("unknown role: '%s'", fromService)
	}

	var action EgressAclDecision
	switch rule.Policy {
	case ConfigEnforcementPolicyReport:
		action = EgressAclDecisionAllowAndReport
	case ConfigEnforcementPolicyEnforce:
		action = EgressAclDecisionDeny
	case ConfigEnforcementPolicyOpen:
		return EgressAclDecisionAllow, nil
	default:
		return 0, fmt.Errorf("unexpected policy value for (%s -> %s): %d", fromService, toHost, rule.Policy)
	}

	for _, host := range rule.DomainGlob {
		if len(host) > 0 && host[0] == '*' {
			postfix := host[1:]
			if strings.HasSuffix(toHost, postfix) {
				return EgressAclDecisionAllow, nil
			}
		} else {
			if host == toHost {
				return EgressAclDecisionAllow, nil
			}
		}
	}

	return action, nil
}

func (ew *EgressAclConfig) Project(fromService string) (string, error) {
	service := ew.ruleForService(fromService)
	if service == nil {
		return "", fmt.Errorf("unknown role: '%s'", fromService)
	}

	return service.Project, nil
}

func (ew *EgressAclConfig) ruleForService(fromService string) *EgressAclRule {
	if fromService != "" {
		if service, found := ew.Services[fromService]; found {
			return &service
		}
	}

	return ew.Default
}

// Configuration

type ServiceRule struct {
	Name         string   `yaml:"name"`
	Project      string   `yaml:"project"`
	Action       string   `yaml:"action"`
	AllowedHosts []string `yaml:"allowed_domains"`
}

type YamlEgressAclConfiguration struct {
	Services []ServiceRule `yaml:"services"`
	Default  *ServiceRule  `yaml:"default"`
	Version  string        `yaml:"version"`
}

func (yamlConf *YamlEgressAclConfiguration) ValidateConfig() error {
	return nil
}

func LoadYamlAclFromFilePath(config *Config, aclPath string) (*EgressAclConfig, error) {
	file, err := os.Open(aclPath)

	if err != nil {
		return nil, err
	}
	defer file.Close()
	return LoadYamlAclFromReader(config, file)
}

func LoadYamlAclFromReader(config *Config, aclReader io.Reader) (*EgressAclConfig, error) {
	fail := func(err error) (*EgressAclConfig, error) { return nil, err }

	yamlConfig := YamlEgressAclConfiguration{}

	yamlFile, err := ioutil.ReadAll(aclReader)
	if err != nil {
		return fail(fmt.Errorf("could not load acl configuration"))
	}

	err = yaml.Unmarshal(yamlFile, &yamlConfig)

	return BuildAclFromYamlConfig(config, &yamlConfig)
}

func BuildAclFromYamlConfig(config *Config, yamlConfig *YamlEgressAclConfiguration) (*EgressAclConfig, error) {
	fail := func(err error) (*EgressAclConfig, error) { return nil, err }

	var err error

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
		res, err := aclConfigToRule(&v, config.DisabledAclPolicyActions)
		if err != nil {
			config.Log.Error("Ignored policy: ", err)
		} else {
			acl.Services[v.Name] = res
		}
	}

	if yamlConfig.Default != nil {
		res, err := aclConfigToRule(yamlConfig.Default, config.DisabledAclPolicyActions)
		if err != nil {
			config.Log.Error("Ignored policy: ", err)
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
			return EgressAclRule{}, fmt.Errorf("glob must represent a full prefix (sub)domain")
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
