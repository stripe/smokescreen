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
	GlobalDenyList []string
	GlobalAllowList []string
}

func (ew *EgressAclConfig) Decide(fromService string, toHost string) (EgressAclDecision, bool, error) {
	var action EgressAclDecision

	rule := ew.ruleForService(fromService)
	if rule == nil {
		action = EgressAclDecisionDeny
		return action, false, nil
	}

	defaultRuleUsed := rule == ew.Default

	// if the host matches any of the rule's allowed domains, allow
	for _, domainGlob := range rule.DomainGlob {
		if hostMatchesGlob(toHost, domainGlob) {
			return EgressAclDecisionAllow, defaultRuleUsed, nil
		}
	}

	// if the host matches any of the global deny list, deny
	for _, domainGlob := range ew.GlobalDenyList {
		if hostMatchesGlob(toHost, domainGlob) {
			return EgressAclDecisionDeny, defaultRuleUsed, nil
		}
	}

	// if the host matches any of the global allow list, allow
	for _, domainGlob := range ew.GlobalAllowList {
		if hostMatchesGlob(toHost, domainGlob) {
			return EgressAclDecisionAllow, defaultRuleUsed, nil
		}
	}

	switch rule.Policy {
	case ConfigEnforcementPolicyReport:
		action = EgressAclDecisionAllowAndReport
	case ConfigEnforcementPolicyEnforce:
		action = EgressAclDecisionDeny
	case ConfigEnforcementPolicyOpen:
		return EgressAclDecisionAllow, defaultRuleUsed, nil
	default:
		return 0, defaultRuleUsed, fmt.Errorf("unexpected policy value for (%s -> %s): %d", fromService, toHost, rule.Policy)
	}

	// use the decision from rule.Policy
	return action, defaultRuleUsed, nil
}

func hostMatchesGlob(toHost string, domainGlob string) (bool) {
	if len(domainGlob) > 0 && domainGlob[0] == '*' {
		postfix := domainGlob[1:]
		if strings.HasSuffix(toHost, postfix) {
			return true
		}
	} else if domainGlob == toHost {
		return true
	}

	return false
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
	GlobalDenyList []string `yaml:"global_deny_list"` // domains which will be blocked even in report mode
	GlobalAllowList []string `yaml:"global_allow_list"` // domains which will be allowed for every host type
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
	} else {
		config.Log.Warn("No default rule set")
	}

	if yamlConfig.GlobalAllowList != nil {
		acl.GlobalAllowList = yamlConfig.GlobalAllowList
	} else {
		acl.GlobalAllowList = []string{}
	}

	if yamlConfig.GlobalDenyList != nil {
		acl.GlobalDenyList = yamlConfig.GlobalDenyList
	} else {
		acl.GlobalDenyList = []string{}
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
