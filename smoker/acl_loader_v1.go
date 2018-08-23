package smoker

import (
	"errors"
	"fmt"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"regexp"
)

type EgressAclRule struct {
	Project                    string
	Policy                     ConfigEnforcementPolicy
	DomainExpressionsOrStrings []interface{}
}

type EgressAclConfig struct {
	Services map[string]EgressAclRule
	Default *EgressAclRule
}

func (ew *EgressAclConfig) Decide(fromService string, toHost string) (EgressAclDecision, error) {

	var (
		found bool
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
		return 0, fmt.Errorf("unknown role role=%#v", fromService)
	}

	if service.Policy == ConfigEnforcementPolicyOpen {
		return EgressAclDecisionAllow, nil
	}

	matches := false
	for _, exp := range service.DomainExpressionsOrStrings {

		switch v := exp.(type) {
		case *regexp.Regexp:
			if v.Match([]byte(toHost)) {
				matches = true
				break
			}
		case *string:
			if *v == toHost {
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
	Name           string   `yaml:"name"`
	Project        string   `yaml:"project"`
	Action         string   `yaml:"action"`
	AllowedDomains []string `yaml:"allowed_domains"`
}

type EgressAclConfiguration struct {
	Services []ServiceRule `yaml:"services"`
	Default *ServiceRule `yaml:"default"`
	Version string `yaml:"version"`
}

func LoadFromYamlFile(configPath string) (*EgressAclConfig, error) {
	fail := func(err error) (*EgressAclConfig, error) { return nil, err }

	yamlConfig := EgressAclConfiguration{}

	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Could not load whitelist configuration at '%s': #%v", configPath, err)
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
		res, err := aclConfigToRule(&v)
		if err != nil {
			return fail(err)
		}
		acl.Services[v.Name] = res
	}

	if yamlConfig.Default != nil {
		res, err := aclConfigToRule(yamlConfig.Default)
		if err != nil {
			return fail(err)
		}
		acl.Default = &res
	}
	return &acl, nil
}


func aclConfigToRule(v *ServiceRule) (EgressAclRule, error) {

	regexRegex, err := regexp.Compile("^/.*/$")
	if err != nil {
		log.Fatal(err)
	}

	domainExpr := make([]interface{}, len(v.AllowedDomains))

	for i, v := range v.AllowedDomains {

		// Is the entry a regex?
		if regexRegex.MatchString(v) {
			v = v[1:len(v)-1] // Drop both '/'
			expr, err := regexp.Compile(v)

			if err != nil {
				return EgressAclRule{}, err
			}
			domainExpr[i] = expr
		} else {
			domainExpr[i] = &v
		}
	}

	var enforcement_policy ConfigEnforcementPolicy

	switch v.Action {
	case "open":
		enforcement_policy = ConfigEnforcementPolicyOpen
	case "report":
		enforcement_policy = ConfigEnforcementPolicyReport
	case "enforce":
		enforcement_policy = ConfigEnforcementPolicyEnforce
	default:
		enforcement_policy = 0
		return EgressAclRule{}, errors.New(fmt.Sprintf("Unknown action '%s' under '%s'.", v.Action, v.Name))
	}

	return EgressAclRule{
		Project:           v.Project,
		Policy:            enforcement_policy,
		DomainExpressionsOrStrings: domainExpr,
	}, nil
}