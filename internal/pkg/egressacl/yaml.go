package egressacl

import (
	"errors"
	"fmt"
	_ "github.com/stripe/smokescreen/pkg/egressacl"
	"github.com/stripe/smokescreen/pkg/egressacl/decision"
	"github.com/stripe/smokescreen/pkg/egressacl/enforcementpolicy"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"regexp"
)

type EgressAclYamlEntry struct {
	Project           string
	Policy            enforcementpolicy.EnforcementPolicy
	DomainExpressions []*regexp.Regexp
}

type EgressAclYaml struct {
	Services map[string]EgressAclYamlEntry
}

func (ew EgressAclYaml) Decide(fromService string, toHost string) (decision.Decision, error) {
	service, found := ew.Services[fromService]

	if !found {
		return 0, errors.New("Unknown service")
	}

	if service.Policy == enforcementpolicy.OPEN {
		return decision.ALLOW, nil
	}

	matches := false
	for idx := range service.DomainExpressions {
		regexp := &service.DomainExpressions[idx]
		if (*regexp).Match([]byte(toHost)) {
			matches = true
			break
		}

	}

	switch service.Policy {
	case enforcementpolicy.REPORT:
		if matches {
			return decision.ALLOW, nil
		} else {
			return decision.ALLOW_REPORT, nil
		}
	case enforcementpolicy.ENFORCE:
		if matches {
			return decision.ALLOW, nil
		} else {
			return decision.DENY, nil
		}
	default:
		return 0, errors.New("unexpected state")
	}
}

// Configuration

type EgressAclConfiguration struct {
	Services []struct {
		Name           string   `yaml:"name"`
		Project        string   `yaml:"project"`
		Action         string   `yaml:"action"`
		AllowedDomains []string `yaml:"allowed_domains"`
	} `yaml:"services"`
}

func LoadFromYamlFile(configPath string) (*EgressAclYaml, error) {

	yamlConfig := EgressAclConfiguration{}

	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Could not load whitelist configuration at '%s': #%v", configPath, err)
		return nil, err
	}

	err = yaml.Unmarshal(yamlFile, &yamlConfig)

	if err != nil {
		return nil, err
	}

	acl := EgressAclYaml{Services: make(map[string]EgressAclYamlEntry)}

	if yamlConfig.Services == nil {
		return nil, errors.New("Top level list 'services' is missing")
	}

	for _, v := range yamlConfig.Services {

		domain_expr := make([]*regexp.Regexp, len(v.AllowedDomains))

		for i, v := range v.AllowedDomains {
			expr, err := regexp.Compile(v)

			if err != nil {
				return nil, err
			}

			domain_expr[i] = expr
		}

		var enforcement_policy enforcementpolicy.EnforcementPolicy

		switch v.Action {
		case "open":
			enforcement_policy = enforcementpolicy.OPEN
		case "report":
			enforcement_policy = enforcementpolicy.REPORT
		case "enforce":
			enforcement_policy = enforcementpolicy.ENFORCE
		default:
			enforcement_policy = 0
			return nil, errors.New(fmt.Sprintf("Unknown action '%s' under '%s'.", v.Action, v.Name))
		}

		acl.Services[v.Name] = EgressAclYamlEntry{
			Project:           v.Project,
			Policy:            enforcement_policy,
			DomainExpressions: domain_expr,
		}
	}
	return &acl, nil
}
