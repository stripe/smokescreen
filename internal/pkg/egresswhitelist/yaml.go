package yaml

import (
	"errors"
	"github.com/stripe/smokescreen/pkg/egresswhitelist"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"regexp"
)


type EgressWhitelistYamlEntry struct {
	Project string
	Action string
	DomainExpressions []regexp.Regexp
}

type EgressWhitelistYaml struct {
	Services map[string]EgressWhitelistYamlEntry
}


func (ew EgressWhitelistYaml) Decide(fromService string, toHost string) (egresswhitelist.Decision, error) {
	service, found := ew.Services[fromService]
	
	if !found {
		return 0, errors.New("Unknown service")
	}
	
	if service.Action == "open" {
		return egresswhitelist.ALLOW, nil
	}
	
	matches := false
	for idx := range service.DomainExpressions {
		regexp := &service.DomainExpressions[idx]
		if regexp.Match([]byte(toHost)) {
			matches = true
			break
		}
	
	}
	
	switch service.Action {
		case "report":
			if matches {
				return egresswhitelist.ALLOW, nil
			} else {
				return egresswhitelist.ALLOWREPORT, nil
			}
		case "enforce":
			if matches {
				return egresswhitelist.ALLOW, nil
			} else {
				return egresswhitelist.DENY, nil
			}
		default:
		  return 0, errors.New("unexpected state")
		}
}


// Configuration

type EgressWhitelistConfiguration struct {
	Services []struct {
		Name           string   `yaml:"name"`
		Project        string   `yaml:"project"`
		Action         string   `yaml:"action"`
		AllowedDomains []string `yaml:"allowed_domains"`
	} `yaml:"services"`
}


func LoadFromYaml(configPath string) (*EgressWhitelistYaml, error) {
	
	yamlConfig := EgressWhitelistConfiguration{}
	
	yamlFile, err := ioutil.ReadFile(configPath)
	if err != nil {
		log.Fatalf("Could not load whitelist configuration at '%s': #%v", configPath, err)
		return nil, err
	}
	
	err = yaml.Unmarshal(yamlFile, &yamlConfig)
	
	if err != nil {
		return nil, err
	}
	
	acl := EgressWhitelistYaml{Services: make(map[string]EgressWhitelistYamlEntry)}
	for _, v := range yamlConfig.Services {
		
		domain_expr := make([]regexp.Regexp, len(v.AllowedDomains))
		
		for i, v := range v.AllowedDomains {
			expr, err := regexp.Compile(v)
			
			if err != nil {
				return nil, err
			}
			
			domain_expr[i] = *expr
		}
		
		acl.Services[v.Name] = EgressWhitelistYamlEntry{
			Project: v.Project,
			Action: v.Action,
			DomainExpressions: domain_expr,
		}
		
	}
	return &acl, nil 
}
