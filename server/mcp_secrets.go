package server

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const mcpSecretPrefix = "ARTEX_MCP_SECRET_"

var mcpSecretReference = regexp.MustCompile(`\$\{(ARTEX_MCP_SECRET_[A-Z0-9_]+)\}`)

func resolveMCPEnv(raw json.RawMessage) (map[string]string, error) {
	return resolveMCPEnvWithLookup(jsonStrMap(raw), os.LookupEnv)
}

func resolveMCPEnvWithLookup(env map[string]string, lookup func(string) (string, bool)) (map[string]string, error) {
	resolved := make(map[string]string, len(env))
	for key, value := range env {
		if !strings.Contains(value, "${"+mcpSecretPrefix) {
			resolved[key] = value
			continue
		}

		matches := mcpSecretReference.FindAllStringSubmatch(value, -1)
		if len(matches) == 0 {
			return nil, fmt.Errorf("MCP 环境变量引用格式无效")
		}
		for _, match := range matches {
			name := match[1]
			secret, ok := lookup(name)
			if !ok || secret == "" {
				return nil, fmt.Errorf("MCP 环境变量未设置: %s", name)
			}
			value = strings.ReplaceAll(value, "${"+name+"}", secret)
		}
		if strings.Contains(value, "${"+mcpSecretPrefix) {
			return nil, fmt.Errorf("MCP 环境变量引用格式无效")
		}
		resolved[key] = value
	}
	return resolved, nil
}
