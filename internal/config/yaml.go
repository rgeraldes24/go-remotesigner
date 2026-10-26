// Copyright 2020 ConsenSys AG.
// Copyright 2026 The go-remotesigner Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
// the License. You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
// an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
// specific language governing permissions and limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by The go-remotesigner Authors, 2026: translated from Java to Go and adapted for QRL.
// Derived from Web3Signer
// commandline/src/main/java/tech/pegasys/web3signer/commandline/valueprovider/YamlConfigFileDefaultProvider.java
// at commit 30af06dc975ba5b8ed0e17e53cba8683ca50ec02.

package config

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

// ErrConfigFile reports an unreadable or invalid --config-file.
var ErrConfigFile = errors.New("config file")

// YAMLSource is a parsed --config-file: a mapping of bare flag names (no
// dashes; a flag's name or a long alias, never a one-letter alias) to
// values, with optional subcommand sections such as `consensus:` holding
// that subcommand's flags. A subcommand's flags may also be given at the top
// level. A list value sets a list flag. Keys that
// name no flag are rejected.
type YAMLSource struct {
	path     string
	top      map[string]*yaml.Node
	sections map[string]map[string]*yaml.Node
	// given holds the names of the flags the file gives a value, and
	// applied those of them that Apply set.
	given, applied map[string]bool
}

// LoadYAML reads and parses the config file at path.
func LoadYAML(path string) (*YAMLSource, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrConfigFile, err)
	}
	return ParseYAML(path, data)
}

// ParseYAML parses config-file content; path is used in messages.
func ParseYAML(path string, data []byte) (*YAMLSource, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%w %s: invalid YAML: %v", ErrConfigFile, path, err)
	}
	if len(doc.Content) == 0 {
		return nil, fmt.Errorf("%w %s: empty", ErrConfigFile, path)
	}
	top, err := mapping(path, "", doc.Content[0])
	if err != nil {
		return nil, err
	}
	s := &YAMLSource{path: path, top: map[string]*yaml.Node{}, sections: map[string]map[string]*yaml.Node{},
		given: map[string]bool{}, applied: map[string]bool{}}
	for k, v := range top {
		if v.Kind == yaml.MappingNode {
			sec, err := mapping(path, k+".", v)
			if err != nil {
				return nil, err
			}
			s.sections[k] = sec
			continue
		}
		s.top[k] = v
	}
	return s, nil
}

func mapping(path, prefix string, n *yaml.Node) (map[string]*yaml.Node, error) {
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w %s: %s must be a mapping of flag names to values", ErrConfigFile, path, nonEmpty(prefix, "the document"))
	}
	out := make(map[string]*yaml.Node, len(n.Content)/2)
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		if k.Kind != yaml.ScalarNode {
			return nil, fmt.Errorf("%w %s: keys must be flag names", ErrConfigFile, path)
		}
		if _, dup := out[k.Value]; dup {
			return nil, fmt.Errorf("%w %s: duplicate key %s%s", ErrConfigFile, path, prefix, k.Value)
		}
		out[k.Value] = n.Content[i+1]
	}
	return out, nil
}

func nonEmpty(s, alt string) string {
	if s == "" {
		return alt
	}
	return strings.TrimSuffix(s, ".")
}

// Validate rejects every key that names no flag: top-level keys must name a
// global flag or a flag of one of commands, sections must be command names,
// and section keys must name that command's flags.
func (s *YAMLSource) Validate(global []cli.Flag, commands map[string][]cli.Flag) error {
	var unknown []string
	known := names(global)
	for _, flags := range commands {
		known = append(known, names(flags)...)
	}
	for k := range s.top {
		if !slices.Contains(known, k) {
			unknown = append(unknown, k)
		}
	}
	for sec, keys := range s.sections {
		flags, ok := commands[sec]
		if !ok {
			unknown = append(unknown, sec)
			continue
		}
		for k := range keys {
			if !slices.Contains(names(flags), k) {
				unknown = append(unknown, sec+"."+k)
			}
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return fmt.Errorf("%w %s: unknown option(s): %s", ErrConfigFile, s.path, strings.Join(unknown, ", "))
	}
	return nil
}

// Apply sets on c each of flags that the file gives and that neither the
// command line nor the environment set. With section "" it reads the top
// level; with a command name it reads that section and the top level, and a
// flag given in both is an error.
func (s *YAMLSource) Apply(c *cli.Context, flags []cli.Flag, section string) error {
	for _, f := range flags {
		v, key, err := s.lookup(f, section)
		if err != nil {
			return err
		}
		if v == nil {
			continue
		}
		s.given[f.Names()[0]] = true
		if c.IsSet(f.Names()[0]) {
			continue
		}
		values, err := scalars(v, isList(f))
		if err != nil {
			return fmt.Errorf("%w %s: %s: %v", ErrConfigFile, s.path, key, err)
		}
		for _, val := range values {
			if err := c.Set(f.Names()[0], val); err != nil {
				return fmt.Errorf("%w %s: %s: %v", ErrConfigFile, s.path, key, err)
			}
		}
		s.applied[f.Names()[0]] = true
	}
	return nil
}

// Path is the config file's path.
func (s *YAMLSource) Path() string { return s.path }

// Applied reports whether Apply set the flag named name (its first name)
// from the file: neither the command line nor the environment had set it.
func (s *YAMLSource) Applied(name string) bool { return s.applied[name] }

// Gives reports whether the file gives a value to the flag named name (its
// first name), whether or not Apply set it: the command line or the
// environment may have set it first.
func (s *YAMLSource) Gives(name string) bool { return s.given[name] }

// lookup finds the value of f by any of its names.
func (s *YAMLSource) lookup(f cli.Flag, section string) (*yaml.Node, string, error) {
	var found *yaml.Node
	var where string
	for _, n := range LongNames(f.Names()) {
		if v, ok := s.top[n]; ok {
			if found != nil {
				return nil, "", fmt.Errorf("%w %s: %s and %s set the same option", ErrConfigFile, s.path, where, n)
			}
			found, where = v, n
		}
		if section == "" {
			continue
		}
		if v, ok := s.sections[section][n]; ok {
			if found != nil {
				return nil, "", fmt.Errorf("%w %s: %s and %s.%s set the same option", ErrConfigFile, s.path, where, section, n)
			}
			found, where = v, section+"."+n
		}
	}
	return found, where, nil
}

// scalars returns a value's text: one scalar, or each item of a list when
// the flag takes a list.
func scalars(v *yaml.Node, list bool) ([]string, error) {
	switch {
	case v.Kind == yaml.ScalarNode && v.ShortTag() != "!!null":
		return []string{v.Value}, nil
	case v.Kind == yaml.SequenceNode && list:
		out := make([]string, 0, len(v.Content))
		for _, item := range v.Content {
			if item.Kind != yaml.ScalarNode {
				return nil, errors.New("list items must be scalars")
			}
			out = append(out, item.Value)
		}
		return out, nil
	case v.Kind == yaml.SequenceNode:
		return nil, errors.New("takes a single value, not a list")
	default:
		return nil, errors.New("needs a value")
	}
}

func isList(f cli.Flag) bool {
	_, ok := f.(*cli.StringSliceFlag)
	return ok
}

// names returns the config-file keys of flags: their long names.
func names(flags []cli.Flag) []string {
	var out []string
	for _, f := range flags {
		out = append(out, LongNames(f.Names())...)
	}
	return out
}
