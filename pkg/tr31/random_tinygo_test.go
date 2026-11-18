// Licensed to The Moov Authors under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. The Moov Authors licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

//go:build tinygo.wasm

package tr31

import (
	"crypto/rand"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tinygoWasmDefaultRand is the fail-closed stub compiled into this build.
// TestMain replaces Rand so the rest of the package tests can wrap.
var tinygoWasmDefaultRand func([]byte) error

func init() {
	tinygoWasmDefaultRand = Rand
}

func TestMain(m *testing.M) {
	Rand = func(b []byte) error {
		_, err := rand.Read(b)
		return err
	}
	os.Exit(m.Run())
}

// TestTinyGoWasmDefaultRand is not parallel: it replaces the package's random source.
func TestTinyGoWasmDefaultRand(t *testing.T) {
	original := Rand
	Rand = tinygoWasmDefaultRand
	t.Cleanup(func() { Rand = original })

	err := Rand(make([]byte, 16))
	require.EqualError(t, err, "tr31: no random source; set tr31.Rand before wrapping")

	_, err = wrapSampleKey()
	require.Error(t, err)
	assert.ErrorContains(t, err, "no random source")

	_, err = GenerateKBPK(KBPKOptions{Version: "D", KeyLength: 16})
	require.Error(t, err)
	assert.ErrorContains(t, err, "no random source")
}
