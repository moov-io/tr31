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

package tr31

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRand is not parallel: it replaces the package's random source.
func TestRand(t *testing.T) {
	kbpk, _ := hex.DecodeString("89E88CF7931444F334BD7547FC3F380C")
	key, _ := hex.DecodeString("F039121BEC83D26B169BDCD5B22AAF8F")
	wrap := func() (string, error) {
		header, err := NewHeader(TR31_VERSION_B, "P0", "T", "E", "00", "N")
		if err != nil {
			return "", err
		}
		kb, err := NewKeyBlock(kbpk, header)
		if err != nil {
			return "", err
		}
		return kb.Wrap(key, nil)
	}
	original := Rand
	t.Cleanup(func() { Rand = original })

	t.Run("wrapping pads from Rand", func(t *testing.T) {
		read := 0
		Rand = func(b []byte) error {
			read += len(b)
			_, err := rand.Read(b)
			return err
		}

		block, err := wrap()
		assert.NoError(t, err)
		assert.NotEmpty(t, block)
		assert.Positive(t, read)
	})

	t.Run("a source that fails stops the wrap", func(t *testing.T) {
		Rand = func([]byte) error { return errors.New("no entropy") }

		_, err := wrap()
		assert.Error(t, err)
	})
}
