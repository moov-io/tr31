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

//go:build wasm

package tr31

import "errors"

// Rand fills b with random bytes: the padding of a wrapped key, or a
// generated KBPK. A WASM build has no default: crypto/rand there may need a
// goroutine scheduler that a plugin built without one lacks. The program sets
// Rand to its host's cryptographically secure source before wrapping anything;
// until then every wrap fails.
var Rand = func([]byte) error {
	return errors.New("tr31: no random source; set tr31.Rand before wrapping")
}
