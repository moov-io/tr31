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

//go:build !wasm

package tr31

import "crypto/rand"

// Rand fills b with random bytes: the padding of a wrapped key, or a
// generated KBPK. It reads crypto/rand unless a program replaces it, before
// wrapping anything, with another cryptographically secure source, such as an
// HSM's own generator. It is a function rather than an io.Reader so that
// TinyGo programs built without a goroutine scheduler can link this package:
// there, an io.Reader-typed source makes os.File's deadline timer reachable.
var Rand = func(b []byte) error {
	_, err := rand.Read(b)
	return err
}
