// HashMapper is a highly concurrent, multi-layered hash identification and
// brute-force tool written in Go with support for 70+ algorithms, salt
// formatting, and deep nested template decryption.
package main

import "github.com/02gur/HashMapper/cmd"

func main() {
	cmd.Execute()
}
