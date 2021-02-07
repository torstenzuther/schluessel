package main

import (
	"fmt"
	"log"

	"schluessel"
)

const prefix = "schluessel_example"

func main() {
	private, err := schluessel.Create(prefix)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Private key:\n%v\n\n", private)
	fmt.Printf("Public key:\n%v\n\n", private.Public())

	schluessels, err := schluessel.Generate(0, 99, private)
	if err != nil {
		log.Fatal(err)
	}
	for i, s := range schluessels {
		fmt.Printf("%3d: %v\n", i, s)
	}
}
