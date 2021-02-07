// Package schluessel implements a simple license mechanism using ECDSA keys.
// An arbitrary number of license keys can be generated using the Generate function.
// License keys can be verified using the Verify function.
// All keys can be stringified and parsed back from strings e.g. to allow being saved to files.
// The normal use case is: You generate keys in a separate application and only verify keys in your client application
// e.g. by hard coding the public key in your client application.
// The private key has always to be kept private.
package schluessel

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// sep is the default separator between values when keys are serialized to strings
const sep = "-"

type (
	// Schluessel instances are license keys (Schluessel means key in German)
	// Values of this type can be stringified (using fmt.Sprintf("%v", schluesselInstance) and can be verified using
	// the Verify function
	Schluessel struct {
		hash [32]byte
		r    *big.Int
		s    *big.Int
	}

	// Private is the private key. Should only be used in license key generating applications and not in your client
	// application. Private implments the Stringer interface for storing the key somewhere. It can be read back with the
	// ParsePrivate function
	Private struct {
		prefix string
		key    *ecdsa.PrivateKey
	}

	// Public is the public key. Instances of this key could be hard-coded in your client application.
	// Public implments the Stringer interface for storing the key somewhere. It can be read back with the
	// ParsePublic function
	Public struct {
		key *ecdsa.PublicKey
	}
)

// Public returns the public key for the private key.
func (private *Private) Public() *Public {
	if private == nil {
		return nil
	}
	return &Public{
		key: &ecdsa.PublicKey{
			X:     private.key.X,
			Y:     private.key.Y,
			Curve: private.key.Curve,
		},
	}
}

// Generate generates to - from + 1 Schluessel for the given Private key given by private.
// For each index between from and to a Schluessel is generated. Note that for equal private keys and equal indices
// equal Schluessel are generated
func Generate(from, to uint, private *Private) []Schluessel {
	if to < from {
		return nil
	}
	res := make([]Schluessel, to-from+1)
	for i := from; i <= to; i++ {
		msg := fmt.Sprintf("%v%v", private.prefix, i)
		hash := sha256.Sum256([]byte(msg))
		r, s, err := ecdsa.Sign(rand.Reader, private.key, hash[:])
		if err != nil {
			panic(err)
		}
		res[i] = Schluessel{
			hash: hash,
			r:    r,
			s:    s,
		}
	}
	return res
}

// Creates a private key using a prefix. Since simple numbers are usi
func Create(prefix string) *Private {
	if strings.Contains(prefix, sep) {
		panic(errors.New(fmt.Sprintf("prefix must not contain %v", sep)))
	}
	if len(prefix) == 0 {
		panic(errors.New("prefix must not have len 0"))
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Private{
		prefix: prefix,
		key:    private,
	}
}

// Verifies the given Schluessel with the public key
func Verify(schluessel Schluessel, public *Public) bool {
	return ecdsa.Verify(public.key, schluessel.hash[:], schluessel.r, schluessel.s)
}

// Parses the given string inp to a Schluessel or returning an error if something went wrong
func FromString(inp string) (*Schluessel, error) {
	split := strings.Split(inp, sep)
	if len(split) != 3 {
		return nil, errors.New("does not contain 3 parts")
	}
	if len(split[0]) != 64 {
		return nil, errors.New("first part does not contain 32 bytes")
	}
	hash, err := hex.DecodeString(split[0])
	if err != nil {
		return nil, err
	}
	if len(hash) != 32 {
		return nil, errors.New("wrong hash length")
	}
	var result Schluessel
	copy(result.hash[:], hash)
	result.r = new(big.Int)
	r, err := hex.DecodeString(split[1])
	if err != nil {
		return nil, err
	}
	result.r.SetBytes(r)
	result.s = new(big.Int)
	s, err := hex.DecodeString(split[2])
	if err != nil {
		return nil, err
	}
	result.s.SetBytes(s)
	return &result, nil
}

// Parses the given string inp to a private key or returning an error if something went wrong
func ParsePrivate(inp string) (*Private, error) {
	split := strings.Split(inp, sep)
	if len(split) != 10 {
		return nil, errors.New("does not contain 11 parts")
	}
	var result Private
	result.prefix = split[0]
	private, err := hex.DecodeString(split[1])
	if err != nil {
		return nil, err
	}
	result.key = &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: nil,
			X:     nil,
			Y:     nil,
		},
		D: new(big.Int),
	}
	result.key.D.SetBytes(private)
	x, err := hex.DecodeString(split[2])
	if err != nil {
		return nil, err
	}
	result.key.X = new(big.Int)
	result.key.X.SetBytes(x)
	y, err := hex.DecodeString(split[3])
	if err != nil {
		return nil, err
	}
	result.key.Y = new(big.Int)
	result.key.Y.SetBytes(y)
	curveParams, err := parseCurveParams(split[4:])
	if err != nil {
		return nil, err
	}
	result.key.Curve = curveParams
	return &result, nil
}

// Parses the given string inp to a private key or returning an error if something went wrong
func ParsePublic(inp string) (*Public, error) {
	split := strings.Split(inp, sep)
	if len(split) != 8 {
		return nil, errors.New("does not contain 9 parts")
	}
	var result Public
	x, err := hex.DecodeString(split[0])
	if err != nil {
		return nil, err
	}
	result.key = &ecdsa.PublicKey{
		Curve: nil,
		X:     nil,
		Y:     nil,
	}
	result.key.X = new(big.Int)
	result.key.X.SetBytes(x)
	y, err := hex.DecodeString(split[1])
	if err != nil {
		return nil, err
	}
	result.key.Y = new(big.Int)
	result.key.Y.SetBytes(y)
	curveParams, err := parseCurveParams(split[2:])
	if err != nil {
		return nil, err
	}
	result.key.Curve = curveParams
	return &result, nil
}

func (schluessel Schluessel) String() string {
	hash := hex.EncodeToString(schluessel.hash[:])
	return fmt.Sprintf("%v%v%x%v%x", hash, sep, schluessel.r.Bytes(), sep, schluessel.s.Bytes())
}

func (public Public) String() string {
	return fmt.Sprintf("%x%v%x%v%v", public.key.X.Bytes(), sep, public.key.Y.Bytes(), sep, toString(public.key.Params()))
}

func (private Private) String() string {
	return fmt.Sprintf("%v%v%x%v%x%v%x%v%v", private.prefix, sep, private.key.D.Bytes(), sep, private.key.X.Bytes(), sep, private.key.Y.Bytes(), sep, toString(private.key.Params()))
}

func toString(c *elliptic.CurveParams) string {
	return fmt.Sprintf("%x%v%x%v%x%v%x%v%x%v%x", c.N.Bytes(), sep, c.B.Bytes(), sep, c.Gx.Bytes(), sep, c.Gy.Bytes(), sep, c.P.Bytes(), sep, c.BitSize)
}

func parseCurveParams(split []string) (*elliptic.CurveParams, error) {
	if len(split) != 6 {
		return nil, errors.New("curve params does not contain 7 parts")
	}
	var result = elliptic.CurveParams{
		P:  new(big.Int),
		N:  new(big.Int),
		B:  new(big.Int),
		Gx: new(big.Int),
		Gy: new(big.Int),
	}
	result.Name = "P-256"
	n, err := hex.DecodeString(split[0])
	if err != nil {
		return nil, err
	}
	result.N.SetBytes(n)
	b, err := hex.DecodeString(split[1])
	if err != nil {
		return nil, err
	}
	result.B.SetBytes(b)
	gx, err := hex.DecodeString(split[2])
	if err != nil {
		return nil, err
	}
	result.Gx.SetBytes(gx)
	gy, err := hex.DecodeString(split[3])
	if err != nil {
		return nil, err
	}
	result.Gy.SetBytes(gy)
	p, err := hex.DecodeString(split[4])
	if err != nil {
		return nil, err
	}
	result.P.SetBytes(p)
	v, err := strconv.ParseInt(split[5], 16, 64)
	if err != nil {
		return nil, err
	}
	result.BitSize = int(v)
	return &result, nil
}
