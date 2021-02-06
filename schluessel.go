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

const sep = "-"

type (
	Schluessel struct {
		hash [32]byte
		r    *big.Int
		s    *big.Int
	}

	Private struct {
		prefix string
		key    *ecdsa.PrivateKey
	}

	Public struct {
		key *ecdsa.PublicKey
	}
)

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

func Generate(from, to uint, private *Private) []Schluessel {
	if to < from {
		return nil
	}
	res := make([]Schluessel, to-from+1)
	for i := uint(0); i <= to-from; i++ {
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

func Verify(schluessel Schluessel, public *Public) bool {
	return ecdsa.Verify(public.key, schluessel.hash[:], schluessel.r, schluessel.s)
}

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
