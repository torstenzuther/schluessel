package schluessel

import (
	"fmt"
	"testing"
)

func TestCreateAndFromString(t *testing.T) {
	type testCase struct {
		prefix string
	}

	for i, test := range []testCase{
		{
			prefix: "123",
		},
		{
			prefix: "abcdefghijklmnopqrstuvwxyz",
		},
	} {
		actual := Create(test.prefix)
		actualString := fmt.Sprintf("%v", actual)
		readBack, err := ParsePrivate(actualString)
		if err != nil {
			t.Error(err)
		}
		if e := fmt.Sprintf("%v", readBack); actualString != e {
			t.Errorf("TestCreate %v: want %v got %v", i, e, actualString)
		}
	}
}

func TestCreateGenerateAndVerify(t *testing.T) {
	type testCase struct {
		prefix string
		from   uint
		to     uint
	}

	for _, test := range []testCase{
		{
			prefix: "123",
			from:   0,
			to:     5,
		},
		{
			prefix: "abcdefghijklmnopqrstuvwxyz",
			from:   0,
			to:     5,
		},
	} {
		actual := Create(test.prefix)
		generated := Generate(test.from, test.to, actual)
		for _, g := range generated {
			gString := g.String()
			t.Logf("%v\n", gString)
			parsedGenerated, err := FromString(gString)
			if err != nil {
				t.Error(err)
				return
			}
			if parsedGenerated.hash != g.hash {
				t.Errorf("Want hashes to be equal")
			}
			if parsedGenerated.r.Cmp(g.r) != 0 {
				t.Errorf("Want r's to be equal but got %v and %v", parsedGenerated.r, g.r)
			}
			if parsedGenerated.s.Cmp(g.s) != 0 {
				t.Errorf("Want s's to be equal but got %v and %v", parsedGenerated.s, g.s)
			}
			if p := actual.Public(); !Verify(g, p) {
				t.Errorf("Want %v verified with %v", g, p)
			}
			publicString := actual.Public().String()
			parsedBack, err := ParsePublic(publicString)
			if err != nil {
				t.Error(err)
				return
			}
			if parsedBack.key.X.Cmp(actual.Public().key.X) != 0 {
				t.Errorf("Want x's to be equal but got %v and %v", parsedBack.key.X, actual.Public().key.X)
			}
			if parsedBack.key.Y.Cmp(actual.Public().key.Y) != 0 {
				t.Errorf("Want x's to be equal but got %v and %v", parsedBack.key.Y, actual.Public().key.Y)
			}
		}
	}
}
