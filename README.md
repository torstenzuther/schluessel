## 🔑 schluessel
Schluessel is an ultra simple license key library written in Go.
Schluessel means key in German.
Its main use case is to give desktop applications written in Go some protection by
implementing a license key mechanism.

An arbitrary number of Schluessel can be generated and verified (true/false) in 
the client application. It uses the ECSDA signature algorithm under the hood.

## 🔧 Usage

Run `go get github.com/torstenzuther/schluessel`


### 1. Generate private and public key
   
Call
   `schluessel.Create("sample-prefix")` in a separate generator application.

The prefix will be part of the private key and should not be exposed. It can be any non empty string.

### 2. Create any number of Schluessel

To create e.g. the Schlussel from 1 to 100 call `schluessel.Generate(1, 100, p)` with p being the private key (result of step 1 above).

To distribute your Schluessel just output them like `fmt.Sprintf("%v", s)` with s being a Schlussel.

### 1. Embed public key

You can retrieve the public key by calling

`p.Public()` on p being the generated private key from above. 

You can then store the public key as a constant
in your app by calling `fmt.Sprintf("%v", p.Public())`

### 2. Verify Schluessel

To verify a Schluessel you should first read it from the string by calling `schluessel.FromString(...)` and then
call `schluessel.Verify(s, p)` with s being the Schluessel and p the public key stored in the client application.

## 🔐 Security considerations

As every client application can be changed and therefore be cracked
so can apps using this library. The public key could be changed in the binary by an attacker or the check could
be disabled as well. Its purpose is to give some security to your honest users, nothing less but also
not more.


## ⭐ Contributing 

Feel free to open an issue if you have any additions, questions or requests.

## 🎨 License

MIT License

Copyright (c) 2021 Torsten Zuther

