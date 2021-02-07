# 🔑 schluessel
Schluessel is an ultra simple license key library written in Go.
Schluessel means key in German.
Its main use case is to give desktop applications written in Go protection by
implementing a license key mechanism.

An arbitrary number of Schluessel can be generated and verified (true/false) in 
the client application. It uses the ECSDA signature algorithm under the hood.

# 🔧 Usage

In a separate generator application
1. Create private and public key
2. Create any number of Schluessel

In your client application which is to be protected
1. Embed public key
2. Verify Schluessel

# 🔐 Security considerations

As every client application can be changed and therefore be cracked
so can this. The public key can be changed in the binary by an attacker or the check could
be disabled as well. It's purpose is to give some security to your honest users, nothing less but also
not more.


# ⭐ Contributing 

Feel free to open an issue if you have any additions, questions or requests.

# 🎨 License

MIT License


