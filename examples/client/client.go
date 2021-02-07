package main

import (
	"fmt"
	"log"

	"schluessel"
)

// public key is stored in the client app
const publicKey = "9e7752bd9216eaa639a1e27061c575df60c772264ee3111cbcebe2098bbd3924-c60074acfb6ca07b58baf0b5388adcaa6a18404653cbf75501e83f91e86b3122-ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551-5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b-6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296-4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5-ffffffff00000001000000000000000000000000ffffffffffffffffffffffff-100"

func main() {
	// parse public key
	public, err := schluessel.ParsePublic(publicKey)
	if err != nil {
		log.Fatal(err)
	}

	// verify 100 valid Schluessel
	for i, s := range []string{
		"e0c0b743a8868f795ab285296df66c0c9372688ea7df3e03236c4a73d7714007-45d0db24abae86ac2b1aa2b349090ee4dbb5c9a32271ef5a9f07dae5d75e76f6-80fe1771e9f904980040600fdd78c7fe8ecafe509b47396a649919687b36e818",
		"9990487c51b2fb7cb383498b98bb0ec7309fda4d56e9efe0091298715e04bd6f-5704ccb97d2b252714e5883f1c1a10cf47ad31f5f10093bdac1fbf696222cdce-f246ab8d51912dd680efbec2667faebe76fff148e943a9857415ca8593b121b5",
		"11a8ccb3b6d28567268ce517df175301b53ec3ee14f98737e4abd494d9a9506e-a1537c263217addd9a6759213f1003d9dd981f7fcaf445af7f1c7905dabae2b2-80ea4a1880946183eda0818f2ec7158c66572de7dce61b25f0e47a0898269782",
		"46571f07e208e7435eecf241e4aae094b6361a68d722efe98c6f84434c1e2e76-8ce55f4915ecc46866c0c3e55bf07c9fade835c316fe61bd9883a029279d602d-3e60e07806e7290582efa2ee70d30d45cb682467fa7650109001a177875cee6c",
		"006bdb03b93419ac9a05f506e32ea34788ce43d38c9bb32d33badb7eb8a3c08a-e8f8b9dc54c79dcda7188396065472ad4a6718866cca1c440d1d2c9c74bdd30a-43c0294c5a9d69c78a26b7a344e43932677c162b77fee50da0efe32cd21a1ecf",
		"f37b7d57ca32b3f96f417c3b1c4261149966c19b0bbf06956a1ad0593c461acf-1abba48111d38b098568d822912b06d78c9f285117c8686af06c4df7839e5fe6-24077adeb0e97c09d51e497d21cca798c79cc1eb5422a3ed188c169590dcfedb",
		"fafd8151136e3fc394238ceadfaf426efd11d6acbe34821bf10b14427547370b-068b9bef31749ad37a00dca40a2942751dbfb0b5ae3d92b4260a82a8c5c90352-53add0b2699e3f33d6fc69bc4fcff0a1578a4174cf65b05aaf1c6cccf75bf5c6",
		"bdd44b5563331305ff86648e00b294644931d73c35edfd0b36a4fd6ad3983cc4-dac6fd766e9a85bed7a8f89cfe2f1ad6aa3ccb24c33ad20c7912c9efca417fa0-06b35b91696a949ec144eefe2cbfc41bb3a3e15672fa27ca6a571ff53ea34714",
		"17b2937946fde60eda88f679cd119b749473a114bafcf9f0b3b71e94345a2633-d114dde5ee4fbae23b936d9648dbb89b622d820d4fffb318c68bc301d0b4da26-1bcb3bc335686a9ee6245c4e53eb465e63ffd966511fe2b600759cdcfba52f27",
		"429602014755bb52f75e6e8f90fe794c8d9475c8e90145e7e71d1b6ac70c1078-20dffbfbc2b67811d3907adfd7ca96fdecfbf1cae9e6a445f3f953479aafcaf0-64cde0c2ebbe4cad9eb62e6030232e42bb0d14d178ab1edca0965e1051726fc0",
		"0dfbfe9e1b3cd4f9823dfc14a64a8be5def1a4e250909b4cdecb525c80cb7e6c-6098240367d09822860f3a087a30480db684f4ee4f4188a534042e7bb50386d9-1aabba45eadbc8b12f7cad1013d9bba3717629a4595d81e8fbbf9882684b8bba",
		"92b564246dc9632d30fae95db276bc08ba5fd23d7e898d05ed07f8ad2408c60d-4a8e6ab72ace928b9fc433855e34f377668ebe938b8cd36413beca05eaeef773-4efe44110e59c2a0226a695473a86694355c5dad38be88523a5c689bdea33361",
		"1c3d97aff6b72ddb4e7cacb0530b3a440b4d75e1069387f59c7cb875b0c0f943-e78b3441cdf0e595d78e144614c1d7ca9556487eb56e29840b00c31e7fcccdc1-cd83c0aaed7f0476dd7b1b8df153138e84f5af7df0ccd1c29c3ba1947068a70d",
		"d26ecf29deb0f86badd27c3d314482b7b6e5b10222dd47ef928adb9568e2edb4-6049bd7e5901a36ec0533afc97ac02768d45fa122abaa9e08266b37c9f5c050d-f90e134b0e9774e13f0f012b234fc9e16ad8b6d61f44096a8b26f4efe6017a95",
		"80d15d003f32864096533858153b4c17a123a57a44daa70e63a3a4780106f6a3-dc0323dffd805ea62c067b3ce39109b99477319a21099e81641082d32a469547-d67ad6769c52059f8e932923b782355776de12a9eea1b039b6aba7f0c3ee52b2",
		"2a8a581fe373121ea628735ab96e1cf11a95b209b3a191fbe9da4ad5ef4aece3-932846bf25fc023d1f0482283e46078f8ebf03974068b5720294cfb7d2ff8a13-d458d136ce818b1cbfdddd39d23e3a5658b98269f114af683b9361b6cdcdc0b2",
		"47ded20180f24e88f28ae20a84edf029b24c17c3c2bc14c584cad0826f9cb76f-7454634dfed31c53d25d313a17f2b4bf6d9a3f28879ba453583d1af49bcda6b2-a8f05af22cbac16e61d9c60d3ccd0ea8ca48f9032183ad44afb478f9eb9ecd37",
		"085a682138c248d9ccc4c235db14ea5ecb7a99ce2422de337e42b5b2e3a41dcc-7e1e10ecf5db6b328ed0ab522a8e910ee1b9430a122c1bad26254909ae30893e-300ffb4a0629c53fad750e2bf8a9fa2fd056a1918ee5d4e8d0f8a55bc0a084e0",
		"22e5b13c0147354b502b64655651be70a5eae883eea41abb422dbb4ee7657135-32fdbb5a41b07dd7cb95d1f51b1476cee2d8515f5b96b6cb4bc915dfd24c9484-0612170419b4dae87a90abb8cbbd3308c07497d68ecdac411778b40b17e3860a",
		"391e8b62a697e1cc811146ed9886e8bc8245c7a9e4a91f5c0fe239b6fcf3d54d-195c5f0e5364a5506651db0b09bd2def92677f39ccafae135cf725c01e756a98-291cd1d937b551e24ec70282b4e32e87b25ec4280428745af40db109bae2a520",
		"ca81ef1da74777fc8bc79c6f3292ff802d4d8f99d3ba13ed1960ba8c3abdc39b-a543c20c35aa91faee7713914454690f5091a0437da5a097728cd43dc45aaaba-8303de26e8087fa8ff29c6f7f4431ecd68b22deee24176c6428702d3017a4a91",
		"d9c7d6d6ef3c7e9dc96ca8070bb26cd3b8fa3e79d2ef59076782f2b34d20d02a-879741ce6f8e52fde73c7229e9f1a5dabfdb746c425f82d1ee5f1efad7ec6f2a-a883972ad3ad3d4ad69f17508589fb297ab714bc8652f21e1088d84ae07c5e85",
		"ea51882266dad25e0e4e7e1198851fbac07f9adbfefe4cec1a5de4c1219e3bfc-1b2ab4d8f3e3b6e4d0b9fee05d69ad4ee5fab4bfcfa41e34151b149f1539fe61-445c61f08d44282d25e80b70ad34d07d3270b7d7fa19b1cf7d8933d3d2f7f359",
		"cc12ce4e82f1210e3032522356b775d8758aa2a2db2bd3e7a51959a9c08a7f3b-aa63e5977d097a70d2ffad694603fc8ff70b7317d1232488bcc2f566f904ed91-3c939670a34965a021c816ce3b7d70ec3773338b1b94e9ae960420b63396d258",
		"6afddb0907058f1a831694420fecb8d1acdc16ec0898ec98678869c6cb5f64c2-b6a2b9496335160d0e52ea28fc618c3b6bc3d895ef8d5c247781d0b8cb3deff2-7e431bd9581bddf4d5e00656d7077866b5791426f855f91720598d35ca9c523f",
		"999aacb73a8cbcad631fa27c5279c768dd554b67825eb59a3d9e3cbfa34ecc96-8a1315f7da8df060f07fffd9a50c2d28fe35a7e6664176ba08bfac59654b7dab-7aaf1ad288b27feda45f5ddc1b1f3641642216f48ade0f9f92123394a5be9728",
		"8826ff57c61f111e51cc1cc8d0aba759f993be6e93fc06ccc562890ce24e5248-01d47c85a22f8e6a6a06e1c8593f0f1e1e2dabceb31b9cd4dbe8ca25c6db23bc-f3fc77ca28e95ea21b182da1b330b425242394862c0a8e8b6e773f88c088aeba",
		"72b6c99c56a9dbbc96e16446d41a3303ae84d565aaa77ccbac31347c6637c2c3-6caf56f3cb29a298b184e1935da6ffc4332b6f8e5137ca2abdc5c98baaf8d5-317cc74e6fe6f47a53f93c1a3500498729adc86999a8d7c60cddf968c9864802",
		"3a52fcb378e7510dae4b87c1674aef0b89f645d988eeca4bd7e5e8eb3cf80cd7-4d57c6168f43291891e605dea8b284923879b55c094e16310aee4182b648ac9e-7f73e3f5a2358b6894952cbe934399caf99b70967a39631de7f64888cc68e44e",
		"1ccba1319df3477e64adaf6fa4a9d1eda35b83a05ac3571394a66ce74a31673c-15afcea805380303e4901d2f6366a046b8f43a97e3fcfad046dd935e3061278b-755080354baa9f980a72c38955f2913f05ea77b830c53cf06277fcd8265346ba",
		"06e1c1b5004bfebfb4658c48c1bf80358a046e9ee694b15de26626a0f5b7aa3c-8e486579874ddc2dfc956634371f82545a1655f87c2259bb8ef8e42939be7642-4e7657a7f59a47559d8e430e22b072ca308123adaf56819c97abd1a6e7385202",
		"cdb16fde784e2ab554c263f14d6e421d54a88efd8394c552c6c8c1aeebdb65da-49c0b43b184884a6e48b8c5e1c9ccffa13be80ac61c996168d25c1dd2ecc238a-8e71f425943ef1466d11c5cf24562f14538c5a3704c844480ef6225bb67ea608",
		"329306117e0fc0b7b97563ff7b18a0def4a960eceec0152bb2424ecf45424da9-727764dcf51733caa8b84b7ad32273e643f3a932fa1bd2e78fe04b2b4b7473c6-0bd0d0078eaaffe0296cc4dc2a4e653c74d7cbffbf538cd5836c88791c8e6087",
		"6a13da8482285a491a9d622f77871fef17fbf79cd0768aea12e0a3db453fd952-bd3720062237fca924bc82e1dcc208bed400628d314a0d7f5127ac59a1072274-641e35f4a9bca97097b3b5ad0205fbd91e706ae5e440ca0df137f2d94b7d4da9",
		"0e4c28d61816303805f5dd5c8980e6abd0ba2ab1597d8b98a021bbb5afdcc125-a34f1244c35dedf5ade7d853411cbd88960696a2ba3e93f59aa354c55ab832a3-8a06f73ae4fb1155f6481aeb316d91a4097ac6b1e5f190150cdf98bf25fed0a6",
		"5f5a0319b9a140d223d29315b38ab25f15f859285f81141c85b344d569dd900b-b1f7172e896845cb58bebf7ea55160499210e346b32554db8a3949a6598adc29-dfb37d72a5f19411a6a1012beec0683efc80527f2545ddafe86fd0884e978ff7",
		"1e675c4375d63498feb64d9c61b7a9535bacdccda421e292c3387f57dafd46d4-80ef04725d3cbe21cd0dc59210ded5d318897a040501dcd8b66d2077cf14151f-c6f96d82ada7e17ebf1cfd262930a61bd9b301db41ea49ea522305c26e932413",
		"8400b2351e0c288eed73606eaffef99c71f28d4e1bb8f1b482a7992b9baf8745-4de55e1b3de7e1f9152106c9cf0dbb58b082d4ca0928f299b064776ceab415ca-165a356eb40abb83e3ac10d9dec348a5e3c97129c2dc29f8937cf1a90965d4af",
		"51ebfddfc566ec20bf6d43d0d30809938bc171c8919adaff288acbfdd9c82f9e-623cd99deb09be25b1968884be5f4253229f97634e8d76154056b8a8cfce031d-66c9dc173573b527ed914af4d17fca151c66d17ec60464b4890ec8b82b9d8e26",
		"b3e0c32e4e620f0a4ab0a0b179255ab60559cd03c70826b7a3940e4667b28741-92e4b943afce4c5484c0db8f06e60cf5c2829d3997c9acf7a6b46a561a5d7cf6-c05f1bfb9dddf6a7cd8948e615e8ac01f9122e46880e56166d0b22c1f5b47016",
		"b7b0217e711c99789b2ebe2ed9e6b39b44bc2ab6cc4e714f4deb82507f850737-2aa054ddecd62574a1225172e0eb2388b987779d0b8a4aebc8a585f190c7c788-276396608b7bbf6d14e948521d825441f16602947f7c72ab3dec14ff337b3c5f",
		"5e90a5187c9d2490602c1fba43623d7a1a5bcb53efd2f08b6153af85fad037d3-139e44c40298a6d18a5e6328af753b3112041a56f4061648a725ee83c1659f77-41302d51484fa48c7c413a76fbef3cf354d6716784433575a9b44456dfc59d84",
		"bed438ec2ba241ca3554d46fcda0015ffaacf93876e6c6bab29eb5c6affb035f-719fb6bb2458b11586ca857c2e49a7b787c3a978246a7dcab5fd5cf5249c2d03-63cc80cdb6970d4acf7a21b509db7cde5c0a68d4916597fdca2ce9111530b334",
		"47d7332cf00db4abc3c1868ad77d3939e36857314577883e3e2b1b7d7e05be74-9d80796c49ffcb84f314fc7009c0bd68d0b432843ac02b76186e8626349694d5-89304327f6080a52a740c222108bd44e58a90b08a920110556dee18876c318a3",
		"72f55daadf5819a6ff78f0dd79bfc144a962ef6f36f9988d95ae48fa4b6bf8e1-0f02d1d39bfea3a5139f41938a4663e59e9da1b2930b7b0cb79cb4335e21439a-385147003c8c4563527fcf6ccc2b88577b7b332c4c6a0157b8dab3b504be1e03",
		"653424a3c3896d58a5b4e11e47d03bdececd0b508b772f19bcf74f0ae19eba5a-738bb5bef9bbf2a77f339262859ee3292dbf4c15eca9b81ac760b5e96b72a5d1-eb26cfe7340ddc84a8413bb4a05b05abf599a1f7d355674f45e8969e000494b7",
		"b911ca53d5b935a4ba648fa2f240875711bc21fc5623f5684cd309ff1f8755cf-f3d7f02dcfd6ff33808d979d7750eea4542e564d280ef2085284b642a3d6acbc-7ed430f86e0587c0beea0f66a425d105488e3598d48b256927519418ea8f7e98",
		"89a1489427162e9a6fec088b4881ab5e5658d607e0654863af79a6b14095d63c-3510624d3ff1d69667b42b314763c811eb061d300eac54726c38b6c82111b5ff-9155942bdb788d621dc7d276eab1271d5ca3f310fc0788f15aa3804e9d4c7639",
		"7f11135ff200b311c98b72460f5612bcfeb578686f80965b71e8090cf5a9a8d4-1b50046ea6b957e8bc5e53772e70108886c5854265c48d4dbeb6ec3d6be2c138-20b423417398747193b3201bc6ac98783520e0aac2c42be00ad7e2c01da09264",
		"715329d5887d93f51a30c4f7994be0a886f96e364fcffb0ef81ea4753960e78e-1f0709d7192d5323e565b923d1b625f5d6389784ecf0fcad636a59d56aee7aa1-6e69e20bc132f0a1502f2b3e85a447968ff81f7f31bbdac805a21d537d7f44bc",
		"62c314d20766ed91920682d5c2c53212dce9cc0572dba708fafd1cd420e2b7eb-232028285b11ef459cf4803918fa0b5ecc82c03fa4e0f2340a8ced719cfc5241-ea6796af17f45474887057601fddf92d4a459c28f0fb676227e5b3a482d30562",
		"bbaedeb332d6b80f9c5983fe4d707d609d46a2c6691ffd17b77a85ba7cfba37e-5f1b02b7392f572f461c1cc1e6dbb03cf02f276972f4a237cc50b904487d0417-d261f9b7bdb31af0764b69b719c1a1b4e9f2d369f5dda183e61c740ffacaf05c",
		"85f7273b669c52942644058342cf23b87f1bc26c8dabefbf98693e0e9ca66f32-b6070d07b8df88a646ae348d4c3a4ddade0e399b8f54c5f8d745228db6668f54-137dee2e1243c56bf9b118b1b1c76ef1d898439b0c60f7e123202fe265d663bb",
		"dfce6f08d989eebc7e23f50707d80e3ff74b3301fa42fbe969df0ff9cb39caea-a5b22729beee41a66488cb5b5d6e7a27d3c271113a2b3c5dc3c67460ee90a3ee-99c94e25ee1afa8ca2dafcb8ec5cf12b84bee23b364aee2e57a504fbc8f41d4b",
		"89f1aa3c3442b6d1e080e64962b3bb77778a07c6976bf4ac31720510f6b37204-bbc4b20ba93c1099b0b2d3e2c244ffdea064ea96971a6788034c235ab885dde5-c986e43aa054c8176ef322f74ff6ccb3c2c3433286046ae22d1765ef91b9fd1a",
		"6f08ab9fb3aa78398bc8d8c1377fd35b475f031c8188727ef12f56b0a9015556-3f97e0c3e1d809154d9b28c76db573d90cea581764182af550c92dade3cc81f6-fc8d0fbb4be5bf08c3d513b98e62ff982e60984c3628e3beaf2fc4ec14566151",
		"386db3f3b92de1e0a4079bcec4d1bbd840e6327099b83c21af2b0a43511f40c3-602808bda81400659fe17c6e60714213cc95e053e05c70d2e7e2ad31a610411b-caf3b0029afa039927d968936da8f0ddacd27e3afa833fdeae8164bcec8d0a56",
		"d7c76573515ba38b7dafd4a170d330fb7d6f9c179a426bc2f504344932ca1b32-569d080b522cf4b4ab239bde99f73da4a4341a7eff72bde673e1488f2325b8c8-757b4073753d505223a9a936264a177dce22fdd0c5efb69b3f73252d94b651dc",
		"88b73202874c7c7bd0e7423725e5b1fbcff3f22752036ab4e145e322ec5136e1-dc63f44647a4984446a761fad49c846f5b199e57e0e47011b351fc3d213df4d6-173b89a5cfa43a0f7a6d4c6a0b91237ee4cad45920eb9be205097e9c8d0928e0",
		"bc5818e21f0e27de13f81afb8be0b97afc58a96a5a93e8c7e8b41380aa92cb35-3d70e82767ca2f0e5460bd8bbf7e2a5d2e1958d8917e053ccfd3f602c9a458a0-7b6945dd1d617e605e8a23ad3f68ae5f6d0cfb3f380fe956ee843cc90411b3aa",
		"7f728abd538f6e6ae9b945df806010caca44c475e43772d81919fe5c2866d787-36ea3d4439a92eef102fcddcf5e680c0c66b67df7b33d4bc66ada608e30e937a-b30025fe39d2ed0fb864da26294469aedf64e2f84714af7980fba9923cb50c6e",
		"53975e42124f16e64a873e61b1107c44ed04cea93cf1794984c3a7744c253b74-7ff0f21af97d1ba15b6f9aafefb9e6e7317ac29e9d9f3e824197396e4fb020bd-fe6919a82f86d71a4b1d36e0ac5e374377b80f76eda0124a16fc6b2212c6104c",
		"c9fad1b18b13293a4e9321d1380effb0824a10f957ee6a90401dd86de7843d61-83dad029473350b0aba50276164489d0a5e4acab22e03d69fa908b39c166e2eb-4e4f68797da3629b7957686c57241df86a2334b27fe71f08c7e450fb5a5380a4",
		"70886b6dbe1f49b9647c20edf1fe9e77bb432583e9d519bdc498798f0cd0c844-5e1d536bcbd98dbc6fe86e8a3dd47c5a17027462451d6def7ba75df58b82d4-c2ef39e4b02e54f87e5722d53acc19ca3926ec0224726cd6534ec9533c6cc9cb",
		"f6aebcdbe60318225e165fcce1552cf626f23f1817274568bccfe3a0c02417a2-79d38075c7fd3db567fc45f7e87f210d714ca8160834ebe05c8134961de36e8c-687e546b58cf8af3d7845c9fc1dc3d29d620250ce667c05e3f68f33925e5a7f1",
		"d9ebf464b6d63b4ffb85a9c2777be9b553a89eac3df255086f1957730d9455c8-7c2cd395cca781365d8a0b3a43f611eacfc493831f6e952d3c20083ce1891097-177add35d7ee866dd37745c4fcdce9749ce0977cf7ee33c708a9036e445104ca",
		"2a75ad32d0c2dcff4af1ad78d7b64f44bb869539af5921953116a34ea938b488-a73b6dd940a5cc7592bea2a02b66984517a9117544ba9320ef5d4a47f7020303-759cd3a3c3f323d2036f466e3ef0bd8b7f66b6b905a5c67e1d1a0cc9dda6108e",
		"1de26e144669ec27d368415da8e2ee719980534fcb342faba1acf02a5949eec2-18b353c586b079488f5874aa0a816a268ea56aea8d9685fae3ed46907eac31dd-433ca848161495b20968b4071ebdf0f617b78bbf8d6ba2199c8ca3b3af9a8b23",
		"17755b152e4e722b34f5b9ae7711071f54873ec6e43972a7824401c4a33a33a9-2c8f79496e9d8bc8319bc99665fc3ab0eabc6705f2650e2f6be22a24e94d1335-fd10336565ff97ff878d2a60d2adf5f4bbb914c453a58e0a9b877e67eeb54fca",
		"141ae67187165907a7a7d68525e63ca944e59478f4cc1bc9f99de663caacdad5-4375f098581efcb33d042e3d1ba4d9fd97dc10a65090feb54e2e627850b365d7-14aa7a7b3deeca5237ebf08596b816057762be67b80a3b91441f5e63f20e88b9",
		"84d5a0b4594a5a444d497d95587266915d4f13a01bcfc666b1b519851900b216-4f92fdbd9230530cce95c790c8be79da129462ab0ba647ce2ea1d00487390f3b-8373e571568934b087e1969a0447a732f55f43a2b76182f3651e408a267d5c04",
		"5c60eb2c3de87624c87831ebea7b3460302aa9857e17c13524e93dc6aa4d14df-cbfad51b8bd3e8963c5b019e203cf179c424160033de04bc2bd0631fc023091b-9bd011ddba31cfa9fd5337baa7cc017d5179391f472b84aa9fb7e2d73695644a",
		"9d908ef6d269149b9b7e1b4db75f5f611e193d4219dc3944d4d82f3829145c59-5ef95040e75521b27139f771d2c6165de02de6b9758a462c6f5c4e59bd55a2e4-1b0b6cb9fdd32db181f3b5620376d31325476bd2824eaebfec0a302a552ccaa6",
		"7036a0f323db40261a7382e859b9d5d7276e6ac07d50a70722431f56de6bf2c2-3d425a1f339f6c815f4bfbba01ff16caf31155aaa2b95bb57f9365564924b67a-38e284503919116ee37c12eefa4e86fbe4cf6f38b17eedb5543e058f168adfa8",
		"111ad242d2f839b3ce4e948d17cef396f330758eca299f4b2a35d7dfa7b08099-7af4f2827b9abcd4b3617f05ad4952465936810bc1fd2131a2f18472907142aa-0cbf8db5b7fba5131903f3426f42a10968fef31a0d60f70b85f1e82871aa926c",
		"563c08bd47b5b8210396291565a86a1387703f948563e3003c8350c91f811ba9-242ef587a4306b7c1bb7bc339f0cb1ab4159ed7cf64e88811d63d8c5ea257c56-603bc597daba4cadff326b6eaf4e2a2ff414678a803cdd7a5159a90f178970da",
		"f8dbd0f3bb276e613efdfe706835e8f42618cd42d860bbafa96a0e7f770d96aa-6d677dd55589023dd13ec1eebbd2478bb5464aeb8caa52978142dada15fed499-5d4997972cef8ad6faaab324e9d5b079d8ae113776d06ae8ad37085639172302",
		"bac02f284da40bb9ca27921b1c6b89b0d4e0a808f0cbeac730e4d9803a521d27-1fbceb345e6f7a57fa57761c44f3b2d3988af5704a722283c761a33257e361cc-ef66485f04942492a12204fb257b240d467e8a4353facfec4c59ec8dfe99dec7",
		"c4007b4b95403640556a67031cebe08e048715c73c38609fb9a3fa2e17e48d69-2e6a9043ae5ccfc1543d9bc42a4a925a1e25c4bba36b24f7b956927e3bfb89be-0e6c4d95c9af8339030b5ede56d1ee2bb49bfb5352027ef8b480df4706dddb40",
		"3fcf0932815e5c04d6027b18c3afa6eba61667487ec414150f054b908904c4fa-1f0cb19978c1c01d3b59b64beccbd30fc86d171b3bab34c5ee2b78bdf6385320-adbb17495b67c3bed328966f6c3c79cf861f356f9723668167e8181a0dac687d",
		"3279ced58f2cfa724b6756fb1cd8807164ff200c1a7088f8eb9ead367a4dc277-fcc2de1f418e622570017f970943d12064caae772cd55d5514c7b806f59c3e74-25523f59f8f6aabac425ec5cac3c7dd3a39cc7f1681ed3672cf9f51e58318e83",
		"640079d021bead61ed7c81ce4a7b02f0dbdc941d713381e226d166eec983799c-98b5d4d181d3d02e0bd87612cf127b537cf6df6388a9d4a2e0b09fbb71711315-a15bc043f0b2a99310e3852e1552e29b49d43aeb0d19321241819fd643eb4a9f",
		"e05e8cf8c8442ba35041ac62eeee10379a39700485e73a84adcd189b9f28e6e8-480686d54996e2d738b8085734698d3c00121a7d350c456dae1cab098454f332-f14d6917e31d0ec01d8c3df0c63cc45d4c41022ef6ddda07e9cebbeb8a6c0cf3",
		"e803c3646ae27ede129dcf1416274f7ce45805bf66fb76e04490aae304fa7342-a740fac88d15da0b77c5630b20e1e024af1d53bfb42d6293e893b50fcda97983-0a7ebab593a5b28d17523849423de91935275f0d2df195f9bd51f39aab99d095",
		"f3552b45b0965d7d6606e42fee19f883eb92187ebb0a596c6a2dcf0217e27880-fb9f79d110f0b07e31cdef628fa69345094bbfebce3d3893192c8e44d1114b33-db81b23816440365acb77c18d6d0a593b280481bf261599db58a91b34d538560",
		"459678c01d4bb7b680c774dd01b2e40855e363c424bbaa51a0404171caf9752e-35ae7365551271a16b6013b8031149fe9ddcf2ff5ab543ab7e7580b8c7fe9b94-660e69b05d3fe31a2acd6b551c45672a392ab2f4bb138d9cca6a64edf45fb31f",
		"0e0ad0c18c21aedd445758c95a13a33e12eb3858037dfa0275fafdb89334eb9c-9ea328342616958a9c27aef68307b1f48d42fe58e8e49b35128468843bd10871-a7ebbf2df3ac72039c00cdcd46e44c9663c3c48500f39830e7bac8637e7c024d",
		"bb3ed308a9eeac554a42c0d2053b3062769dad5d5cc68febd71421fd8b329f3e-9b2f40b7fe2bfb8651e549abbbb77c490f7ca1fe8d3a49e4387d3942ad8da878-7c70ddfbdd39ebed8bff92944cd189e24f0fee663d0cb7407f9cbcfd7534d23e",
		"14e5a70cbb467f99832f31dd55bb8a01c7e16e657f196a939f67a42dde6810d1-a58582ea5543ae14e75993691e59801484aae91633b91ac3a3f618a14f790984-06551259e8873c4d7a3361a43d44acccbbb33d6f714b8a827b5e0bf467b80267",
		"b8be7dfcb21b6b2e1c1063427ed924424315e770d5adc20bcf488752b6a5a520-38a965f4f06b8e5504952a96cf2836cb61304f2c22f41777395075e605c6e50c-de03767e4cf1865b22836a6d4ce7be4ef448098a0a3367dbf038fc2c40d103fa",
		"637d63055c841c83a308c5db04e5e2b1737a70d5ff84e1e9a19c8826edfa888a-4c582605671264a7ed44134c62798d212949625df87db2bcae11014ed7c74874-057ca8cfe07a58f8cb469a9bb98e99a71be602f6a9029f4e7624604057cf73c0",
		"da752a42603d1518d21e454103bf32faa267d333593fadac4f7fdd76cd8a2e6f-d3828a1198784453c3dff887b7e6bd46163b6f2740b8d8a88e469db52f17b51b-826cf23607398037e3909f3be457a0e26739f48ccfd3dfaa5e9c946d7807affa",
		"5cafddfb7203bff3b722ae62444ca70330d5ce8b69c4c11186197629114a9c06-a540960200991ca43d57bf03ca59b8a1bf36d77846fbea7bda51965ceec8b26b-f2e2bde47dc3fab0926e263951c1db58a5908ffe7e2f1f281f27000ca649570d",
		"9c6545a6ca7293babeb48cb3460bab6bb97f3a33cc35f7d355a07e59a6022104-86f52be15606098db370efa32c42b2443834262fa5d27dc0dc1fde305e1939c9-1c17b670f0439357b0f2b055083c8154b9759b7850a2de07478aba6f27c7b099",
		"a67e4262127faa0f947d084f88d40048625f4cff458784aa38aa916e8d40f2a9-9ede93939f3e90ca2912e663d3f62d17d91df5d972faae51dd9fa6e700936a60-5173a326ed3e09271cf19e0af98bd7827e8c77de1ecf3fd03ca15724e04c1372",
		"0f1700839eb397f119105a6d304311f09aa79e3981ffd28d8b567e73aa278dde-0313027e8b0162612b41c8d738dd31a984035eabf3d063ab2c46816bd57eae8b-c5181afe30f831de90347ef36ad8f7eb2542786346cf532111ace9459b932473",
		"d727c311545cfa90f8fbad8d3e95dbb0296a6608fb4d8a4fef9472267f285916-e9b56cc785b8c97d778bd87f9b8c490e932346b803a51dcc51d2dc3df28dfc2a-5a6a526443c873d5601a69a645e4686475801b8c6cc2f375c8f0f111fc53e43d",
		"03b51ea5a52b6787e5334f303b3111006b30fda8d97fd11f461a390b0a09c789-bce6dd5e608c735a12a85416aa31299f76db55e25e13b056c267dbf39b4f95bc-408920f8e56dd36413fd514c311d47fc0562bae1a5e949cb7d274b82b147a2c2",
		"34e781766ef6ae305113ce173887057343381b0d8427f1d33959272cd6fd441b-6367cd2ecee02e810c880a164d81f750113549e2c88a3d28dfb92268b9059d5c-78997654ba6dcd4e754bedf2d7e1dde80b0c8ea940a355f901fbac72bc483847",
		"565bc57af9fd05c520332fff9d63aa38fdfe79c3f7e4648d625e5d9fdedad07b-9be3d78aad842c274f95439a9ac65f6fe3093464d71d26fdbb3c6360e8faa956-3ccc7e4bdf5df948198e0d395d1aba6eb782a9a76fdda482bb85146ab03d6f8a",
	} {
		sch, err := schluessel.FromString(s)
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("%3d: %v\n", i, schluessel.Verify(sch, public))
	}
}