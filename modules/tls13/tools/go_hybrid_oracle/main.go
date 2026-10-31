// SPDX-License-Identifier: MIT

// Command go_hybrid_oracle is the foreign anchor of tls13's SecP256r1MLKEM768
// (0x11eb) and SecP384r1MLKEM1024 (0x11ed) key exchange.
//
// It is a COMPOSITION oracle, not Go's crypto/tls code: crypto/tls's
// hybridKeyExchange is unexported, so this program rebuilds the hybrid from
// Go's public primitives (crypto/ecdh, crypto/mlkem) following, line for line,
// the layout in the Go 1.26 source:
//
//	crypto/tls/key_schedule.go:188-196  client share  = ECDH point || ML-KEM key
//	                                    (X25519MLKEM768 is the other way round)
//	crypto/tls/key_schedule.go:200-238  server share  = ECDH point || ciphertext
//	                                    shared secret = ECDH x || ML-KEM secret
//	                                    ("else" branch of `ke.id == X25519MLKEM768`)
//
// What it anchors: the two primitives against Go's implementations and the
// ORDER of the halves in all three places. What it does not: Go's TLS state
// machine; end-to-end interop comes with tlsserver offering the groups.
//
// Modes (stdlib only, no network):
//
//	go run . client            Go's fixed-seed CLIENT shares (printed as hex)
//	go run . server            Go's SERVER answer to the embedded Zig client
//	                           shares: server share + shared secret
//	go run . verify            Go's client decapsulates the embedded Zig
//	                           server answers: prints the shared secrets
//
// Recipe for src/kex_nist_hybrid_kat.zig: `client` -> embed in the Zig vector
// printer -> Zig prints its client shares and its answers to Go's client
// shares -> embed below -> `server` and `verify` -> embed in the Zig KAT.
package main

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"encoding/hex"
	"fmt"
	"os"
)

// Zig side, from kex.generate / kex.serverExchange under fixed seeds. Filled
// in by the recipe above.
var (
	zigClientP256 = "04a29709571bc73d5ac72a4513c81ac1fe027ef0abfa29b672fa3613baf51466cdbf8fcb1cfc0a113c8bbf7710a1e8c812a67557e83f047276ce0bf9cda1ec03c547b012f3e7807688c09ad316c53490f3f489b9581788d92df30a8f8305be86b56a78f606e900b2674c264fc4adfb121db31862dc355cda4510e541981106c24c794e2a01b7d5ec45e465439ca676d450917a30cbb56cb38526b5a9580bbe81b7e83767ffe09fae54bc53a1cd452c26688b9110364150596b01e6713c5a85a048783f138144cba029aacc8391343254c64f540c4c04a59ac25e4fe13519b732a5893428baa472e9b6ac7c7b2a66227d349fd9c84ab244b0cb3458f28186a0e9c1d7b2bc0e4168db26320f159eb25486006380f102c5ab8622357556deb6af647014bd756f05c222ea9a8d05dc519150a17e425b967972c2b2089e5320d70c30c719ca1f712f50d0bb63da8ab9c3b36830707859886090943a7002251abff1d4225bf9a82b2763dada414039a23656952d073a0ec2892a1032806ab1b1c949a3440c10cc34df363843918b97ab900277b8f27a0ad79a576b94aa1688a92ad2481d3a3da2685e52b5c805d9a92b8862bb80974538914fba61fee229ca638b64979a073978ffc3caf470b3f32c34321608612c60b4f32130bba09840a9b550ba96aba7af57a30ab70ac53b5a44358f971c0734919a026c4abfdc2df6761ec6e72ceee491ee616f236702fba03745b913f281cc4669b58811b46fe01669b32d53b203bdcc6d2e17c86c22a509f0c1407cc3024527c785a9d223b15c844ff0b74f6014530c2c03c0166943f7303643785753a5ef09a6fd467e74c1c0a3f706c58bb146cbc1eaa451f28901714a5b648a6e0bec1bf2aa1e074525139a149575c475fcb2fc883f8cc630f3592c71656ed4489e4ab91c88327a5937536a598d3d856430d903bee3b2d5c64582948a0665c9a3a04c7bc8a2bcdc573e3b6d845b565ff39df1649e4e3a30f4da96d29b411f53168aa3a8c6b3b159c83964477e89985ee8336980eac8b27b3c84784a8c789776694e0183cf121c5340a558f6aa830d622c3d9b9329f215cc657f2e4ba4fd7090ed98769118c924a6891cb801bc1a145c5748369c139b224c763caeda29bd515b48e87a8190e55ac4060f7bd869c497a185790bca1522f5caba5d8b3b21208aecd2cfaaacccafd10a50a97ce79418bfd1b924246fb6bcbe20e98866f66f867914488097e553ca08a89858318cfedc6602b33db36144260a34c16a334303a1c9f0511cc9c70a815a08506c763576e4c0c818b7b859b1bb96843807c254b0663ae1a23d6751989c880d00b2796bfba04fab72fb166fe685767c258c5270048baa72fa446d58362095a7caa06c4663b8c9c0db91bf060c9871899bf2993cb593169378a91c0adfd683069a0da26309e2c1c104a2619447920eb31da6f0c82eb71d66e30a0ec485962a51f199319914813aacb9d72425a6701fae315417bb0094678c61b99a476ba429b9a499f884abe9c00435b3db717777fabb1dc631cf95ce7e3203295a08fb3c8728510321825f76258a789c12c703285ee7cecc02140090c1ddb8683aea3a9296455c281f90b4c6a55c6bc3ac89266654b0056ef42c274af48c294b6251120023c3abba289f5db06bf336baf531463eb4aff34813fa619e4d6b00682a8e2e7a5489aacd92320a38607a70aa4a1ec67b60330c0d19f417ef0c7fb237187c578e5e7f8ed040258169d757396487"
	zigClientP384 = "04cc7415f3cad8e18cf263eba16d5d6def4c1333213701eb9eb25ed18a7fe79ec23d6064b92fc272e6270dae5ca90a48abbd6758e568b7c1a61e500133990250780c2b8936847ece72d2706e8e40c57e09166dce425f58f6e014ba5d0d5d1f6477c287bd704b859e7ac4e85a77f789c1c5198a0715c7cd1bc886918c0a47a38a26ae5f145d498285950c4a4ea1cc71f891b27aa8b6724ceb68538ab7962831c9c1439901aa94d5b453013ca05e65c12330c85f509570c85103606914a0304484c82b20658db86f909a93ac5bc4c91922b9f73559c1a05689328b18ac5d647e941c64ae178d36c61fc6e5a2338a6df8d90b87399478238e4c8c56f5b0668ada68210777e11acf51836b4cc01b7dc1c9bed998b7028f17828574da9dda2bc2bb89b8e11535b3c0c04cc68ef64ac7116a14ef20896a9a1b8bca94ae5b706a3bb0097118d69819f8f42585c9435610cf05950606e82d62e5350de86e243b428f9265d506bf022c3e2c6534d28021e96248eb0a82a22424be68640741222bf0540f361c7e727aaed429fa5c1dff4b244da73551ac0ee207a73d240b207b67595a98712cc6fea90df8004ce70a446ec230d9ca5eed0c08650b00f42c40f2615e13f3ad3c0c01570c2d206ac8ce290484c59913365d4efab51f375bc1c6a298c547ed6b2c04fa9e162c6038575191c91a51ec7ba7c63c0e63b9a3d1c3c7b08c6d14b5e1d9826b3393709b6b2c1242afca931790572108594053b520370801a446cfea6051ec137ba83b13cbc74e623c1ec70d7cc79c41d039f05885c2f33ff2f79faac42ad1f402f4d38e150c92d4ca7020bcbf2024136a7a39903bc1ac866a5d39b46ce09603ca871be2a2238293b6e73dbca6cb35d39dd6d886ab3b60df545a61a2697cc2778deaaf82304263118ffbe73e7100a5561b386ab0862d01a5dcd4624e061b0d1c577ab9bc7e95b87a83137b424e4e834465d948fef30e42a31ed69146ec547f992371b1f044dd983ee0a52ebdec76f2f28ef0fc6746a53c6c1519c55138787aba38da2f075451638014af579c57583b27ba27842a7132b37632462d9780507083c534540201405990a66f09d6becaf303efe5330eb298399a34a3b553ec3bcafdc16be366be25c6a085b2961591227f5c1b0899c197dab2aad70a7da20c46e5b9b5b1b56b567e458b2f26195f91297ade7619fef80678251a3c795aecc21c34c5c40d678a81b64bf8a985d0c7834fd33f628c8ffedc5c364067d1d5ccb39c29bf24a305dc4dd72c6ec2da154ab826c0f22c88dc33ce43988d3771697c4900033427549911c422fb47be88b50a75d12ab1996fe0a005029705140289f996cbac8a3d2bab30946a7956d685a9d4c30a19cc878b75e3c51a6ba38817b1a0157a4cbaaa64f2957e290017c3a42834e560d3b759cae37ee82728ea3b958bb101555a2be3b58e6b0574bfe69fd5fc1e8a3bba6059b9f4999692299b5c0a8c03d7083f25ce9d88308ae1947e5989e3e0a4d6daa42eec15dd355283127412e34ef985bf5bf76e2d547e54ec2b94d56b37bb80abc263e4b7ca6942b488c3c278894d0dd6c308e388dcdbcf56c04a9ad0c4828b566d01972c6b48171b45d19b6e611426686bbf0c955b2bd9c63ca3b4e7f4217df90715ac515b54545fe1bda210914f6cbabd484259f79816ac80ae7941ce120583988fd875495e5c14acf15dcfa9685f428230114a62c8bd2adc57f96122c2c8ccdb31752afc786e963640b173900c498554910fc914229a34b0a7420811c10d47201da33231e83f65923d7f7688b24250a9b0b9d9824fe44cc29286515e878bdc3320bad464821c75c2cc106e155d35643b45207dc79854373c2bd984be6ca198581b939b6aab609568f45750efd8a32227941868b80e27c5c4680c18c589eaac0b963632fc60bd07396014b460164c596fc9acbd8175e13c7fa9ac65bbd4c078ac81bf166d3891c067e36b2f77111718b8fadc28e4658c05a206bbd36b09675ed6f3cbea0544cb5b6cbb3b6caae47b0d5399372551f6320f51da030d43b8370a631563cf99a9524bf9a6db940eaabb00dc50436a5075f7f7626b3a4f0e3b536c23ad4fd42445601e3981bd44a7cef5177b50d23206da5947240132327788545a4688710be198369a522a98cdecc722bc115407541d83712cac536bbbf2b3a222958116879b467c27f756af98073530ce15e5aeca1a54a4d32d0d86594664aac17cc59af736238b7b2862627a1b253ac014a3f73bcd92bcbfd06ec1b05a26caaafc04702d562fa4e9166fb4901b9654ed6a1ab358da963cd5d9a7af48693f9db993704c696edbb0fe7dda67cf841750"
	// Zig's server answers to goClient* (fixed seeds below).
	zigServerP256 = "0479c9bf450e3dfee6bd0c4725f85abf07b92c6c77cb859bb18017f63db14a0fe5d4b85ee0e6376ce8bdcfb91ebace8280292c1ba0b49df221acbc13fb4ece5b65c82af2d6da599681bdc4c18de340180b017617b8c4d555a3f54f7262bf1696c6c2736c2250d70c69646ce81f1d43e5a6caf1ec0faa2e7d81bf380c8e96f4d4fe892fa358e36be96691918e07115f63819f92e44000275fd65157b41a1e4a585f5aef9875042b04af632fc772501a35a228a2a3af48d9bf9a183169c1b5f55d25706f289989c7c8e12b2e38f97eac3d5a9be13076775833a337fffdb6804237f54a3dea6e7b0ce0613352dae45bbd0c40f7414bc53b1a1a5a5e28cb4f5a5d281769e88390ab2305de0721c6bc595adfe8c3557826e6e053cd356238e37782aec6adffc5e510031ace13be56ca09c6a01c2081cf1c48bd8f7200ffc254657fc1737d998221d4b0a8003e3ee59337a4107136c0adff2726d05445620acba62ac13dbfb8d07740caa3034d0d79e65141206f8de9b8c74d2302c2a6983389cc7f0bc399c8753bda3dc393e0202fb014b08a03d4c9e745383c56f13be673cd5c036c09ecb0ad2675dec5cd2fdaa92ed92d9901c40f25d78b28e0b8139fb434940edcdd5572bb1c2e9fcca76c7e9e4e5e0da8dc74322858e143864e3059270c7f22f3d572f9c84a0669a95c68870cec209121358e16207052477e6ed785782eb0759ccfe410ddea6da0751470f628a0bf683c64801488171b81871275ff44fe495fc8b5fe83cac9204b6dbe734d455efbc06ddc5993ef6565e4c012d21039bf06183dfc11520b7699007e0a9a5f9d2679794bfc090bb398575ca81077f5f9fdb9a4a40e51842ef0da62edecd643a5bd29a1501da34ae5bf5cdd6a12c15ce82ab34bb68a8dd2ebfe9d03f7bf38f576673d5a905731320ee7d1f8aa567dfdc79c772d29455f6b3c83dea130884271f2de71272a167fe793d2ef18bfb101819585d4d378522e0876f63c84303e029d6b9c6135c7b93c3e3c57e0ae9bacaf2ca236efd411817efc6716d0021851be563dcd3ac3b6a0dd42e8a76fd0f665a8f3e5f92f0be88889b1e9c7b772e556e38bb2d4b521831e290b218c80bd286cd0e27bec12fe6a65d5bb0255bb9ec2a099d249b8ff461493054b62d0740f8c14663faf83f16180f9cd1243375dffdb43e0adac097e0a51d6b2afd2903753a338da51d98a5ed7b694a8104b1f66a19e04ae4a11ca49c43bd41d814a93aba1201c8ba6cd9ee11b483cd5eeeb361c52cfe733dabd71dea3dc6b28874d58484f25c384be9581be460c462a191ac4fd84a1001811984bac9822e71a0304d5d1eeb6bc3561e46321463dc14da3f950232df2fbb27fbc9a8b43cd849c0237da02a46b2dac2bd56613639e156ffa873ed1226153ad8b2847eb43f6e846d6128e74e90513bac8cd7a64d6ab8417c89f4ddfba345b59030ec061084474d91a47c943989ab8c18a9ef1b6d1c20edcd1cf69aa7f0fd30d92db169e1de1f2ffcb47eacbe0a3133ed5e0d1fec5562084d18fa0b7d7b5ed14d374f2fbaf4a9d9f9d34c45d23c229a2527e68f9cda42e98329a43c7e84d5d493c9f5a145db153e40a9f7594c95399ac22f53843e7937e"
	zigServerP384 = "0453cb7387eaf10c1191354d437f3dde18c3fbbcf41f45d7a89b9447a62e94fcb67a5c318e8ad5d4e1a1b68be7251e8fac0b276211bc6579a0d1d5ecc0dc4b7d452344b4829878ad3d6089c5737a06b8b532f838aec40768e485e2c61564add2ef5d3b65b1d771a0aa092aab2eb1474f1a09aee8f9089c58706de1794f0535ae0c17797cfc463cdff090afcfc85ae686b510995f09c87ef0b29179fda4571bbd8d290a7bd4338d53cda52369c5c3246a2b26ab74eda14aead46d2f6276f311ffc9187c98f84d43940739ab9aab193bf7824b038fecc6ba29201dc9d716b4b89f72a55f4daa0ac420fd859b33a51957619fbddee248d3adc1c0cba6083a59324cac596831fc52bf6c8eea395fc956cc24f5aa54b43d35a35a244579ced30ad41b35c86ae66c838606b7d548de535700d60e6597fd0b9d29a22b9002e8e1003cc9042b3549d36fb804037f9826517b1a881a6e558f0124778f390191ae07410a7bf3e1a32708235a8ce3a2f163e9b8dd0362ad4472a07d5d1360e79bc39d0da41826d5bbec2455bb0354d60955edc672a87857dafdf4c0636961332f974b87e02a83d193c30b1399ba33189e80219ab543cf0bb3371444245e4a9b08c5c2424e1159d3561714b6d63c6fe437113de2bfbc286fe1095484f3f16e02c0332617fc9895dd22d9175f1408cb93c9bd8fd35f5e566d2e72ef5c2b90966a5c36aa4a3508498731f9fbd5af2eafa3544df632f23ba071d542109bb0dd0bfa9bdfe18ce842e5d7f4f7e2cbaa11ab4ae6dd2bea9dd09779989538300a8a911df18dd045f493fae7d1b97f777d7d3b7961db59f6a06551713e7325f1fbd3f0245583868d11f662037061e01d7774b23e064e2836f895f09f4690a937c93ca6a59b204a37b5b85bd2d31c6785038d7cf300a07131f23bf3e5dcff97078ac612ad0ac923ac3dbb06725bb03a97e686e0f86ea74194afad2951083f9486bd17cd6b121a038584bbbc10c15ab34087fb3b2fcb49dbce5f6998b93ab4eece3f41d4ec81c4a2be1456c8fc61b2ba75d53b9e9930e23269b19348b8be22e73d51e09d7eae24f9b37e748df9a564e34fa1c81a72d445352f0c08e348c00c8ba8727937482f711d6a5d804423e96c41f7cbf623354e07d7892c1de293e970bb1f52390dfcb938a02ac8541543263e4c925258aef1f141ea297640c452b3afcfb3674cbbbe45d2fb42801da1f8d46768e8c50d8bfdce74aa6012248535e33a8a8814ab5cd1e5067cec2d8e480caa38286e5f8bf63ecf649b051d4ebd9dde7dfc55be5ccbdac217680875bc35ae6037a9253a4234eaa6bd4156f8ddf5441713dd7e035474bd92420af1cf410895f7c6e961a2370be6b0693c00e1f3da3f039f1834d768e3e9014c80a450811ca01799925c8341fef72abcfb0c1742bb6f11d1e86a13e468e55875c89d2361dfd27f8d8ca2474181ba0eac79964a40346e70f2bdc66d01a7033609d89ef716df6dacfc9d6c2a9f2e14245087764503540a2148f19eb6638f4187e3709c84ce6188994f69741aa63c8184a0521cc7a595f328087c72170e27153293f75e9a4b3b36cb87a9f02a3d30a88f7de9f719c69a7642c0ef4386f148e52745d3ea3089f4dafe1fbe50fea70d2a478f2c2049aba961f4c341f17e9f3e3dc9690cf34a2a8c61dcf2229e2eb250c75f8f79e4109ebf5b107c5ac412036c528c8a0573ad255e87ee914e59a25b45834c0e38c0c881aa08b280414158be969ccda8f1be39f2e1168c193e9385c800e55c30ddea842bd6cf29a6f30980fe2b9e11ddad523c48627915a55404ea937c62e20439a130b499ff29e21e4585a9f6ee4dea5f447bccbcf54ee438376fd0bcd298419ba21651883f07de28b939dfe5b5f387e9e51281cfff506cc908db5015204b6ce93b49b8922afc476c3277a65c1a1f83ed922b5f3a85ab639a37cd7f812ab382d4066c333370bc2c3ff95bafe0f19db5db4670bb566900c8dc914952fa9639185bf6e961bfee3ed2d66351aab1d740c26f8a0aabeab294378eae5ea2f41328384a16a11559cbee50e0fb04f3c851dcb061b97328e40f791731491f7e59dcb1711ba3d8e0f4efd6a47b4047af94e8b6054893d58dff4fff3ff34c994b2ac865f0c32d4b5fec37e60c165772bca846991af877352a8877ee267eea2a42a594bc2face0807519f5cbb445d8df055c9ee800e9f13001792e9c5b8462be5e04bb554712e6d2ccd88f30cb98cca06ae55d4e461c00f10c443ca69b09cb152e81ad638e79377c7a7d25a4844d80e1e002d7827a0dbd48935b8537abf2f2eda06ad1c2c616b7a3e897e952f2d02f4a413b7b5e4f10231cb2ee"
)

type variant struct {
	name   string
	curve  ecdh.Curve
	point  int // SEC1 uncompressed point length
	ekLen  int
	ctLen  int
	scalar []byte // fixed ECDH scalar of Go's client
	seed   [64]byte
	newDK  func(seed []byte) (decapsulator, error)
	newEK  func(b []byte) (encapsulator, error)
	zigCli *string
	zigSrv *string
}

type decapsulator interface {
	Decapsulate(ct []byte) ([]byte, error)
	EncapsulationKeyBytes() []byte
}
type encapsulator interface{ Encapsulate() (ss, ct []byte) }

type dk768 struct{ k *mlkem.DecapsulationKey768 }

func (d dk768) Decapsulate(ct []byte) ([]byte, error) { return d.k.Decapsulate(ct) }
func (d dk768) EncapsulationKeyBytes() []byte         { return d.k.EncapsulationKey().Bytes() }

type dk1024 struct{ k *mlkem.DecapsulationKey1024 }

func (d dk1024) Decapsulate(ct []byte) ([]byte, error) { return d.k.Decapsulate(ct) }
func (d dk1024) EncapsulationKeyBytes() []byte         { return d.k.EncapsulationKey().Bytes() }

func variants() []variant {
	v := []variant{
		{name: "SecP256r1MLKEM768", curve: ecdh.P256(), point: 65, ekLen: mlkem.EncapsulationKeySize768, ctLen: mlkem.CiphertextSize768,
			newDK:  func(s []byte) (decapsulator, error) { k, e := mlkem.NewDecapsulationKey768(s); return dk768{k}, e },
			newEK:  func(b []byte) (encapsulator, error) { return mlkem.NewEncapsulationKey768(b) },
			zigCli: &zigClientP256, zigSrv: &zigServerP256},
		{name: "SecP384r1MLKEM1024", curve: ecdh.P384(), point: 97, ekLen: mlkem.EncapsulationKeySize1024, ctLen: mlkem.CiphertextSize1024,
			newDK:  func(s []byte) (decapsulator, error) { k, e := mlkem.NewDecapsulationKey1024(s); return dk1024{k}, e },
			newEK:  func(b []byte) (encapsulator, error) { return mlkem.NewEncapsulationKey1024(b) },
			zigCli: &zigClientP384, zigSrv: &zigServerP384},
	}
	for i := range v {
		n := 32
		if i == 1 {
			n = 48
		}
		v[i].scalar = make([]byte, n)
		for j := range v[i].scalar {
			v[i].scalar[j] = byte(0x40*(i+1)) + byte(j) // below the group order
		}
		for j := range v[i].seed {
			v[i].seed[j] = byte(0xa0 + i*0x10 + j)
		}
	}
	return v
}

func must[T any](x T, err error) T {
	if err != nil {
		fmt.Fprintln(os.Stderr, "oracle:", err)
		os.Exit(1)
	}
	return x
}

func unhex(s string) []byte {
	if s == "" {
		fmt.Fprintln(os.Stderr, "oracle: embedded Zig vector is empty; run the recipe in the file header")
		os.Exit(1)
	}
	return must(hex.DecodeString(s))
}

func (v *variant) goClient() (share []byte, dk decapsulator, priv *ecdh.PrivateKey) {
	priv = must(v.curve.NewPrivateKey(v.scalar))
	dk = must(v.newDK(v.seed[:]))
	// key_schedule.go:188-196: ECDH share first for the NIST hybrids.
	share = append(priv.PublicKey().Bytes(), dk.EncapsulationKeyBytes()...)
	return
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run . client|server|verify")
		os.Exit(2)
	}
	for _, v := range variants() {
		switch os.Args[1] {
		case "client":
			share, _, _ := v.goClient()
			fmt.Printf("go_client_share_%s = %x\n", v.name, share)
		case "server":
			// key_schedule.go:200-238, `else` branches.
			cs := unhex(*v.zigCli)
			if len(cs) != v.point+v.ekLen {
				fmt.Fprintln(os.Stderr, "oracle: bad client share length")
				os.Exit(1)
			}
			pub := must(v.curve.NewPublicKey(cs[:v.point]))
			eph := must(v.curve.GenerateKey(rand()))
			ecdhSS := must(eph.ECDH(pub))
			ek := must(v.newEK(cs[v.point:]))
			kemSS, ct := ek.Encapsulate()
			share := append(eph.PublicKey().Bytes(), ct...)
			ss := append(ecdhSS, kemSS...)
			fmt.Printf("go_server_share_%s = %x\ngo_shared_%s = %x\n", v.name, share, v.name, ss)
		case "verify":
			// key_schedule.go:240-: client side, ECDH element first.
			ss := unhex(*v.zigSrv)
			if len(ss) != v.point+v.ctLen {
				fmt.Fprintln(os.Stderr, "oracle: bad server share length")
				os.Exit(1)
			}
			_, dk, priv := v.goClient()
			pub := must(v.curve.NewPublicKey(ss[:v.point]))
			ecdhSS := must(priv.ECDH(pub))
			kemSS := must(dk.Decapsulate(ss[v.point:]))
			fmt.Printf("go_decap_shared_%s = %x\n", v.name, append(ecdhSS, kemSS...))
		}
	}
}
