package main

/*
#cgo LDFLAGS: -L ../lib -lmonerocrypto
#include "./crypto/keys.h"
#include "./crypto/signatures.h"
#include "./crypto/rangeproofs.h"
#include "./crypto/hash/hash.h"
#include "./utils/utils.h"
*/
import "C"

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"unsafe"
)

/* There are two types of transaction versions in Monero, identified as
 * type in rct_signatures:
 *	1: RCTTypeFull - Used for single input transactions
 *	2: RCTTypeSimple - Used for multiple-input transactions
 * the reasoning is that if you used multiple inputs with type (1), if one were to
 * find the secret index for a single input, it would be the same for all other inputs
 */

//TxInToKey holds information for an input that was destined to a key
//Currently this is the only supported input type
type TxInToKey struct {
	Amount     uint64   `json:"amount"`
	KeyOffsets []uint64 `json:"key_offsets"`
	KeyImage   Key      `json:"k_image"`
}

//TxOutToKey holds the key for the destination of this output
//Currently this is the only supported output type
type TxOutToKey struct {
	Dest       Key    `json:"-"`
	DestString string `json:"key"`
}

//TxOut holds the information for a tx output: the amount (0 for rct) and the target
type TxOut struct {
	Amount uint64     `json:"amount"`
	Target TxOutToKey `json:"target"`
}

//EcdhInfo holds information on transmitting the amount and mask to the receiver
type EcdhInfo struct {
	Mask         Point  `json:"-"`
	Amount       Point  `json:"-"`
	MaskString   string `json:"mask"`
	AmountString string `json:"amount"`
}

//RctSignatures holds the data for the ring sig info
type RctSignatures struct {
	RctType     uint       `json:"type"`
	Fee         uint64     `json:"txnFee"`
	Ecdhs       []EcdhInfo `json:"ecdhInfo"`
	OutPk       []Key      `json:"-"`
	OutPkString []string   `json:"outPk"`

	Message         Scalar   `json:"-"`
	PseudoOuts      []Key    `json:"-"` //Only used in simple
	PseudoOutString []string `json:"pseudoOuts"`
}

//BorromeanSig holds the information for the borromean sig used in range proofs
type BorromeanSig struct {
	s0 [64]Key
	s1 [64]Key
	e0 Key
}

//RangeSig holds information for range proofs. One for each output
type RangeSig struct {
	Asig       BorromeanSig `json:"-"`
	Ci         [64]Key      `json:"-"`
	AsigString string       `json:"asig"`
	CiString   string       `json:"Ci"`
}

//MGSig holds the information for a single MLSAG signature
type MGSig struct {
	SS       [][2]Scalar `json:"-"`
	CC       Scalar      `json:"-"`
	SSString string      `json:"ss"`
	CCString string      `json:"cc"`
}

//MG holds all the MGSigs for a transaction
type MG struct {
	MGs []MGSig `json:"MGs"`
}

//RctsigPrunable holds the range signatures and MLSAG signatures, which can
//be pruned in the future
type RctsigPrunable struct {
	RangeSigs []RangeSig `json:"rangeSigs"`
	Mg        MG         `json:"MGs"`
}

//TransactionPrefix holds all the information of a transaction besides signatures
type TransactionPrefix struct {
	Version    uint64      `json:"version"`
	UnlockTime uint64      `json:"unlock_time"`
	Inputs     []TxInToKey `json:"vin"`
	Outputs    []TxOut     `json:"vout"`
	Extra      []byte      `json:"extra"`
}

//Transaction will hold all information that is encoded in a transaction (publicly)
type Transaction struct {
	Prefix   TransactionPrefix
	RctSigs  RctSignatures  `json:"rct_signatures"`
	Prunable RctsigPrunable `json:"rctsig_prunable"`
}

//genTxPrefixHash will generate a hash of the given TransactionPrefix
func genTxPrefixHash(prefix TransactionPrefix) Scalar {
	pre := prefix.SerializeTx()
	var res Scalar
	C.cn_fast_hash(unsafe.Pointer(&pre), C.ulong(len(pre)), GoKeyToUcharPtr(&res))
	return res
}

//Hash that the MLSAG signs. A combination of the TransactionPrefix hash,
//the RctSignatures and rangeproofs
func genPreMLSAGHash(rv Transaction) (Scalar, error) {
	var hash, res Scalar
	var buffer bytes.Buffer

	//buffer += message (hash of prefix)
	buffer.WriteString(hex.EncodeToString(rv.RctSigs.Message[:]))

	serial, err := rv.RctSigs.SerializeRct()
	if err != nil {
		return hash, err
	}

	//buffer += H(rct)
	C.cn_fast_hash(unsafe.Pointer(&serial), C.ulong(len(serial)), GoKeyToUcharPtr(&res))
	buffer.WriteString(hex.EncodeToString(res[:]))

	rangeSerial, err := rv.Prunable.SerializeRangeProofs()
	if err != nil {
		return hash, err
	}

	//buffer += H(rangeProofs)
	C.cn_fast_hash(unsafe.Pointer(&rangeSerial), C.ulong(len(rangeSerial)), GoKeyToUcharPtr(&res))
	buffer.WriteString(hex.EncodeToString(res[:]))

	buf := buffer.String()
	C.cn_fast_hash(unsafe.Pointer(&buf), C.ulong(len(buf)), GoKeyToUcharPtr(&hash))
	return hash, nil
}

/* GenRctFull will return a signed transaction for spending the input given the parameters:
 *
 *	msg - Transaction message (prefix hash)
 *	uTime - unlock time
 */
func GenRctFull(msg Scalar, secV, destinations []Key, amounts []uint64) (tx Transaction, err error) {
	if len(amounts) != len(destinations) {
		err = errors.New("Amounts and destinations do not match")
		return
	}
	//if len()

	tx.Prefix.Version = 2
	tx.Prefix.UnlockTime = 0
	tx.RctSigs.RctType = 1

	tx.RctSigs.Message = msg

	for i := 0; i < len(destinations); i++ {

	}
	return
}

func GenRctSimple() {

}

func VerRctFull() {

}

func VerRctSimple() {

}

//TestRctFull will verify the signature for transaction ID
//	b43a7ac21e1b60ad748ec905d6e03cf3165e5d8c9e1c61c263d328118c42eaa6
func TestRctFull() {

}

func TestVerRange() {
	fmt.Println("Testing verify range...")
	sigBytes := []byte(` {
        "asig": "b9b544a75ad5a4df48156aff37800994cb906cef835709b0d139eee1c85e39037f79e2434edb0038971775926ced8de2df00a0ba91eec023e2adb2bfc6aa9907178d6faffcf66cfe2acb5a9b2d24ed2336b4520a0250a6cf08f2817572d42a07b786ac61b76124d41048d59126f1df353d959692154fcef4d4bcf1874c70d9074c8415afe5a4a251199dbb9c66fdaa27b052b94daddaec96d14d3b6166004600759f38fda5a18bd49d196a442a56e17709b0f86f4b87a95cefa26d0ccde7c3042f4599f6bc41e5c8c1c19ec63dfdc660870339c67c1bdc2e1828023d36d76e0d578c13bf4119e6b336e48030419f78488f08981a9f078b808030951317eb18052b94fa43bc9618efd0d1f3917f935f49a292d61f109ee166fdbe0b2f9541ce058569df9d95a99eb320a43c3a5a73b2a0e7d04c48de5092dc102339e9f635150db7546f948d586645b32575735131b9bbaa7882810bb6a3c5c9089a4f84f6a90e26cd5be07a1e86cbbed36e855f4027b4f492c9c646967e4f77c58e877f094606254f655312ff61b206d4091e93eb2a7ee781a7d1d2f0f00fe17b7e284b1f4609e9d80c4905415867ecdd5917c5b2b4329e194dd81d593d318f5f55d126f959036c93dd1f0525729056c3ed594cd9f85d282844ef213b196ba3b18bbe28166a02c25d5b58d1af1ddde3605b641a491165fd5895b8e58ab26ba54f13c68765ab00da449fed7f9499f963b72fdcdfcc61e80186510a457b5a15647fd39d4e8e060e7dca3f84ced64fd1d6c7d6892991b63bd84b53713b642551f2cc1a67a4b4ca06fa74e4d75cb4af8c4ceb9c06b9047a177db103600a55ec0740afc8e5e1f9710e3467d35b2e2c19eb9fe8a96ff8a12670b89d4cb5432aa035f4b0d4cb0497720760dc701f225f06b1731e12cf9e8e6e58653e037db0ccd628065f3caff715d00637054d156f1bf76e7538ab5c11ecd18059093e3abd377b42b6f6470e817fa30b201ff5ac0a9e79e4cfcf3e4fb5a3e5db8f8e39ebd837124545b252b28f8fdf03ffe44f4357b907c95b6386161a612a7658d685be7415a79348370a8dd7421c0bd5718484434c11d1095daa16581181d4eec075dce940d30873e596957b90160114c841108e32e4a50be7a69ea297d05af86be46ebe0e5e0777945380cf903a06bda79071fb1ac71991786fe64438bc3ecb7cf9edf273653158db5e5a82fd0e03da379c768c036c4de2b44feb13fbf7caa7bb24e1471e2c71fdaa6caa0179fa0b878e3b16e58fd012167f6735952cc6546b0cd92028aecbd036e15e4f0aac9903fd6d1cef10a6359c1af7e7e486b9ba2825bd78586cd4736a90b705ca724a98045cd53d8facfa077c33c689b51ea40468721660e63fc3950f3abf524a7017420f0939e0d6c66bbdb1663ddc1344ee8360bf18918ad24fc6212bfd7d3b7691a302be42b78b2f9f1d7059b1c8a0de00ef4e4d5638828d6904cfe2417099d4e1d204b0b094b00e02aad6c0463e3b1729ab5fea7b274d301254d609379cfc575de30c0d9b2926a06b7500c34c189d6275e8f0e6f12dacf97cc6f6c99f8d4f981917016847bd2288347cd398bd29b26875e1447ff606e3827c450a73cac8dc0a63ac0daac031698dce131aad69ca9da8fb2f2c2d3d17dec7169bfc96f15851e257cf0fa894c5406d0bac021890f1bb1da3e577be0ad4598836b8c27938c6a6acaf46049322c38075d773d83af782ad6e13597ca84221d04f1a428a5b1651e97fdf680ef36ee19580700d6574b2b8894c32ac3840a3f3a3a675cdec32caef0b1923660f6706028988cdb7d7fed7de65380db888a597d45d9c55b9ab54ec5ec411c50301b2e6f580109c4a4085e1e96995f171f58211d3ed1c4ab4ded6d811fe7524ae0b14bc7e2583b1f5b05fbfd0c1e2be67c089bc4502074165be32c97fe944fbf909dd59a1a45c338f94cffb4959587d18e6047b18eeac71cca77205742310bb2e009488d439d37c63d9a1e6b33b8f525c77049412208f86e4adc640e4f340668f0d27a5fa83d84feeff791f3bd96f88f1476bd490c175fc6e055e4992ebb0845e0c5f84219b03d618ee62d5c41b71cb9eef13a625381ce750116711f220e4461b021323f986e18d05080696bcf81440512255b1daee5eb449267736a35f757a71015ceaae0cde58d4deea0c8c1f6d60d3b9f0bb54e5351b36e5c69f7115c14c750cd8ad7ac3dfe49ab74c5952a06ccd94ab5d6a16cba583509bc1aed108d8eaf10e31be0a5e537ca6227030cf1f36e22226863ed8c396e9f6eed26447a5c1e5f108162a2d9b88c7efaa297f92d9cde1e3be521b6cf270d285f11976d82c8387cb0e5c81468fc8f89e207d7ace46f9f5e2a3cd84119e0ab6c99757f1182abe5c3c0bd6461930c3061105c0e64db80efb9120c3e991cc08ac0904fd4235d07e67a50967ec8d97c476392975e5f6d7b62b44abe7ae27795a025b2262dbb0c42cd3790ab204e08f91508dab69ae9cb2b273f0d286153537d8af06a7f17443667c830c0293bea634ff203f3feada7c8792d5a5547e51d25be453b2f19b18c348cb6fff0352f2fb6d6b65ffa528df82d0beba7f5b824f5ca44befe7b5b773ed0fa2df090c9798cc81e4c5fe8c32aa9b3d231046232566af93e142c9931df040c2bacfab0db340f9bdf8747d37fe21cfd16891b2aa01db915371a1a68afa395d09019896037b1f50dc40fde64538462aacf26f8e4007eae0897c18389b77a7c036c18cf90f71c966569970bb842151a9346017390e0cf24d39d3e2a94f84d80c035719540df8e1c6465c2260cc8dc965efa9efc84f5bb7e4e3c186d6a8346d8687f0eeab0fed4b9baf3287c0ef58f82d83c5811cb231efa93b9ed90d894661a8951489c50c0f567c73ab8a3b7c052fa24f5c70fe265718bd10acebe1323bc507a5b94bbb01d1bd15dd880bb37a79f4ead21cc3a7074264ce4afd24f946a83dc1cea53c71024a81583ae0a8d03daee6980190cb2e74ae69e0c1161f9583d24de34803626303b548fd8e8e5c18dfed0e3a413037bf73481d69715dfdccb978ecac108c18fe005dff08ddc912fb33aec32cf829b69d7db49e90ebede4491fefdb9cf2eddfdf020fd1b878c4d4799c07bbb2b770f5d88617a6685b218a8257bb92ac2173331c0929c630beddaca6916d7e1d24ef5b77d80c322cb56ba2d586dfae9d414667240b94e1d8cd984eca91d4486ea2a41c3ea48fb8ef5a5180c2b4361ed9ba63d078080955a46d68a0d0c1b6b744d5844c3f3136f98c611b50e8840a396c688499e70336f72284464be3abe75728d90e4bf625bffc5a1baf3fcf7844d45a872f627a0ae98e5487097369551fd27527fe36f643625571c0765d700ddeb3c99d8e4fbb0967f2de04de741b44ea52b463fa9aeaf9b6cfa42575b27f3bc5b946670c5fe103e273cc1490ee97b6e166d3b970f8e1ae3627f877dd0a4ebddb776097fae9f30f58745e588c5fd0dbd71fdf775f98c991c9381c568ba6d94d75e93ffed3de6f08aa7e1203e02f87daae4aa657059ad04b038523e9fda514c0b3c63f2970d4a00981c8047c2852b000f505e8c5a211a8d1755539d529ba36dbb699e1a6e380bf03e999d2247573e424276f485b17b20f39dab133c07b83fa40d47bab2e7424b30df768a7c5c9fd12546c95592103cc33c0ce743da65faeec410434ec3c379bb00cebc8a21967b05cc65886efe944a7b487a0fa9c133d85763f3423e30fec75a20c7468d43f7e292c5b2e6fbfbbf7514ca6fc9fd567e9e2d764da6946919482d90c23e5d3403d19ff42b26620144a58c9f7528c975553256c92232bbbac2dbc170c7722209157c82078b855d439b6fa81d2d090e55903b1e9111624c7ee32347c04f4ae622af2ec4781d71d9f201a197bdb05c73f05f2ec33b25498a665e4b7a408d3e6ec1aaedaf79cfee296f8251451e0d616b5ebc5383ec61a05d7eb3ed09d0bb85d8b361a16d94b6c24437a73b8f9effe05da721a3fb576409d20d250105a0d47e90c5538580dab2546944aecbbfb9f86a07e0b6617f72b0d7e6f33e5d9790609b81aa9808f51e675d1ee2ee9f29552b07470c6f8a2d49c0c545da259dd550be8835585ab93a9c381eed54f08ef36192198f76611fafe6744a18e6674338b0319935792e2f0893d743b6435a099ef70374dc1c6800aa67472e7ad16bdef880209a66f3062a9bf89e53f3106c72fc10857f3e7be924f4589a10f47745832f306e8584a6e66975d5ba3a526cabe7d24dbd75c5031045fe1bc4ff77e94d102d20eeb0a62f43bc3788bc22002f69ca56758a5952f3352db399c370e5ad89085130927bb7c640f316fa7bed901c3bf9a0a630936c625234278694056bda9a9b876058135500d62f19256ea06a948df06b7e559f425f61767e8c6cf4e04ae49324c057de8b5ad070930bcb8c0850b7cf510b56f832dad2220769570a29489ee4d5c054f77113f1fe96a4dd2a8e65c553e8d2c06686a3aaa9362636a7118473fb3510d7c6ed1e296f0cae069853407ee0435d674b011f9e50fdf6e56180546b5f2f40701cfd424df1504e695c1c62e7ccd447087242fe9bb5e4afea5f665cf2c6e63018b51b441984dcb5d03316ac0aa7d08054c2836f61b1fba50ade6401c5c222601c830a10844b17248dfa99c96e2a90968d37b34738db7137f37d144f1fd92fc0c84c219de0366728a4caea612d786ff2d7031deea627153699442e48dbe6358012ba373eed74ffb992f5e5732faa8b26ac4b402db5a2aca25ea626b040434be0fa01de4134dbed0fb99735c439058fd88278bbb4cd7c21237620840d71271bd0b30f33f612edbcdab36e64dd6cc50ee0b9494e2344bc41669dab5d6e1b01fbc0ab973d1edaf017dbbede2f1efb064f44d8709e936b10674f0254f600b822a3809684f1c856325f77217ebe97774dfd710478a50c6005641629b7a57c1145ce40e69e192b0fc155601669ce9af0511789ba5a18345ffe0de0b5eb7fb09c50eb90c1ef575e2c29b7acbbeee84f962c65a14c28461e8169fa8e6f0d3886ff9e96209c10cae6f4a5e34b20589df86cfd55fd48ac2aec18f42a12fc68e6598d63c3309c0bdb65b9eb9649e281d7974f7a7a8f4d9d939af486790e727c7afefa0922101927afda118c80abb1fab7952481e2fb7b3c5ece0bc7cb147bbfddb8bd4438d017856c235fdf7be47d86d704d0357e8e013ceacbd3e1ed77d209c9b0467a3e40dea113e03c68a8cebedce66c9b55f03a4a87d891ca29d972253e4f35190f6a101168a092bd04765870929f594c2c32081a010da282aa87f60b8b5b97c95ee950461706b0336e5546f0b8bd6104363a4b18d73be08e2fb4a077eca3517af52920be8265ef2320ff112fc1a35ff4623918f60b764d1dfba38e2d3954b692c0d790124c9659c1b0d2f5a396015aa2f9c9ecd798170abef0d4827ff6f2ca63fa3830b205f48e2e29662f8b8f226153ab4ee2e87ac901ab53da7035a67af9f77e11c0aa6946d116eef66980338ed755ea60671b96a258e7b682a2b66da8cd17582ba0a56d09bc74961d24fe63d1d077b977a8b273c9592b8f4ab44bad8b4365f35cc0f7fc2a37cdff5b8a8322fd1d358cbcfaef36465a4150b19ad0804613c76292200804367e16fe88b4b407c1459ccaff2cfa87e0acfb5780f17373cc3352041f50219db8bf88e9a70b25504f12cc0a1d088466b99e15710ea711a983f69576a6c0cdba2e78ee911db97c306bffb1220fe9574a6b75a64e9676066218dfd0accb908f053a9122876fae57498147740331e64c73bd4c5726e81c4c4b6205dacc05208", 
        "Ci": "bc7ae45729f2084c01b10a766c7c397cc1039798d86cbfe9789cd196a60f32cf2f9a3c9d9854b355978830e39350fe6ef04b71c33b72d9fdb72a34cbc90a370dc99ca464e53b4110018a50f32e8521afe1bb69e8a08f15a8229b4c925db0baabb76d47e110d644ccb0c68c2039584caa0712045076aaecfbdc26d248fa31d8696178fcec6cba1fd54356300538653317fa990b3ddf7e9bf0eeabbf7df4d3a9383561b9fbbbd0457026dd6b1b171731f418aaf08b72d6fac50bd5485b10994b8b09419ade40de119ecad69eb6fa116f4a3256c70e179aed4370dfa20bec1eb9b97a0f5f6fdb7bae2f4051100fad7070e6d065845290675baa98851dcd8677b5b964df38b0a8945d8b1a27f7c49e947ca801cb3abaa24b2bac58fd1edbd69736722f522b4719970e1255e8b344d3e309eadda2f9fccd423604cab35b89227f90b28febefe091c738a9dd1804e610fbe17ba1578c83616d73df305a12a2cdc5c087336af4646e32ec09460c3e8d0a14686808e3290c9e341404d937ee520ab2844c5bc85735faa42388dc2c1b4844cb2abb4dafe5e6047a676beee9f7aecb782bfad8f106fd87b62a47e4cd9f040819b24e51ad4dec266548eef2e3306d235a5da0d558535a010b8dfe196b7a9e624e1bc5bd5a37142a327b84e92e0d4bc86b280c7074b799ca34eeb76bbf316700d275a6c0e96de73642f8f3aaedbdc1795f803be947a47fd67773053373e4013f8fa20419166a0b81ca93a64427c8e2f5b529d28dd776e455b89d4061ab97f53efdab8698b37a0bd9cc1b34a656a848ef6e8f22c778ca59e806480d2b64f0cb522d2dc5c330c3db93a25e96d18b77d0c24fbc3a636375af4fd726b96834ef6e0495eb7c8ddc57504e162ad42c1dc2513b8e0502de93f9992e41121779abbfde8fb5f8ce11866d037c77bf03c3323985e979376133a57be3f1bdca2d4983cc2abd0ac9a0189f0e5ce8687c25f50707f1c07d35783da76f4a30b736f3a050f22dd902027eb4b2fc2f38b98dc8d24512330c9a6e270197693fd266f45d9c5f53da116865f20969ee0528837bcf7ca190446ffb64842f154637f32c59874c7f3596ead221836fa4e562bbfef3a47ee4accad55c85ad3ff2336672b66a6ec897287da6d991872debf9ae2d740a0be79f9d4871b8a89558427c677dfc5f61d612ac889918c61410d8908e0844e79318c6e93d491ce0764eabca769b96ccbcce8f670805f05bd5e8ef183956265a9abdc20376af2615c032c21da6bbbd0affb571695968f26d08d14140dc7bd3fb7fb91f32e35d4ee8c08439f3055eaebb395888c5744122a6f4064d587262b6cb31c3ac1275a0c11a4cce9b5aa64a2f2d5cc930035834f009f5c8987b1f354e527e82093967f022bdc4bd818f9557ec18164653d3e3ca8be896fe94a844a4c0541f111165ff9c23d39ddade586a884fe2a962c1499d03077bd0d9d1354a05bcdbb97c03bc66de933ee433c2e7e085688032c4cd5e4e963887927a6339dd5926108e661edb07a6c7e8830ddb320f25aab848cba850235ff18b2c2dc0fa3ca8d63b01da36fb93906899fd83f4bc86b02a768a5d321ad7acf9877e82e4ce4a20f49a8d0938f5a44f84a3720c20c70e56ff70bda03d3d7cdf7d29fe91aaaf3e7dc80ed8d2729a2e5a6301f54132a57759fc438ad7fa207d329955442f11d4247ec6c83aadb9b20cc54f09d1d53952aa3444942f3512365d001fc08794b4258a7812a05d0afc19fe656be7da8236b3676e8178ea5735dd30bd4a710ada19c6a7909c07be8aeb2a5a563709a9b4f1838440ba2212959abedd2978f390106a0c87b54afbf6f587366c5535119767517ab9e8e9b8d4848b6e772df73aa637ab0e02610fe910d22ccea347c35d3451f5e44ca052604678f327b6bdc47fe100312fbf1b27da2f79b35e64c16d8e482f6b7118efd22e335df149c822ea172d632327fabc4697bcea7b64e1d8f67da7fd939d026c121e664b1c4ad376daf614f09981afe72f1256ee0d4d0f41d5b5035f0264bb60a37c6e520e959673499f28ce17bf30596c898115a59aad5d7711f73b18b4c3f0015b39ee3a88e054ed43797aaefffb154ac1f730be3275fbb6b0c2f67cd060f2b92dc24e1727a15be1a23bdd4e2068272c384a95467feb069d1516d3e87678b0ec6701a28f6b2a36c7a0bdb67cb886949a1ac828e0448dab09bf916fabb1d883ee176669b9370311ec7edefe264c13f08f66ceae4e0fc46d9cb634f190be84eb0d908505950c2326948adb55944a065e879dd3f75302c008609011c331881c6a9f61efe5b9c5e17fe73f5b91b554cc0e3e2a7398b97c389d6f9cf98fd603c028712d8ff01d823b2733cb592cca1004913864c825c86a5adedc97273fdb2059d485dee00b67110f2ddc3c67df3a4538ffe41c0aeb0c1cedade043eba962a81b4bbf619b783a184865c8d0dc51ee48b71b4012e742be7cd585c915f5ceb4acf9b783ba903dc1c29100dcc429b1c0e7134ce9620a31e2413057c337463b802eefe4d49796315d90502a0527859375ef8ca024a4ad624b239248ee41bb0d34ffd1772c23264d43b6f59750a9626e7f36c36b996a5e5305fc1e09c371937ab63135c6549b4bcac37a9f4d11750eaabc459bf2b1b385f4cbc1d544db17b1c139beba46bbec36e48414d9fef616a1a6ba9f0ac30c9f605d735dba79ecd1e26f5dac664b332620d67a003838aa1eca9f28120a463fbd2c673a6617bbeea0cf269749d7d0773b717c1838660e71d2d7a69b7516972288aa37ca4f1618a4d2fedbc11285743f6e3b5324a804efad66ff8d56580e4ab28de551435c9f149658f9eb0df04567532381f428eb6e7647937f4ddd8b879b7cc5756bb8743dfe490458"
	}`)

	var sig RangeSig
	sig.UnmarshallJSON(sigBytes)
	CBytes, _ := hex.DecodeString("cf141f5dfe04df14afad6b451d600aa5826a9be44a76a1630850c1d5951d482e")

	var crange C.range_proof
	var Cval Key
	copy(Cval[:], CBytes[:])

	for i := 0; i < 64; i++ {
		crange.Ci[i] = *GoKeyToCScalar(&sig.Ci[i])
		crange.sig.s0[i] = *GoKeyToCScalar(&sig.Asig.s0[i])
		crange.sig.s1[i] = *GoKeyToCScalar(&sig.Asig.s1[i])
	}
	crange.sig.e0 = *GoKeyToCScalar(&sig.Asig.e0)

	res := C.verifyRange(GoKeyToUcharPtr(&Cval), &crange)
	fmt.Printf("Does the range proof verify? %v\n", res)
}

func TestRange() {
	var C, mask Scalar
	var amount C.uint64_t
	amount = 5

	var proof C.range_proof
	C.proveRange(GoKeyToUcharPtr(&C), GoKeyToUcharPtr(&mask), amount, &proof)

	res := C.verifyRange(GoKeyToUcharPtr(&C), &proof)
	res = res
	//fmt.Println(res)
}

func TestMG() {

}
