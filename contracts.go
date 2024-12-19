// Copyright 2014 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	//"crypto/sha256"

	"encoding/binary"
	"errors"
	"math/big"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/blake2b"
	"github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/ethereum/go-ethereum/crypto/bn256"
	"github.com/ethereum/go-ethereum/params"

	"context"
	"fmt"
	"strings"

	fcommon "github.com/project-flogo/rules/common"
	"github.com/project-flogo/rules/common/model"
	"github.com/project-flogo/rules/ruleapi"
)

// PrecompiledContract is the basic interface for native Go contracts. The implementation
// requires a deterministic gas count based on the input size of the Run method of the
// contract.
type PrecompiledContract interface {
	RequiredGas(input []byte) uint64                      // RequiredPrice calculates the contract gas use
	Run(caller ContractRef, input []byte) ([]byte, error) // Run runs the precompiled contract
}

// PrecompiledContractsHomestead contains the default set of pre-compiled Ethereum
// contracts used in the Frontier and Homestead releases.
var PrecompiledContractsHomestead = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
}

// PrecompiledContractsByzantium contains the default set of pre-compiled Ethereum
// contracts used in the Byzantium release.
var PrecompiledContractsByzantium = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{6}): &bn256AddByzantium{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMulByzantium{},
	common.BytesToAddress([]byte{8}): &bn256PairingByzantium{},
}

// PrecompiledContractsIstanbul contains the default set of pre-compiled Ethereum
// contracts used in the Istanbul release.
var PrecompiledContractsIstanbul = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}): &ecrecover{},
	common.BytesToAddress([]byte{2}): &sha256hash{},
	common.BytesToAddress([]byte{3}): &ripemd160hash{},
	common.BytesToAddress([]byte{4}): &dataCopy{},
	common.BytesToAddress([]byte{5}): &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{6}): &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}): &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}): &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}): &blake2F{},
}

// PrecompiledContractsYoloV2 contains the default set of pre-compiled Ethereum
// contracts used in the Yolo v2 test release.
var PrecompiledContractsYoloV2 = map[common.Address]PrecompiledContract{
	common.BytesToAddress([]byte{1}):  &ecrecover{},
	common.BytesToAddress([]byte{2}):  &sha256hash{},
	common.BytesToAddress([]byte{3}):  &ripemd160hash{},
	common.BytesToAddress([]byte{4}):  &dataCopy{},
	common.BytesToAddress([]byte{5}):  &bigModExp{eip2565: false},
	common.BytesToAddress([]byte{6}):  &bn256AddIstanbul{},
	common.BytesToAddress([]byte{7}):  &bn256ScalarMulIstanbul{},
	common.BytesToAddress([]byte{8}):  &bn256PairingIstanbul{},
	common.BytesToAddress([]byte{9}):  &blake2F{},
	common.BytesToAddress([]byte{10}): &bls12381G1Add{},
	common.BytesToAddress([]byte{11}): &bls12381G1Mul{},
	common.BytesToAddress([]byte{12}): &bls12381G1MultiExp{},
	common.BytesToAddress([]byte{13}): &bls12381G2Add{},
	common.BytesToAddress([]byte{14}): &bls12381G2Mul{},
	common.BytesToAddress([]byte{15}): &bls12381G2MultiExp{},
	common.BytesToAddress([]byte{16}): &bls12381Pairing{},
	common.BytesToAddress([]byte{17}): &bls12381MapG1{},
	common.BytesToAddress([]byte{18}): &bls12381MapG2{},
}

var (
	PrecompiledAddressesYoloV2    []common.Address
	PrecompiledAddressesIstanbul  []common.Address
	PrecompiledAddressesByzantium []common.Address
	PrecompiledAddressesHomestead []common.Address
)

var REcontroller common.Address

//var tag = 0

var startTime time.Time
var elapsed time.Duration

/*
var elapsed2 time.Duration
var elapsed3 time.Duration
var counter int
var trigger int
*/

type conditionCreator func([]string) model.ConditionEvaluator
type actionCreator func([]string) model.ActionFunction

var rs model.RuleSession

var resultMap = make(map[string]string)

var ruleMap = make(map[string]model.MutableRule)
var tupleMap = make(map[string]model.MutableTuple)

var retractQueue []string
var resultcache = make(map[string]string)
var synccache = make(map[string]string)

var conditionmap = map[string]conditionCreator{
	"checkBalance": checkBalance,
	"checkID":      checkID,
	"testconfunc":  testconfunc,
	"test2confunc": test2confunc,
	"Comparator":   Comparator,
	"Equals":       Equals,
}

var actionmap = map[string]actionCreator{
	"exchange":     exchange,
	"testactfunc":  testactfunc,
	"test4actfunc": test4actfunc,
	"Airdrop":      Airdrop,
}

func init() {
	for k := range PrecompiledContractsHomestead {
		PrecompiledAddressesHomestead = append(PrecompiledAddressesHomestead, k)
	}
	for k := range PrecompiledContractsByzantium {
		PrecompiledAddressesHomestead = append(PrecompiledAddressesByzantium, k)
	}
	for k := range PrecompiledContractsIstanbul {
		PrecompiledAddressesIstanbul = append(PrecompiledAddressesIstanbul, k)
	}
	for k := range PrecompiledContractsYoloV2 {
		PrecompiledAddressesYoloV2 = append(PrecompiledAddressesYoloV2, k)
	}
}

// RunPrecompiledContract runs and evaluates the output of a precompiled contract.
// It returns
// - the returned bytes,
// - the _remaining_ gas,
// - any error that occurred
func RunPrecompiledContract(caller ContractRef, p PrecompiledContract, input []byte, suppliedGas uint64) (ret []byte, remainingGas uint64, err error) {
	gasCost := p.RequiredGas(input)
	if suppliedGas < gasCost {
		return nil, 0, ErrOutOfGas
	}
	suppliedGas -= gasCost
	output, err := p.Run(caller, input)
	return output, suppliedGas, err
}

// ECRECOVER implemented as a native contract.
type ecrecover struct{}

func (c *ecrecover) RequiredGas(input []byte) uint64 {
	return params.EcrecoverGas
}

func (c *ecrecover) Run(caller ContractRef, input []byte) ([]byte, error) {
	const ecRecoverInputLength = 128

	input = common.RightPadBytes(input, ecRecoverInputLength)
	// "input" is (hash, v, r, s), each 32 bytes
	// but for ecrecover we want (r, s, v)

	r := new(big.Int).SetBytes(input[64:96])
	s := new(big.Int).SetBytes(input[96:128])
	v := input[63] - 27

	// tighter sig s values input homestead only apply to tx sigs
	if !allZero(input[32:63]) || !crypto.ValidateSignatureValues(v, r, s, false) {
		return nil, nil
	}
	// We must make sure not to modify the 'input', so placing the 'v' along with
	// the signature needs to be done on a new allocation
	sig := make([]byte, 65)
	copy(sig, input[64:128])
	sig[64] = v
	// v needs to be at the end for libsecp256k1
	pubKey, err := crypto.Ecrecover(input[:32], sig)
	// make sure the public key is a valid one
	if err != nil {
		return nil, nil
	}

	// the first byte of pubkey is bitcoin heritage
	return common.LeftPadBytes(crypto.Keccak256(pubKey[1:])[12:], 32), nil
}

// SHA256 implemented as a native contract.
type sha256hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *sha256hash) RequiredGas(input []byte) uint64 {
	//return uint64(len(input)+31)/32*params.Sha256PerWordGas + params.Sha256BaseGas
	return uint64(1000)
}
func (c *sha256hash) Run(caller ContractRef, input []byte) ([]byte, error) {
	//h := sha256.Sum256(input)

	h := []byte("Error")

	if len(input) == 0 {
		return h[:], nil
	}

	strs := strings.Split(string(input), "$")

	synccache = nil
	//fmt.Println("Synccache Refreshed")

	if input[0] == '1' {

		//test_Init()

		tupleDescriptorInit(strs[1])
		h = []byte("TupleDescriptor Initialized")

	} else if input[0] == '2' {

		success := ruleInit(strs[1:])

		if success {
			h = []byte("Rule Initialized")
		}

	} else if input[0] == '3' {

		sessionStart()
		h = []byte("Session Started")

	} else if input[0] == '4' {

		if resultcache[strs[1]] != "" {
			println("~~~~~~~~~~~~~~~~~~~~~Re-assert same tuple : " + strs[1] + " , use cache~~~~~~~~~~~~~~~~~~~~~")
			h = []byte(resultcache[strs[1]])
			return h[:], nil
		}

		println("New distinct tuple : " + strs[1])
		success := tupleAssert(strs[2:])

		if !success {
			h = []byte("error:error")
			return h[:], nil
		}

		result := ""

		for key, value := range resultMap {
			result = result + key + ":" + value + "&"
		}

		if len(result) > 1 {
			result = result[:len(result)-1]
			fmt.Println(result)
		}

		result = result + "$"
		result = scanRetractedTuples(result)

		resultcache[strs[1]] = result
		resultMap = make(map[string]string)
		fmt.Println(result)

		h = []byte(result)

	} else if input[0] == '5' {

		tupleRetract(strs[1])
		h = []byte("Tuple Retracted")

	} else if input[0] == '6' {

		ruleDetele(strs[1])
		h = []byte("Rule Deleted")

	} else if input[0] == '7' {

		sessionDischarge()
		h = []byte("Session Discharged")

	} else if input[0] == '8' {

		//synccache = nil

		if synccache[strs[1]] != "" {
			println("~~~~~~~~~~~~~~~~~~~~~Re-assert same tuple : " + strs[1] + " , use cache~~~~~~~~~~~~~~~~~~~~~")
			h = []byte(synccache[strs[1]])
			return h[:], nil
		}

		println("Syncing tuple : " + strs[1])
		success := tupleAssert(strs[2:])

		if !success {
			h = []byte("error:error")
			return h[:], nil
		}

		result := ""

		for key, value := range resultMap {
			result = result + key + ":" + value + "&"
		}

		if len(result) > 1 {
			result = result[:len(result)-1]
			fmt.Println(result)
		}

		result = result + "$"
		result = scanRetractedTuples(result)

		synccache[strs[1]] = result
		resultMap = make(map[string]string)
		fmt.Println(result)

		h = []byte(result)
	} else if input[0] == '9' {
		retractTuples()
	}

	//h := []byte{'t', 'e', 's', 't'}
	//h := []byte("This is a string")
	return h[:], nil
}

// RIPEMD160 implemented as a native contract.
type ripemd160hash struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *ripemd160hash) RequiredGas(input []byte) uint64 {
	//return uint64(len(input)+31)/32*params.Ripemd160PerWordGas + params.Ripemd160BaseGas
	return uint64(1)
}
func (c *ripemd160hash) Run(caller ContractRef, input []byte) ([]byte, error) {
	/*
		ripemd := ripemd160.New()
		ripemd.Write(input)
		return common.LeftPadBytes(ripemd.Sum(nil), 32), nil
	*/

	//startTime = time.Now()

	REcontroller = caller.Address()

	fmt.Println(REcontroller)

	return []byte(""), nil

}

// data copy implemented as a native contract.
type dataCopy struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
//
// This method does not require any overflow checking as the input size gas costs
// required for anything significant is so high it's impossible to pay for.
func (c *dataCopy) RequiredGas(input []byte) uint64 {
	//return uint64(len(input)+31)/32*params.IdentityPerWordGas + params.IdentityBaseGas
	return uint64(1)
}
func (c *dataCopy) Run(caller ContractRef, in []byte) ([]byte, error) {
	//return in, nil

	//elapsed = time.Since(startTime)
	//fmt.Printf("End Timing, elapsed: %s \n", elapsed)

	return []byte(""), nil
}

// bigModExp implements a native big integer exponential modular operation.
type bigModExp struct {
	eip2565 bool
}

var (
	big0      = big.NewInt(0)
	big1      = big.NewInt(1)
	big3      = big.NewInt(3)
	big4      = big.NewInt(4)
	big7      = big.NewInt(7)
	big8      = big.NewInt(8)
	big16     = big.NewInt(16)
	big20     = big.NewInt(20)
	big32     = big.NewInt(32)
	big64     = big.NewInt(64)
	big96     = big.NewInt(96)
	big480    = big.NewInt(480)
	big1024   = big.NewInt(1024)
	big3072   = big.NewInt(3072)
	big199680 = big.NewInt(199680)
)

// modexpMultComplexity implements bigModexp multComplexity formula, as defined in EIP-198
//
// def mult_complexity(x):
//
//	if x <= 64: return x ** 2
//	elif x <= 1024: return x ** 2 // 4 + 96 * x - 3072
//	else: return x ** 2 // 16 + 480 * x - 199680
//
// where is x is max(length_of_MODULUS, length_of_BASE)
func modexpMultComplexity(x *big.Int) *big.Int {
	switch {
	case x.Cmp(big64) <= 0:
		x.Mul(x, x) // x ** 2
	case x.Cmp(big1024) <= 0:
		// (x ** 2 // 4 ) + ( 96 * x - 3072)
		x = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(x, x), big4),
			new(big.Int).Sub(new(big.Int).Mul(big96, x), big3072),
		)
	default:
		// (x ** 2 // 16) + (480 * x - 199680)
		x = new(big.Int).Add(
			new(big.Int).Div(new(big.Int).Mul(x, x), big16),
			new(big.Int).Sub(new(big.Int).Mul(big480, x), big199680),
		)
	}
	return x
}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bigModExp) RequiredGas(input []byte) uint64 {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Retrieve the head 32 bytes of exp for the adjusted exponent length
	var expHead *big.Int
	if big.NewInt(int64(len(input))).Cmp(baseLen) <= 0 {
		expHead = new(big.Int)
	} else {
		if expLen.Cmp(big32) > 0 {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), 32))
		} else {
			expHead = new(big.Int).SetBytes(getData(input, baseLen.Uint64(), expLen.Uint64()))
		}
	}
	// Calculate the adjusted exponent length
	var msb int
	if bitlen := expHead.BitLen(); bitlen > 0 {
		msb = bitlen - 1
	}
	adjExpLen := new(big.Int)
	if expLen.Cmp(big32) > 0 {
		adjExpLen.Sub(expLen, big32)
		adjExpLen.Mul(big8, adjExpLen)
	}
	adjExpLen.Add(adjExpLen, big.NewInt(int64(msb)))
	// Calculate the gas cost of the operation
	gas := new(big.Int).Set(math.BigMax(modLen, baseLen))
	if c.eip2565 {
		// EIP-2565 has three changes
		// 1. Different multComplexity (inlined here)
		// in EIP-2565 (https://eips.ethereum.org/EIPS/eip-2565):
		//
		// def mult_complexity(x):
		//    ceiling(x/8)^2
		//
		//where is x is max(length_of_MODULUS, length_of_BASE)
		gas = gas.Add(gas, big7)
		gas = gas.Div(gas, big8)
		gas.Mul(gas, gas)

		gas.Mul(gas, math.BigMax(adjExpLen, big1))
		// 2. Different divisor (`GQUADDIVISOR`) (3)
		gas.Div(gas, big3)
		if gas.BitLen() > 64 {
			return math.MaxUint64
		}
		// 3. Minimum price of 200 gas
		if gas.Uint64() < 200 {
			return 200
		}
		return gas.Uint64()
	}
	gas = modexpMultComplexity(gas)
	gas.Mul(gas, math.BigMax(adjExpLen, big1))
	gas.Div(gas, big20)

	if gas.BitLen() > 64 {
		return math.MaxUint64
	}
	return gas.Uint64()
}

func (c *bigModExp) Run(caller ContractRef, input []byte) ([]byte, error) {
	var (
		baseLen = new(big.Int).SetBytes(getData(input, 0, 32)).Uint64()
		expLen  = new(big.Int).SetBytes(getData(input, 32, 32)).Uint64()
		modLen  = new(big.Int).SetBytes(getData(input, 64, 32)).Uint64()
	)
	if len(input) > 96 {
		input = input[96:]
	} else {
		input = input[:0]
	}
	// Handle a special case when both the base and mod length is zero
	if baseLen == 0 && modLen == 0 {
		return []byte{}, nil
	}
	// Retrieve the operands and execute the exponentiation
	var (
		base = new(big.Int).SetBytes(getData(input, 0, baseLen))
		exp  = new(big.Int).SetBytes(getData(input, baseLen, expLen))
		mod  = new(big.Int).SetBytes(getData(input, baseLen+expLen, modLen))
	)
	if mod.BitLen() == 0 {
		// Modulo 0 is undefined, return zero
		return common.LeftPadBytes([]byte{}, int(modLen)), nil
	}
	return common.LeftPadBytes(base.Exp(base, exp, mod).Bytes(), int(modLen)), nil
}

// newCurvePoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newCurvePoint(blob []byte) (*bn256.G1, error) {
	p := new(bn256.G1)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// newTwistPoint unmarshals a binary blob into a bn256 elliptic curve point,
// returning it, or an error if the point is invalid.
func newTwistPoint(blob []byte) (*bn256.G2, error) {
	p := new(bn256.G2)
	if _, err := p.Unmarshal(blob); err != nil {
		return nil, err
	}
	return p, nil
}

// runBn256Add implements the Bn256Add precompile, referenced by both
// Byzantium and Istanbul operations.
func runBn256Add(input []byte) ([]byte, error) {
	x, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	y, err := newCurvePoint(getData(input, 64, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.Add(x, y)
	return res.Marshal(), nil
}

// bn256Add implements a native elliptic curve point addition conforming to
// Istanbul consensus rules.
type bn256AddIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256AddIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256AddGasIstanbul
}

func (c *bn256AddIstanbul) Run(caller ContractRef, input []byte) ([]byte, error) {
	return runBn256Add(input)
}

// bn256AddByzantium implements a native elliptic curve point addition
// conforming to Byzantium consensus rules.
type bn256AddByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256AddByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256AddGasByzantium
}

func (c *bn256AddByzantium) Run(caller ContractRef, input []byte) ([]byte, error) {
	return runBn256Add(input)
}

// runBn256ScalarMul implements the Bn256ScalarMul precompile, referenced by
// both Byzantium and Istanbul operations.
func runBn256ScalarMul(input []byte) ([]byte, error) {
	p, err := newCurvePoint(getData(input, 0, 64))
	if err != nil {
		return nil, err
	}
	res := new(bn256.G1)
	res.ScalarMult(p, new(big.Int).SetBytes(getData(input, 64, 32)))
	return res.Marshal(), nil
}

// bn256ScalarMulIstanbul implements a native elliptic curve scalar
// multiplication conforming to Istanbul consensus rules.
type bn256ScalarMulIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256ScalarMulIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256ScalarMulGasIstanbul
}

func (c *bn256ScalarMulIstanbul) Run(caller ContractRef, input []byte) ([]byte, error) {
	return runBn256ScalarMul(input)
}

// bn256ScalarMulByzantium implements a native elliptic curve scalar
// multiplication conforming to Byzantium consensus rules.
type bn256ScalarMulByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256ScalarMulByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256ScalarMulGasByzantium
}

func (c *bn256ScalarMulByzantium) Run(caller ContractRef, input []byte) ([]byte, error) {
	return runBn256ScalarMul(input)
}

var (
	// true32Byte is returned if the bn256 pairing check succeeds.
	true32Byte = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	// false32Byte is returned if the bn256 pairing check fails.
	false32Byte = make([]byte, 32)

	// errBadPairingInput is returned if the bn256 pairing input is invalid.
	errBadPairingInput = errors.New("bad elliptic curve pairing size")
)

// runBn256Pairing implements the Bn256Pairing precompile, referenced by both
// Byzantium and Istanbul operations.
func runBn256Pairing(input []byte) ([]byte, error) {
	// Handle some corner cases cheaply
	if len(input)%192 > 0 {
		return nil, errBadPairingInput
	}
	// Convert the input into a set of coordinates
	var (
		cs []*bn256.G1
		ts []*bn256.G2
	)
	for i := 0; i < len(input); i += 192 {
		c, err := newCurvePoint(input[i : i+64])
		if err != nil {
			return nil, err
		}
		t, err := newTwistPoint(input[i+64 : i+192])
		if err != nil {
			return nil, err
		}
		cs = append(cs, c)
		ts = append(ts, t)
	}
	// Execute the pairing checks and return the results
	if bn256.PairingCheck(cs, ts) {
		return true32Byte, nil
	}
	return false32Byte, nil
}

// bn256PairingIstanbul implements a pairing pre-compile for the bn256 curve
// conforming to Istanbul consensus rules.
type bn256PairingIstanbul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256PairingIstanbul) RequiredGas(input []byte) uint64 {
	return params.Bn256PairingBaseGasIstanbul + uint64(len(input)/192)*params.Bn256PairingPerPointGasIstanbul
}

func (c *bn256PairingIstanbul) Run(caller ContractRef, input []byte) ([]byte, error) {
	return runBn256Pairing(input)
}

// bn256PairingByzantium implements a pairing pre-compile for the bn256 curve
// conforming to Byzantium consensus rules.
type bn256PairingByzantium struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bn256PairingByzantium) RequiredGas(input []byte) uint64 {
	return params.Bn256PairingBaseGasByzantium + uint64(len(input)/192)*params.Bn256PairingPerPointGasByzantium
}

func (c *bn256PairingByzantium) Run(caller ContractRef, input []byte) ([]byte, error) {
	return runBn256Pairing(input)
}

type blake2F struct{}

func (c *blake2F) RequiredGas(input []byte) uint64 {
	// If the input is malformed, we can't calculate the gas, return 0 and let the
	// actual call choke and fault.
	if len(input) != blake2FInputLength {
		return 0
	}
	return uint64(binary.BigEndian.Uint32(input[0:4]))
}

const (
	blake2FInputLength        = 213
	blake2FFinalBlockBytes    = byte(1)
	blake2FNonFinalBlockBytes = byte(0)
)

var (
	errBlake2FInvalidInputLength = errors.New("invalid input length")
	errBlake2FInvalidFinalFlag   = errors.New("invalid final flag")
)

func (c *blake2F) Run(caller ContractRef, input []byte) ([]byte, error) {
	// Make sure the input is valid (correct length and final flag)
	if len(input) != blake2FInputLength {
		return nil, errBlake2FInvalidInputLength
	}
	if input[212] != blake2FNonFinalBlockBytes && input[212] != blake2FFinalBlockBytes {
		return nil, errBlake2FInvalidFinalFlag
	}
	// Parse the input into the Blake2b call parameters
	var (
		rounds = binary.BigEndian.Uint32(input[0:4])
		final  = (input[212] == blake2FFinalBlockBytes)

		h [8]uint64
		m [16]uint64
		t [2]uint64
	)
	for i := 0; i < 8; i++ {
		offset := 4 + i*8
		h[i] = binary.LittleEndian.Uint64(input[offset : offset+8])
	}
	for i := 0; i < 16; i++ {
		offset := 68 + i*8
		m[i] = binary.LittleEndian.Uint64(input[offset : offset+8])
	}
	t[0] = binary.LittleEndian.Uint64(input[196:204])
	t[1] = binary.LittleEndian.Uint64(input[204:212])

	// Execute the compression function, extract and return the result
	blake2b.F(&h, m, t, final, rounds)

	output := make([]byte, 64)
	for i := 0; i < 8; i++ {
		offset := i * 8
		binary.LittleEndian.PutUint64(output[offset:offset+8], h[i])
	}
	return output, nil
}

var (
	errBLS12381InvalidInputLength          = errors.New("invalid input length")
	errBLS12381InvalidFieldElementTopBytes = errors.New("invalid field element top bytes")
	errBLS12381G1PointSubgroup             = errors.New("g1 point is not on correct subgroup")
	errBLS12381G2PointSubgroup             = errors.New("g2 point is not on correct subgroup")
)

// bls12381G1Add implements EIP-2537 G1Add precompile.
type bls12381G1Add struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1Add) RequiredGas(input []byte) uint64 {
	return params.Bls12381G1AddGas
}

func (c *bls12381G1Add) Run(caller ContractRef, input []byte) ([]byte, error) {
	// Implements EIP-2537 G1Add precompile.
	// > G1 addition call expects `256` bytes as an input that is interpreted as byte concatenation of two G1 points (`128` bytes each).
	// > Output is an encoding of addition operation result - single G1 point (`128` bytes).
	if len(input) != 256 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0, p1 *bls12381.PointG1

	// Initialize G1
	g := bls12381.NewG1()

	// Decode G1 point p_0
	if p0, err = g.DecodePoint(input[:128]); err != nil {
		return nil, err
	}
	// Decode G1 point p_1
	if p1, err = g.DecodePoint(input[128:]); err != nil {
		return nil, err
	}

	// Compute r = p_0 + p_1
	r := g.New()
	g.Add(r, p0, p1)

	// Encode the G1 point result into 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G1Mul implements EIP-2537 G1Mul precompile.
type bls12381G1Mul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1Mul) RequiredGas(input []byte) uint64 {
	return params.Bls12381G1MulGas
}

func (c *bls12381G1Mul) Run(caller ContractRef, input []byte) ([]byte, error) {
	// Implements EIP-2537 G1Mul precompile.
	// > G1 multiplication call expects `160` bytes as an input that is interpreted as byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiplication operation result - single G1 point (`128` bytes).
	if len(input) != 160 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0 *bls12381.PointG1

	// Initialize G1
	g := bls12381.NewG1()

	// Decode G1 point
	if p0, err = g.DecodePoint(input[:128]); err != nil {
		return nil, err
	}
	// Decode scalar value
	e := new(big.Int).SetBytes(input[128:])

	// Compute r = e * p_0
	r := g.New()
	g.MulScalar(r, p0, e)

	// Encode the G1 point into 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G1MultiExp implements EIP-2537 G1MultiExp precompile.
type bls12381G1MultiExp struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G1MultiExp) RequiredGas(input []byte) uint64 {
	// Calculate G1 point, scalar value pair length
	k := len(input) / 160
	if k == 0 {
		// Return 0 gas for small input length
		return 0
	}
	// Lookup discount value for G1 point, scalar value pair length
	var discount uint64
	if dLen := len(params.Bls12381MultiExpDiscountTable); k < dLen {
		discount = params.Bls12381MultiExpDiscountTable[k-1]
	} else {
		discount = params.Bls12381MultiExpDiscountTable[dLen-1]
	}
	// Calculate gas and return the result
	return (uint64(k) * params.Bls12381G1MulGas * discount) / 1000
}

func (c *bls12381G1MultiExp) Run(caller ContractRef, input []byte) ([]byte, error) {
	// Implements EIP-2537 G1MultiExp precompile.
	// G1 multiplication call expects `160*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G1 point (`128` bytes) and encoding of a scalar value (`32` bytes).
	// Output is an encoding of multiexponentiation operation result - single G1 point (`128` bytes).
	k := len(input) / 160
	if len(input) == 0 || len(input)%160 != 0 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	points := make([]*bls12381.PointG1, k)
	scalars := make([]*big.Int, k)

	// Initialize G1
	g := bls12381.NewG1()

	// Decode point scalar pairs
	for i := 0; i < k; i++ {
		off := 160 * i
		t0, t1, t2 := off, off+128, off+160
		// Decode G1 point
		if points[i], err = g.DecodePoint(input[t0:t1]); err != nil {
			return nil, err
		}
		// Decode scalar value
		scalars[i] = new(big.Int).SetBytes(input[t1:t2])
	}

	// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
	r := g.New()
	g.MultiExp(r, points, scalars)

	// Encode the G1 point to 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2Add implements EIP-2537 G2Add precompile.
type bls12381G2Add struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2Add) RequiredGas(input []byte) uint64 {
	return params.Bls12381G2AddGas
}

func (c *bls12381G2Add) Run(caller ContractRef, input []byte) ([]byte, error) {
	// Implements EIP-2537 G2Add precompile.
	// > G2 addition call expects `512` bytes as an input that is interpreted as byte concatenation of two G2 points (`256` bytes each).
	// > Output is an encoding of addition operation result - single G2 point (`256` bytes).
	if len(input) != 512 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0, p1 *bls12381.PointG2

	// Initialize G2
	g := bls12381.NewG2()
	r := g.New()

	// Decode G2 point p_0
	if p0, err = g.DecodePoint(input[:256]); err != nil {
		return nil, err
	}
	// Decode G2 point p_1
	if p1, err = g.DecodePoint(input[256:]); err != nil {
		return nil, err
	}

	// Compute r = p_0 + p_1
	g.Add(r, p0, p1)

	// Encode the G2 point into 256 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2Mul implements EIP-2537 G2Mul precompile.
type bls12381G2Mul struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2Mul) RequiredGas(input []byte) uint64 {
	return params.Bls12381G2MulGas
}

func (c *bls12381G2Mul) Run(caller ContractRef, input []byte) ([]byte, error) {
	// Implements EIP-2537 G2MUL precompile logic.
	// > G2 multiplication call expects `288` bytes as an input that is interpreted as byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiplication operation result - single G2 point (`256` bytes).
	if len(input) != 288 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	var p0 *bls12381.PointG2

	// Initialize G2
	g := bls12381.NewG2()

	// Decode G2 point
	if p0, err = g.DecodePoint(input[:256]); err != nil {
		return nil, err
	}
	// Decode scalar value
	e := new(big.Int).SetBytes(input[256:])

	// Compute r = e * p_0
	r := g.New()
	g.MulScalar(r, p0, e)

	// Encode the G2 point into 256 bytes
	return g.EncodePoint(r), nil
}

// bls12381G2MultiExp implements EIP-2537 G2MultiExp precompile.
type bls12381G2MultiExp struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381G2MultiExp) RequiredGas(input []byte) uint64 {
	// Calculate G2 point, scalar value pair length
	k := len(input) / 288
	if k == 0 {
		// Return 0 gas for small input length
		return 0
	}
	// Lookup discount value for G2 point, scalar value pair length
	var discount uint64
	if dLen := len(params.Bls12381MultiExpDiscountTable); k < dLen {
		discount = params.Bls12381MultiExpDiscountTable[k-1]
	} else {
		discount = params.Bls12381MultiExpDiscountTable[dLen-1]
	}
	// Calculate gas and return the result
	return (uint64(k) * params.Bls12381G2MulGas * discount) / 1000
}

func (c *bls12381G2MultiExp) Run(caller ContractRef, input []byte) ([]byte, error) {
	// Implements EIP-2537 G2MultiExp precompile logic
	// > G2 multiplication call expects `288*k` bytes as an input that is interpreted as byte concatenation of `k` slices each of them being a byte concatenation of encoding of G2 point (`256` bytes) and encoding of a scalar value (`32` bytes).
	// > Output is an encoding of multiexponentiation operation result - single G2 point (`256` bytes).
	k := len(input) / 288
	if len(input) == 0 || len(input)%288 != 0 {
		return nil, errBLS12381InvalidInputLength
	}
	var err error
	points := make([]*bls12381.PointG2, k)
	scalars := make([]*big.Int, k)

	// Initialize G2
	g := bls12381.NewG2()

	// Decode point scalar pairs
	for i := 0; i < k; i++ {
		off := 288 * i
		t0, t1, t2 := off, off+256, off+288
		// Decode G1 point
		if points[i], err = g.DecodePoint(input[t0:t1]); err != nil {
			return nil, err
		}
		// Decode scalar value
		scalars[i] = new(big.Int).SetBytes(input[t1:t2])
	}

	// Compute r = e_0 * p_0 + e_1 * p_1 + ... + e_(k-1) * p_(k-1)
	r := g.New()
	g.MultiExp(r, points, scalars)

	// Encode the G2 point to 256 bytes.
	return g.EncodePoint(r), nil
}

// bls12381Pairing implements EIP-2537 Pairing precompile.
type bls12381Pairing struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381Pairing) RequiredGas(input []byte) uint64 {
	return params.Bls12381PairingBaseGas + uint64(len(input)/384)*params.Bls12381PairingPerPairGas
}

func (c *bls12381Pairing) Run(caller ContractRef, input []byte) ([]byte, error) {
	// Implements EIP-2537 Pairing precompile logic.
	// > Pairing call expects `384*k` bytes as an inputs that is interpreted as byte concatenation of `k` slices. Each slice has the following structure:
	// > - `128` bytes of G1 point encoding
	// > - `256` bytes of G2 point encoding
	// > Output is a `32` bytes where last single byte is `0x01` if pairing result is equal to multiplicative identity in a pairing target field and `0x00` otherwise
	// > (which is equivalent of Big Endian encoding of Solidity values `uint256(1)` and `uin256(0)` respectively).
	k := len(input) / 384
	if len(input) == 0 || len(input)%384 != 0 {
		return nil, errBLS12381InvalidInputLength
	}

	// Initialize BLS12-381 pairing engine
	e := bls12381.NewPairingEngine()
	g1, g2 := e.G1, e.G2

	// Decode pairs
	for i := 0; i < k; i++ {
		off := 384 * i
		t0, t1, t2 := off, off+128, off+384

		// Decode G1 point
		p1, err := g1.DecodePoint(input[t0:t1])
		if err != nil {
			return nil, err
		}
		// Decode G2 point
		p2, err := g2.DecodePoint(input[t1:t2])
		if err != nil {
			return nil, err
		}

		// 'point is on curve' check already done,
		// Here we need to apply subgroup checks.
		if !g1.InCorrectSubgroup(p1) {
			return nil, errBLS12381G1PointSubgroup
		}
		if !g2.InCorrectSubgroup(p2) {
			return nil, errBLS12381G2PointSubgroup
		}

		// Update pairing engine with G1 and G2 ponits
		e.AddPair(p1, p2)
	}
	// Prepare 32 byte output
	out := make([]byte, 32)

	// Compute pairing and set the result
	if e.Check() {
		out[31] = 1
	}
	return out, nil
}

// decodeBLS12381FieldElement decodes BLS12-381 elliptic curve field element.
// Removes top 16 bytes of 64 byte input.
func decodeBLS12381FieldElement(in []byte) ([]byte, error) {
	if len(in) != 64 {
		return nil, errors.New("invalid field element length")
	}
	// check top bytes
	for i := 0; i < 16; i++ {
		if in[i] != byte(0x00) {
			return nil, errBLS12381InvalidFieldElementTopBytes
		}
	}
	out := make([]byte, 48)
	copy(out[:], in[16:])
	return out, nil
}

// bls12381MapG1 implements EIP-2537 MapG1 precompile.
type bls12381MapG1 struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381MapG1) RequiredGas(input []byte) uint64 {
	return params.Bls12381MapG1Gas
}

func (c *bls12381MapG1) Run(caller ContractRef, input []byte) ([]byte, error) {
	// Implements EIP-2537 Map_To_G1 precompile.
	// > Field-to-curve call expects `64` bytes an an input that is interpreted as a an element of the base field.
	// > Output of this call is `128` bytes and is G1 point following respective encoding rules.
	if len(input) != 64 {
		return nil, errBLS12381InvalidInputLength
	}

	// Decode input field element
	fe, err := decodeBLS12381FieldElement(input)
	if err != nil {
		return nil, err
	}

	// Initialize G1
	g := bls12381.NewG1()

	// Compute mapping
	r, err := g.MapToCurve(fe)
	if err != nil {
		return nil, err
	}

	// Encode the G1 point to 128 bytes
	return g.EncodePoint(r), nil
}

// bls12381MapG2 implements EIP-2537 MapG2 precompile.
type bls12381MapG2 struct{}

// RequiredGas returns the gas required to execute the pre-compiled contract.
func (c *bls12381MapG2) RequiredGas(input []byte) uint64 {
	return params.Bls12381MapG2Gas
}

func (c *bls12381MapG2) Run(caller ContractRef, input []byte) ([]byte, error) {
	// Implements EIP-2537 Map_FP2_TO_G2 precompile logic.
	// > Field-to-curve call expects `128` bytes an an input that is interpreted as a an element of the quadratic extension field.
	// > Output of this call is `256` bytes and is G2 point following respective encoding rules.
	if len(input) != 128 {
		return nil, errBLS12381InvalidInputLength
	}

	// Decode input field element
	fe := make([]byte, 96)
	c0, err := decodeBLS12381FieldElement(input[:64])
	if err != nil {
		return nil, err
	}
	copy(fe[48:], c0)
	c1, err := decodeBLS12381FieldElement(input[64:])
	if err != nil {
		return nil, err
	}
	copy(fe[:48], c1)

	// Initialize G2
	g := bls12381.NewG2()

	// Compute mapping
	r, err := g.MapToCurve(fe)
	if err != nil {
		return nil, err
	}

	// Encode the G2 point to 256 bytes
	return g.EncodePoint(r), nil
}

func tupleDescriptorInit(input string) {

	//fmt.Println("** rulesapp: Example usage of the Rules module/API **")

	/////////////////////////REGISTER///////////////////////////////////

	//Load the tuple descriptor file (relative to GOPATH)

	//tupleDescAbsFileNm := fcommon.GetAbsPathForResource("src/github.com/project-flogo/rules/examples/rulesapp/rulesapp.json")
	//tupleDescriptor := fcommon.FileToString(tupleDescAbsFileNm)

	//tupleDescriptor := "[{\"name\": \"n1\",\"properties\":[{\"name\": \"name\",\"type\": \"string\",\"pk-index\": 0}]},{\"name\": \"n2\",\"properties\": [{\"name\": \"name\",\"type\": \"string\",\"pk-index\": 0}]}]"
	//fmt.Println(tupleDescriptor)

	if rs != nil {
		rs.Unregister()
		rs = nil
	}

	tupleDescriptor := input
	fmt.Printf("Loaded tuple descriptor: \n%s\n", tupleDescriptor)

	//First register the tuple descriptors
	err := model.RegisterTupleDescriptors(tupleDescriptor)
	if err != nil {
		fmt.Printf("Error [%s]\n", err)
		return
	}

	//Create a RuleSession
	rs, _ = ruleapi.GetOrCreateRuleSession("asession")

}

func ruleInit(strs []string) bool {

	if rs == nil || len(strs) < 4 {
		return false
	}

	rulename := strs[0]

	if ruleMap[rulename] != nil {
		println("Rule [" + rulename + "] already initialized")
		return true
	}

	rule := ruleapi.NewRule(rulename)
	//ruleMap[rulename] = rule

	rulestrs := strings.Split(strs[1], "&")

	for i := 0; i < len(rulestrs); i++ {
		cur := strings.Split(rulestrs[i], ";")
		rule.AddCondition(cur[0], strings.Split(cur[1][1:len(cur[1])-1], ","), conditionFactory(cur[2], strings.Split(cur[3], ",")), nil)
	}

	rule.SetAction(actionFactory(strs[2], strings.Split(strs[3], "&")))

	//rule.SetContext("This is a test of context")
	rs.AddRule(rule)
	ruleMap[rulename] = rule

	fmt.Printf("Rule added: [%s]\n", rule.GetName())

	return true
	/*
		//// check for name "Bob" in n1
		rulename := "n1.name == Bob"
		rule := ruleapi.NewRule(rulename)
		ruleMap[rulename] = rule

		rule.AddCondition("c1", []string{"n1"}, checkForBob, nil)
		rule.SetAction(checkForBobAction)
		rule.SetContext("This is a test of context")
		rs.AddRule(rule)
		fmt.Printf("Rule added: [%s]\n", rule.GetName())

		// check for name "Bob" in n1, match the "name" field in n2,
		// in effect, fire the rule when name field in both tuples is "Bob"
		rule2name := "n1.name == Bob && n1.name == n2.name"
		rule2 := ruleapi.NewRule(rule2name)
		ruleMap[rule2name] = rule2

		rule2.AddCondition("c1", []string{"n1"}, checkForBob, nil)
		rule2.AddCondition("c2", []string{"n1", "n2"}, checkSameNamesCondition, nil)
		rule2.SetAction(checkSameNamesAction)
		rs.AddRule(rule2)
		fmt.Printf("Rule added: [%s]\n", rule2.GetName())
	*/
}

func sessionStart() {
	if rs == nil {
		return
	}
	//Start the rule session
	rs.Start(nil)
}

func tupleAssert(strs []string) bool {
	if rs == nil {
		return false
	}

	retractQueue = nil

	if tupleMap[strs[0]] != nil {
		rs.Retract(context.TODO(), tupleMap[strs[0]])
		tupleMap[strs[0]] = nil
		fmt.Printf("Re-Assert Tuple , Retract Old One: [%s]\n", strs[0])
	}

	input := make([]interface{}, len(strs)-2)
	for i := 0; i < len(strs)-2; i++ {
		input[i] = strs[i+2]
	}

	t, _ := model.NewTupleWithKeyValues(model.TupleType(strs[1]), input...)
	tupleMap[strs[0]] = t
	t.GetKey().SetTupleName(strs[0])

	rs.Assert(context.TODO(), t)
	fmt.Printf("Tuple Asserted: [%s]\n", strs[0])

	return true
}

func tupleRetract(str string) {
	if rs == nil || tupleMap[str] == nil {
		return
	}
	rs.Retract(context.TODO(), tupleMap[str])
	tupleMap[str] = nil
	fmt.Printf("Tuple Retracted: [%s]\n", str)
}

func ruleDetele(str string) {
	if rs == nil || ruleMap[str] == nil {
		return
	}

	rs.DeleteRule(ruleMap[str].GetName())
	ruleMap[str] = nil
	fmt.Printf("Rule Deleted: [%s]\n", str)
}

func sessionDischarge() {

	ruleMap = make(map[string]model.MutableRule)
	tupleMap = make(map[string]model.MutableTuple)

	if rs == nil {
		fmt.Printf("Session is not existed")
		return
	}

	rs.Unregister()

	rs = nil

	fmt.Printf("Session Discharged")
}

// UtilFunc////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

func conditionFactory(conditionFuncName string, args []string) model.ConditionEvaluator {
	return conditionmap[conditionFuncName](args)
}

func actionFactory(actionFuncName string, args []string) model.ActionFunction {
	return actionmap[actionFuncName](args)
}

// args[0]:payerType
func checkBalance(args []string) model.ConditionEvaluator {
	return func(ruleName string, condName string, tuples map[model.TupleType]model.Tuple, ctx model.RuleContext) bool {

		t1 := tuples[model.TupleType(args[0])]
		account, _ := t1.GetString("account")

		fmt.Printf("checking balance of [%s]\n", account)

		balance, _ := t1.GetString("balance")
		value, _ := t1.GetString("value")

		aFloat := new(big.Float)
		aFloat.SetString(balance)

		bFloat := new(big.Float)
		bFloat.SetString(value)

		result := new(big.Float).Sub(aFloat, bFloat)

		if result.Cmp(big.NewFloat(0)) > 0 {
			return true
		} else {
			retractQueue = append(retractQueue, t1.GetKey().GetTupleName())
			return false
		}

	}
}

// args[0]:payerType,args[1]:recipientType
func checkID(args []string) model.ConditionEvaluator {
	return func(ruleName string, condName string, tuples map[model.TupleType]model.Tuple, ctx model.RuleContext) bool {
		t1 := tuples[model.TupleType(args[0])]
		t2 := tuples[model.TupleType(args[1])]

		payerid, _ := t1.GetString("id")
		reciid, _ := t2.GetString("id")

		fmt.Printf("checking id of [%s] and [%s]\n", payerid, reciid)

		return payerid == reciid
	}
}

// args[0]:payerType,args[1]:recipientType,args[2]:rate
func exchange(args []string) model.ActionFunction {
	return func(ctx context.Context, rs model.RuleSession, ruleName string, tuples map[model.TupleType]model.Tuple, ruleCtx model.RuleContext) {

		fmt.Printf("Rule fired: [%s] to [%s]\n", args[0], args[1])

		t1 := tuples[model.TupleType(args[0])]
		t2 := tuples[model.TupleType(args[1])]

		balance, _ := t1.GetString("balance")
		value, _ := t1.GetString("value")

		aFloat := new(big.Float)
		aFloat.SetString(balance)

		bFloat := new(big.Float)
		bFloat.SetString(value)

		payerResult := new(big.Float).Sub(aFloat, bFloat)

		balance, _ = t2.GetString("balance")

		aFloat = new(big.Float)
		aFloat.SetString(balance)

		rateFloat := new(big.Float)
		rateFloat.SetString(args[2])

		reciResult := new(big.Float).Add(aFloat, new(big.Float).Mul(bFloat, rateFloat))

		payerAccount, _ := t1.GetString("account")
		reciAccount, _ := t2.GetString("account")

		resultMap[payerAccount] = payerResult.String()
		resultMap[reciAccount] = reciResult.String()

		retractQueue = append(retractQueue, t1.GetKey().GetTupleName(), t2.GetKey().GetTupleName())
	}
}

func scanRetractedTuples(result string) string {
	if retractQueue == nil {
		return result
	}

	for _, tuplename := range retractQueue {
		tuple := tupleMap[tuplename]
		if tuple == nil {
			continue
		}
		//rs.Retract(context.TODO(), tuple)
		//tupleMap[tuplename] = nil
		result = result + tuplename + "&"
	}
	//retractQueue = nil
	return result[:len(result)-1]
}

func retractTuples() {
	if retractQueue == nil {
		return
	}

	for _, tuplename := range retractQueue {
		tuple := tupleMap[tuplename]
		if tuple == nil {
			continue
		}
		rs.Retract(context.TODO(), tuple)
		tupleMap[tuplename] = nil
	}

	retractQueue = nil
}

// Experiment/////////////////////////////////////////////////////////////////////////////////////////////////////////////
func test_Init() {

	//fmt.Println("** rulesapp: Example usage of the Rules module/API **")

	/////////////////////////REGISTER///////////////////////////////////

	//Load the tuple descriptor file (relative to GOPATH)

	//tupleDescAbsFileNm := fcommon.GetAbsPathForResource("src/github.com/project-flogo/rules/examples/rulesapp/rulesapp.json")
	//tupleDescriptor := fcommon.FileToString(tupleDescAbsFileNm)

	//tupleDescriptor := "[{\"name\": \"n1\",\"properties\":[{\"name\": \"name\",\"type\": \"string\",\"pk-index\": 0}]},{\"name\": \"n2\",\"properties\": [{\"name\": \"name\",\"type\": \"string\",\"pk-index\": 0}]}]"
	//fmt.Println(tupleDescriptor)

	if rs != nil {
		rs.Unregister()
		rs = nil
	}

	tupleDescAbsFileNm := fcommon.GetAbsPathForResource("test4.json")
	tupleDescriptor := fcommon.FileToString(tupleDescAbsFileNm)
	fmt.Printf("Loaded tuple descriptor: \n%s\n", tupleDescriptor)

	//First register the tuple descriptors
	err := model.RegisterTupleDescriptors(tupleDescriptor)
	if err != nil {
		fmt.Printf("Error [%s]\n", err)
		return
	}

	//Create a RuleSession
	rs, _ = ruleapi.GetOrCreateRuleSession("asession")

	rulename := "test"
	rule := ruleapi.NewRule(rulename)
	ruleMap[rulename] = rule
	rule.AddCondition("c0", []string{"n1"}, conditionFactory("testconfunc", nil), nil)
	rule.SetAction(actionFactory("testactfunc", []string{"n1"}))
	rule.SetContext("This is a test of context")
	rs.AddRule(rule)
	fmt.Printf("Rule added: [%s]\n", rule.GetName())

	//Start the rule session
	rs.Start(nil)

	fmt.Println("==================================RuleSession started========================================")

}

// Experiment/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// args[]:nil
func testconfunc(args []string) model.ConditionEvaluator {
	return func(ruleName string, condName string, tuples map[model.TupleType]model.Tuple, ctx model.RuleContext) bool {

		println("Condition Activated")

		return true
	}
}

// args[0]:nil
func testactfunc(args []string) model.ActionFunction {
	return func(ctx context.Context, rs model.RuleSession, ruleName string, tuples map[model.TupleType]model.Tuple, ruleCtx model.RuleContext) {

		println("Action Activated")

		t1 := tuples[model.TupleType(args[0])]

		retractQueue = append(retractQueue, t1.GetKey().GetTupleName())

		//tag = 1

	}
}

// args[0]:tupleType,args[1]:prop(n)
func test2confunc(args []string) model.ConditionEvaluator {
	return func(ruleName string, condName string, tuples map[model.TupleType]model.Tuple, ctx model.RuleContext) bool {

		//fmt.Println("Condition Activated")

		tuple := tuples[model.TupleType(args[0])]

		prop, _ := tuple.GetString(args[1])

		fmt.Println(args[1] + ":" + prop)

		return true
	}
}

// args[0]:tupleType
func test4actfunc(args []string) model.ActionFunction {
	return func(ctx context.Context, rs model.RuleSession, ruleName string, tuples map[model.TupleType]model.Tuple, ruleCtx model.RuleContext) {

		tuple := tuples[model.TupleType(args[0])]

		//counter++

		//fmt.Println(fmt.Sprint("counter:", counter))

		tuplename := tuple.GetKey().GetTupleName()

		resultMap[tuplename] = tuplename
		resultMap[tuplename] = tuplename

		retractQueue = append(retractQueue, tuplename)

	}
}

// args[0].args[1]>args[2].args[3] ?
func Comparator(args []string) model.ConditionEvaluator {
	return func(ruleName string, condName string, tuples map[model.TupleType]model.Tuple, ctx model.RuleContext) bool {

		v1, _ := tuples[model.TupleType(args[0])].GetInt(args[1])
		v2, _ := tuples[model.TupleType(args[2])].GetInt(args[3])

		return v1 > v2

	}
}

// args[0].args[1] == args[2].args[3] ?
func Equals(args []string) model.ConditionEvaluator {
	return func(ruleName string, condName string, tuples map[model.TupleType]model.Tuple, ctx model.RuleContext) bool {

		v1, _ := tuples[model.TupleType(args[0])].GetString(args[1])
		v2, _ := tuples[model.TupleType(args[2])].GetString(args[3])

		return v1 == v2

	}
}

// args[0].args[1] += args[2]//
func Airdrop(args []string) model.ActionFunction {
	return func(ctx context.Context, rs model.RuleSession, ruleName string, tuples map[model.TupleType]model.Tuple, ruleCtx model.RuleContext) {
		//读取用户地址
		user := tuples[model.TupleType(args[0])]
		address, _ := user.GetString("address")
		//读取用户余额
		balance := 0
		if resultMap[address] == "" {
			balance, _ = user.GetInt(args[1])
		} else {
			balance, _ = strconv.Atoi(resultMap[address])
		}
		//发放空投
		bonus, _ := strconv.Atoi(args[2])
		balance += bonus
		//保存结果至状态更新表
		resultMap[address] = strconv.Itoa(balance)
		//将用户元组放入销毁队列
		retractQueue = append(retractQueue, user.GetKey().GetTupleName())
	}
}
