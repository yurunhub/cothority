package medco

import (
	"testing"
	"time"
	"github.com/dedis/cothority/log"
	"github.com/dedis/cothority/network"
	"github.com/dedis/cothority/protocols/medco"
	"github.com/dedis/cothority/sda"
	. "github.com/dedis/cothority/services/medco/libmedco"
	"github.com/dedis/crypto/random"
	"reflect"
)

var clientPrivate = network.Suite.Scalar().Pick(random.Stream)
var clientPublic = network.Suite.Point().Mul(network.Suite.Point().Base(), clientPrivate)

//NewProbabilisticSwitchingTest default constructor such that each node use it and generates a SurveyPHKey needed
func NewProbabilisticSwitchingTest(tni *sda.TreeNodeInstance) (sda.ProtocolInstance, error) {

	pi, err := medco.NewProbabilisticSwitchingProtocol(tni)
	protocol := pi.(*medco.ProbabilisticSwitchingProtocol)
	priv := protocol.Private()
	protocol.SurveyPHKey = &priv

	return protocol, err
}

//TestProbabilisticSwitching tests probabilistic switching protocol
func TestProbabilisticSwitching(t *testing.T) {
	defer log.AfterTest(t)
	local := sda.NewLocalTest()
	log.TestOutput(testing.Verbose(), 1)
	_, entityList, tree := local.GenTree(5, false, true, true)
	sda.ProtocolRegisterName("ProbabilisticSwitchingTest", NewProbabilisticSwitchingTest)

	defer local.CloseAll()

	rootInstance, _ := local.CreateProtocol(tree, "ProbabilisticSwitchingTest")
	protocol := rootInstance.(*medco.ProbabilisticSwitchingProtocol)

	//create dummy data
	aggregateKey := entityList.Aggregate

	expRes := []int64{1,1}
	point := network.Suite.Scalar().SetInt64(1)
	multPoint := network.Suite.Point().Mul(network.Suite.Point().Base(), point)
	multPoint.Add(multPoint, aggregateKey)
	det := DeterministCipherText{multPoint}

	var mapi map[TempID]DeterministCipherVector
	mapi = make(map[TempID]DeterministCipherVector)
	mapi[TempID(1)] = DeterministCipherVector{det, det}
	mapi[TempID(1)] = DeterministCipherVector{det, det}
	protocol.TargetOfSwitch = &mapi
	protocol.TargetPublicKey = &clientPublic

	//run protocol
	feedback := protocol.FeedbackChannel

	go protocol.StartProtocol()

	timeout := network.WaitRetry * time.Duration(network.MaxRetry*5*2) * time.Millisecond

	//verify results
	select {
		case encryptedResult := <-feedback:
			val1 := encryptedResult[TempID(1)]
			cv1 := DecryptIntVector(clientPrivate, &val1)
			val2 := encryptedResult[TempID(1)]
			cv2 := DecryptIntVector(clientPrivate, &val2)
			if !reflect.DeepEqual(cv1, expRes) {
				t.Fatal("Wrong results, expected ", expRes, " and got ", cv1)
			}
			if !reflect.DeepEqual(cv2, expRes) {
				t.Fatal("Wrong results, expected ", expRes, " and got ", cv2)
			}

	case <-time.After(timeout):
			t.Fatal("Didn't finish in time")
	}
}