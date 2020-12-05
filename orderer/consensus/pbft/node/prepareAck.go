package node

import "github.com/hyperledger/fabric/orderer/consensus/pbft/message"

func (n *Node) IsPrepareAck(msg *message.Prepare) bool {
	return n.buffer.IsTrueOfPrepareMsg(msg.Digest, n.cfg.FaultNum)
}