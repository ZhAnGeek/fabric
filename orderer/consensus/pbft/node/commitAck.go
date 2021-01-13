package node

import (
	"github.com/hyperledger/fabric/orderer/consensus/pbft/message"
)

func (n *Node) IsCommitAck(msg *message.Commit) bool {
	return n.buffer.IsCommitStateReady(msg.Digest)
}