package node

import (
	"github.com/hyperledger/fabric/orderer/consensus/pbft/message"
	"github.com/hyperledger/fabric/orderer/consensus/pbft/server"
	"log"
)

func (n *Node) prepareRecvAndCommitSendThread() {
	for {
		select {
		case msg := <-n.prepareRecv:
			if !n.checkPrepareMsg(msg) {
				continue
			}
			// buffer the prepare msg
			n.buffer.BufferPrepareMsg(msg)
			// verify send commit msg
			if !n.IsPrimary() {
				content, msg, err := message.NewCommitMsg(n.id, msg)
				if err != nil {
					continue
				}
				n.Primary(content, server.CommitEntry)
				n.GetAck(content, server.CommitACKEntry, func() {
					// if commit success, it is time to execute
					n.readytoExecute(msg.Digest)
				})
				continue
			}
			if n.IsPrimary() && n.buffer.IsTrueOfPrepareMsg(msg.Digest, n.cfg.FaultNum) {
				log.Printf("[Prepare] prepare msg(%d) vote success and to send commit", msg.Sequence)
				_, msg, err := message.NewCommitMsg(n.id, msg)
				if err != nil {
					continue
				}
				// buffer commit msg
				n.buffer.BufferCommitMsg(msg)
				// TODO broadcast error when buffer the commit msg
			}
			if n.buffer.IsReadyToExecute(msg.Digest, n.cfg.FaultNum, msg.View, msg.Sequence) {
				n.readytoExecute(msg.Digest)
			}
		}
	}
}

func (n *Node) checkPrepareMsg(msg *message.Prepare) bool {
	if n.view != msg.View {
		return false
	}
	if !n.sequence.CheckBound(msg.Sequence) {
		return false
	}
	return true
}