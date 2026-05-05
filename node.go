package aegis

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/zoobz-io/sctx"
)

// NodeType represents the type of node in the mesh.
type NodeType string

const (
	// NodeTypeGeneric is the default node type.
	NodeTypeGeneric NodeType = "generic"
)

// Node represents a node in the mesh network.
type Node struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Type        NodeType     `json:"type"`
	Address     string       `json:"address"`
	Services    []ServiceInfo `json:"services,omitempty"`
	Health      *HealthInfo  `json:"health"`
	PeerManager *PeerManager `json:"-"`
	MeshServer  *MeshServer  `json:"-"`
	Topology    *Topology    `json:"-"`
	TLSConfig   *TLSConfig   `json:"-"`
	Admin       sctx.Admin[Metadata]  `json:"-"`
	Guards      *GuardRegistry        `json:"-"`
	nodeToken   sctx.SignedToken
}

// NewNode creates a new mesh node.
func NewNode(id, name string, nodeType NodeType, address string) *Node {
	node := &Node{
		ID:      id,
		Name:    name,
		Type:    nodeType,
		Address: address,
		Health:  NewHealthInfo(),
	}

	node.PeerManager = NewPeerManager(id)
	node.MeshServer = NewMeshServer(node)
	node.Topology = NewTopology()

	// Add self to topology
	nodeInfo := NodeInfo{
		ID:       id,
		Name:     name,
		Type:     nodeType,
		Address:  address,
		Services: node.Services,
	}
	_ = node.Topology.AddNode(nodeInfo)

	return node
}

// EnableTLS enables TLS for the node using the specified certificate directory.
func (n *Node) EnableTLS(certDir string) error {
	tlsConfig, err := LoadOrGenerateTLS(n.ID, certDir)
	if err != nil {
		return fmt.Errorf("failed to setup TLS: %w", err)
	}

	n.TLSConfig = tlsConfig

	if n.MeshServer != nil {
		n.MeshServer.SetTLSConfig(tlsConfig)
	}

	if n.PeerManager != nil {
		n.PeerManager.SetTLSConfig(tlsConfig)
	}

	return nil
}

// String returns a string representation of the node.
func (n *Node) String() string {
	return fmt.Sprintf("Node[%s:%s] %s @ %s", n.Type, n.ID, n.Name, n.Address)
}

// MarshalJSON implements json.Marshaler.
func (n *Node) MarshalJSON() ([]byte, error) {
	type Alias Node
	return json.Marshal((*Alias)(n))
}

// UnmarshalJSON implements json.Unmarshaler.
func (n *Node) UnmarshalJSON(data []byte) error {
	type Alias Node
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(n),
	}
	return json.Unmarshal(data, &aux)
}

// Validate validates the node configuration.
func (n *Node) Validate() error {
	if n.ID == "" {
		return fmt.Errorf("node ID cannot be empty")
	}
	if n.Name == "" {
		return fmt.Errorf("node name cannot be empty")
	}
	if n.Address == "" {
		return fmt.Errorf("node address cannot be empty")
	}

	_, _, err := net.SplitHostPort(n.Address)
	if err != nil {
		return fmt.Errorf("invalid address format: %w", err)
	}

	return nil
}

// SetHealth updates the node's health status.
func (n *Node) SetHealth(status HealthStatus, message string, err error) {
	if n.Health == nil {
		n.Health = NewHealthInfo()
	}
	n.Health.Update(status, message, err)
}

// GetHealth returns the node's health status and message.
func (n *Node) GetHealth() (HealthStatus, string) {
	if n.Health == nil {
		return HealthStatusUnknown, "Health not initialized"
	}
	status, _, message, errMsg := n.Health.Get()
	if errMsg != "" {
		return status, fmt.Sprintf("%s (Error: %s)", message, errMsg)
	}
	return status, message
}

// IsHealthy returns whether the node is healthy.
func (n *Node) IsHealthy() bool {
	if n.Health == nil {
		return false
	}
	return n.Health.IsHealthy()
}

// CheckHealth runs a health check using the provided checker.
func (n *Node) CheckHealth(ctx context.Context, checker HealthChecker) error {
	if checker == nil {
		n.SetHealth(HealthStatusUnhealthy, "No health checker provided", fmt.Errorf("health checker is nil"))
		return fmt.Errorf("health checker is nil")
	}

	err := checker.Check(ctx)
	if err != nil {
		n.SetHealth(HealthStatusUnhealthy, fmt.Sprintf("Health check failed: %s", checker.Name()), err)
		return err
	}

	n.SetHealth(HealthStatusHealthy, fmt.Sprintf("Health check passed: %s", checker.Name()), nil)
	return nil
}

// StartServer starts the gRPC mesh server.
func (n *Node) StartServer() error {
	if n.MeshServer == nil {
		return fmt.Errorf("mesh server not initialized")
	}
	return n.MeshServer.Start()
}

// StopServer stops the gRPC mesh server.
func (n *Node) StopServer() {
	if n.MeshServer != nil {
		n.MeshServer.Stop()
	}
}

// AddPeer adds a peer connection.
func (n *Node) AddPeer(info PeerInfo) error {
	if n.PeerManager == nil {
		return fmt.Errorf("peer manager not initialized")
	}
	return n.PeerManager.AddPeer(info)
}

// RemovePeer removes a peer connection.
func (n *Node) RemovePeer(peerID string) error {
	if n.PeerManager == nil {
		return fmt.Errorf("peer manager not initialized")
	}
	return n.PeerManager.RemovePeer(peerID)
}

// GetPeer returns a peer by ID.
func (n *Node) GetPeer(peerID string) (*Peer, bool) {
	if n.PeerManager == nil {
		return nil, false
	}
	return n.PeerManager.GetPeer(peerID)
}

// GetAllPeers returns all connected peers.
func (n *Node) GetAllPeers() []*Peer {
	if n.PeerManager == nil {
		return nil
	}
	return n.PeerManager.GetAllPeers()
}

// PingPeer sends a ping to a peer.
func (n *Node) PingPeer(ctx context.Context, peerID string) (*PingResponse, error) {
	if n.PeerManager == nil {
		return nil, fmt.Errorf("peer manager not initialized")
	}
	return n.PeerManager.PingPeer(ctx, peerID)
}

// GetPeerHealth retrieves the health status of a peer.
func (n *Node) GetPeerHealth(ctx context.Context, peerID string) (*HealthResponse, error) {
	if n.PeerManager == nil {
		return nil, fmt.Errorf("peer manager not initialized")
	}
	return n.PeerManager.GetPeerHealth(ctx, peerID)
}

// GetPeerNodeInfo retrieves node information from a peer.
func (n *Node) GetPeerNodeInfo(ctx context.Context, peerID string) (*NodeInfoResponse, error) {
	if n.PeerManager == nil {
		return nil, fmt.Errorf("peer manager not initialized")
	}
	return n.PeerManager.GetPeerNodeInfo(ctx, peerID)
}

// GetTopologyVersion returns the current topology version.
func (n *Node) GetTopologyVersion() int64 {
	if n.Topology == nil {
		return 0
	}
	return n.Topology.GetVersion()
}

// GetMeshNodes returns all nodes in the topology.
func (n *Node) GetMeshNodes() []NodeInfo {
	if n.Topology == nil {
		return nil
	}
	return n.Topology.GetAllNodes()
}

// SyncTopology synchronizes topology with a specific peer.
func (n *Node) SyncTopology(ctx context.Context, peerID string) error {
	if n.Topology == nil || n.PeerManager == nil {
		return fmt.Errorf("topology or peer manager not initialized")
	}

	peer, exists := n.GetPeer(peerID)
	if !exists {
		return fmt.Errorf("peer %s not found", peerID)
	}

	req := &TopologySyncRequest{
		SenderId: n.ID,
		Version:  n.Topology.GetVersion(),
	}

	resp, err := peer.Client.SyncTopology(ctx, req)
	if err != nil {
		return err
	}

	if resp.Version > n.Topology.GetVersion() {
		newTopology := NewTopology()
		for _, nodeProto := range resp.Nodes {
			_ = newTopology.AddNode(protoToNodeInfo(nodeProto))
		}
		newTopology.Version = resp.Version
		newTopology.UpdatedAt = time.Unix(resp.UpdatedAt, 0)

		n.Topology.Merge(newTopology)
	}

	return nil
}

// SyncTopologyWithAllPeers synchronizes topology with all connected peers.
func (n *Node) SyncTopologyWithAllPeers(ctx context.Context) error {
	if n.Topology == nil || n.PeerManager == nil {
		return fmt.Errorf("topology or peer manager not initialized")
	}

	peers := n.GetAllPeers()
	var lastErr error

	for _, peer := range peers {
		if err := n.SyncTopology(ctx, peer.Info.ID); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// Guard registers a guard for a gRPC method on this node.
func (n *Node) Guard(method string, guard sctx.Guard) {
	if n.Guards == nil {
		n.Guards = NewGuardRegistry()
	}
	n.Guards.Register(method, guard)
}

// Shutdown gracefully shuts down the node.
func (n *Node) Shutdown() error {
	n.StopServer()

	if n.PeerManager != nil {
		return n.PeerManager.Close()
	}

	return nil
}
