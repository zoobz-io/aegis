package aegis

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/zoobz-io/sctx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// ServiceRegistrar is called to register additional gRPC services.
type ServiceRegistrar func(*grpc.Server)

// MeshServer handles gRPC mesh service requests.
type MeshServer struct {
	UnimplementedMeshServiceServer
	node       *Node
	server     *grpc.Server
	listener   net.Listener
	tlsConfig  *TLSConfig
	registrars []ServiceRegistrar
	admin      sctx.Admin[Metadata]
	guards     *GuardRegistry
	nodeToken  sctx.SignedToken
}

// NewMeshServer creates a new mesh server for the node.
func NewMeshServer(node *Node) *MeshServer {
	return &MeshServer{
		node: node,
	}
}

// SetTLSConfig sets the TLS configuration for the server.
func (ms *MeshServer) SetTLSConfig(tlsConfig *TLSConfig) {
	ms.tlsConfig = tlsConfig
}

// RegisterService adds a service registrar to be called when the server starts.
func (ms *MeshServer) RegisterService(r ServiceRegistrar) {
	ms.registrars = append(ms.registrars, r)
}

// SetAuth configures auth for the server, enabling guard interceptors.
func (ms *MeshServer) SetAuth(admin sctx.Admin[Metadata], guards *GuardRegistry) {
	ms.admin = admin
	ms.guards = guards
}

// Start starts the gRPC server.
func (ms *MeshServer) Start() error {
	if ms.node == nil {
		return fmt.Errorf("node cannot be nil")
	}

	if ms.tlsConfig == nil {
		return fmt.Errorf("TLS configuration is required but not set")
	}

	lc := &net.ListenConfig{}
	listener, err := lc.Listen(context.Background(), "tcp", ms.node.Address)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", ms.node.Address, err)
	}

	ms.listener = listener

	creds := credentials.NewTLS(ms.tlsConfig.GetServerTLSConfig())
	opts := []grpc.ServerOption{grpc.Creds(creds)}

	if ms.admin != nil && ms.guards != nil {
		opts = append(opts,
			grpc.ChainUnaryInterceptor(UnaryGuardInterceptor(ms.guards, ms.admin, ms.nodeToken)),
			grpc.ChainStreamInterceptor(StreamGuardInterceptor(ms.guards, ms.admin, ms.nodeToken)),
		)
	}

	ms.server = grpc.NewServer(opts...)
	RegisterMeshServiceServer(ms.server, ms)

	// Register additional services
	for _, r := range ms.registrars {
		r(ms.server)
	}

	go func() {
		_ = ms.server.Serve(listener)
	}()

	return nil
}

// Stop gracefully stops the gRPC server.
func (ms *MeshServer) Stop() {
	if ms.server != nil {
		ms.server.GracefulStop()
	}
	if ms.listener != nil {
		_ = ms.listener.Close()
	}
}

// Ping responds to ping requests.
func (ms *MeshServer) Ping(ctx context.Context, req *PingRequest) (*PingResponse, error) {
	return &PingResponse{
		ReceiverId: ms.node.ID,
		Timestamp:  time.Now().Unix(),
		Success:    true,
	}, nil
}

// GetHealth returns the health status of this node.
func (ms *MeshServer) GetHealth(ctx context.Context, req *HealthRequest) (*HealthResponse, error) {
	if ms.node.Health == nil {
		return &HealthResponse{
			NodeId:      ms.node.ID,
			Status:      string(HealthStatusUnknown),
			LastChecked: 0,
			Message:     "Health not initialized",
			Error:       "",
		}, nil
	}

	status, lastChecked, message, errMsg := ms.node.Health.Get()

	return &HealthResponse{
		NodeId:      ms.node.ID,
		Status:      string(status),
		LastChecked: lastChecked.Unix(),
		Message:     message,
		Error:       errMsg,
	}, nil
}

// GetNodeInfo returns information about this node.
func (ms *MeshServer) GetNodeInfo(ctx context.Context, req *NodeInfoRequest) (*NodeInfoResponse, error) {
	healthResp, err := ms.GetHealth(ctx, &HealthRequest{SenderId: req.SenderId})
	if err != nil {
		return nil, fmt.Errorf("failed to get health info: %w", err)
	}

	return &NodeInfoResponse{
		Id:      ms.node.ID,
		Name:    ms.node.Name,
		Type:    string(ms.node.Type),
		Address: ms.node.Address,
		Health:  healthResp,
	}, nil
}

// SyncTopology handles topology synchronization requests.
func (ms *MeshServer) SyncTopology(ctx context.Context, req *TopologySyncRequest) (*TopologySyncResponse, error) {
	if ms.node.Topology == nil {
		return &TopologySyncResponse{
			Version:   0,
			UpdatedAt: time.Now().Unix(),
			Nodes:     nil,
		}, nil
	}

	nodes := ms.node.Topology.GetAllNodes()
	protoNodes := make([]*TopologyNode, 0, len(nodes))

	for _, node := range nodes {
		protoNodes = append(protoNodes, nodeInfoToProto(node))
	}

	return &TopologySyncResponse{
		Version:   ms.node.Topology.GetVersion(),
		UpdatedAt: ms.node.Topology.UpdatedAt.Unix(),
		Nodes:     protoNodes,
	}, nil
}

// GetTopology returns the current topology.
func (ms *MeshServer) GetTopology(ctx context.Context, req *GetTopologyRequest) (*GetTopologyResponse, error) {
	if ms.node.Topology == nil {
		return &GetTopologyResponse{
			Version: 0,
			Nodes:   nil,
		}, nil
	}

	nodes := ms.node.Topology.GetAllNodes()
	protoNodes := make([]*TopologyNode, 0, len(nodes))

	for _, node := range nodes {
		protoNodes = append(protoNodes, nodeInfoToProto(node))
	}

	return &GetTopologyResponse{
		Version: ms.node.Topology.GetVersion(),
		Nodes:   protoNodes,
	}, nil
}

// nodeInfoToProto converts a NodeInfo to a TopologyNode proto message.
func nodeInfoToProto(node NodeInfo) *TopologyNode {
	protoServices := make([]*Service, 0, len(node.Services))
	for _, svc := range node.Services {
		protoServices = append(protoServices, &Service{
			Name:    svc.Name,
			Version: svc.Version,
		})
	}

	return &TopologyNode{
		Id:        node.ID,
		Name:      node.Name,
		Type:      string(node.Type),
		Address:   node.Address,
		JoinedAt:  node.JoinedAt.Unix(),
		UpdatedAt: node.UpdatedAt.Unix(),
		Services:  protoServices,
	}
}

// protoToNodeInfo converts a TopologyNode proto message to a NodeInfo.
func protoToNodeInfo(node *TopologyNode) NodeInfo {
	services := make([]ServiceInfo, 0, len(node.Services))
	for _, svc := range node.Services {
		services = append(services, ServiceInfo{
			Name:    svc.Name,
			Version: svc.Version,
		})
	}

	return NodeInfo{
		ID:        node.Id,
		Name:      node.Name,
		Type:      NodeType(node.Type),
		Address:   node.Address,
		Services:  services,
		JoinedAt:  time.Unix(node.JoinedAt, 0),
		UpdatedAt: time.Unix(node.UpdatedAt, 0),
	}
}
