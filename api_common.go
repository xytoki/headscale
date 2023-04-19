package headscale

import (
	"fmt"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

func (h *Headscale) getDERPMapByMachine(machine *Machine) *tailcfg.DERPMap {
	ignRegions := make(map[string]bool)
	for _, tag := range machine.ForcedTags {
		// tag:ignore-derp-{x}
		if strings.HasPrefix(tag, "tag:ignore-derp-") {
			ignRegions[strings.TrimPrefix(tag, "tag:ignore-derp-")] = true
		}
	}

	if len(ignRegions) == 0 {
		return h.DERPMap
	}
	regions := make(map[int]*tailcfg.DERPRegion)
	for id, region := range h.DERPMap.Regions {
		if _, ok := ignRegions[fmt.Sprintf("%d", id)]; ok {
			continue
		}
		regions[id] = region
	}

	return &tailcfg.DERPMap{
		Regions:            regions,
		OmitDefaultRegions: h.DERPMap.OmitDefaultRegions,
	}
}

func (h *Headscale) filterPeerDERP(machine *Machine, nodePeers []*tailcfg.Node) {
	derpMagicIP := "127.3.3.40:"
	ignRegions := make(map[string]bool)
	defaultDerp := "0"
	for _, tag := range machine.ForcedTags {
		// tag:ignore-derp-{x}
		if strings.HasPrefix(tag, "tag:ignore-derp-") {
			ignRegions[strings.TrimPrefix(tag, "tag:ignore-derp-")] = true
		}
		if strings.HasPrefix(tag, "tag:fallback-derp-") {
			defaultDerp = strings.TrimPrefix(tag, "tag:fallback-derp-")
		}
	}
	if len(ignRegions) == 0 {
		return
	}
	for _, node := range nodePeers {
		derpPort := strings.TrimPrefix(node.DERP, derpMagicIP)
		if _, ok := ignRegions[derpPort]; ok {
			node.DERP = derpMagicIP + defaultDerp
		}
	}
}

func (h *Headscale) generateMapResponse(
	mapRequest tailcfg.MapRequest,
	machine *Machine,
) (*tailcfg.MapResponse, error) {
	log.Trace().
		Str("func", "generateMapResponse").
		Str("machine", mapRequest.Hostinfo.Hostname).
		Msg("Creating Map response")
	node, err := h.toNode(*machine, h.cfg.BaseDomain, h.cfg.DNSConfig)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "generateMapResponse").
			Err(err).
			Msg("Cannot convert to node")

		return nil, err
	}

	peers, err := h.getValidPeers(machine)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "generateMapResponse").
			Err(err).
			Msg("Cannot fetch peers")

		return nil, err
	}

	profiles := h.getMapResponseUserProfiles(*machine, peers)

	nodePeers, err := h.toNodes(peers, h.cfg.BaseDomain, h.cfg.DNSConfig)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "generateMapResponse").
			Err(err).
			Msg("Failed to convert peers to Tailscale nodes")

		return nil, err
	}
	h.filterPeerDERP(machine, nodePeers)

	dnsConfig := getMapResponseDNSConfig(
		h.cfg.DNSConfig,
		h.cfg.BaseDomain,
		*machine,
		peers,
	)

	now := time.Now()

	resp := tailcfg.MapResponse{
		KeepAlive: false,
		Node:      node,

		// TODO: Only send if updated
		DERPMap: h.getDERPMapByMachine(machine),

		// TODO: Only send if updated
		Peers: nodePeers,

		// TODO(kradalby): Implement:
		// https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L1351-L1374
		// PeersChanged
		// PeersRemoved
		// PeersChangedPatch
		// PeerSeenChange
		// OnlineChange

		// TODO: Only send if updated
		DNSConfig: dnsConfig,

		// TODO: Only send if updated
		Domain: h.cfg.BaseDomain,

		// Do not instruct clients to collect services, we do not
		// support or do anything with them
		CollectServices: "false",

		// TODO: Only send if updated
		PacketFilter: h.aclRules,

		UserProfiles: profiles,

		// TODO: Only send if updated
		SSHPolicy: h.sshPolicy,

		ControlTime: &now,

		Debug: &tailcfg.Debug{
			DERPRoute:           "true",
			DisableLogTail:      !h.cfg.LogTail.Enabled,
			RandomizeClientPort: h.cfg.RandomizeClientPort,
		},
	}

	log.Trace().
		Str("func", "generateMapResponse").
		Str("machine", mapRequest.Hostinfo.Hostname).
		// Interface("payload", resp).
		Msgf("Generated map response: %s", tailMapResponseToString(resp))

	return &resp, nil
}
