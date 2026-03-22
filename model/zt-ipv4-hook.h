/*

Authors:Rahul S,Dr.Subbulakshmi T,Arun Santhosh R A
Github ID:Rahul-252506
VIT CHENNAI,INDIA
*/
/*
 This header defines the ZtIpv4Hook class used for
 integrating Zero Trust policy enforcement into
 the IPv4 transmission layer.

 - Inherits from ns3::Object.
 - Attaches to a node’s IPv4 stack.
 - Intercepts outgoing (Tx) packets.
 - Delegates access control decisions to the
   ZtPolicyEngine before packet transmission.

 This enables real-time micro-segmentation
 enforcement at the network layer.
*/
#ifndef ZT_IPV4_HOOK_H
#define ZT_IPV4_HOOK_H

#include "ns3/object.h"
#include "ns3/node.h"
#include "ns3/ipv4.h"
#include "ns3/packet.h"
#include "ns3/address.h"

namespace ns3 {

class ZtPolicyEngine;

class ZtIpv4Hook : public Object
{
public:
  // Registers the class type with ns-3 object system.
  // Enables runtime identification and integration with simulation framework.
  static TypeId GetTypeId();

  // Constructor initializes hook object.
  // Prepares internal pointers for node and policy engine.
  ZtIpv4Hook();

  // Destructor cleans up allocated resources.
  // Ensures proper object lifecycle management.
  virtual ~ZtIpv4Hook();

  // Sets the Zero Trust policy engine instance.
  // Used for making access control decisions during packet interception.
  void SetPolicyEngine(Ptr<ZtPolicyEngine> engine);

  // Attaches this hook to a specific ns-3 node.
  // Enables interception of IPv4 traffic for that node.
  void AttachToNode(Ptr<Node> node);

private:
  // Intercepts outgoing IPv4 packets from the node.
  // Applies policy engine checks before allowing transmission.
  void InterceptPacket(Ptr<const Packet> packet,
                       Ptr<Ipv4> ipv4,
                       uint32_t interface);

  Ptr<ZtPolicyEngine> m_engine;
  Ptr<Node> m_node;
};

} // namespace ns3

#endif
