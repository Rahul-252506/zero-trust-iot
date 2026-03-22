#ifndef ZT_POLICY_ENGINE_H
#define ZT_POLICY_ENGINE_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <map>

#include <ns3/object.h>
#include <ns3/node.h>

#include <cryptopp/rsa.h>

using namespace CryptoPP;

namespace ns3 {

/**
 * \ingroup zerotrust
 * \brief Zero Trust Policy Engine with:
 * - Identity-based authorization
 * - Certificate validation
 * - Revocation support
 * - Micro-segmentation (custom extension)
 */
class ZtPolicyEngine : public Object
{
public:
  static TypeId GetTypeId();
  // Registers the class type within ns-3 system.
  // Enables runtime type identification and object creation.

  ZtPolicyEngine();
  // Constructor initializes policy engine state.
  // Sets default values for rules, version, and storage.

  virtual ~ZtPolicyEngine();
  // Destructor cleans up allocated resources.
  // Ensures proper object destruction in ns-3 environment.

  /* =====================================================
     EXISTING FUNCTIONALITY (DO NOT MODIFY)
  ===================================================== */

  void AddAuthorized(uint32_t nodeId, const std::string& role);
  // Adds a node with a specific role into authorization table.
  // Used to define which roles a node is allowed to have.

  bool Authorize(uint32_t nodeId, const std::string& role);
  // Checks if a node is authorized for a given role.
  // Returns true if node-role mapping exists and is valid.

  void SetCaPublicKey(RSA::PublicKey pub);
  // Sets the Certificate Authority public key.
  // Used later for validating node certificates.

  void Revoke(uint32_t nodeId);
  // Marks a node as revoked in the system.
  // Prevents further authorization regardless of role.

  bool AuthorizeWithCert(uint32_t nodeId,
                         const std::string& role,
                         const std::string& certStr);
  // Validates certificate and checks role-based authorization.
  // Combines cryptographic verification with access control.

  /* =====================================================
     NEW: MICRO-SEGMENTATION EXTENSION
  ===================================================== */

  enum RuleEffect
  {
    ALLOW = 0,
    DENY  = 1
  };

  struct RolePolicyRule
  {
    std::string srcRole;
    std::string dstRole;
    std::string action;

    uint32_t startHour;
    uint32_t endHour;

    uint32_t windowSeconds;
    uint32_t maxTransfers;

    RuleEffect effect;
  };

  void AddRolePolicyRule(const RolePolicyRule& rule);
  // Adds a micro-segmentation rule into the policy engine.
  // Defines allowed/denied interactions between roles.

  bool EvaluateMicroSegmentation(
      Ptr<Node> srcNode,
      Ptr<Node> dstNode,
      const std::string& action);
  // Evaluates whether communication between nodes is permitted.
  // Applies role rules, time constraints, and behavior limits.

  uint32_t GetPolicyVersion() const;
  // Returns current version of the policy configuration.
  // Helps track updates and synchronization of rules.

  std::string GetPolicyIntegrityHash() const;
  // Generates a hash representing current policy state.
  // Used to verify integrity and detect rule tampering.

private:
  /* ================= EXISTING ================= */
  std::unordered_map<uint32_t, std::string> authTable;
  std::unordered_set<uint32_t> revoke;
  RSA::PublicKey caPublicKey;

  /* ================= NEW ================= */
  bool IsWithinTime(uint32_t startHour,
                    uint32_t endHour);
  // Checks if current system time falls within allowed range.
  // Used to enforce time-based access restrictions.

  uint32_t GetBehaviorState(uint32_t nodeId,
                           uint32_t windowSeconds);
  // Tracks recent activity of a node within a time window.
  // Helps enforce rate limits or anomaly detection.

private:
  /* ================= NEW STORAGE ================= */
  std::vector<RolePolicyRule> m_rules;

  std::map<uint32_t, std::vector<uint64_t>> m_transferHistory;

  uint32_t m_policyVersion;
};

} // namespace ns3

#endif // ZT_POLICY_ENGINE_H
