Feature: Policy API Management

  @wip
  Scenario: Create an existing policy
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to add a new policy called "policy/cyb3rhq/0"
    Then I should receive a failed response indicating "Policy already exists: policy/cyb3rhq/0"

  Scenario: Create a valid policy
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to add a new policy called "policy/cyb3rhq/1"
    Then I should receive a success response

  Scenario: Delete an existing policy
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to remove the policy called "policy/cyb3rhq/0"
    Then I should receive a success response

  Scenario: Delete a non-existent policy
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to remove the policy called "policy/cyb3rhq/1"
    Then I should receive a failed response

  Scenario: Get a valid policy without assets loaded with namespace filters
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to get the policy called "policy/cyb3rhq/0" in the namespaces "cyb3rhq system user"
    Then I should receive a policy with 0 assets in those namespaces

  Scenario: Get a valid policy without assets loaded with namespace system
    Given I have a policy called "policy/cyb3rhq/0"
    Given I load an integration called "cyb3rhq-core-test" in the namespace "cyb3rhq"
    When I send a request to get the policy called "policy/cyb3rhq/0" in the namespaces "system"
    Then I should receive a policy with 0 assets in those namespaces

  Scenario: Get a valid policy with assets loaded in the namespace system
    Given I have a policy called "policy/cyb3rhq/0"
    Given I load an integration called "cyb3rhq-core-test" in the namespace "cyb3rhq"
    When I send a request to get the policy called "policy/cyb3rhq/0" in the namespaces "cyb3rhq"
    Then I should receive a policy with 1 assets in those namespaces

  Scenario: Obtain a nonexistent policy
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to get the policy called "policy/cyb3rhq/1" in the namespaces "cyb3rhq system user"
    Then I should receive a failed response

  Scenario: Get a policy with invalid name
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to get the policy called "policy/cyb3rhq" in the namespaces "cyb3rhq system user"
    Then I should receive a failed response indicating "Error: Policy name (/policy) must have 3 parts"

  Scenario: List all policies
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to add a new policy called "policy/cyb3rhq/1"
    And I send a request to add a new policy called "policy/cyb3rhq/2"
    And I send a request to add a new policy called "policy/cyb3rhq/3"
    Then I should receive a list with size 4

  Scenario: Add a new asset to an existing policy
    Given I have a policy called "policy/cyb3rhq/0"
    When I load an integration called "cyb3rhq-core-test" in the namespace "cyb3rhq" to the policy "policy/cyb3rhq/0"
    Then I should receive a success response

  Scenario: Add an asset to a non-existent policy
    Given I have a policy called "policy/cyb3rhq/0"
    When I load an integration called "cyb3rhq-core-test" in the namespace "cyb3rhq" to the policy "policy/cyb3rhq/1"
    Then I should receive a failed response

  Scenario: Delete an asset from an existing policy
    Given I have a policy called "policy/cyb3rhq/0"
    Given I load an integration called "cyb3rhq-core-test" in the namespace "cyb3rhq"
    When I send a request to delete the asset "cyb3rhq-core-test" from the policy called "policy/cyb3rhq/0" in the namespace "cyb3rhq"
    And I send a request to get the policy called "policy/cyb3rhq/0" in the namespaces "cyb3rhq"
    Then I should receive a policy with 0 assets in those namespaces

  Scenario: Delete a non-existent asset from policy
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to delete the asset "cyb3rhq-core-test" from the policy called "policy/cyb3rhq/0" in the namespace "cyb3rhq"
    Then I should receive a failed response indicating "Asset not found"

  Scenario: Delete an asset from non-existent policy
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to delete the asset "cyb3rhq-core-test" from the policy called "policy/cyb3rhq/1" in the namespace "cyb3rhq"
    Then I should receive a failed response

  Scenario: Set the non-exist default parent of a namespace
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to set the default parent called "default" in the namespace "cyb3rhq"
    Then I should receive a success response with a validation warning indicating "Saved invalid policy: Default parent 'default' in namespace 'cyb3rhq' is neither a decoder or a rule"

  @exclude
  Scenario: Set the default parent of a namespace
    Given I have a policy called "policy/cyb3rhq/0"
    Given I load an integration called "parent-cyb3rhq-core-test" in the namespace "cyb3rhq"
    When I send a request to set the default parent called "decoder/parent-message/0" in the namespace "cyb3rhq"
    Then I should receive a failed response indicating "Engine base graph: Node "decoder/Input" has no children."

  Scenario: Get the non-exist default parent of a namespace
    Given I have a policy called "policy/cyb3rhq/0"
    When I send a request to get the default parent of policy "policy/cyb3rhq/0" in the namespace "cyb3rhq"
    Then I should an error indicating "Namespace cyb3rhq not found"

  Scenario: Get namespaces in policy
    Given I have a policy called "policy/cyb3rhq/0"
    Given I load an integration called "parent-cyb3rhq-core-test" in the namespace "cyb3rhq"
    Given I load an integration called "other-cyb3rhq-core-test" in the namespace "system"
    When I send a request to get namespaces of policy "policy/cyb3rhq/0"
    Then I should receive a list of namespace with size 2
