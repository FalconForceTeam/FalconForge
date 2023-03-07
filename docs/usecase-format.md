# Usecase.yml file format

A `usecase.yml` file describes a detection use-case including both the detection query and associated metadata, such as reference links and [MITRE ATT&CK](https://attack.mitre.org/) mappings for the relevant techniques.

*Note: the schema for the usecase.yml file is described in machine-readable format based on the [JSON Schema](https://json-schema.org/) format in the [usecase_schema.json](/docs/schemas/usecase_schema.json) file located in the `docs/schemas` directory of the repository.*

## Root level elements
The root level of the usecase.yml file consists of the following elements:
* `name` - The name of the use-case. This is used as a human-readable description of the use-case that is used in various reports. Also, it will typically be part of the use-case title when deployed.
* `id` - A unique identifier for the use-case. Formatted as `<ID number>-<Name>-<Platform>`. This ID needs to match exactly (case-sensitive) with the directory name in which the usecase.yml file is located.
* `tags` - A list of tags that can be used for referencing specific use-cases. In case new tags are defined, these should be added to the [usecase_schema.json](/docs/schemas/usecase_schema.json) file. By convention the tags are in [PascalCase](https://techterms.com/definition/pascalcase) meaning that there are no spaces and each word is capitalized.
* `os_family` - A list of operating systems this use-case is relevant for. The most common values are `WindowsEndpoint`, `WindowsServer` and `MacOS`. Refer to the [usecase_schema.json](/docs/schemas/usecase_schema.json) for a full list of supported operating systems.
* `fp_rate` - The expected false-positive rate, valid values are `Low`, `Medium` and `High`.
* `severity` - The severity for an alert created in case the use-case triggers. Valid values are `Low`, `Medium` and `High`.
* `attack` - The mapping to MITRE ATT&CK. See below for details of how this element is structured.
* `data_sources` - The list of data sources used by the use-case. See below for details of how this element is structured.
* `permission_required` - Indicates the permissions an attacker requires to execute the attack described in the use-case. The most common values are `Administrator`, `User` and `Domain Admin`. Refer to the [usecase_schema.json](/docs/schemas/usecase_schema.json) for a full list of supported values.
* `description` - The description of the use-case. By convention, this should start by providing context on the type of attack the use-case can detect and explain why this type of attack is relevant, followed by a high level explanation of the technique used to detect it. Further details on the detection logic are provided in the `technical_description` field.
* `technical_description` - The technical description of the query, documenting how the query works on a technical level. Note that the combination of description and technical description is used in various places such as the query description field in Sentinel. This means that ideally no information from the `description` field should be repeated.
* `considerations` - Relevant information for users of the use-case that is not present in other fields. For example, it could provide specific logging settings to apply to allow the use-case to function properly.
* `false_positives` - Description of false-positives that can be expected when deploying the use-case.
* `blindspots` - Description of the blind-spots, meaning valid attacks that the use-case cannot detect, for example, because of a lack of telemetry.
* `response_plan` - Short description of how to respond when the use-case triggers.
* `change_log` - The version history of the use-case. See below for details of how this element is structured.
* `references` - List of relevant references. Each reference should be a valid publicly available URL that is relevant to the use-case.
* `silence_warnings` - List of warnings that are silenced for this use-case. See below for details of how this element is structured.
* `detection_query` - The detection query. See below for details of how this element is structured.

## Attack element

The `attack` element contains the mapping of the use-case to MITRE ATT&CK (sub-)techniques. This element consists of a list of sub-elements each containing a single MITRE ATT&CK reference.

Each sub-element is structured as follows:
* `tactic` - The tactic identifier, formatted as `TA<4-digit-number>` of the relevant technique. Note that many (sub-)techniques are linked to multiple tactics. In this case all tactics relevant for the use-case should be specified as a separate attack mapping element.
* `technique` - The technique identifier, formatted as `T<4-digit-number>` of the relevant technique.
* `sub_technique` - The sub_technique number, formatted as a `<3-digit-number>` of the relevant technique. This element is only used in case the use-case is mapped to a sub-technique.

*Note: The first entry specified is considered to be the 'main' mapping, meaning that in cases where only a single mapping can be provided only this first mapping will be used.*

## Data_sources element

The `data_sources` element contains the data sources that are used by the query. This element contains of list of sub-elements each containing a single data source.

Each sub-element is structured as follows:
* `provider` - The provider of the data source. This is typically the name of the Sentinel connector that is used to provide the relevant logs. Refer to the [usecase_schema.json](/docs/schemas/usecase_schema.json) for a full list of supported providers. In case a new provider is required it should be added to the `usecase_schema.json` file.
* `event_id` - For Windows event log-based events, this contains the name of the event. For providers where logs are based on table names in combination with action types or operations (such as MDE), this field contains the action type, for example, `CreateRemoteThreadApiCall`.
* `table_name` - Specifies the name of the table there this data is queried from.
* `data_availability_test` - An object specifying a `column_name` and `column_value`. This is used in case the specified `table_name` contains logs from multiple connectors to distinguish between these connectors. This value is used in the `find_suitable` command which identifies which use-cases are suitable for a client based on the available data.
* `attack_data_source` - Reference to the relevant data source name as defined in MITRE ATT&CK.
* `attack_data_component` - Reference to the relevant data component name as defined in MITRE ATT&CK.

Only the `provider` element is mandatory, the other fields are preferred to be populated as well.

## Change_log element

The `change_log` element contains a log of the changes made to the use-case. Each time the use-case is updated, an entry should be added to the change log. This element contains of list of sub-elements each containing a single data source.

Each sub-element is structured as follows:
* `version` - Version number for the rule, formatted as `<major>.<minor>` where the major version is updated each time there are significant changes to the rule.
* `date` - The date when the change took place, formatted as `<year>-<month>-<day>`.
* `impact` - The impact of the change. This can be either `major` or `minor`.
* `message` - Short description of the change made.

*Note: the elements in the change log should be sorted with the latest version on top.*

## Silence_warnings element

The `silence_warnings` element contains a list of warnings that are silenced.

Each sub-element is structured as follows:
* `warning` - Identifier of the warning that is silenced, these are strings starting with `W_`. Refer to the [usecase_schema.json](/docs/schemas/usecase_schema.json) for a full list of supported warning identifiers.
* `reason` - Optional string description of why the warning has been silenced.

## Detection_query element

The `detection_query` element contains a detection query.

The structure is as follows:
* `language` - Query language that is used. Typically this will be `Kusto`, but other languages are also supported. Refer to the [usecase_schema.json](/docs/schemas/usecase_schema.json) for a full list of supported languages. In case a new language is required it should be added to the `usecase_schema.json` file.
* `platform` - Platform where the query runs. The most common values are `Sentinel` and `M365 Security`. Refer to the [usecase_schema.json](/docs/schemas/usecase_schema.json) for a full list of supported platforms.
* `query` - Contains the actual query that will be executed. This query can be customized by using [jinja templating](https://jinja.palletsprojects.com/en/3.0.x/) refer to the [Query Customization](query-customization.md) documentation page for full details on query customization.
* `deployment_variables` - Additional metadata required for deploying the query, such as the entity mapping information. The format of this element is dependent on the `platform` specified. See below for details of how this element is structured.

## Deployment_variables element

The `deployment_variables` element provides additional metadata required for deploying query. The format depends on the platform where the query is deployed.

For `M365 Security` the structure is as follows:
* `query_frequency` - Frequency the query should run. This is expressed as an [ISO 8601 duration](https://www.digi.com/resources/documentation/digidocs/90001437-13/reference/r_iso_8601_duration_format.htm). The following frequencies are supported by the `M365 Security` platform: `PT1H`, `PT3H`, `PT12H`, `PT24H` indicating 1 hour, 3 hours, 12 hours and 24 hours respectively. Note that M365 does not allow specifying a query data period since this is determined automatically from the query frequency. Refer to [Microsoft Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender/custom-detection-rules?view=o365-worldwide#rule-frequency) for more details on how this is determined.
* `entity_mapping` - Specification of how entities should be mapped from the query results. This is specified as a dictionary with allowed keys `machine`, `user` and `mailbox` which specify the entity type. Each of these keys can be specified a single time and should contain the column name as a value. Refer to [Microsoft Documentation](https://docs.microsoft.com/en-us/microsoft-365/security/defender/custom-detection-rules?view=o365-worldwide#required-columns-in-the-query-results) for details on which columns are allowed to be mapped to specific entity types.


For `Sentinel` the structure is as follows:
* `query_frequency` - Frequency the query should run. This is expressed as an [ISO 8601 duration](https://www.digi.com/resources/documentation/digidocs/90001437-13/reference/r_iso_8601_duration_format.htm).
* `query_period` - Contains the period for which data is available in the query. This should be at least the value specified in the `query_frequency`, but it can be extended in case the query requires access to historic data.
* `aggregation` - Boolean indicating whether multiple results should be aggregated into a single alert.
* `grouping` - List of conditions under which alerts will be grouped into a single alert. The following can be specified: `reopen_closed_incident`, `lookback_duration`, `matching_method`, `group_by_entities`, `group_by_alert_details` , `group_by_custom_details`. Refer to the [Microsoft Documentation](https://docs.microsoft.com/en-us/azure/sentinel/detect-threats-custom#alert-grouping) for documentation on the individual sub-elements.
* `alert_display_name_format` - Alert display name format. This can be used to override the alert name format using a formatting template that can include custom entities in the alert format.
* `custom_details` - Object that specifies custom details to be extracted from the query results. This element is a dictionary with the keys being the entity key names and the values the name of the column in the query result that will be mapped.
* `entity_mapping` - Specification of how entities should be mapped from the query results. This is specified as a nested dictionary with the first key being the entity, type such as `Account` or `AzureResource`; the second key being the entity identifier, such as `AadUserId`, and the value being the column name. Refer to [Microsoft Documentation](https://docs.microsoft.com/en-us/azure/sentinel/map-data-fields-to-entities) for details on Sentinel entity mapping. An example of a valid Sentinel entity mapping is provided below.

*Note: Automated deployment for other platforms is not supported and therefore no `deployment_variables` format is defined for these platforms.*


### Example Sentinel entity mapping

Below is an example of a Sentinel entity mapping:

TODO update.

```
entity_mapping:
  Account:
    FullName: EntityCallerName
    ObjectGuid: EntityCallerId
  IP:
    Address: EntityCallerIPAddress
  AzureResource:
    ResourceId: ResourceId
```

## Example usecase.yml file

Below is an example of a `usecase.yml` file:

```
name: AWS Assume Role Added from Unknown External Account
id: 0xFF-0238-Assume_Role_Added_from_Unknown_External_Account-AWS
tags:
  - AWS
  - SuspiciousBehavior
os_family:
  - N/A
fp_rate: Low
severity: Medium
attack:
  - {tactic: 'TA0003', technique: T1098, sub_technique: "001"}
data_sources:
  - provider: AWS
    event_id: CreateRole
    table_name: AWSCloudTrail
    attack_data_source: User Account
    attack_data_component: User Account Modification
  - provider: AWS
    event_id: UpdateAssumeRolePolicy
    table_name: AWSCloudTrail
    attack_data_source: User Account
    attack_data_component: User Account Modification
permission_required: User
technical_description: >
  This query searches for roles being created or updated where `sts:AssumeRole` is granted with an external AWS account. If the external AWS account id is not in
  a list of known accounts an alert is raised.
description: >
  When an attacker gains access to an account with access to AWS, they might abuse that account to grant the 'AssumeRole' privilege to an external AWS account.
  Once this privilege is assigned, the external account can be used to access the role and perform actions in the compromised AWS account.
considerations: >
  The rule requires setting up a list of known trusted AWS accounts.
false_positives: >
  There might be sharing of resources with external accounts for business reasons. Such sharing will have to be filtered.
blindspots: >
  None known.
response_plan: >
  Confirm if the user responsible for the providing external access to the role has done so for a valid business reason.
references:
  - https://github.com/DataDog/stratus-red-team
change_log:
  - {version: '1.2', date: '2022-08-31', impact: minor, message: Entity mapping added.}
  - {version: '1.1', date: '2022-02-22', impact: minor, message: 'Use ingestion_time for event selection and include de-duplication logic.' }
  - {version: '1.0', date: '2022-02-02', impact: major, message: Initial version.}
detection_query:
  language: Kusto
  platform: Sentinel
  deployment_variables:
    query_frequency: PT1H
    query_period: PT2H
    entity_mapping:
      - Account:
          Name: UserAccount
  query: |
    let timeframe = 2*1h;
    let TrustedAccounts= dynamic([]);
    AWSCloudTrail
    | where ingestion_time() >= ago(timeframe)
    | where EventName in ("CreateRole","UpdateAssumeRolePolicy")
    | extend AssumeRoleDocument=iif(EventName == "CreateRole", parse_json(RequestParameters).assumeRolePolicyDocument, parse_json(RequestParameters).policyDocument)
    | extend Statement=parse_json(tostring(AssumeRoleDocument)).Statement
    | mv-expand Statement
    | where Statement.Action =~ "sts:AssumeRole"
    | where Statement.Effect =~ "Allow"
    | mv-expand AddedAccount=Statement.Principal.AWS
    | where not(isempty(AddedAccount))
    | extend AddedAccount=iif(AddedAccount contains "*", "*", AddedAccount)
    | extend AddedAccount=iif(AddedAccount startswith "arn:", split(AddedAccount, ":")[4], AddedAccount)
    | where not(AddedAccount == UserIdentityAccountId)
    | where not(AddedAccount in (TrustedAccounts))
    | project-reorder AddedAccount
    // Begin client-specific filter.
    // End client-specific filter.
    | extend UserAccount=tostring(split(UserIdentityArn, "/")[-1])
```
