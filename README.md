# RGW-OPA-IAM Adaptor

OPA sends a request to this HTTP server when an Indigo IAM user ID is missing from its documents. It Authenticates with the SCIM API of Indigo IAM and forms a JSON document containing information about users: User ID, Username and list of their groups. Finally, it responds after uploading the document to OPA's data API.

[IAM OPA ADAPTOR](../docs/images/rgw-opa-adaptor.png)

