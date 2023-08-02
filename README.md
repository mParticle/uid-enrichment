# Trade Desk UID2

This project contains source code and supporting files for a serverless application that you can deploy with the SAM
CLI. It includes the following files and folders.

- Trade Desk Enrichment - Code for the application's Lambda function.
- Events - Invocation events that you can use to invoke the function.
- Trade Desk Enrichment/tests - Unit tests for the application code.
- template.yaml - A template that defines the application's AWS resources.

## Architecture Diagram

![Architecture Diagram](UID2%20Enrichment%20Service.png)

## Data Flow

1. An Audience connection to the enrichment module will send emails that need a raw UID value.
    1. Set the audience criteria to capture all users who haven't had their user profile enriched in the last n days.
       You can tweak the criteria as you required. ![Reference](UID%20Audience%20Criteria.png)

2. The enrichment service talks to either a private or public UID instance to retrieve the token
3. Once the UID value is obtained, it will make send a custom event to mP via custom feed input, to add the UID value
   as a partner ID.