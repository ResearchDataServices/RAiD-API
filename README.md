![RAiD Logo](raid-logo.png)

# RAiD API

The [Data LifeCycle Framework](www.dlc.edu.au) (DLC) has been initiated by five primary organisations; [Australian Access Federation](https://aaf.edu.au/) (AAF), [Australia’s Academic and Research Network](https://www.aarnet.edu.au/) (AARNet), [Australian National Data Service](http://www.ands.org.au/) (ANDS), [National eResearch Collaboration Tools and Resources](https://nectar.org.au/) (NeCTAR) and [Research Data Services](http://www.rds.edu.au/) (RDS).

The DLCF is a nationwide effort to connect research resources and activities such that researchers can make the best use of existing national, state-based, local, and commercial eResearch tools. It aims to provide a simple path to reliable provenance, more effective collaboration across organisations and assist researchers to position themselves to address the growing potential of increasingly open data.

The DLCF will connect critical elements and points in time of the data journey from grant approval through to project finalisation, results publication and archiving. It will leverage existing eResearch investment to provide a flexible and dynamic national framework supporting research.

The Resource and Activity Persistent identifier (RAiD) is the first of the enabling technologies required for the DLCF.*RAiD API* is a '**proof of concept**' [Serverless](https://aws.amazon.com/serverless/) implementation designed to be hosted on Amazon Web Services (AWS) that will help create and manage RAiDs.

## Current version: 1.1.2

## Serverless Components
AWS serverless applications are able to conform to a [multi-tier architecture]( https://d0.awsstatic.com/whitepapers/AWS_Serverless_Multi-Tier_Architectures.pdf), consisting of three defined tiers:
* Data - Store all research activity information and generated JWT tokens for research organisations and providers in AWS DynamoDB (NOSQL). AFF authenticated users JWT tokens are not stored as they are provided by RAPID AAF.
* Logic - RESTful api calls are mapped to end points mapped in Amazon API Gateway. API Gateway processes HTTP requests by using micro-services (AWS Lambda using Python runtime) behind a custom security policy (JWT token validation). HTTP status codes and responses are generated depending on the result of the AWS Lambda function.
* Presentation - Static assets (HTML, JavaScript, CSS, etc.) are stored in AWS S3 buckets with public HTTP GET access. AWS provides a HTTP endpoint for content hosting, but disallows server side generated content. This is overcome by storing authenticated sessions as cookies and producing dynamic content with RESTful calls to API Gateway with CORS enabled.

*RAiD API* is made and deployed using [AWS Serverless Application Model (AWS SAM)](https://github.com/awslabs/serverless-application-model) extension of CloudFormation.

![Image SAM](https://github.com/awslabs/serverless-application-model/blob/master/aws_sam_introduction.png?raw=true)

> "The AWS Serverless Application Model (AWS SAM, previously known as Project Flourish) extends AWS CloudFormation to provide a simplified way of defining the Amazon API Gateway APIs, AWS Lambda functions, and Amazon DynamoDB tables needed by your serverless application". [(AWS 2016)](https://aws.amazon.com/about-aws/whats-new/2016/11/introducing-the-aws-serverless-application-model/)

## Getting Started
Development and deployment of the framework will require the following:

### Third-Party Integrations
*RAiD* uses the [*ANDS Handle Service*](https://www.ands.org.au/online-services/handle-service) to generate unique and citable 'handles'. This allows organisations and researchers to have a 'clickable' link in their datasets, collections and papers. Handles act as the primary key for a RAiD and are associated with a URL content path which can be changed, but the handle will remain the same. The following steps a required for *RAiD API* to interact with the minting service:
  1. Create a VPC and subnet in AWS that will have all outbound traffic come from a single static IPv4 Address.
  2. [Register with ANDS](https://documentation.ands.org.au/pages/viewpage.action?pageId=59409375), providing the static IP Address from the previous step for the demo and live handle service.
  3. Use the 'appID' for the 'AndsAppId' parameter in the deployment steps mentioned later in this document.

### AWS Environment Prerequisites
* AWS S3 Bucket for SAM code packages.

### System Deployment Prerequisites
* [Git](https://git-scm.com/downloads): Source code version control.
    * [Github Desktop](https://desktop.github.com/): (Optional) Github Specific UI for managing source code hosted on Github.
* [Python](https://www.python.org/downloads/release/python-3810/): AWS Lambda supported Python language runtime 3.8.
* [Bash Shell](https://www.gnu.org/software/bash/): Examples below will use Unix shell like commands when giving examples on how to configure or deploy something. Linux and OSX by default should have a shell available to you, but if you are using Windows there it no guarantee that Command Prompt or Powershell will give you the desired output.
    * [Git BASH via Git for Windows](https://gitforwindows.org/): (Optional) An easy way to get Bash available on Windows is using Git Bash.
* [PIP](https://pip.pypa.io/en/stable/) : Install and manage Python Modules
* [Docker](https://docs.docker.com/get-docker/): OS-level virtualization to deliver software in packages called containers.
* [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html): Unified tool to manage your AWS services.
* [AWS SAM](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html): AWS SAM provides you with a command line tool, the AWS SAM CLI, that makes it easy for you to create and manage serverless applications.
* [Boto3](https://boto3.readthedocs.io/en/latest/) : Amazon Web Services SDK for Python.

### Installing System Deployment Prerequisites

```bash
# Configure AWS CLI
aws configure
AWS Access Key ID [None]: <Access Key>
AWS Secret Access Key [None]: <Secret>
Default region name [None]: ap-southeast-2
Default output format [None]: ENTER
```

## AWS Deployment

RAiD consists of two Cloudformation Stacks "*RAiD*" and "*RAiD-Admin*", which are deployed via AWS SAM / Cloudformation in that order.

The RAiD stack contains the backend API and other resources (e.g DynamoDB Databases) that Service/Providers and Institutions interact with (e.g. creating a RAiD) using their authentication token (long term JSON Web Token). Please note, The *RAiD API* "*Demo*" and "*Live*" API's are both contained as part of this stack.

The RAiD-Admin stack contains a backend API to assist administrators of RAiD (i.e ARDC) to create the authentication tokens that the Providers and Institutions use. The Admins use their AWS API Gateway API Keys to authenticate. Which can be generated via the AWS Console.

### RAiD
```bash
# Replace Swagger AWS account id and region placeholders with your own
sed -i "s/<<account>>/AWS_ACCOUNT_ID/g" 'sam/swagger.yaml'
sed -i "s/<<region>>/ap-southeast-2/g" 'sam/swagger.yaml'

# Build Local Python dependencies to '.aws-sam' directory
sam build --use-container -t sam/template.yaml

# Package SAM code and replace MY_S3_Bucket with your own
sam package \
    --output-template-file .aws-sam/build/template-out.yaml \
    --s3-bucket MY_S3_Bucket

# Deploy SAM as an S3 CloudFormation Stack
## Replacing YOUR_SECRET ANDS_APP_ID ANDS_SECRET
### NOTE #####
### 1. "RAiD-Testing" is an example deployment name, in reality in might be just "RAiD".
### 2. When testing, have AndsService as "https://demo.ands.org.au:8443/pids/"
### and your AndsSecret value as "ANDS_DEMO_SECRET". This wiil prevent
### you from creating real minted AND Handle's.
###
sam deploy \
    --stack-name RAiD-Testing \
    --template-file .aws-sam/build/template-out.yaml \
    --confirm-changeset \
    --parameter-overrides \
        JwtSecret="YOUR_SECRET" \
        AndsService="https://handle.ands.org.au/pids/" \
        DemoAndsService="https://demo.ands.org.au:8443/pids/" \
        AndsAppId="ANDS_APP_ID" \
        AndsSecret="ANDS_SECRET" \
        AndsDemoSecret="ANDS_DEMO_SECRET" \
    --capabilities CAPABILITY_IAM

# You can view the outputs via a Cloudformation in the AWS console or view
# the CLI output from the command above. E.g.
# ---------------------------------------
# CloudFormation outputs from deployed stack
# ---------------------------------------
# Outputs
# ---------------------------------------
# Key                 MetadataDB
# Description         -
# Value               RAiD-Testing-MetadataTable-123ABCDEFGHIK

# Key                 RaidDemoDB
# Description         -
# Value               RAiD-Testing-RAiDDemoDB-123ABCDEFGHIK-RAiDTable-123ABCDEFGHIK

# Key                 RAiDAssociationLiveDB
# Description         -
# Value               RAiD-Testing-RAiDLiveDB-8RNJNC123ABCDEFGHIK9FV1KV-AssociationIndexTable-123ABCDEFGHIK

# Key                 RAiDAssociationDemoDB
# Description         -
# Value               RAiD-Testing-RAiDDemoDB-123ABCDEFGHIK-AssociationIndexTable-123ABCDEFGHIK

# Key                 RaidLiveDB
# Description         -
# Value               RAiD-Testing-RAiDLiveDB-123ABCDEFGHIK-RAiDTable-123ABCDEFGHIK

# Key                 TokenDB
# Description         -
# Value               RAiD-Testing-TokenTable-123ABCDEFGHIK 
```

### RAiD-Admin
```bash
# Replace Swagger AWS account id and region placeholders with your own
sed -i "s/<<account>>/AWS_ACCOUNT_ID/g" 'sam/admin-swagger.yaml'
sed -i "s/<<region>>/ap-southeast-2/g" 'sam/admin-swagger.yaml'

# Build Local Python dependencies to '.aws-sam' directory
sam build --use-container -t sam/admin-template.yaml

# Package SAM code and replace MY_S3_Bucket with your own
sam package \
    --output-template-file .aws-sam/build/admin-template-out.yaml \
    --s3-bucket MY_S3_Bucket

# Deploy SAM as an S3 CloudFormation Stack
## Replacing YOUR_SECRET, YOUR_METADATA_TABLE (from MetadataDB output from RAiD Deployment), YOUR_TOKEN_TABLE (from TokenDB output from RAiD Deployment)
## "RAiD-Testing-Admin" is an example deployment name, in reality in might be just "RAiD-Admin".
sam deploy \
    --stack-name RAiD-Testing-Admin \
    --template-file .aws-sam/build/admin-template-out.yaml \
    --confirm-changeset \
    --parameter-overrides \
        JwtSecret="YOUR_SECRET" \
        MetadataTable="YOUR_METADATA_TABLE" \
        TokenTable="YOUR_TOKEN_TABLE" \
    --capabilities CAPABILITY_IAM
```

## License

MIT-Style akin to ORCiD. See LICENCE.txt for details.
