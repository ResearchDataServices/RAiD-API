# SUPERSESSION NOTICE

Note that this repo is now superseded.  The production RAiD app can be found at: https://github.com/au-research/raido

Please create a discussion on that repo, or email contact@raid.org if you have any questions.


# RAiD API

The [Data LifeCycle Framework](www.dlc.edu.au) (DLC) has been initiated by five primary organisations; [Australian Access Federation](https://aaf.edu.au/) (AAF), [Australia’s Academic and Research Network](https://www.aarnet.edu.au/) (AARNet), [Australian National Data Service](http://www.ands.org.au/) (ANDS), [National eResearch Collaboration Tools and Resources](https://nectar.org.au/) (NeCTAR) and [Research Data Services](http://www.rds.edu.au/) (RDS).

The DLCF is a nationwide effort to connect research resources and activities such that researchers can make the best use of existing national, state-based, local, and commercial eResearch tools. It aims to provide a simple path to reliable provenance, more effective collaboration across organisations and assist researchers to position themselves to address the growing potential of increasingly open data.

The DLCF will connect critical elements and points in time of the data journey from grant approval through to project finalisation, results publication and archiving. It will leverage existing eResearch investment to provide a flexible and dynamic national framework supporting research.

The Resource and Activity Persistent identifier (RAiD) is the first of the enabling technologies required for the DLCF.*RAiD API* is a '**proof of concept**' [Serverless](https://aws.amazon.com/serverless/) implementation designed to be hosted on Amazon Web Services (AWS) that will help create and manage RAiDs.

## Current version: 1.1.1

## Serverless Components
AWS serverless applications are able to conform to a [multi-tier architecture]( https://d0.awsstatic.com/whitepapers/AWS_Serverless_Multi-Tier_Architectures.pdf), consisting of three defined tiers:
* Data - Store all research activity information and generated JWT tokens for research organisations and providers in AWS DynamoDB (NOSQL). AFF authenticated users JWT tokens are not stored as they are provided by RAPID AAF.
* Logic - RESTful api call are mapped to end points mapped in Amazon API Gateway. API Gateway processes HTTP requests by using micro-services (AWS Lambda using Python runtime) behind a custom security policy (JWT token validation). HTTP status codes and responses are generated depending on the result of the AWS Lambda function.
* Presentation - Static assets (HTML, JavaScript, CSS, etc.) are stored in AWS S3 buckets with public HTTP GET access. AWS provides a HTTP endpoint for content hosting, but disallows server side generated content. This is overcome by storing authenticated sessions as cookies and producing dynamic content with RESTful calls to API Gateway with CORS enabled.

*RAiD API* is made and deployed using [AWS Serverless Application Model (AWS SAM)](https://github.com/awslabs/serverless-application-model) extension of CloudFormation.

![Image SAM](https://github.com/awslabs/serverless-application-model/blob/master/aws_sam_introduction.png?raw=true)

> "The AWS Serverless Application Model (AWS SAM, previously known as Project Flourish) extends AWS CloudFormation to provide a simplified way of defining the Amazon API Gateway APIs, AWS Lambda functions, and Amazon DynamoDB tables needed by your serverless application". [(AWS 2016)](https://aws.amazon.com/about-aws/whats-new/2016/11/introducing-the-aws-serverless-application-model/)

## Getting Started
Development and deployment of the framework will require the following:

### Third-Party Integrations
*RAiD* uses the [*ANDS Handle Service*](https://www.ands.org.au/online-services/handle-service) to generate unique and citable 'handles'. This allows organisations and researchers to have a 'clickable' link in their datasets, collections and papers. Handles act as the primary key for a RAiD and are associated to a URL content path which can be changed, but the handle will remain the same. The following steps a required for *RAiD API* to interact with the minting service:
  1. Create a VPC and subnet in AWS that will have all outbound traffic come from a single static IPv4 Address.
  2. [Register with ANDS](https://documentation.ands.org.au/pages/viewpage.action?pageId=59409375), providing the static IP Address from the previous step for the demo and live handle service.
  3. Use the 'appID' for the 'AndsAppId' parameter in the deployment steps mentioned later in this document.

### AWS Environment Prerequisites
* AWS VPC, Subnets and Security to interact with ANDS.
* AWS S3 Bucket for SAM code packages.
* Amazon Elasticsearch Service endpoint for logging and monitoring.

### System Deployment Prerequisites
* [Python](https://www.python.org/download/releases/2.7/):  AWS Lambda supported Python language runtime 2.7.
* [PIP](https://pip.pypa.io/en/stable/) : Install and manage Python Modules
* [AWS Command Line Interface](https://aws.amazon.com/cli/): Unified tool to manage your AWS services.
* [Boto3](https://boto3.readthedocs.io/en/latest/) : Amazon Web Services SDK for Python.

### Installing System Deployment Prerequisites

```bash
# Install PIP
python get-pip.py

# Install AWS CLI
pip install awscli

# Configure AWS CLI
aws configure
AWS Access Key ID [None]: <Access Key>
AWS Secret Access Key [None]: <Secret>
Default region name [None]: <Region>
Default output format [None]: ENTER

# Install Boto3
pip install boto3==1.4.4
```

## Deployment

### SAM
```bash
# Install packages listed in requirements to a directory for package deployment
pip install -r src/requirements.txt -t src/

# Change path into SAM
cd sam

# Package SAM code and replace MY_S3_Bucket with your own
aws cloudformation package --template-file template.yaml --output-template-file template-out.yaml --s3-bucket MY_S3_Bucket

# Replace Swagger AWS account id and region placeholders with your own
sed -i "s/<<account>>/AWS_ACCOUNT_ID/g" 'swagger.yaml'
sed -i "s/<<region>>/AWS_REGION/g" 'swagger.yaml'

# Deploy SAM as an S3 CloudFormation Stack
## Replacing YOUR_SECRET ANDS_APP_ID SUBNET_ID SECURITY_GROUP ES_URL
aws cloudformation deploy --template-file template-out.yaml \
--stack-name RAiD --parameter-overrides \
JwtSecret=YOUR_SECRET \
AndsAppId=ANDS_APP_ID \
AndsSecret=ANDS_SECRET \
AndsSubnets=SUBNET_ID \
AndsSecurityGroups=SECURITY_GROUP \
ElasticsearchHost=ES_URL \
--capabilities CAPABILITY_IAM
```

## License

MIT-Style akin to ORCiD. See LICENCE.txt for details.
