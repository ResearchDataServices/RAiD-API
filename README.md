# RAiD API

The [Data LifeCycle Framework](www.dlc.edu.au) (DLC) has been initiated by five primary organisations; [Australian Access Federation](https://aaf.edu.au/) (AAF), [Australia’s Academic and Research Network](https://www.aarnet.edu.au/) (AARNet), [Australian National Data Service](http://www.ands.org.au/) (ANDS), [National eResearch Collaboration Tools and Resources](https://nectar.org.au/) (NeCTAR) and [Research Data Services](http://www.rds.edu.au/) (RDS).

The DLCF is a nationwide effort to connect research resources and activities such that researchers can make the best use of existing national, state-based, local, and commercial eResearch tools. It aims to provide a simple path to reliable provenance, more effective collaboration across organisations and assist researchers to position themselves to address the growing potential of increasingly open data.

The DLCF will connect critical elements and points in time of the data journey from grant approval through to project finalisation, results publication and archiving. It will leverage existing eResearch investment to provide a flexible and dynamic national framework supporting research.

The Resource and Activity Persistent identifier (RAiD) is the first of the enabling technologies required for the DLCF. The RAiD API is a [Serverless](https://aws.amazon.com/serverless/) application designed to be hosted on Amazon Web Services (AWS) that will help create and manage RAiDs.

## Serverless Components
AWS serverless applications are able to conform to a [multi-tier architecture]( https://d0.awsstatic.com/whitepapers/AWS_Serverless_Multi-Tier_Architectures.pdf), consisting of three defined tiers:
* Data - Store all research activity information and generated JWT tokens for research organisations and providers in AWS DynamoDB (NOSQL). AFF authenticated users JWT tokens are not stored as they are provided by RAPID AAF.
* Logic - RESTful api call are mapped to end points mapped in Amazon API Gateway. API Gateway processes HTTP requests by using micro-services (AWS Lambda using Python runtime) behind a custom security policy (JWT token validation). HTTP status codes and responses are generated depending on the result of the AWS Lambda function.
* Presentation - Static assets (HTML, JavaScript, CSS, etc.) are stored in AWS S3 buckets with public HTTP GET access. AWS provides a HTTP endpoint for content hosting, but disallows server side generated content. This is overcome by storing authenticated sessions as cookies and producing dynamic content with RESTful calls to API Gateway.

## Getting Started
Development and deployment of the framework will require the following:
### Prerequisites
* [Python](https://www.python.org/download/releases/2.7/):  AWS Lambda supported Python language runtime 2.7.
* [PIP](https://pip.pypa.io/en/stable/) : Install and manage Python Modules
* [AWS Command Line Interface](https://aws.amazon.com/cli/): Unified tool to manage your AWS services.
* [Boto3](https://boto3.readthedocs.io/en/latest/) : Amazon Web Services SDK for Python. 

### Installing
```
# Install PIP
$ python get-pip.py

# Configure AWS CLI
$ aws configure
AWS Access Key ID [None]: <Access Key>
AWS Secret Access Key [None]: <Secret>
Default region name [None]: <Region>
Default output format [None]: ENTER

# Install Boto3
pip install boto3==1.4.4
```

### Environment & Secrets
Micro-services depend on environment variables to allow for an environment stage agnostic deployment model.

#### auth.py
- `JWT_SECRET` Secret used for encryption/decryption of all JWT tokens.
- `SITE_URL` URL for all JWT authentication calls to be redirected to. This should be the URL endpoint of the static website.
- `SITE_DOMAIN` Shared domain of API Gateway and S3 static site. Setting and sharing authentication cookies requires a shared root domain. For example: The S3 site would be hosted on 'example.com' and API Gateway on 'api.example.com/v1/' with the shared domain as 'example.com'.
- `JWT_ISSUER` Name of 3rd party issuer of JWT provided token.
- `JWT_AUDIENCE` Name of intended audience. Prevent valid tokens meant for other application to be used with this application.

TBC
...
### Running locally
Install AWS Lambda functions module requirements using PIP.

```
# Install packages listed in requirements
$ pip install -r Lambda/Function/Path/requirements.txt
```

Run AWS Lambda handle locally using [Python Lambda Local](https://pypi.python.org/pypi/python-lambda-local/0.1.2) and a provided event json file.

```
# Install Python Lambda Local
$ pip install python-lambda-local==0.1.2

# Run Lambda handler with given event.json file
python-lambda-local -f lambda_handle -t 5 lambda_file.py event.json

```

## Deployment
[AWS Serverless Application Model](http://docs.aws.amazon.com/lambda/latest/dg/deploying-lambda-apps.html) (SAM) extends the traditional Cloud Formation temployment deployment model to special in the the deployment of serverless application.
When the resources defined below are configured, deploy the SAM via AWS CloudFormation with following commands using resources in the SAM directory.
```
# Create Cloudformation package that:
# Zips the index.js file.
# Uploads it to an S3 bucket
# Adds a CodeUri property, specifying the location of the zip file in the bucket for each function in app_spec.yml.
$ aws cloudformation package --template-file app_spec.yml --output-template-file new_app_spec.yml --s3-bucket <your-bucket-name>

# Deploy the CloudFormation package which will:
# Use new SAM file.
# Call the CloudFormation CreateChangeSet operation with app_spec.yml
# Call the CloudFormation ExecuteChangeSet operation with the name of the changeset you created in step
# Provide CloudFormation with the capability to create IAM role
$aws cloudformation deploy --template-file new_app_spec.yml --stack-name <your-stack-name> --capabilities CAPABILITY_IAM
```

TBC
...
### AWS Lambda
Prepare Lambda files by creating [AWS Lambda Python Packages](http://docs.aws.amazon.com/lambda/latest/dg/lambda-python-how-to-create-deployment-package.html) and uploading them to a private Amazon S3 Bucket.
```
# Copy Lambda functions to artifacts directory
$cp -R LambdaFunctions/. Artifacts/LambdaFunctions/

# Install packages listed in requirements to a directory for package deployment
$ pip install -r Artifacts/LambdaFunctions/Function/requirements.txt -t Artifacts/LambdaFunctions/Function

# Create zip of function at root level and upload to private S3 bucket
$ zip -r Artifacts/LambdaFunctions/Function/function.zip *
$ aws s3 cp Artifacts/LambdaFunctions/Function/function.zip s3://myPrivateBucket//function.zip
```
### API Gateway
API Gateway paths are defined explicitly in the 'swagger.yaml' file in SAM directory. 

### S3 Static site
Structure of StaticSite directory will match the public S3 bucket and website structure. Upload it to a publicly accessible bucket.
```
# Upload all of static site content to the public S3 bucket
$ aws s3 cp StaticSite s3://myPublicBucket/ --recursive
```

## License

TBD