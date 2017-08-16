# RAiD Admin
*RAiD Admin* is a client and token management system for *institutions* and *services*. It is made up of AWS backend 
components for the creation, modification, storage and querying of JWT tokens. Variables related to the creation of JWT 
Tokens (secret, audience, issuer) are provided when launching the CloudFormation stack (via AWS SAM). This, along with 
dynamic resource names will allow for multiple environments to be deployed to the same AWS account. 

In addition, a frontend 'static' site is provided to directly interact with the AWS backend, via a provided AWS 
credential. It is designed to be accessible only to those managing a RAiD environment, by restricting access to the 
site by IP Address in addition to the AWS Credential. 

## Admin Backend (via AWS SAM)
The backend is deployable using 
[AWS SAM](https://github.com/awslabs/serverless-application-model/blob/master/versions/2016-10-31.md), an extension of 
CloudFormation that simplifies the template for serverless architectures. Ensure you have the latest version of 
*AWS CLI* to be able to run the deployment commands.

### Prerequisites
* *AWS CLI* configured with an access key with permissions to deploy a CloudFormation stack.
* Existing  private *Amazon S3* that you can upload a *AWS Lambda* code package.
### Deployment
* Copy the AWS Lambda Python file and requirements to artifacts directory.
```commandline
cp raid_admin.py deployment/raid_admin.py
cp requirements.txt deployment/requirements.txt
```
* Install packages listed in requirements to a directory for package deployment.
```commandline
pip install -r Deployment/requirements.txt -t Deployment
```
* Package your serverless deployment to an *Amazon S3* bucket and generate a *CloudFormation* template.
```commandline
aws cloudformation package --template-file template.yaml --output-template-file template-out.yaml --s3-bucket <<S3_BUCKET_NAME>>
```
* Deploy *CloudFormation* stack with parameters.
```commandline
aws cloudformation deploy --template-file template-out.yaml --stack-name <<STACK_NAME>> --parameter-overrides Tracing=Active JwtIssuer=<<TOKEN_ISSUER>> JwtAudience=<<TOKEN_AUDIENCE>> JwtSecret=<<TOKEN_SECRET>> --capabilities CAPABILITY_IAM
```