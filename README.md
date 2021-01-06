# Shield Advanced solution

## Overview

This repo hosts the code that helps build, monitoring, alert and report on Shield Advanced usage.  It's also used to help centralise WAF logs from Cloudfront and Load balancers to the airnz-monitoring account by creating Kinesis Firehose delivery streams in each AWS account.

Resource protection is also done via a daily state machine run of lambdas. Notifications of new protections (Cloudfront, internet facing load balancers and Route 53 public hosted zones) are posted into #security-shield slack channel


## Requirements

The Ansible playbook will require the below.

- python3
- awscli >v1.17.0
- ansible 2.7.x >= 2.9.x   (Newer versions may be incompatible with some modules and will need updating)


## Usage

- Modify the variables in the playbook to match your app requirements
- Run the playbook with
```
ansible-playbook pb-s3bucket.yml
ansible-playbook pb.yml
```

the s3 bucket playbook has been separated out at this stage but will be merged into the core playbook

## Feedback

Please email awsplatform@airnz.co.nz

## Changelog

- *v0.1* - Initial release
