# aws_audit

#### Table of Contents

1. [Overview](#overview)
2. [Project Description - What aws_audit does and why it is useful](#project-description)
3. [Setup - The basics of getting started with aws_audit](#setup)
    * [What aws_audit affects](#what-aws_audit-affects)
    * [Setup requirements](#setup-requirements)
    * [Beginning with aws_audit](#beginning-with-aws_audit)
4. [Usage - Configuration options and additional functionality](#usage)
5. [Reference - An under-the-hood peek at what aws_audit is doing and how](#reference)
5. [Limitations - Resource type compatibility, etc.](#limitations)
6. [Development - Guide for contributing](#development)

## Overview

Amazon Web Services lacks a way to enforce tag schemes on instances for usage tracking inside an organization that is sharing a IAM across the org to provide self service IaaS. To overcome this issue we wrote a script that queries the various AWS API endpoints to grab a shanpshot of what is currently provisioned and validate it has a set of associated meta-data and report a rollup to ElasticSearch. If the meta-data does not match our expectations we have the choice of terminating it.

## Project Description

Like many young companies of this era we ended up leveraging AWS without a strategy attached to it or any idea of growth.  Once spend got higher than we could stomach we began to look at ways to track who was spending what and why.  We needed to do this without abandoning already in production workflows and tools plus we wished to have the options of enforcing these policies in close to real time.

Reporting on what and how much is easier once everyone adheres to a strict scheme.  Cloudability being one of the simplist reporting platforms but it completely lacks the enforcement portion of our requirement and is not all that realtime because of the limitations of the Amazon billing and usage API.  We decided to take an idea from [Jon Spinks](https://twitter.com/jon_spinks) at [Sourced](http://www.sourcedgroup.com) who a couple of us have worked with on various projects, something he called "Soup Nazi".  It was a bash script that used the AWS CLI to validate running instances against a set of tags.  Being as that I am horrible at bash and have no desire to get better at it and I'd been looking for something to write from scratch in Python, I rewrote it.

## Setup

### What aws_audit affects

* Currently only audits EC2 instances: terminates, disables API termination protection, and reports tag scheme violations to ElasticSearch.

### Setup Requirements

* Python
  * Tested on 2.7.x and 3.x
  * Libraries: boto, pytz, requests, and sendgrid (if you want to send daily reports)
* Amazon
  * Running of the script currently has a hard requirement on one instance being defined in stopped state in every region you wish to audit, a canary.
    * Used to make sure Amazon's API endpoint is able to return expected data.
    * Avoid situation where API returns no data but a 200 and registers no outage on the Amazon side.
    * Any instance type capable of being stopped without termination, i.e. EBS backed
    * Instances to be tagged is this fashion:
      * created_by : cody
      * project    : API canary
      * department : sysops
      * Name       : api-canary-$REGION
  * A user with appropriate access to EC2 across all auditable regions
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "iam:ListAccountAliases",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "ec2:Describe*",
                "ec2:TerminateInstances",
                "ec2:ModifyInstanceAttribute",
                "ec2:CreateTags"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "elasticloadbalancing:Describe*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "cloudwatch:ListMetrics",
                "cloudwatch:GetMetricStatistics",
                "cloudwatch:Describe*"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "autoscaling:Describe*",
            "Resource": "*"
        }
    ]
}
```
* ElasticSearch
  * One index: aws-audits, two mappings: aws_tag_audit, aws_tag_violator
    * aws_tag_audit: A rollup of all instances in violation
    * aws_tag_violator: A document for each instance in violation
```json
{
    "aws_tag_audit": {
        "properties": {
            "@timestamp": {
                "format": "dateOptionalTime",
                "type": "date"
            },
            "account": {
                "index": "not_analyzed",
                "type": "string"
            },
            "tag_scheme": {
                "index": "not_analyzed",
                "type": "string"
            },
            "violator_count": {
                "type": "long"
            },
            "violators": {
                "properties": {
                    "age": {
                        "type": "double"
                    },
                    "id": {
                        "index": "not_analyzed",
                        "type": "string"
                    },
                    "region": {
                        "index": "not_analyzed",
                        "type": "string"
                    },
                    "state": {
                        "index": "not_analyzed",
                        "type": "string"
                    },
                    "tags": {
                        "index": "not_analyzed",
                        "type": "string"
                    }
                }
            }
        }
    },
    "aws_tag_violator": {
        "properties": {
            "@timestamp": {
                "format": "dateOptionalTime",
                "type": "date"
            },
            "account": {
                "index": "not_analyzed",
                "type": "string"
            },
            "age": {
                "type": "double"
            },
            "id": {
                "index": "not_analyzed",
                "type": "string"
            },
            "region": {
                "index": "not_analyzed",
                "type": "string"
            },
            "state": {
                "index": "not_analyzed",
                "type": "string"
            },
            "tags": {
                "index": "not_analyzed",
                "type": "string"
            }
        }
    }
}
```

### Beginning with aws_audit

* Install pre-requisites using pip
* Run awsaudit command with options: access and secret AWS API keys, comma seperated list of regions to check, and tag scheme are required.  If you want to modify the grace period you give to people or if you choose to terminate violations, those options are optional.

```
pip install -r requirements.txt
awsaudit -a $AWS_ACCESS_KEY -s $AWS_SECRET_KEY -r "us-west-1,us-west-2,us-east-1,eu-west-1,sa-east-1,ap-southeast-2,ap-southeast-1,ap-northeast-1,eu-central-1" -t "created_by,department,project" -g 45 --terminate
```

## Usage

`aws_audit [-a|--aws_access_key ACCESS_KEY] [-s|--aws_secret_key SECRET_KEY] [-r|--regions REGIONS] [-t|--tags TAGS] [-g|--grace MINUTES] [-k|--terminate] [-c|--confirm] [-h|--help]`

`--aws_access_key`

> AWS access key for the user that has appropriate audit and termination permissions.

`--aws_secret_key`

> AWS secret key for the user access key used for option `--aws_access_key`.

`--regions`

> A comma separated list of regions you wish to audit.

`--tags`

> The tags you wish verify exist for each instances.

`--grace`

> The amount of time an instance can exist before it is checked against the tag scheme.

`--terminate`

> Terminate instances that are in violation of the scheme and have an expired grace period.

`--confirm`

> Confirm that the value set for the created_by tag is an actual IAM user.

`--help`

> Prints out command usage information.

## Reference

### Methods

`awsaudit.AwsAudit.audit`

> The method that basically kicks everything off and steps down through the process of doing an audit; calling other methods, probably most impotantly creating
>
> **Parameters**: none
>
> **Return Type**: none
>
> **Returns**: none

`awsaudit.AwsAudit.alias`

> Queries IAM to obtain the user defined alias for the AWS account because the number based AWS identifier doesn't often mean much to a human.
>
> **Parameters**: none
>
> **Return Type**: string
>
> **Returns**: A single string which is the AWS account alias for the IAM root.

`awsaudit.AwsAudit.send`

> Compiles an ElasticSearch document and sends it to our ElasticSearch URL.
>
> **Parameters**:
> * violators (*list of dictionaries*) - All the violators found from quering all desired regions.
> * account (*string*) - The account you are associating these violators with.
>
> **Return Type**: N/A
>
> **Returns**: N/A

`awsaudit.AwsAuditRegion.canary`

> Special precrafted query to return a defined instance that we will used to validate that the AWS API in a region is functional.
>
> **Parameters**: none
>
> **Return Type**: none
>
> **Returns**: Non-zero and exits process if canary host is not found.

`awsaudit.AwsAuditRegion.violators`

> Queries a EC2 region for all "active" instances to verify their tag scheme.
>
> **Parameters**: none
>
> **Return Type**: list
>
> **Returns**: A list of dictionaries containing information about a violating instance.

`awsaudit.AwsAuditRgion.terminate`

> When requested, will first check if instance ID is protected from API initiated termination and if True will flip it to false then kill all instance IDs.
>
> **Parameters**:
> * instances (*list*) - A list of instance IDs.
>
> **Return Type**: none
>
> **Returns**: none

## Limitations

* Currently only audits EC2 VM resources
* Doesn't understand how to handle instances tagged improperly that are part of an virtual machine conversion task.
* Doesn't validate values of assigned tags, just makes sure they exist

## Development

This script was the first time I really sat down to write my own python from scratch and while I am mostly happy with the attempt it could still do with some improvement and features added.

A couple things to remember when working on the code base: nothing works if you haven't deployed canary hosts, pay close attention to how you manage time and stick with UTC, these scripts **terminate** instances and will cause loss of data.
