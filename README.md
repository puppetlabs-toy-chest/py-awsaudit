AWS tag auditor
==============

{
  "aws_tag_audit" : {
    "properties" : {
      "@timestamp" : { "format" : "dateOptionalTime", "type" : "date" },
      "tag_scheme" : { "type" : "string", "index" : "not_analyzed" },
      "account" : { "type" : "string", "index" : "not_analyzed" },
      "violator_count" : { "type" : "long" },
      "violators" : {
        "properties" : {
          "tags" : { "type" : "string", "index" : "not_analyzed" },
          "region" : { "type" : "string", "index" : "not_analyzed" },
          "id" : { "type" : "string", "index" : "not_analyzed" },
          "state" : { "type" : "string", "index" : "not_analyzed" }
        }
      }
    }
  }
}

{
  "aws_tag_violator": {
    "properties" : {
      "@timestamp" : { "format" : "dateOptionalTime", "type" : "date" },
      "tags" : { "type" : "string", "index" : "not_analyzed" },
      "region" : { "type" : "string", "index" : "not_analyzed" },
      "id" : { "type" : "string", "index" : "not_analyzed" },
      "state" : { "type" : "string", "index" : "not_analyzed" },
      "account" : { "type" : "string", "index" : "not_analyzed" }
    }
  }
}

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
      "Action": "ec2:Describe*",
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
