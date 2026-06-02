# Creating the s3 bucket to store the vpc flow logs

resource "aws_s3_bucket" "flow_logs_bucket" {
  bucket                  = "vpc-flow-logs-${data.aws_caller_identity.current.account_id}"
  force_destroy           = true

  tags                    = {
    Name                  = "vpc-flow-logs"
    Purpose               = "Network Security Auditing"
  }
}

resource "aws_s3_bucket_public_access_block" "flow_logs_bucket" {
  bucket                  = aws_s3_bucket.flow_logs_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "flow_logs_bucket"{
  bucket                  = aws_s3_bucket.flow_logs_bucket.id

  versioning_configuration {
    status                = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "flow_logs_bucket" {
  bucket                  = aws_s3_bucket.flow_logs_bucket.id

  rule {
    id                    = "expire-old-logs"
    status                = "Enabled"

    expiration {
      days                = 90
    }
  }
}


# Creating Cloudwatch Log Group

resource "aws_cloudwatch_log_group" "flow_logs" {
  name                    = "/aws/vpc/flow-logs"
  retention_in_days       = 30

  tags {
    Name                  = "vpc-flow-logs"
    Purpose               = "Network Security Auditing"
  }
}

# Creating the IAM Role shared by both destinations

resource "aws_iam_role" "flow_logs_role" {
  name                    = "vpc-flow-logs-role"

  assume_role_policy      = jsonencode ({
    Version               = "2012-10-17"
    Statement             = [
      {
        Effect            = "Allow"
        Principal         = {
          Service         = "aws-flow-logs.amazonaws.com"
        }
        Action            = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "flow_logs_policy" {
  name                    = "vpc-flow-logs-policy"
  role                    = aws_iam_role.flow_logs_role.id

  policy                  = jsonencode ({
    Version               = "2012-10-17"
    Statement             = [
      # Cloudwatch permissions
      {
        Effect            = "Allow"
        Action            = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource          = "${aws_cloudwatch_log_group.flow_logs.arn}:*"
      },
      # S3 permissions
      {
        Effect            = "Allow"
        Action            = [
          "s3:PutObject"
        ]
        Resource          = "${aws_s3_bucket.flow_logs_bucket.arn}/*"
      }
    ]
  })
}


# Sending VPC Flow Logs to Cloudwatch

resource "aws_flow_logs" "cloudwatch" {
  vpc_id                  = aws_vpc.auditor_vpc.id
  traffic_type            = "ALL"
  iam_role_arn            = aws_iam_role.flow_logs_role.arn
  log_destination         = aws_cloudwatch_log_group.flow_logs.arn
  log_destination_type    = "cloud-watch-logs"

  tags                    = {
    Name                  = "vpc-flow-log-cloudwatch"
  }
}

# Sending VPC Flow Logs to S3

resource "aws_flow_logs" "s3" {
  vpc_id                  = aws_vpc.auditor_vpc.id
  traffic_type            = "ALL"
  iam_role_arn            = aws_iam_role.flow_logs_role.arn
  log_destination         = aws_s3_bucket.flow_logs_bucket.arn
  log_destination_type    = "s3"

  tags                    = {
    Name                  = "vpc-flow-log-s3"
  }
}