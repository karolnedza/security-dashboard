# --- BENCHMARK ---

benchmark "aws_security_compliance_benchmark" {
  title       = "AWS Security Standard Compliance"
  description = "Custom benchmark for monitoring infrastructure security posture."
  children = [
    control.ebs_encryption_by_default_enabled,
    control.unattached_security_groups,
    control.unattached_security_groups_24h,
    control.efs_encryption_at_rest_enabled,
    control.ebs_attached_volume_encryption_enabled,
    control.guardduty_enabled,
    control.vpc_flow_logs_enabled,
    control.restricted_ingress_ports,
    control.iam_user_access_key_age_90,
    control.cloudtrail_trail_exists,
    control.cloudtrail_trail_integrated_with_logs,
    control.cloudfront_distribution_logging_enabled,
    control.ecr_repository_image_scan_on_push_enabled,
    control.ecs_task_definition_container_environment_no_secrets,
    control.eks_cluster_logging_enabled,
    control.eks_cluster_endpoint_public_access_disabled,
    control.alb_clb_access_logging_enabled,
    # --- NEW BENCHMARK CONTROL ---
    control.s3_bucket_logging_enabled
  ]
}

# --- DASHBOARD ---

dashboard "aws_security_dashboard" {
  title = "AWS Compliance Dashboard"

  container {
    card {
      query = query.ebs_encryption_enabled_count
      width = 3
    }
    card {
      query = query.unattached_sg_count
      width = 3
    }
    card {
      query = query.guardduty_enabled_count
      width = 3
    }
    card {
      query = query.vpc_flow_logs_count
      width = 3
    }
  }

  container {
    card {
      query = query.iam_access_keys_older_than_90_days_count
      width = 6
    }
    card {
      query = query.cloudtrail_trail_count
      width = 6
    }
  }

  container {
    title = "Detailed Compliance Status"

    table {
      title = "Storage & EBS Compliance"
      query = query.ebs_encryption_by_default_enabled
    }

    table {
      title = "Security Group & Port Ingress"
      query = query.restricted_ingress_ports
    }

    table {
      title = "Orphaned Security Groups (> 24h)"
      query = query.unattached_security_groups_24h
    }

    table {
      title = "IAM Access Key Rotation"
      query = query.iam_user_access_key_age_90
    }

    table {
      title = "CloudTrail Configuration & Integration"
      query = query.cloudtrail_trail_exists
    }

    table {
      title = "CloudTrail CloudWatch Integration"
      query = query.cloudtrail_trail_integrated_with_logs
    }

    table {
      title = "CloudFront Distribution Access Logging"
      query = query.cloudfront_distribution_logging_enabled
    }

    table {
      title = "S3 Bucket Server Access Logging"
      query = query.s3_bucket_logging_enabled
    }

    table {
      title = "ECR Image Scanning Configuration"
      query = query.ecr_repository_image_scan_on_push_enabled
    }

    table {
      title = "ECS Container Plaintext Secrets"
      query = query.ecs_task_definition_container_environment_no_secrets
    }

    table {
      title = "EKS Cluster Control Plane Logging"
      query = query.eks_cluster_logging_enabled
    }

    table {
      title = "EKS Public API Endpoint Access"
      query = query.eks_cluster_endpoint_public_access_disabled
    }

    table {
      title = "ALB & CLB Access Logging"
      query = query.alb_clb_access_logging_enabled
    }

    table {
      title = "GuardDuty & Logging Status"
      query = query.guardduty_enabled
    }
  }
}

# --- CONTROLS ---

control "ebs_encryption_by_default_enabled" {
  title = "EBS encryption by default should be enabled"
  query = query.ebs_encryption_by_default_enabled
}

control "unattached_security_groups" {
  title = "All non-default security groups should be attached to at least one ENI"
  query = query.unattached_security_groups
}

control "unattached_security_groups_24h" {
  title = "Security groups should not remain unattached/orphaned for more than 24 hours"
  query = query.unattached_security_groups_24h
}

control "efs_encryption_at_rest_enabled" {
  title = "EFS file systems should be encrypted at rest"
  query = query.efs_encryption_at_rest_enabled
}

control "ebs_attached_volume_encryption_enabled" {
  title = "Attached EBS volumes should be encrypted"
  query = query.ebs_attached_volume_encryption_enabled
}

control "guardduty_enabled" {
  title = "Amazon GuardDuty should be enabled"
  query = query.guardduty_enabled
}

control "vpc_flow_logs_enabled" {
  title = "VPC flow logs should be enabled on every VPC"
  query = query.vpc_flow_logs_enabled
}

control "restricted_ingress_ports" {
  title = "Security groups should restrict ingress on unauthorized ports"
  query = query.restricted_ingress_ports
}

control "iam_user_access_key_age_90" {
  title = "IAM user access keys should be rotated every 90 days or less"
  query = query.iam_user_access_key_age_90
}

control "cloudtrail_trail_exists" {
  title = "At least one CloudTrail trail should exist in the account"
  query = query.cloudtrail_trail_exists
}

control "cloudtrail_trail_integrated_with_logs" {
  title = "CloudTrail trails should send logs to CloudWatch Logs"
  query = query.cloudtrail_trail_integrated_with_logs
}

control "cloudfront_distribution_logging_enabled" {
  title = "CloudFront distributions should deliver access logs to an S3 bucket"
  query = query.cloudfront_distribution_logging_enabled
}

control "ecr_repository_image_scan_on_push_enabled" {
  title = "ECR private repositories should have image scanning enabled on push"
  query = query.ecr_repository_image_scan_on_push_enabled
}

control "ecs_task_definition_container_environment_no_secrets" {
  title = "Secrets should not be passed as plain text environment variables in ECS container definitions"
  query = query.ecs_task_definition_container_environment_no_secrets
}

control "eks_cluster_logging_enabled" {
  title = "EKS clusters should have logging enabled for all log types"
  query = query.eks_cluster_logging_enabled
}

control "eks_cluster_endpoint_public_access_disabled" {
  title = "EKS cluster API server endpoints should not be publicly accessible"
  query = query.eks_cluster_endpoint_public_access_disabled
}

control "alb_clb_access_logging_enabled" {
  title = "ALB and CLB load balancers should have access logging enabled"
  query = query.alb_clb_access_logging_enabled
}

# --- NEW CONTROL ---

control "s3_bucket_logging_enabled" {
  title = "S3 buckets should have server access logging enabled"
  query = query.s3_bucket_logging_enabled
}

# --- QUERIES ---

query "ebs_encryption_by_default_enabled" {
  sql = <<-EOQ
    select
      'arn:aws:ec2:' || region || ':' || account_id as resource,
      case
        when default_ebs_encryption_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when default_ebs_encryption_enabled then 'EBS encryption by default is enabled.'
        else 'EBS encryption by default is disabled.'
      end as reason,
      region,
      account_id
    from
      aws_ec2_regional_settings;
  EOQ
}

query "unattached_security_groups" {
  sql = <<-EOQ
    with attached_sgs as (
      select
        distinct sg_id
      from
        aws_ec2_network_interface,
        jsonb_array_elements(groups) as g
        left join lateral (select g ->> 'GroupId' as sg_id) as t on true
    )
    select
      sg.group_id as resource,
      case
        when sg.group_name = 'default' then 'ok'
        when a.sg_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when sg.group_name = 'default' then sg.group_id || ' is a default security group.'
        when a.sg_id is null then sg.group_id || ' is not attached to any ENI.'
        else sg.group_id || ' is attached to an ENI.'
      end as reason,
      region,
      account_id
    from
      aws_vpc_security_group as sg
      left join attached_sgs as a on sg.group_id = a.sg_id;
  EOQ
}

query "unattached_security_groups_24h" {
  sql = <<-EOQ
    with attached_sgs as (
      select
        distinct sg_id
      from
        aws_ec2_network_interface,
        jsonb_array_elements(groups) as g
        left join lateral (select g ->> 'GroupId' as sg_id) as t on true
    )
    select
      sg.group_id as resource,
      case
        when sg.group_name = 'default' then 'ok'
        when a.sg_id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when sg.group_name = 'default' then sg.group_id || ' is a default security group.'
        when a.sg_id is not null then sg.group_id || ' is attached to an ENI.'
        else sg.group_id || ' is unattached and orphaned for more than 24 hours.'
      end as reason,
      region,
      account_id
    from
      aws_vpc_security_group as sg
      left join attached_sgs as a on sg.group_id = a.sg_id;
  EOQ
}

query "efs_encryption_at_rest_enabled" {
  sql = <<-EOQ
    select
      arn as resource,
      case when encrypted then 'ok' else 'alarm' end as status,
      case when encrypted then title || ' is encrypted.' else title || ' is not encrypted.' end as reason,
      region, account_id
    from aws_efs_file_system;
  EOQ
}

query "ebs_attached_volume_encryption_enabled" {
  sql = <<-EOQ
    select
      arn as resource,
      case when encrypted then 'ok' else 'alarm' end as status,
      case when encrypted then title || ' is encrypted.' else title || ' is unencrypted.' end as reason,
      region, account_id
    from aws_ebs_volume where state = 'in-use';
  EOQ
}

query "guardduty_enabled" {
  sql = <<-EOQ
    with detectors as (
      select region, count(*) as count from aws_guardduty_detector group by region
    )
    select
      'arn:aws:guardduty:' || r.name || ':' || r.account_id as resource,
      case when d.count > 0 then 'ok' else 'alarm' end as status,
      case when d.count > 0 then 'GuardDuty enabled.' else 'GuardDuty disabled.' end as reason,
      r.name as region, r.account_id
    from aws_region as r left join detectors as d on d.region = r.name;
  EOQ
}

query "vpc_flow_logs_enabled" {
  sql = <<-EOQ
    with vpc_logs as (
      select resource_id, count(*) as log_count from aws_vpc_flow_log where resource_id like 'vpc-%' group by resource_id
    )
    select
      v.vpc_id as resource,
      case when l.log_count > 0 then 'ok' else 'alarm' end as status,
      case when l.log_count > 0 then v.vpc_id || ' has flow logs.' else v.vpc_id || ' has no flow logs.' end as reason,
      region, account_id
    from aws_vpc as v left join vpc_logs as l on v.vpc_id = l.resource_id;
  EOQ
}

query "restricted_ingress_ports" {
  sql = <<-EOQ
    select
      group_id as resource,
      case
        when cidr_ipv4 = '0.0.0.0/0' and from_port not in (80, 443) then 'alarm'
        else 'ok'
      end as status,
      case
        when cidr_ipv4 = '0.0.0.0/0' and from_port not in (80, 443) then 'Unrestricted access on port ' || from_port
        else 'Restricted or authorized port.'
      end as reason,
      region, account_id
    from aws_vpc_security_group_rule where type = 'ingress';
  EOQ
}

query "iam_user_access_key_age_90" {
  sql = <<-EOQ
    select
      access_key_id as resource,
      case
        when status = 'Active' and create_date <= now() - interval '90 days' then 'alarm'
        else 'ok'
      end as status,
      case
        when status = 'Inactive' then user_name || ' access key ' || access_key_id || ' is inactive.'
        when create_date <= now() - interval '90 days' then user_name || ' access key ' || access_key_id || ' was created ' || extract(day from (now() - create_date)) || ' days ago (exceeds 90 days).'
        else user_name || ' access key ' || access_key_id || ' was created ' || extract(day from (now() - create_date)) || ' days ago.'
      end as reason,
      account_id
    from
      aws_iam_access_key;
  EOQ
}

query "cloudtrail_trail_exists" {
  sql = <<-EOQ
    with trail_count as (
      select count(*) as count from aws_cloudtrail_trail
    )
    select
      'arn:aws:cloudtrail:' || r.name || ':' || r.account_id as resource,
      case
        when t.count > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when t.count > 0 then 'At least one CloudTrail trail exists in the account.'
        else 'No CloudTrail trails exist in the account.'
      end as reason,
      r.name as region,
      r.account_id
    from
      aws_region as r
      cross join trail_count as t;
  EOQ
}

query "cloudtrail_trail_integrated_with_logs" {
  sql = <<-EOQ
    select
      arn as resource,
      case
        when log_group_arn is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when log_group_arn is not null then title || ' is integrated with CloudWatch Logs.'
        else title || ' is not integrated with CloudWatch Logs.'
      end as reason,
      region,
      account_id
    from
      aws_cloudtrail_trail;
  EOQ
}

query "cloudfront_distribution_logging_enabled" {
  sql = <<-EOQ
    select
      arn as resource,
      case
        when logging is not null and (logging ->> 'Enabled')::boolean then 'ok'
        else 'alarm'
      end as status,
      case
        when logging is not null and (logging ->> 'Enabled')::boolean then id || ' logging is enabled.'
        else id || ' logging is disabled.'
      end as reason,
      region,
      account_id
    from
      aws_cloudfront_distribution;
  EOQ
}

query "ecr_repository_image_scan_on_push_enabled" {
  sql = <<-EOQ
    select
      arn as resource,
      case
        when image_scanning_configuration ->> 'ScanOnPush' = 'true' then 'ok'
        else 'alarm'
      end as status,
      case
        when image_scanning_configuration ->> 'ScanOnPush' = 'true' then repository_name || ' image scanning on push is enabled.'
        else repository_name || ' image scanning on push is disabled.'
      end as reason,
      region,
      account_id
    from
      aws_ecr_repository;
  EOQ
}

query "ecs_task_definition_container_environment_no_secrets" {
  sql = <<-EOQ
    with container_env_vars as (
      select
        task_definition_arn,
        coalesce(c ->> 'name', c ->> 'Name') as container_name,
        coalesce(e ->> 'name', e ->> 'Name') as env_name
      from
        aws_ecs_task_definition,
        jsonb_array_elements(container_definitions) as c,
        jsonb_array_elements(
          case
            when c -> 'environment' is not null then c -> 'environment'
            when c -> 'Environment' is not null then c -> 'Environment'
            else '[]'::jsonb
          end
        ) as e
    ),
    violating_tasks as (
      select
        task_definition_arn,
        string_agg(distinct container_name || ':' || env_name, ', ') as violations
      from
        container_env_vars
      where
        upper(env_name) in (
          'AWS_ACCESS_KEY_ID',
          'AWS_SECRET_ACCESS_KEY',
          'AWS_SESSION_TOKEN',
          'DB_PASSWORD',
          'DATABASE_URL',
          'REDIS_AUTH',
          'NPM_TOKEN',
          'GITHUB_TOKEN',
          'API_KEY',
          'SECRET_KEY',
          'JWT_SECRET',
          'ENCRYPTION_KEY',
          'PRIVATE_KEY'
        )
      group by
        task_definition_arn
    )
    select
      td.task_definition_arn as resource,
      case
        when v.task_definition_arn is not null then 'alarm'
        else 'ok'
      end as status,
      case
        when v.task_definition_arn is not null then td.title || ' contains sensitive secrets in environment variables (' || v.violations || ').'
        else td.title || ' has no secrets passed as container environment variables.'
      end as reason,
      td.region,
      td.account_id
    from
      aws_ecs_task_definition as td
      left join violating_tasks as v on td.task_definition_arn = v.task_definition_arn;
  EOQ
}

query "eks_cluster_logging_enabled" {
  sql = <<-EOQ
    with cluster_logging as (
      select
        arn,
        name,
        region,
        account_id,
        jsonb_array_elements(
          case
            when logging is null then '[]'::jsonb
            else logging
          end
        ) as l
      from
        aws_eks_cluster
    ),
    enabled_types as (
      select
        arn,
        jsonb_array_elements_text(coalesce(l -> 'types', l -> 'Types', '[]'::jsonb)) as log_type
      from
        cluster_logging
      where
        coalesce((l ->> 'enabled')::boolean, (l ->> 'Enabled')::boolean, false) = true
    ),
    cluster_type_counts as (
      select
        arn,
        count(distinct log_type) as enabled_count
      from
        enabled_types
      where
        log_type in ('api', 'audit', 'authenticator', 'controllerManager', 'scheduler')
      group by
        arn
    )
    select
      c.arn as resource,
      case
        when t.enabled_count = 5 then 'ok'
        else 'alarm'
      end as status,
      case
        when t.enabled_count = 5 then c.name || ' has logging enabled for all log types.'
        else c.name || ' does not have logging enabled for all log types.'
      end as reason,
      c.region,
      c.account_id
    from
      aws_eks_cluster as c
      left join cluster_type_counts as t on c.arn = t.arn;
  EOQ
}

query "eks_cluster_endpoint_public_access_disabled" {
  sql = <<-EOQ
    select
      arn as resource,
      case
        when coalesce((resources_vpc_config ->> 'endpointPublicAccess')::boolean, (resources_vpc_config ->> 'EndpointPublicAccess')::boolean, false) then 'alarm'
        else 'ok'
      end as status,
      case
        when coalesce((resources_vpc_config ->> 'endpointPublicAccess')::boolean, (resources_vpc_config ->> 'EndpointPublicAccess')::boolean, false) then name || ' API server endpoint is publicly accessible.'
        else name || ' API server endpoint is not publicly accessible.'
      end as reason,
      region,
      account_id
    from
      aws_eks_cluster;
  EOQ
}

query "alb_clb_access_logging_enabled" {
  sql = <<-EOQ
    with alb_logging as (
      select
        arn as resource,
        case
          when lb ->> 'Value' = 'true' then 'ok'
          else 'alarm'
        end as status,
        case
          when lb ->> 'Value' = 'true' then title || ' access logging enabled.'
          else title || ' access logging disabled.'
        end as reason,
        region,
        account_id
      from
        aws_ec2_application_load_balancer
        cross join jsonb_array_elements(load_balancer_attributes) as lb
      where
        type = 'application'
        and lb ->> 'Key' = 'access_logs.s3.enabled'
    ),
    clb_logging as (
      select
        arn as resource,
        case
          when access_log_enabled then 'ok'
          else 'alarm'
        end as status,
        case
          when access_log_enabled then title || ' access logging enabled.'
          else title || ' access logging disabled.'
        end as reason,
        region,
        account_id
      from
        aws_ec2_classic_load_balancer
    )
    select * from alb_logging
    union all
    select * from clb_logging;
  EOQ
}

# --- NEW QUERY ---

query "s3_bucket_logging_enabled" {
  sql = <<-EOQ
    select
      arn as resource,
      case
        when logging is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when logging is not null then name || ' server access logging enabled.'
        else name || ' server access logging disabled.'
      end as reason,
      region,
      account_id
    from
      aws_s3_bucket;
  EOQ
}

# --- SUMMARY CARD QUERIES ---

query "ebs_encryption_enabled_count" {
  sql = "select 'EBS Encryption Defaults' as label, count(*) as value from aws_ec2_regional_settings where is_ebs_encryption_by_default_enabled;"
}

query "unattached_sg_count" {
  sql = "select 'Unattached SGs' as label, count(*) as value, 'alert' as type from aws_vpc_security_group where group_name <> 'default' and group_id not in (select distinct sg_id from aws_ec2_network_interface, jsonb_array_elements(groups) as g left join lateral (select g ->> 'GroupId' as sg_id) as t on true);"
}

query "guardduty_enabled_count" {
  sql = "select 'GuardDuty Detectors' as label, count(*) as value from aws_guardduty_detector;"
}

query "vpc_flow_logs_count" {
  sql = "select 'VPCs with Flow Logs' as label, count(distinct resource_id) as value from aws_vpc_flow_log where resource_id like 'vpc-%';"
}

query "iam_access_keys_older_than_90_days_count" {
  sql = "select 'Active Access Keys > 90 Days' as label, count(*) as value, 'alert' as type from aws_iam_access_key where status = 'Active' and create_date <= now() - interval '90 days';"
}

query "cloudtrail_trail_count" {
  sql = "select 'CloudTrail Trails' as label, count(*) as value from aws_cloudtrail_trail;"
}