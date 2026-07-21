# --- BENCHMARK ---

benchmark "aws_security_compliance_benchmark" {
  title       = "AWS Security Standard Compliance"
  description = "Custom benchmark for monitoring infrastructure security posture."
  children = [
    control.ebs_encryption_by_default_enabled,
    control.unattached_security_groups,
    control.efs_encryption_at_rest_enabled,
    control.ebs_attached_volume_encryption_enabled,
    control.guardduty_enabled,
    control.vpc_flow_logs_enabled,
    control.restricted_ingress_ports,
    # --- ADDED BENCHMARK CONTROLS ---
    control.iam_user_access_key_age_90,
    control.cloudtrail_trail_exists
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
      title = "IAM Access Key Rotation"
      query = query.iam_user_access_key_age_90
    }

    table {
      title = "CloudTrail Configuration"
      query = query.cloudtrail_trail_exists
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

# --- ADDED CONTROLS ---

control "iam_user_access_key_age_90" {
  title = "IAM user access keys should be rotated every 90 days or less"
  query = query.iam_user_access_key_age_90
}

control "cloudtrail_trail_exists" {
  title = "At least one CloudTrail trail should exist in the account"
  query = query.cloudtrail_trail_exists
}

# --- QUERIES ---

query "ebs_encryption_by_default_enabled" {
  # UPDATED: Using 'is_ebs_encryption_by_default_enabled' based on schema behavior
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

# --- ADDED QUERIES ---

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

# --- SUMMARY CARD QUERIES ---

query "ebs_encryption_enabled_count" {
  # UPDATED: Match logic for is_ebs_encryption_by_default_enabled
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

# --- ADDED SUMMARY CARD QUERIES ---

query "iam_access_keys_older_than_90_days_count" {
  sql = "select 'Active Access Keys > 90 Days' as label, count(*) as value, 'alert' as type from aws_iam_access_key where status = 'Active' and create_date <= now() - interval '90 days';"
}

query "cloudtrail_trail_count" {
  sql = "select 'CloudTrail Trails' as label, count(*) as value from aws_cloudtrail_trail;"
}